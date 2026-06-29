package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

type item struct {
	Key  []byte          // encryption key for the sidecar
	Meta json.RawMessage // caller-supplied metadata
}

type Server struct {
	buckets      *Client
	mu           sync.RWMutex
	items        map[string]item
	consumerHost string
	consumerRepo string
}

func main() {
	bucketsURL := os.Getenv("BUCKETS_URL")
	if bucketsURL == "" {
		log.Fatal("BUCKETS_URL is required")
	}
	consumerHost := os.Getenv("CONSUMER_HOST")
	consumerRepo := os.Getenv("CONSUMER_REPO")
	if consumerHost == "" || consumerRepo == "" {
		log.Fatal("CONSUMER_HOST and CONSUMER_REPO are required")
	}

	srv := &Server{
		buckets:      NewBucketsClient(bucketsURL),
		items:        make(map[string]item),
		consumerHost: consumerHost,
		consumerRepo: consumerRepo,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/store", srv.handleStore)
	mux.HandleFunc("/push", srv.handlePush)

	httpSrv := &http.Server{
		Addr:              ":8089",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	go func() {
		log.Printf("confidential-secret-storage listening on :8089")
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type storeRequest struct {
	Data     string          `json:"data"`
	Metadata json.RawMessage `json:"metadata"`
}

func (s *Server) handleStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req storeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 data")
		return
	}

	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		writeError(w, http.StatusInternalServerError, "generating key: "+err.Error())
		return
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "generating id: "+err.Error())
		return
	}
	id := hex.EncodeToString(idBytes)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := s.buckets.Put(ctx, id, plaintext, encKey); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.mu.Lock()
	s.items[id] = item{Key: encKey, Meta: req.Metadata}
	s.mu.Unlock()

	log.Printf("/store: stored item %s (%d bytes)", id, len(plaintext))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"item_id": id})
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sc := client.NewSecureClient(s.consumerHost, s.consumerRepo)
	httpClient, err := sc.HTTPClient()
	if err != nil {
		log.Printf("/push: attestation failed: %v", err)
		writeError(w, http.StatusBadGateway, "consumer attestation failed: "+err.Error())
		return
	}

	s.mu.RLock()
	ids := make([]string, 0, len(s.items))
	for id := range s.items {
		ids = append(ids, id)
	}
	s.mu.RUnlock()

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	type receiveItem struct {
		ID       string          `json:"id"`
		Data     string          `json:"data"`
		Metadata json.RawMessage `json:"metadata"`
	}
	items := make([]receiveItem, 0, len(ids))
	for _, id := range ids {
		s.mu.RLock()
		it := s.items[id]
		s.mu.RUnlock()

		plaintext, err := s.buckets.Get(ctx, id, it.Key)
		if err != nil {
			log.Printf("/push: retrieving %s: %v", id, err)
			continue
		}
		items = append(items, receiveItem{
			ID:       id,
			Data:     base64.StdEncoding.EncodeToString(plaintext),
			Metadata: it.Meta,
		})
	}

	body, _ := json.Marshal(items)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+s.consumerHost+"/receive", bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "push failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("consumer returned %d", resp.StatusCode))
		return
	}

	log.Printf("/push: pushed %d items to consumer", len(items))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"pushed": len(items)})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
