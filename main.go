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

type Server struct {
	buckets *Client
	store   Store
	mu      sync.RWMutex
	keys    map[string][]byte // userID -> encryption key (in-memory; re-uploaded via /upload_key)
}

func main() {
	bucketsURL := os.Getenv("BUCKETS_URL")
	if bucketsURL == "" {
		log.Fatal("BUCKETS_URL is required")
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store, err := NewStore(ctx, databaseURL)
	if err != nil {
		log.Fatalf("opening db: %v", err)
	}
	defer store.Close()

	srv := &Server{
		buckets: NewBucketsClient(bucketsURL, "secret-storage"),
		store:   store,
		keys:    make(map[string][]byte),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/upload_key", srv.handleUploadKey)
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

	shutdownCtx, sCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer sCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type uploadKeyRequest struct {
	UserID string `json:"user_id"`
	Key    string `json:"key"`
}

func (s *Server) handleUploadKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req uploadKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	key, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 key")
		return
	}
	if len(key) != 32 {
		writeError(w, http.StatusBadRequest, "key must be 32 bytes after base64 decode")
		return
	}

	s.mu.Lock()
	s.keys[req.UserID] = key
	s.mu.Unlock()

	log.Printf("/upload_key: registered key for user %s", req.UserID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type storeRequest struct {
	UserID   string          `json:"user_id"`
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
	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	s.mu.RLock()
	encKey, ok := s.keys[req.UserID]
	s.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusForbidden, "no key registered for user_id; call /upload_key first")
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 data")
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

	if err := s.store.PutItem(ctx, id, req.UserID, req.Metadata); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("/store: stored item %s for user %s (%d bytes)", id, req.UserID, len(plaintext))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"item_id": id})
}

type pushRequest struct {
	Host string `json:"host"`
	Repo string `json:"repo"`
}

type keyBundle struct {
	ID       string          `json:"id"`
	Key      string          `json:"key"`
	Metadata json.RawMessage `json:"metadata"`
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req pushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Host == "" || req.Repo == "" {
		writeError(w, http.StatusBadRequest, "host and repo are required")
		return
	}

	// Attest the consumer and open an attested TLS channel to it.
	// Keys are delivered over this channel to the consumer's /receive,
	// not returned in the /push response, so only the attested consumer
	// gets the keys - not whoever called /push.
	sc := client.NewSecureClient(req.Host, req.Repo)
	httpClient, err := sc.HTTPClient()
	if err != nil {
		log.Printf("/push: attestation failed for %s (%s): %v", req.Host, req.Repo, err)
		writeError(w, http.StatusBadGateway, "consumer attestation failed: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	items, err := s.store.AllItems(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "querying items: "+err.Error())
		return
	}

	bundles := make([]keyBundle, 0, len(items))
	for _, it := range items {
		s.mu.RLock()
		encKey, ok := s.keys[it.UserID]
		s.mu.RUnlock()
		if !ok {
			log.Printf("/push: no key for user %s, skipping item %s", it.UserID, it.ID)
			continue
		}
		bundles = append(bundles, keyBundle{
			ID:       it.ID,
			Key:      base64.StdEncoding.EncodeToString(encKey),
			Metadata: it.Metadata,
		})
	}

	body, _ := json.Marshal(bundles)
	pushReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+req.Host+"/receive", bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	pushReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(pushReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "push failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("consumer returned %d", resp.StatusCode))
		return
	}

	log.Printf("/push: pushed %d key bundles to %s (%s)", len(bundles), req.Host, req.Repo)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"pushed": len(bundles)})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
