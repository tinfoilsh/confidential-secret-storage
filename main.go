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
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

type Server struct {
	buckets      *Client
	inventory    InventoryDB // public inventory DB (Postgres); private data is in S3 via Tinfoil buckets
	mu           sync.RWMutex
	keys         map[string][]byte // userID -> encryption key (in-memory; re-uploaded via /upload_key)
	consumerRepo string            // GitHub repo of the consumer to attest (hardcoded trust)
}

func main() {
	bucketsURL := os.Getenv("BUCKETS_URL")
	if bucketsURL == "" {
		log.Fatal("BUCKETS_URL is required")
	}
	consumerRepo := os.Getenv("CONSUMER_REPO")
	if consumerRepo == "" {
		log.Fatal("CONSUMER_REPO is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inventory, err := NewInventoryDBFromEnv(ctx)
	if err != nil {
		log.Fatalf("opening db: %v", err)
	}
	defer inventory.Close()

	srv := &Server{
		buckets:      NewBucketsClient(bucketsURL, "secret-storage"),
		inventory:    inventory,
		keys:         make(map[string][]byte),
		consumerRepo: consumerRepo,
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

	log.Printf("confidential-secret-storage listening on :8089")
	log.Fatal(httpSrv.ListenAndServe())
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

	if err := s.inventory.PutItem(ctx, id, req.UserID, req.Metadata); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("/store: stored item %s for user %s (%d bytes)", id, req.UserID, len(plaintext))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"item_id": id})
}

type pushRequest struct {
	Host string `json:"host"` // consumer's domain, provided by the consumer
}

type keyBundle struct {
	ID  string `json:"id"`
	Key string `json:"key"`
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
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}

	// Attest the consumer using the hardcoded repo (trust decision).
	// Keys are delivered over this attested TLS channel to the consumer's /receive,
	// not returned in the /push response, so only the attested consumer gets them.
	sc := client.NewSecureClient(req.Host, s.consumerRepo)
	httpClient, err := sc.HTTPClient()
	if err != nil {
		log.Printf("/push: attestation failed for %s (%s): %v", req.Host, s.consumerRepo, err)
		writeError(w, http.StatusBadGateway, "consumer attestation failed: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	items, err := s.inventory.AllItems(ctx)
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
			ID:  it.ID,
			Key: base64.StdEncoding.EncodeToString(encKey),
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

	log.Printf("/push: pushed %d key bundles to %s (%s)", len(bundles), req.Host, s.consumerRepo)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"pushed": len(bundles)})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
