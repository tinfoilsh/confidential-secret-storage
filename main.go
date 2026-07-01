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
	consumerRepo := os.Getenv("CONSUMER_REPO")
	if consumerRepo == "" {
		log.Fatal("CONSUMER_REPO is required")
	}

	// Open the inventory DB (Postgres)
	inventory, err := NewInventoryDBFromEnv(context.Background())
	if err != nil {
		log.Fatalf("opening db: %v", err)
	}
	defer inventory.Close()

	// Start the secret storage server
	srv := &Server{
		buckets:      NewBucketsClient(os.Getenv("BUCKETS_URL"), "secret-storage"),
		inventory:    inventory,
		keys:         make(map[string][]byte),
		consumerRepo: consumerRepo,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("POST /upload_key", srv.handleUploadKey)
	mux.HandleFunc("POST /store", srv.handleStore)
	mux.HandleFunc("POST /push", srv.handlePush)

	log.Printf("confidential-secret-storage listening on :8089")
	log.Fatal(http.ListenAndServe(":8089", mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type uploadKeyRequest struct {
	UserID string `json:"user_id"`
	Key    string `json:"key"`
}

func (s *Server) handleUploadKey(w http.ResponseWriter, r *http.Request) {
	var req uploadKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.UserID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	key, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		http.Error(w, "invalid base64 key", http.StatusBadRequest)
		return
	}
	if len(key) != 32 {
		http.Error(w, "key must be 32 bytes after base64 decode", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.keys[req.UserID] = key
	s.mu.Unlock()

	log.Printf("/upload_key: registered key for user %s", req.UserID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type storeRequest struct {
	UserID   string          `json:"user_id"`
	Data     string          `json:"data"`
	Metadata json.RawMessage `json:"metadata"`
}

func (s *Server) handleStore(w http.ResponseWriter, r *http.Request) {
	var req storeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.UserID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	encKey, ok := s.keys[req.UserID]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "no key registered for user_id; call /upload_key first", http.StatusForbidden)
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		http.Error(w, "invalid base64 data", http.StatusBadRequest)
		return
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := hex.EncodeToString(idBytes)

	ctx := r.Context()

	if err := s.buckets.Put(ctx, id, plaintext, encKey); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.inventory.PutItem(ctx, id, req.UserID, req.Metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("/store: stored item %s for user %s (%d bytes)", id, req.UserID, len(plaintext))
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"item_id": id})
}

type pushRequest struct {
	Host string `json:"host"`
}

type keyBundle struct {
	UserID string `json:"user_id"`
	Key    string `json:"key"`
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	var req pushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}

	// Attest the consumer using the hardcoded repo (trust decision).
	// Keys are delivered over this attested TLS channel to the consumer's /receive,
	// not returned in the /push response, so only the attested consumer gets them.
	sc := client.NewSecureClient(req.Host, s.consumerRepo)
	httpClient, err := sc.HTTPClient()
	if err != nil {
		log.Printf("/push: attestation failed for %s (%s): %v", req.Host, s.consumerRepo, err)
		http.Error(w, "consumer attestation failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	s.mu.RLock()
	bundles := make([]keyBundle, 0, len(s.keys))
	for userID, encKey := range s.keys {
		bundles = append(bundles, keyBundle{
			UserID: userID,
			Key:    base64.StdEncoding.EncodeToString(encKey),
		})
	}
	s.mu.RUnlock()

	body, _ := json.Marshal(bundles)
	pushReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://"+req.Host+"/receive", bytes.NewReader(body))
	pushReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(pushReq)
	if err != nil {
		http.Error(w, "push failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("consumer returned %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	log.Printf("/push: pushed %d key bundles to %s (%s)", len(bundles), req.Host, s.consumerRepo)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"pushed": len(bundles)})
}
