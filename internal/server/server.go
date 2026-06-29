// Package server implements the HTTP handlers for the confidential-secret-storage
// enclave: /health, /store, and /push.
//
// /store encrypts and stores data with a caller-supplied key via a BucketStore.
// /push verifies the consumer enclave's attestation via tinfoil-go's SecureClient,
// then pushes all stored secrets to the consumer's /receive endpoint over attested TLS.
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tinfoilsh/confidential-secret-storage/internal/store"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

type Item struct {
	ID        string          `json:"id"`
	Metadata  json.RawMessage `json:"metadata"`
	Size      int             `json:"size"`
	CreatedAt time.Time       `json:"created_at"`
}

type Server struct {
	store        store.BucketStore
	mu           sync.RWMutex
	items        map[string]*Item
	keys         map[string][]byte
	consumerHost string
	consumerRepo string
}

func New(s store.BucketStore, consumerHost, consumerRepo string) *Server {
	return &Server{
		store:        s,
		items:        make(map[string]*Item),
		keys:         make(map[string][]byte),
		consumerHost: consumerHost,
		consumerRepo: consumerRepo,
	}
}

type StoreRequest struct {
	Data string          `json:"data"`
	ID   json.RawMessage `json:"id"`
	Key  string          `json:"key"`
}

type StoreResponse struct {
	ItemID string `json:"item_id"`
}

type PushResponse struct {
	Pushed int `json:"pushed"`
}

type ReceiveItem struct {
	ID       string          `json:"id"`
	Data     string          `json:"data"`
	Metadata json.RawMessage `json:"metadata"`
}

// Routes returns the HTTP handler with all routes registered.
func (s *Server) Routes() http.Handler {	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/store", s.handleStore)
	mux.HandleFunc("/push", s.handlePush)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "decoding request: "+err.Error())
		return
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "decoding data: "+err.Error())
		return
	}

	key, err := store.DecodeKey(req.Key)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	itemID := uuid.NewString()

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := s.store.Put(ctx, itemID, plaintext, key); err != nil {
		writeError(w, http.StatusInternalServerError, "storing item: "+err.Error())
		return
	}

	s.mu.Lock()
	s.items[itemID] = &Item{
		ID:        itemID,
		Metadata:  req.ID,
		Size:      len(plaintext),
		CreatedAt: time.Now().UTC(),
	}
	s.keys[itemID] = key
	s.mu.Unlock()

	log.Printf("/store: stored item %s (%d bytes)", itemID, len(plaintext))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(StoreResponse{ItemID: itemID})
}

// handlePush verifies the consumer enclave's attestation via tinfoil-go's
// SecureClient, then pushes all stored secrets to the consumer's /receive
// endpoint over attested TLS.
func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.consumerHost == "" || s.consumerRepo == "" {
		writeError(w, http.StatusInternalServerError, "consumer host/repo not configured")
		return
	}

	sc := client.NewSecureClient(s.consumerHost, s.consumerRepo)
	httpClient, err := sc.HTTPClient()
	if err != nil {
		log.Printf("/push: consumer attestation verification failed: %v", err)
		writeError(w, http.StatusBadGateway, "consumer attestation failed: "+err.Error())
		return
	}
	log.Printf("/push: consumer attested (repo=%s, tls=%s)", s.consumerRepo, sc.GroundTruth().TLSPublicKey)

	s.mu.RLock()
	ids := make([]string, 0, len(s.items))
	for id := range s.items {
		ids = append(ids, id)
	}
	s.mu.RUnlock()

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	items := make([]ReceiveItem, 0, len(ids))
	for _, id := range ids {
		s.mu.RLock()
		key := s.keys[id]
		meta := s.items[id]
		s.mu.RUnlock()

		plaintext, err := s.store.Get(ctx, id, key)
		if err != nil {
			log.Printf("/push: error retrieving item %s: %v", id, err)
			continue
		}

		items = append(items, ReceiveItem{
			ID:       id,
			Data:     base64.StdEncoding.EncodeToString(plaintext),
			Metadata: meta.Metadata,
		})
	}

	body, _ := json.Marshal(items)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+s.consumerHost+"/receive", nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(bytes.NewReader(body))

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("/push: error pushing to consumer: %v", err)
		writeError(w, http.StatusBadGateway, "push to consumer failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("consumer returned %d", resp.StatusCode))
		return
	}

	log.Printf("/push: pushed %d items to consumer", len(items))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PushResponse{Pushed: len(items)})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
