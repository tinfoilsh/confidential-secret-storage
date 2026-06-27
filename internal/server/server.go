// Package server implements the HTTP handlers for the confidential-secret-storage
// enclave: /health, /store, and /pull.
//
// /store encrypts and stores data with a caller-supplied key via a BucketStore.
// /pull releases all stored data, gated by attested-client verification: the
// caller must present a valid SNP/TDX attestation bound to a TLS client
// certificate whose code measurement matches an allow-listed repo.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tinfoilsh/confidential-secret-storage/internal/store"
)

// Item is the metadata record for a stored secret.
type Item struct {
	ID        string          `json:"id"`
	Metadata  json.RawMessage `json:"metadata"`
	Size      int             `json:"size"`
	CreatedAt time.Time       `json:"created_at"`
}

// Server holds the BucketStore, in-memory index, per-item keystore, and
// attestation config for /pull verification.
type Server struct {
	store   store.BucketStore
	attCfg  *AttestationConfig
	mu      sync.RWMutex
	items   map[string]*Item  // itemID -> metadata
	keys    map[string][]byte // itemID -> encryption key (v0: in-memory)
}

// New returns a Server backed by the given BucketStore. Pass a non-nil
// attCfg to enable attested-client verification on /pull; pass nil to
// allow /pull without attestation (dev/test only).
func New(s store.BucketStore, attCfg *AttestationConfig) *Server {
	return &Server{
		store:  s,
		attCfg: attCfg,
		items:  make(map[string]*Item),
		keys:   make(map[string][]byte),
	}
}

// StoreRequest is the JSON body for POST /store.
type StoreRequest struct {
	Data string          `json:"data"` // base64-encoded plaintext
	ID   json.RawMessage `json:"id"`   // arbitrary metadata JSON
	Key  string          `json:"key"`  // base64-encoded 32-byte AES key
}

// StoreResponse is the JSON response for POST /store.
type StoreResponse struct {
	ItemID string `json:"item_id"`
}

// PullItem is one decrypted secret returned by POST /pull.
type PullItem struct {
	ID       string          `json:"id"`
	Data     string          `json:"data"`     // base64-encoded plaintext
	Metadata json.RawMessage `json:"metadata"`
}

// PullResponse is the JSON response for POST /pull.
type PullResponse struct {
	Items []PullItem `json:"items"`
}

// Routes returns the HTTP handler with all routes registered.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/store", s.handleStore)
	mux.HandleFunc("/pull", s.handlePull)
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

func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Attested-client verification: verify the caller's SNP attestation,
	// bind the TLS client cert to the attested key, and (optionally) check
	// the code measurement against a Sigstore-published release.
	var repo string
	if s.attCfg != nil {
		var err error
		repo, err = verifyAttestedClient(r, s.attCfg)
		if err != nil {
			log.Printf("/pull rejected: %v", err)
			writeError(w, http.StatusForbidden, "attested client required: "+err.Error())
			return
		}
	} else {
		// Dev/test mode: no attestation required.
		repo = "dev"
	}
	log.Printf("/pull: releasing all items to attested client (repo=%s)", repo)

	s.mu.RLock()
	ids := make([]string, 0, len(s.items))
	for id := range s.items {
		ids = append(ids, id)
	}
	s.mu.RUnlock()

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	items := make([]PullItem, 0, len(ids))
	for _, id := range ids {
		s.mu.RLock()
		key := s.keys[id]
		meta := s.items[id]
		s.mu.RUnlock()

		plaintext, err := s.store.Get(ctx, id, key)
		if err != nil {
			log.Printf("/pull: error retrieving item %s: %v", id, err)
			continue
		}

		items = append(items, PullItem{
			ID:       id,
			Data:     base64.StdEncoding.EncodeToString(plaintext),
			Metadata: meta.Metadata,
		})
	}

	log.Printf("/pull: released %d items", len(items))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PullResponse{Items: items})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ItemCount returns the number of stored items (for health/diagnostics).
func (s *Server) ItemCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

// String returns a summary string for logging.
func (s *Server) String() string {
	return fmt.Sprintf("storage-server(items=%d)", s.ItemCount())
}
