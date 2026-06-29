package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/confidential-secret-storage/internal/store"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return New(store.NewInEnclaveStore(), "", "")
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStore(t *testing.T) {
	srv := newTestServer(t)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	storeBody, _ := json.Marshal(map[string]interface{}{
		"data": base64.StdEncoding.EncodeToString([]byte("my secret")),
		"id":   map[string]string{"user": "alice", "env": "dev"},
		"key":  base64.StdEncoding.EncodeToString(key),
	})

	req := httptest.NewRequest(http.MethodPost, "/store", strings.NewReader(string(storeBody)))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("/store: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var storeResp StoreResponse
	if err := json.NewDecoder(rec.Body).Decode(&storeResp); err != nil {
		t.Fatalf("decoding store response: %v", err)
	}
	if storeResp.ItemID == "" {
		t.Fatal("expected non-empty item_id")
	}
}

func TestStoreMultiple(t *testing.T) {
	srv := newTestServer(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	for i := 0; i < 3; i++ {
		storeBody, _ := json.Marshal(map[string]interface{}{
			"data": base64.StdEncoding.EncodeToString([]byte("secret-" + string(rune('A'+i)))),
			"id":   map[string]int{"index": i},
			"key":  base64.StdEncoding.EncodeToString(key),
		})
		req := httptest.NewRequest(http.MethodPost, "/store", strings.NewReader(string(storeBody)))
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("/store[%d]: expected 201, got %d", i, rec.Code)
		}
	}

	srv.mu.RLock()
	got := len(srv.items)
	srv.mu.RUnlock()
	if got != 3 {
		t.Fatalf("expected 3 items, got %d", got)
	}
}

func TestPushWithoutConsumerConfig(t *testing.T) {
	srv := newTestServer(t)

	// Store an item first
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	storeBody, _ := json.Marshal(map[string]interface{}{
		"data": base64.StdEncoding.EncodeToString([]byte("my secret")),
		"key":  base64.StdEncoding.EncodeToString(key),
	})
	req := httptest.NewRequest(http.MethodPost, "/store", strings.NewReader(string(storeBody)))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	// Push without consumer configured should return 500
	req = httptest.NewRequest(http.MethodPost, "/push", nil)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("/push without config: expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStoreMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/store", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestStoreInvalidBase64Data(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(map[string]string{
		"data": "not-valid-base64!!!",
		"key":  base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	req := httptest.NewRequest(http.MethodPost, "/store", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStoreInvalidKey(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(map[string]string{
		"data": base64.StdEncoding.EncodeToString([]byte("data")),
		"key":  base64.StdEncoding.EncodeToString(make([]byte, 16)),
	})
	req := httptest.NewRequest(http.MethodPost, "/store", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short key, got %d: %s", rec.Code, rec.Body.String())
	}
}
