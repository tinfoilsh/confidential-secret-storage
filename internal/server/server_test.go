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
	return New(store.NewInEnclaveStore(), nil)
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

func TestStoreAndPull(t *testing.T) {
	srv := newTestServer(t)

	// Store a secret
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

	// Pull without attestation (nil attCfg = dev/test mode, should succeed)
	req = httptest.NewRequest(http.MethodPost, "/pull", nil)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/pull without attestation in dev mode: expected 200, got %d", rec.Code)
	}

	// Pull should return the stored item
	req = httptest.NewRequest(http.MethodPost, "/pull", nil)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/pull with verified header: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var pullResp PullResponse
	if err := json.NewDecoder(rec.Body).Decode(&pullResp); err != nil {
		t.Fatalf("decoding pull response: %v", err)
	}
	if len(pullResp.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(pullResp.Items))
	}

	decoded, err := base64.StdEncoding.DecodeString(pullResp.Items[0].Data)
	if err != nil {
		t.Fatalf("decoding item data: %v", err)
	}
	if string(decoded) != "my secret" {
		t.Fatalf("item data = %q, want %q", decoded, "my secret")
	}
}

func TestStoreMultipleAndPullAll(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "/pull", nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/pull: expected 200, got %d", rec.Code)
	}

	var pullResp PullResponse
	json.NewDecoder(rec.Body).Decode(&pullResp)
	if len(pullResp.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(pullResp.Items))
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
