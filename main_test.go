package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-dependent tests")
	}
	meta, err := newMetadata(context.Background(), url)
	if err != nil {
		t.Fatalf("newMetadata: %v", err)
	}
	t.Cleanup(func() { meta.Close() })
	return &Server{
		buckets:      NewBucketsClient("", "secret-storage"),
		meta:         meta,
		keys:         make(map[string][]byte),
		consumerRepo: "tinfoilsh/confidential-debug-secret-consumer",
	}
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestStoreRequiresKey(t *testing.T) {
	srv := newTestServer(t)

	body, _ := json.Marshal(map[string]string{
		"user_id": "alice",
		"data":    base64.StdEncoding.EncodeToString([]byte("secret")),
	})
	req := httptest.NewRequest(http.MethodPost, "/store", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleStore(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without uploaded key, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadKeyAndStore(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	srv := newTestServer(t)

	keyBody, _ := json.Marshal(map[string]string{
		"user_id": "alice",
		"key":     base64.StdEncoding.EncodeToString(key),
	})
	req := httptest.NewRequest(http.MethodPost, "/upload_key", bytes.NewReader(keyBody))
	rec := httptest.NewRecorder()
	srv.handleUploadKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/upload_key: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var storedData []byte
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			storedData = make([]byte, r.ContentLength)
			r.Body.Read(storedData)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer sidecar.Close()
	srv.buckets = NewBucketsClient(sidecar.URL, "secret-storage")

	storeBody, _ := json.Marshal(map[string]string{
		"user_id": "alice",
		"data":    base64.StdEncoding.EncodeToString([]byte("my secret")),
	})
	req = httptest.NewRequest(http.MethodPost, "/store", bytes.NewReader(storeBody))
	rec = httptest.NewRecorder()
	srv.handleStore(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("/store: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(storedData) == 0 {
		t.Fatal("sidecar received no data")
	}

	items, err := srv.meta.AllItems(req.Context())
	if err != nil {
		t.Fatalf("AllItems: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item in db, got %d", len(items))
	}
	if items[0].UserID != "alice" {
		t.Fatalf("expected user alice, got %s", items[0].UserID)
	}
}

func TestUploadKeyInvalid(t *testing.T) {
	srv := newTestServer(t)

	body, _ := json.Marshal(map[string]string{
		"user_id": "alice",
		"key":     base64.StdEncoding.EncodeToString([]byte("short")),
	})
	req := httptest.NewRequest(http.MethodPost, "/upload_key", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleUploadKey(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short key, got %d", rec.Code)
	}
}

func TestPushMissingHost(t *testing.T) {
	srv := newTestServer(t)

	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/push", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handlePush(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("/push with missing host: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
