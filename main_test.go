package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		buckets:      NewBucketsClient(""),
		items:        make(map[string]item),
		consumerHost: "",
		consumerRepo: "",
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

func TestStoreAndPushNoConsumer(t *testing.T) {
	// Stand up a fake sidecar that just stores in memory
	var stored []byte
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			stored = make([]byte, r.ContentLength)
			r.Body.Read(stored)
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer sidecar.Close()

	srv := &Server{
		buckets:      NewBucketsClient(sidecar.URL),
		items:        make(map[string]item),
		consumerHost: "",
		consumerRepo: "",
	}

	// Store an item
	storeBody, _ := json.Marshal(map[string]string{
		"data": "bXkgc2VjcmV0", // "my secret"
	})
	req := httptest.NewRequest(http.MethodPost, "/store", bytes.NewReader(storeBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.handleStore(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("/store: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(stored) == 0 {
		t.Fatal("sidecar received no data")
	}

	// Push without consumer configured should fail at attestation
	req = httptest.NewRequest(http.MethodPost, "/push", nil)
	rec = httptest.NewRecorder()
	srv.handlePush(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("/push without consumer: expected 502, got %d", rec.Code)
	}
}
