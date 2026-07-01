package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func testStore(t *testing.T) Metadata {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB tests")
	}
	store, err := newMetadata(context.Background(), url)
	if err != nil {
		t.Fatalf("newMetadata: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestStorePutAndAllItems(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	store.PutItem(ctx, "id1", "alice", json.RawMessage(`{"env":"dev"}`))
	store.PutItem(ctx, "id2", "bob", json.RawMessage(`{"env":"prod"}`))

	items, err := store.AllItems(ctx)
	if err != nil {
		t.Fatalf("AllItems: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
}
