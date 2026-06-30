package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func testStore(t *testing.T) Store {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB tests")
	}
	store, err := NewStore(context.Background(), url)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
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

func TestStoreItemsByUser(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	store.PutItem(ctx, "test-id1", "alice", json.RawMessage(`{}`))
	store.PutItem(ctx, "test-id2", "alice", json.RawMessage(`{}`))
	store.PutItem(ctx, "test-id3", "bob", json.RawMessage(`{}`))

	items, err := store.ItemsByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ItemsByUser: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items for alice, got %d", len(items))
	}
	for _, it := range items {
		if it.UserID != "alice" {
			t.Fatalf("expected alice, got %s", it.UserID)
		}
	}
}
