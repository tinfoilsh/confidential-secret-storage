package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating key: %v", err)
	}

	plaintext := []byte("super secret data that needs encryption")
	ciphertext, err := encryptAESGCM(plaintext, key)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	decrypted, err := decryptAESGCM(ciphertext, key)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	ciphertext, err := encryptAESGCM([]byte("secret"), key1)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	_, err = decryptAESGCM(ciphertext, key2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestInEnclaveStoreRoundTrip(t *testing.T) {
	s := NewInEnclaveStore()
	ctx := context.Background()
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("test secret data")
	if err := s.Put(ctx, "item-1", plaintext, key); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get(ctx, "item-1", key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Fatalf("Get returned %q, want %q", got, plaintext)
	}
}

func TestInEnclaveStoreGetMissing(t *testing.T) {
	s := NewInEnclaveStore()
	key := make([]byte, 32)
	rand.Read(key)

	_, err := s.Get(context.Background(), "nonexistent", key)
	if err == nil {
		t.Fatal("expected error for missing item")
	}
}

func TestInEnclaveStoreDelete(t *testing.T) {
	s := NewInEnclaveStore()
	ctx := context.Background()
	key := make([]byte, 32)
	rand.Read(key)

	if err := s.Put(ctx, "item-1", []byte("data"), key); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "item-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "item-1", key); err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestDecodeKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	b64 := base64.StdEncoding.EncodeToString(key)

	decoded, err := DecodeKey(b64)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded key length %d, want 32", len(decoded))
	}
}

func TestDecodeKeyInvalidLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err := DecodeKey(short)
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestEncryptInvalidKeyLength(t *testing.T) {
	_, err := encryptAESGCM([]byte("data"), make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}
