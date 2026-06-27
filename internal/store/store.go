// Package store defines the BucketStore interface and its implementations.
//
// v0 uses an in-enclave AES-256-GCM store that keeps ciphertext in memory
// (ephemeral, lost on restart). v1 will swap in a buckets-sidecar backed
// store that persists encrypted blobs to S3 via the colocated
// tinfoil-buckets-sidecar.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
)

// BucketStore abstracts encrypted blob storage. The caller supplies the
// per-item key; the store handles encryption-at-rest and retrieval.
type BucketStore interface {
	// Put encrypts plaintext under key and stores it at itemID.
	Put(ctx context.Context, itemID string, plaintext, key []byte) error
	// Get retrieves and decrypts the blob at itemID using key.
	Get(ctx context.Context, itemID string, key []byte) ([]byte, error)
	// Delete removes the blob at itemID.
	Delete(ctx context.Context, itemID string) error
}

// inEnclaveStore is the v0 BucketStore: AES-256-GCM with the caller-supplied
// key, ciphertext kept in an in-memory map. Ephemeral; lost on restart.
type inEnclaveStore struct {
	mu  sync.RWMutex
	data map[string][]byte // itemID -> ciphertext (nonce prepended)
}

// NewInEnclaveStore returns a v0 in-memory BucketStore.
func NewInEnclaveStore() BucketStore {
	return &inEnclaveStore{data: make(map[string][]byte)}
}

func (s *inEnclaveStore) Put(_ context.Context, itemID string, plaintext, key []byte) error {
	ciphertext, err := encryptAESGCM(plaintext, key)
	if err != nil {
		return fmt.Errorf("encrypting item %s: %w", itemID, err)
	}
	s.mu.Lock()
	s.data[itemID] = ciphertext
	s.mu.Unlock()
	return nil
}

func (s *inEnclaveStore) Get(_ context.Context, itemID string, key []byte) ([]byte, error) {
	s.mu.RLock()
	ciphertext, ok := s.data[itemID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("item %s not found", itemID)
	}
	return decryptAESGCM(ciphertext, key)
}

func (s *inEnclaveStore) Delete(_ context.Context, itemID string) error {
	s.mu.Lock()
	delete(s.data, itemID)
	s.mu.Unlock()
	return nil
}

// encryptAESGCM encrypts plaintext with AES-256-GCM under key (must be 32
// bytes). The returned ciphertext has the 12-byte nonce prepended.
func encryptAESGCM(plaintext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// decryptAESGCM decrypts a ciphertext (nonce-prepended) with AES-256-GCM.
func decryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return plaintext, nil
}

// DecodeKey decodes a base64-encoded 32-byte AES key.
func DecodeKey(b64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decoding key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes after decode, got %d", len(key))
	}
	return key, nil
}
