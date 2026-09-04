// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package registry

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LocalKMSClient is a single-node KMSClient that persists encryption
// keys as 32-byte AES-256-GCM keys under <root>/<keyID>.key. Used by
// Phase 5.1 to wire image encryption without requiring an external
// QuicBaaS KMS endpoint.
//
// The key files are mode 0600 — same approach the platform uses for
// other on-disk secret material before XKMS is reached. When the
// XKMS-backed KMSClient lands, the Registry's encryptor wiring stays
// identical; only the LocalKMSClient swap to XKMSClient changes.
//
// All encryption is AES-256-GCM with a per-call random 12-byte nonce
// prepended to the ciphertext. The context parameter is bound into
// the GCM additional-authenticated-data so a ciphertext from one
// layer cannot be replayed against another.
type LocalKMSClient struct {
	root string
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewLocalKMSClient creates the keys directory under root and returns
// a ready client. Existing keys on disk are NOT eagerly loaded — they
// are read on first use to keep startup cheap.
func NewLocalKMSClient(root string) (*LocalKMSClient, error) {
	if root == "" {
		return nil, &MessageError{Msg: "registry: kms root cannot be empty"}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("registry: mkdir %s", root), Err: err}
	}
	return &LocalKMSClient{
		root: root,
		keys: make(map[string][]byte),
	}, nil
}

// keyPath returns the on-disk path for a key.
func (c *LocalKMSClient) keyPath(keyID string) string {
	// SHA-256 the keyID so arbitrary user strings can't escape the
	// keys directory via "../" injection.
	sum := sha256.Sum256([]byte(keyID))
	return filepath.Join(c.root, fmt.Sprintf("%x.key", sum))
}

// loadKey returns the raw key material, reading from disk on cache
// miss. Holds c.mu in write mode while populating the cache.
func (c *LocalKMSClient) loadKey(keyID string) ([]byte, error) {
	c.mu.RLock()
	if k, ok := c.keys[keyID]; ok {
		c.mu.RUnlock()
		return k, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.keys[keyID]; ok {
		return k, nil
	}
	data, err := os.ReadFile(c.keyPath(keyID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrKeyNotFoundLocal{KeyID: keyID}
		}
		return nil, err
	}
	if len(data) != 32 {
		return nil, &MessageError{Msg: fmt.Sprintf("registry: kms key %s: invalid length %d", keyID, len(data))}
	}
	c.keys[keyID] = data
	return data, nil
}

// GenerateKey creates a new 32-byte random key, persists it, and
// returns its ID. The supplied algorithm + usage are recorded only as
// best-effort metadata — Phase 5.1 only supports AES-256-GCM and the
// usage flags are advisory.
func (c *LocalKMSClient) GenerateKey(ctx context.Context, name, algorithm string, usage []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", &WrappedError{Msg: "registry: generate key", Err: err}
	}
	keyID := fmt.Sprintf("local-%x", sha256.Sum256([]byte(name+time.Now().Format(time.RFC3339Nano))))[:24]
	path := c.keyPath(keyID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return "", &WrappedError{Msg: fmt.Sprintf("registry: persist key %s", keyID), Err: err}
	}
	c.keys[keyID] = key
	// Persist metadata sidecar so callers asking GetKey for a
	// previously-generated key get reasonable answers.
	meta := KeyInfo{
		KeyID:     keyID,
		Name:      name,
		Algorithm: algorithm,
		Version:   1,
		Usage:     usage,
		CreatedAt: time.Now().UTC(),
	}
	if mb, err := json.Marshal(meta); err == nil {
		_ = os.WriteFile(path+".meta", mb, 0o600)
	}
	return keyID, nil
}

// GetKey returns the metadata for a key without exposing the raw
// material. Used by ImageEncryptor.getOrCreateKey to decide whether
// to GenerateKey.
func (c *LocalKMSClient) GetKey(ctx context.Context, keyID string) (*KeyInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := c.loadKey(keyID); err != nil {
		return nil, err
	}
	metaPath := c.keyPath(keyID) + ".meta"
	if data, err := os.ReadFile(metaPath); err == nil {
		var info KeyInfo
		if err := json.Unmarshal(data, &info); err == nil {
			return &info, nil
		}
	}
	return &KeyInfo{
		KeyID:     keyID,
		Algorithm: "AES-256-GCM",
		Version:   1,
		Usage:     []string{"encrypt", "decrypt", "wrap", "unwrap"},
	}, nil
}

// Encrypt wraps the supplied plaintext under keyID. The context
// parameter is bound as additional authenticated data so a
// ciphertext from one layer cannot be replayed under a different
// layer digest.
func (c *LocalKMSClient) Encrypt(ctx context.Context, keyID string, plaintext, aad []byte) ([]byte, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	key, err := c.loadKey(keyID)
	if err != nil {
		return nil, 0, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, 0, err
	}
	// Wire format: nonce || ciphertext || tag, unchanged. This used to be
	// assembled by hand from cipher.NewGCM plus an explicit rand nonce;
	// NewGCMWithRandomNonce emits exactly the same layout with the same
	// 12-byte nonce, so ciphertexts written before and after this change are
	// interchangeable in both directions (TestLocalKMS_WireFormatUnchanged).
	// The swap is required because cipher.NewGCM itself fails under
	// GODEBUG=fips140=only, which took this path down in a FIPS build (#209).
	return gcm.Seal(nil, nil, plaintext, aad), 1, nil
}

// Decrypt unwraps a ciphertext produced by Encrypt under keyID.
func (c *LocalKMSClient) Decrypt(ctx context.Context, keyID string, ciphertext, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := c.loadKey(keyID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	// The length check stays explicit so a truncated blob keeps reporting a
	// typed platform error rather than the stdlib's opaque "message
	// authentication failed", which is what an undersized input would
	// otherwise produce.
	if len(ciphertext) < NonceSize+TagSize {
		return nil, &MessageError{Msg: "registry: ciphertext too short"}
	}
	// Open splits the nonce prefix itself; the nonce argument must be empty.
	return gcm.Open(nil, nil, ciphertext, aad)
}

// ErrKeyNotFoundLocal is returned when GetKey is asked about a key
// that has never been generated. The wrapping ImageEncryptor reads
// this as a signal to call GenerateKey.
type ErrKeyNotFoundLocal struct {
	KeyID string
}

func (e ErrKeyNotFoundLocal) Error() string {
	return fmt.Sprintf("registry: kms key %s not found", e.KeyID)
}
