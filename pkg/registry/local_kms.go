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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
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
//
// It is also the registry's single-node SigningKMSClient: one ECDSA P-256
// signing key per key ID, a PKCS#8 PEM file <root>/<sha256(keyID)>.sign.pem
// (mode 0600) created on the key's first use, so encryption and signing
// keys share one directory and one swap.
type LocalKMSClient struct {
	root        string
	mu          sync.RWMutex
	keys        map[string][]byte
	signingKeys map[string]*ecdsa.PrivateKey
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
		root:        root,
		keys:        make(map[string][]byte),
		signingKeys: make(map[string]*ecdsa.PrivateKey),
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
	// Random, not derived from name and time: two keys of the same name made
	// within one clock tick would otherwise share an ID and the second would
	// overwrite the first key file (#284).
	keyID := "local-" + uuid.NewString()
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
	// Wire format: nonce || ciphertext || tag, unchanged since this was
	// assembled by hand from cipher.NewGCM plus an explicit rand nonce, so
	// every stored DEK still opens (TestLocalKMS_WireFormatUnchanged).
	sealed, err := gcm.Seal(key, plaintext, aad)
	if err != nil {
		return nil, 0, err
	}
	return sealed, 1, nil
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
	// A blob shorter than nonce + tag is refused with the typed
	// aesgcm.ErrCiphertextTooShort before any decryption is attempted.
	return gcm.Open(key, ciphertext, aad)
}

// ErrKeyNotFoundLocal is returned when GetKey is asked about a key
// that has never been generated. The wrapping ImageEncryptor reads
// this as a signal to call GenerateKey.
// SignatureAlgorithmECDSAP256SHA256 names the algorithm LocalKMSClient
// signs with: ECDSA over P-256, SHA-256 digest, ASN.1 DER signature.
const SignatureAlgorithmECDSAP256SHA256 = "ECDSA-P256-SHA256"

// signingKeyPEMType is the PEM block type of a persisted signing key.
const signingKeyPEMType = "PRIVATE KEY"

// Sign signs a SHA-256 digest with keyID's signing key, creating the key
// on its first use.
func (c *LocalKMSClient) Sign(ctx context.Context, keyID string, digest []byte) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if keyID == "" {
		return nil, "", &MessageError{Msg: "registry: signing key ID cannot be empty"}
	}
	if len(digest) != sha256.Size {
		return nil, "", &MessageError{Msg: fmt.Sprintf("registry: signing digest must be %d bytes, got %d", sha256.Size, len(digest))}
	}
	key, err := c.signingKey(keyID)
	if err != nil {
		return nil, "", err
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		return nil, "", &WrappedError{Msg: fmt.Sprintf("registry: sign with key %s", keyID), Err: err}
	}
	return sig, SignatureAlgorithmECDSAP256SHA256, nil
}

// signingKeyPath hashes keyID like keyPath; the .sign.pem suffix keeps a
// signing key apart from an encryption key of the same ID.
func (c *LocalKMSClient) signingKeyPath(keyID string) string {
	sum := sha256.Sum256([]byte(keyID))
	return filepath.Join(c.root, fmt.Sprintf("%x.sign.pem", sum))
}

// signingKey returns keyID's signing key, loading it from disk or
// generating and persisting it on first use.
func (c *LocalKMSClient) signingKey(keyID string) (*ecdsa.PrivateKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.signingKeys[keyID]; ok {
		return k, nil
	}
	path := c.signingKeyPath(keyID)
	k, err := loadSigningKey(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err = generateSigningKey(path)
	}
	if err != nil {
		return nil, err
	}
	c.signingKeys[keyID] = k
	return k, nil
}

// loadSigningKey reads a PKCS#8 PEM ECDSA P-256 key from path.
func loadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != signingKeyPEMType {
		return nil, &MessageError{Msg: fmt.Sprintf("registry: signing key %s is not a PEM %s", path, signingKeyPEMType)}
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("registry: parse signing key %s", path), Err: err}
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, &MessageError{Msg: fmt.Sprintf("registry: signing key %s is not ECDSA P-256", path)}
	}
	return key, nil
}

// generateSigningKey creates a P-256 key and writes it to path. O_EXCL
// keeps an existing key from ever being overwritten.
func generateSigningKey(path string) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, &WrappedError{Msg: "registry: generate signing key", Err: err}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, &WrappedError{Msg: "registry: marshal signing key", Err: err}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("registry: create signing key %s", path), Err: err}
	}
	if err := pem.Encode(f, &pem.Block{Type: signingKeyPEMType, Bytes: der}); err != nil {
		return nil, errors.Join(&WrappedError{Msg: fmt.Sprintf("registry: write signing key %s", path), Err: err}, f.Close())
	}
	if err := f.Close(); err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("registry: close signing key %s", path), Err: err}
	}
	return key, nil
}

type ErrKeyNotFoundLocal struct {
	KeyID string
}

func (e ErrKeyNotFoundLocal) Error() string {
	return fmt.Sprintf("registry: kms key %s not found", e.KeyID)
}
