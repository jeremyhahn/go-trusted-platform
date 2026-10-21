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
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SignatureAlgorithmECDSAP256SHA256 names the algorithm LocalManifestSigner
// signs with: ECDSA over P-256, SHA-256 digest, ASN.1 DER signature.
const SignatureAlgorithmECDSAP256SHA256 = "ECDSA-P256-SHA256"

// defaultSigningKeyID is the signing key a push uses when it names none,
// the same default the encryption path uses for its key.
const defaultSigningKeyID = "registry-default"

// signingKeyPEMType is the PEM block type of a persisted signing key.
const signingKeyPEMType = "PRIVATE KEY"

// ManifestSignature is a signature over a manifest's signing payload.
type ManifestSignature struct {
	KeyID     string
	Algorithm string
	Signature []byte
}

// ManifestSigner signs a manifest's signing payload with a named key.
// Registry.Push calls it when a push asks for signing; without one the
// push is refused with ErrSigningNotConfigured.
type ManifestSigner interface {
	SignManifest(ctx context.Context, keyID string, payload []byte) (ManifestSignature, error)
}

// LocalManifestSigner is a single-node ManifestSigner that persists one
// ECDSA P-256 key per key ID as a PKCS#8 PEM file under <root>, mode 0600,
// created on the key's first use. It sits beside LocalKMSClient: the same
// directory discipline, and the same single swap when an SDK-backed signer
// replaces it.
type LocalManifestSigner struct {
	root string
	mu   sync.Mutex
	keys map[string]*ecdsa.PrivateKey
}

// NewLocalManifestSigner returns a signer whose keys live under root,
// creating the directory (0700) if needed.
func NewLocalManifestSigner(root string) (*LocalManifestSigner, error) {
	if root == "" {
		return nil, &MessageError{Msg: "registry: signing key root cannot be empty"}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("registry: mkdir %s", root), Err: err}
	}
	return &LocalManifestSigner{
		root: root,
		keys: make(map[string]*ecdsa.PrivateKey),
	}, nil
}

// SignManifest signs the SHA-256 digest of payload with keyID's key.
func (s *LocalManifestSigner) SignManifest(ctx context.Context, keyID string, payload []byte) (ManifestSignature, error) {
	if err := ctx.Err(); err != nil {
		return ManifestSignature{}, err
	}
	key, err := s.key(keyID)
	if err != nil {
		return ManifestSignature{}, ErrManifestSigningFailed{KeyID: keyID, Err: err}
	}
	digest := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return ManifestSignature{}, ErrManifestSigningFailed{KeyID: keyID, Err: err}
	}
	return ManifestSignature{
		KeyID:     keyID,
		Algorithm: SignatureAlgorithmECDSAP256SHA256,
		Signature: sig,
	}, nil
}

// keyPath hashes keyID so an arbitrary key name cannot escape root.
func (s *LocalManifestSigner) keyPath(keyID string) string {
	sum := sha256.Sum256([]byte(keyID))
	return filepath.Join(s.root, fmt.Sprintf("%x.pem", sum))
}

// key returns keyID's private key, loading it from disk or generating and
// persisting it on first use.
func (s *LocalManifestSigner) key(keyID string) (*ecdsa.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[keyID]; ok {
		return k, nil
	}
	path := s.keyPath(keyID)
	k, err := loadSigningKey(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err = generateSigningKey(path)
	}
	if err != nil {
		return nil, err
	}
	s.keys[keyID] = k
	return k, nil
}

// loadSigningKey reads a PKCS#8 PEM ECDSA key from path.
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
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: signingKeyPEMType, Bytes: der}); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

// manifestSigningPayload is the byte string a manifest signature covers:
// the manifest JSON bound to ref, without the signature annotations and
// without the storage timestamps, so a verifier can rebuild it from the
// stored manifest.
func manifestSigningPayload(ref string, m *ImageManifest) ([]byte, error) {
	unsigned := *m
	unsigned.Reference = ref
	unsigned.Annotations = withoutSignatureAnnotations(m.Annotations)
	unsigned.CreatedAt = time.Time{}
	unsigned.UpdatedAt = time.Time{}
	return json.Marshal(&unsigned)
}

// withoutSignatureAnnotations returns a copy of annotations with every
// signature annotation removed; nil when nothing remains.
func withoutSignatureAnnotations(annotations map[string]string) map[string]string {
	out := make(map[string]string, len(annotations))
	for k, v := range annotations {
		if _, isSignature := signatureAnnotations[k]; !isSignature {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
