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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
)

func signTestDigest(msg string) []byte {
	sum := sha256.Sum256([]byte(msg))
	return sum[:]
}

// signingPublicKey reads keyID's persisted signing key, the key a verifier
// would be given.
func signingPublicKey(t *testing.T, kms *LocalKMSClient, keyID string) *ecdsa.PublicKey {
	t.Helper()
	key, err := loadSigningKey(kms.signingKeyPath(keyID))
	if err != nil {
		t.Fatalf("loadSigningKey: %v", err)
	}
	return &key.PublicKey
}

func TestLocalKMS_SignVerifiesAndPersistsKey(t *testing.T) {
	root := t.TempDir()
	kms, err := NewLocalKMSClient(root)
	if err != nil {
		t.Fatalf("NewLocalKMSClient: %v", err)
	}
	digest := signTestDigest("manifest")

	sig, alg, err := kms.Sign(context.Background(), "registry-default", digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if alg != SignatureAlgorithmECDSAP256SHA256 {
		t.Fatalf("algorithm = %q, want %q", alg, SignatureAlgorithmECDSAP256SHA256)
	}
	pub := signingPublicKey(t, kms, "registry-default")
	if !ecdsa.VerifyASN1(pub, digest, sig) {
		t.Fatal("signature does not verify against the persisted key")
	}
	info, err := os.Stat(kms.signingKeyPath("registry-default"))
	if err != nil {
		t.Fatalf("stat signing key: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("signing key mode = %o, want 600", mode)
	}

	// A restarted client signs with the same key, not a fresh one.
	restarted, err := NewLocalKMSClient(root)
	if err != nil {
		t.Fatalf("NewLocalKMSClient (restart): %v", err)
	}
	sig2, _, err := restarted.Sign(context.Background(), "registry-default", digest)
	if err != nil {
		t.Fatalf("Sign after restart: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest, sig2) {
		t.Fatal("restarted client signed with a different key")
	}
}

func TestLocalKMS_SignKeysAreIndependent(t *testing.T) {
	kms, err := NewLocalKMSClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalKMSClient: %v", err)
	}
	digest := signTestDigest("manifest")

	sigA, _, err := kms.Sign(context.Background(), "key-a", digest)
	if err != nil {
		t.Fatalf("Sign key-a: %v", err)
	}
	if _, _, err := kms.Sign(context.Background(), "key-b", digest); err != nil {
		t.Fatalf("Sign key-b: %v", err)
	}
	if ecdsa.VerifyASN1(signingPublicKey(t, kms, "key-b"), digest, sigA) {
		t.Fatal("key-a's signature verifies under key-b: the key IDs share a key")
	}
}

func TestLocalKMS_SigningKeyLeavesEncryptionKeyIntact(t *testing.T) {
	kms, keyID := newTestKMS(t)
	ctx := context.Background()

	// Signing with the encryption key's ID creates a separate signing key.
	if _, _, err := kms.Sign(ctx, keyID, signTestDigest("manifest")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if kms.signingKeyPath(keyID) == kms.keyPath(keyID) {
		t.Fatal("signing and encryption keys share a path")
	}
	sealed, _, err := kms.Encrypt(ctx, keyID, []byte("layer"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plain, err := kms.Decrypt(ctx, keyID, sealed, []byte("aad"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plain, []byte("layer")) {
		t.Fatalf("Decrypt = %q, want %q", plain, "layer")
	}
}

func TestLocalKMS_SignRejectsBadInput(t *testing.T) {
	kms, err := NewLocalKMSClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalKMSClient: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name   string
		ctx    context.Context
		keyID  string
		digest []byte
	}{
		{name: "empty key ID", ctx: context.Background(), keyID: "", digest: signTestDigest("m")},
		{name: "short digest", ctx: context.Background(), keyID: "k", digest: []byte("short")},
		{name: "nil digest", ctx: context.Background(), keyID: "k", digest: nil},
		{name: "cancelled context", ctx: cancelled, keyID: "k", digest: signTestDigest("m")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sig, _, err := kms.Sign(tc.ctx, tc.keyID, tc.digest)
			if err == nil {
				t.Fatal("Sign succeeded, want an error")
			}
			if sig != nil {
				t.Fatal("Sign returned a signature with its error")
			}
			if _, statErr := os.Stat(kms.signingKeyPath(tc.keyID)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("a refused Sign created a key file (stat err %v)", statErr)
			}
		})
	}
}

func TestLocalKMS_SignRefusesCorruptKeyFile(t *testing.T) {
	kms, err := NewLocalKMSClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalKMSClient: %v", err)
	}
	path := kms.signingKeyPath("corrupt")
	garbage := []byte("not a pem key")
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatalf("plant corrupt key: %v", err)
	}

	if _, _, err := kms.Sign(context.Background(), "corrupt", signTestDigest("m")); err == nil {
		t.Fatal("Sign with a corrupt key file succeeded")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if !bytes.Equal(got, garbage) {
		t.Fatal("Sign overwrote an existing key file")
	}
}
