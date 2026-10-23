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
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/aesgcm"
)

// plantKey writes a caller-chosen key straight into the key store, so a test
// can decrypt a fixed vector. GenerateKey deliberately produces random keys.
func plantKey(t *testing.T, key []byte) (*LocalKMSClient, string) {
	t.Helper()

	root := t.TempDir()
	kms, err := NewLocalKMSClient(root)
	if err != nil {
		t.Fatalf("NewLocalKMSClient: %v", err)
	}
	const keyID = "local-fixedvector"
	if err := os.WriteFile(kms.keyPath(keyID), key, 0o600); err != nil {
		t.Fatalf("plant key: %v", err)
	}
	return kms, keyID
}

func newTestKMS(t *testing.T) (*LocalKMSClient, string) {
	t.Helper()

	kms, err := NewLocalKMSClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalKMSClient: %v", err)
	}
	keyID, err := kms.GenerateKey(context.Background(), "test-key", "AES-256-GCM", []string{"encrypt", "decrypt"})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return kms, keyID
}

// TestLocalKMS_EncryptDecryptRoundTrip is the coverage this path never had:
// Encrypt and Decrypt had no direct test at all, which is why the FIPS nightly
// showed five red packages and not six — the break was real but unexercised
// (#209).
func TestLocalKMS_EncryptDecryptRoundTrip(t *testing.T) {
	kms, keyID := newTestKMS(t)
	ctx := context.Background()

	plaintext := []byte("per-layer data encryption key")
	aad := []byte("sha256:layer1")

	sealed, version, err := kms.Encrypt(ctx, keyID, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}
	if len(sealed) != NonceSize+len(plaintext)+TagSize {
		t.Errorf("sealed length = %d, want nonce+plaintext+tag = %d",
			len(sealed), NonceSize+len(plaintext)+TagSize)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Error("plaintext appears verbatim in the sealed blob")
	}

	got, err := kms.Decrypt(ctx, keyID, sealed, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip = %q, want %q", got, plaintext)
	}
}

// TestLocalKMS_WireFormatUnchanged is the point of the #209 change: moving to
// cipher.NewGCMWithRandomNonce must not alter a single byte of the on-disk
// layout, so blobs sealed by the pre-#209 code stay readable. It holds the
// same line for #248, which moved the cipher into pkg/crypto/aesgcm.
//
// The vector below was produced by that pre-#209 code — cipher.NewGCM with an
// explicit 12-byte nonce, the nonce prepended by hand — and is checked in as a
// literal rather than recomputed. Recomputing it would need the very API a FIPS
// build refuses, so the test would have had to skip in exactly the build whose
// compatibility it exists to prove. As a constant it runs identically in both
// builds and cannot rot with the code it is pinning.
// TestLocalKMS_GenerateKeySameNameDistinctKeys pins #284: key IDs were hashed
// from the name and the time, so two same-name keys made within one clock
// tick collided and the second overwrote the first key file, stranding
// everything sealed under it.
func TestLocalKMS_GenerateKeySameNameDistinctKeys(t *testing.T) {
	kms, firstID := newTestKMS(t)
	ctx := context.Background()

	plaintext := []byte("sealed under the first key")
	aad := []byte("sha256:layer1")
	sealed, _, err := kms.Encrypt(ctx, firstID, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	secondID, err := kms.GenerateKey(ctx, "test-key", "AES-256-GCM", []string{"encrypt", "decrypt"})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if secondID == firstID {
		t.Fatalf("two keys named %q share ID %s", "test-key", firstID)
	}

	got, err := kms.Decrypt(ctx, firstID, sealed, aad)
	if err != nil {
		t.Fatalf("the first key must survive a second same-name key: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip = %q, want %q", got, plaintext)
	}
}

// TestLocalKMS_GenerateKeyCancelledContext covers GenerateKey's error path: a
// cancelled context mints no key.
func TestLocalKMS_GenerateKeyCancelledContext(t *testing.T) {
	kms, err := NewLocalKMSClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalKMSClient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := kms.GenerateKey(ctx, "test-key", "AES-256-GCM", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("GenerateKey on a cancelled context = %v, want context.Canceled", err)
	}
}

func TestLocalKMS_WireFormatUnchanged(t *testing.T) {
	const (
		legacyKeyHex    = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		legacySealedHex = "a0a1a2a3a4a5a6a7a8a9aaab957d1d4120af22dd0703e8a1625ab4b6158c1f59" +
			"c2e46201f56954e70bc21a6f3f2212780fa1d0892a6fbb167cca079b"
		legacyPlaintext = "sealed before the FIPS migration"
		legacyAAD       = "sha256:layer1"
	)

	key, err := hex.DecodeString(legacyKeyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	sealed, err := hex.DecodeString(legacySealedHex)
	if err != nil {
		t.Fatalf("decode sealed: %v", err)
	}

	kms, keyID := plantKey(t, key)

	got, err := kms.Decrypt(context.Background(), keyID, sealed, []byte(legacyAAD))
	if err != nil {
		t.Fatalf("the current Decrypt must read a pre-#209 blob: %v", err)
	}
	if string(got) != legacyPlaintext {
		t.Errorf("legacy blob decrypted to %q, want %q", got, legacyPlaintext)
	}

	// And what we write now must have the same shape, so the next reader of
	// this format sees no drift: nonce || ciphertext || tag.
	current, _, err := kms.Encrypt(context.Background(), keyID, []byte(legacyPlaintext), []byte(legacyAAD))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(current) != len(sealed) {
		t.Errorf("sealed length changed: new %d, pre-#209 %d", len(current), len(sealed))
	}
}

// TestLocalKMS_DecryptRejectsTampering covers the error paths: the AAD binding
// that stops a layer's ciphertext being replayed under another layer's digest,
// a corrupted tag, and a truncated blob.
func TestLocalKMS_DecryptRejectsTampering(t *testing.T) {
	kms, keyID := newTestKMS(t)
	ctx := context.Background()

	plaintext := []byte("per-layer data encryption key")
	aad := []byte("sha256:layer1")

	sealed, _, err := kms.Encrypt(ctx, keyID, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("a different layer digest does not authenticate", func(t *testing.T) {
		if _, err := kms.Decrypt(ctx, keyID, sealed, []byte("sha256:layer2")); err == nil {
			t.Error("a ciphertext must not open under another layer's AAD")
		}
	})

	t.Run("a corrupted tag does not authenticate", func(t *testing.T) {
		corrupt := append([]byte{}, sealed...)
		corrupt[len(corrupt)-1] ^= 0xff
		if _, err := kms.Decrypt(ctx, keyID, corrupt, aad); err == nil {
			t.Error("a corrupted tag must not open")
		}
	})

	t.Run("a truncated blob reports a typed platform error", func(t *testing.T) {
		_, err := kms.Decrypt(ctx, keyID, sealed[:NonceSize+TagSize-1], aad)
		if err == nil {
			t.Fatal("a blob shorter than nonce+tag must not open")
		}
		var tooShort aesgcm.ErrCiphertextTooShort
		if !errors.As(err, &tooShort) {
			t.Errorf("want aesgcm.ErrCiphertextTooShort for a truncated blob, got %T: %v", err, err)
		}
	})

	t.Run("a cancelled context is refused before any crypto", func(t *testing.T) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := kms.Decrypt(cancelled, keyID, sealed, aad); err == nil {
			t.Error("a cancelled context must be refused")
		}
		if _, _, err := kms.Encrypt(cancelled, keyID, plaintext, aad); err == nil {
			t.Error("a cancelled context must be refused by Encrypt too")
		}
	})
}
