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
	"encoding/json"
	"strings"
	"testing"
)

func TestEncodeDecodeEncryptedLayer_RoundTrip(t *testing.T) {
	layer := &EncryptedLayer{
		Digest:       "sha256:abc",
		MediaType:    "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
		Encrypted:    []byte("nonce||ciphertext||tag"),
		WrappedDEK:   []byte("wrapped"),
		KeyID:        "local-key",
		OriginalSize: 4096,
	}

	blob, err := encodeEncryptedLayer(layer)
	if err != nil {
		t.Fatalf("encodeEncryptedLayer: %v", err)
	}

	got, err := decodeEncryptedLayer(blob)
	if err != nil {
		t.Fatalf("decodeEncryptedLayer: %v", err)
	}

	if got.Digest != layer.Digest || got.MediaType != layer.MediaType || got.KeyID != layer.KeyID {
		t.Errorf("identity fields not preserved: %+v", got)
	}
	if !bytes.Equal(got.Encrypted, layer.Encrypted) || !bytes.Equal(got.WrappedDEK, layer.WrappedDEK) {
		t.Error("binary fields not preserved")
	}
	if got.OriginalSize != layer.OriginalSize {
		t.Errorf("OriginalSize = %d, want %d", got.OriginalSize, layer.OriginalSize)
	}
	if got.Size != int64(len(layer.Encrypted)) {
		t.Errorf("Size = %d, want the ciphertext length %d", got.Size, len(layer.Encrypted))
	}
}

// TestEncodeEncryptedLayer_WritesCurrentVersion pins the version actually
// emitted, and that the retired "nonce" field is gone rather than emitted empty
// — an empty field would read to a future maintainer as a nonce that failed to
// be recorded.
func TestEncodeEncryptedLayer_WritesCurrentVersion(t *testing.T) {
	blob, err := encodeEncryptedLayer(&EncryptedLayer{Digest: "sha256:abc", Encrypted: []byte("x")})
	if err != nil {
		t.Fatalf("encodeEncryptedLayer: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(blob, &raw); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}

	if v, ok := raw["v"].(float64); !ok || int(v) != encryptedLayerEnvelopeVersion {
		t.Errorf("v = %v, want %d", raw["v"], encryptedLayerEnvelopeVersion)
	}
	if _, present := raw["nonce"]; present {
		t.Error("v2 must not carry a nonce field; the nonce lives inside the ciphertext")
	}
}

// TestDecodeEncryptedLayer_RejectsRetiredVersion is why the version was bumped
// rather than v1 being silently redefined.
//
// A v1 envelope holds its nonce in a separate field and a ciphertext with no
// nonce prefix. Had v1 kept its number, this blob would have been accepted and
// its first 12 bytes of ciphertext mistaken for a nonce, surfacing as a
// decryption failure — which reads as key trouble or corruption. With the bump
// the reader names the real problem. No v1 envelope has ever existed outside a
// test (no registry was deployed before the format changed), so this is a
// diagnosis path, not a migration.
func TestDecodeEncryptedLayer_RejectsRetiredVersion(t *testing.T) {
	v1 := []byte(`{"v":1,"key_id":"local-key","wrapped_dek":"d3JhcHBlZA==",` +
		`"nonce":"YWFhYWFhYWFhYWFh","ciphertext":"Y2lwaGVydGV4dA==",` +
		`"original_size":4096,"media_type":"application/x","digest":"sha256:abc"}`)

	_, err := decodeEncryptedLayer(v1)
	if err == nil {
		t.Fatal("a v1 envelope must be refused, not decoded as v2")
	}
	if !strings.Contains(err.Error(), "unsupported encrypted-layer envelope version 1") {
		t.Errorf("the error must name the version; got: %v", err)
	}
}

func TestEncodeDecodeEncryptedLayer_Errors(t *testing.T) {
	t.Run("a nil layer is refused", func(t *testing.T) {
		if _, err := encodeEncryptedLayer(nil); err == nil {
			t.Error("encoding a nil layer must fail")
		}
	})

	t.Run("malformed JSON is refused", func(t *testing.T) {
		if _, err := decodeEncryptedLayer([]byte("{not json")); err == nil {
			t.Error("decoding malformed JSON must fail")
		}
	})

	t.Run("an empty blob is refused", func(t *testing.T) {
		if _, err := decodeEncryptedLayer(nil); err == nil {
			t.Error("decoding an empty blob must fail")
		}
	})
}
