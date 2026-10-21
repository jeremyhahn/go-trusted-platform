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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// newSigningTestRegistry builds a registry that encrypts and signs through
// one LocalKMSClient, the daemon's wiring.
func newSigningTestRegistry(t *testing.T) (*Registry, *LocalKMSClient) {
	t.Helper()
	storage, err := NewQuicBaaSStorage(newMockStorageClient())
	if err != nil {
		t.Fatalf("NewQuicBaaSStorage: %v", err)
	}
	kms, err := NewLocalKMSClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalKMSClient: %v", err)
	}
	enc, err := NewImageEncryptor(kms)
	if err != nil {
		t.Fatalf("NewImageEncryptor: %v", err)
	}
	reg, err := NewRegistry(validTestConfig(), testLogger(), WithStorage(storage), WithEncryptor(enc), WithSigner(kms))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	return reg, kms
}

// signTestImage is an image with one layer per content.
func signTestImage(annotations map[string]string, layers ...[]byte) *Image {
	const layerType = "application/vnd.oci.image.layer.v1.tar"
	img := &Image{Manifest: &ImageManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Annotations:   annotations,
	}}
	for _, content := range layers {
		sum := sha256.Sum256(content)
		d := "sha256:" + hex.EncodeToString(sum[:])
		img.Layers = append(img.Layers, Layer{Digest: d, MediaType: layerType, Size: int64(len(content)), Content: content})
		img.Manifest.Layers = append(img.Manifest.Layers, Descriptor{MediaType: layerType, Digest: d, Size: int64(len(content))})
	}
	return img
}

// manifestSignatureVerifies rebuilds m's signing payload for ref, as a
// verifier holding the stored manifest would, and checks the recorded
// signature against the KMS's key for the recorded key ID.
func manifestSignatureVerifies(t *testing.T, kms *LocalKMSClient, ref string, m *ImageManifest) bool {
	t.Helper()
	sig, err := base64.StdEncoding.DecodeString(m.Annotations[ManifestAnnotationSignature])
	if err != nil {
		t.Fatalf("decode signature annotation: %v", err)
	}
	payload, err := manifestSigningPayload(ref, m)
	if err != nil {
		t.Fatalf("manifestSigningPayload: %v", err)
	}
	digest := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(signingPublicKey(t, kms, m.Annotations[ManifestAnnotationSigningKeyID]), digest[:], sig)
}

func TestRegistryPush_SignsAfterEncryption(t *testing.T) {
	reg, kms := newSigningTestRegistry(t)
	ctx := context.Background()
	const ref = "apps/web:v1"

	err := reg.Push(ctx, ref, signTestImage(nil, []byte("layer-one")), PushOptions{Encrypt: true, SignImage: true})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	stored, err := reg.storage.GetManifest(ctx, ref)
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	want := map[string]string{
		ManifestAnnotationSigned:             "true",
		ManifestAnnotationSigningKeyID:       defaultSigningKeyID,
		ManifestAnnotationSignatureAlgorithm: SignatureAlgorithmECDSAP256SHA256,
		ManifestAnnotationEncrypted:          "true",
	}
	for k, v := range want {
		if got := stored.Annotations[k]; got != v {
			t.Errorf("annotation %s = %q, want %q", k, got, v)
		}
	}
	if !manifestSignatureVerifies(t, kms, ref, stored) {
		t.Fatal("the stored manifest's signature does not verify")
	}

	// The signature covers the encryption annotations: rewriting the
	// recorded encryption key breaks it.
	stored.Annotations[ManifestAnnotationKeyID] = "attacker-key"
	if manifestSignatureVerifies(t, kms, ref, stored) {
		t.Fatal("the signature does not cover the encryption key annotation")
	}
}

func TestRegistryPush_SignsWithTheNamedKey(t *testing.T) {
	reg, kms := newSigningTestRegistry(t)
	ctx := context.Background()
	const ref = "apps/web:v2"

	if err := reg.Push(ctx, ref, signTestImage(nil, []byte("layer")), PushOptions{SignImage: true, SigningKeyID: "web-sign"}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	stored, err := reg.storage.GetManifest(ctx, ref)
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if got := stored.Annotations[ManifestAnnotationSigningKeyID]; got != "web-sign" {
		t.Fatalf("signing key ID = %q, want web-sign", got)
	}
	if !manifestSignatureVerifies(t, kms, ref, stored) {
		t.Fatal("signature does not verify under web-sign")
	}
}

func TestRegistryPush_StripsForgedSignatureAnnotations(t *testing.T) {
	forged := func() map[string]string {
		return map[string]string{
			ManifestAnnotationSigned:             "true",
			ManifestAnnotationSigningKeyID:       "registry-default",
			ManifestAnnotationSignatureAlgorithm: SignatureAlgorithmECDSAP256SHA256,
			ManifestAnnotationSignature:          base64.StdEncoding.EncodeToString([]byte("forged")),
			"org.example.owner":                  "web-team",
		}
	}

	t.Run("unsigned push stores no signature", func(t *testing.T) {
		reg, _ := newSigningTestRegistry(t)
		ctx := context.Background()
		if err := reg.Push(ctx, "apps/web:v1", signTestImage(forged(), []byte("layer")), PushOptions{}); err != nil {
			t.Fatalf("Push: %v", err)
		}
		stored, err := reg.storage.GetManifest(ctx, "apps/web:v1")
		if err != nil {
			t.Fatalf("GetManifest: %v", err)
		}
		for k := range signatureAnnotations {
			if v, ok := stored.Annotations[k]; ok {
				t.Errorf("forged annotation %s = %q survived an unsigned push", k, v)
			}
		}
		if got := stored.Annotations["org.example.owner"]; got != "web-team" {
			t.Errorf("caller annotation = %q, want web-team", got)
		}
	})

	t.Run("signed push replaces the forged signature", func(t *testing.T) {
		reg, kms := newSigningTestRegistry(t)
		ctx := context.Background()
		if err := reg.Push(ctx, "apps/web:v1", signTestImage(forged(), []byte("layer")), PushOptions{SignImage: true}); err != nil {
			t.Fatalf("Push: %v", err)
		}
		stored, err := reg.storage.GetManifest(ctx, "apps/web:v1")
		if err != nil {
			t.Fatalf("GetManifest: %v", err)
		}
		if stored.Annotations[ManifestAnnotationSignature] == forged()[ManifestAnnotationSignature] {
			t.Fatal("the forged signature was stored")
		}
		if !manifestSignatureVerifies(t, kms, "apps/web:v1", stored) {
			t.Fatal("the registry's signature does not verify")
		}
	})
}

// failingSigner is a SigningKMSClient whose KMS refuses every signature.
type failingSigner struct{}

var errSignerDown = errors.New("kms unavailable")

func (failingSigner) Sign(context.Context, string, []byte) ([]byte, string, error) {
	return nil, "", errSignerDown
}

func TestRegistryPush_SigningFailureStoresNothing(t *testing.T) {
	storage, err := NewQuicBaaSStorage(newMockStorageClient())
	if err != nil {
		t.Fatalf("NewQuicBaaSStorage: %v", err)
	}
	reg, err := NewRegistry(validTestConfig(), testLogger(), WithStorage(storage), WithSigner(failingSigner{}))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	ctx := context.Background()
	img := signTestImage(nil, []byte("layer"))

	err = reg.Push(ctx, "apps/web:v1", img, PushOptions{SignImage: true, SigningKeyID: "web-sign"})
	var signErr ErrManifestSigningFailed
	if !errors.As(err, &signErr) {
		t.Fatalf("Push error = %v, want ErrManifestSigningFailed", err)
	}
	if signErr.KeyID != "web-sign" || !errors.Is(err, errSignerDown) {
		t.Errorf("ErrManifestSigningFailed = %+v, want key web-sign wrapping the KMS error", signErr)
	}
	if _, err := reg.storage.GetManifest(ctx, "apps/web:v1"); err == nil {
		t.Error("a manifest was stored for a push whose signing failed")
	}
	if _, err := reg.storage.GetBlob(ctx, img.Layers[0].Digest); err == nil {
		t.Error("a layer was stored for a push whose signing failed")
	}
}

func TestRegistryPush_SignWithoutSignerIsRefused(t *testing.T) {
	reg := newTestRegistry(t)
	err := reg.Push(context.Background(), "apps/web:v1", signTestImage(nil, []byte("layer")), PushOptions{SignImage: true})
	if !errors.As(err, &ErrSigningNotConfigured{}) {
		t.Fatalf("Push error = %v, want ErrSigningNotConfigured", err)
	}
}

func TestManifestSigningPayload(t *testing.T) {
	base := func() *ImageManifest {
		return signTestImage(map[string]string{"org.example.owner": "web-team"}, []byte("layer")).Manifest
	}
	want, err := manifestSigningPayload("apps/web:v1", base())
	if err != nil {
		t.Fatalf("manifestSigningPayload: %v", err)
	}

	t.Run("ignores timestamps and signature annotations", func(t *testing.T) {
		m := base()
		m.CreatedAt = time.Now()
		m.UpdatedAt = time.Now()
		m.Annotations[ManifestAnnotationSigned] = "true"
		m.Annotations[ManifestAnnotationSignature] = "c2ln"
		got, err := manifestSigningPayload("apps/web:v1", m)
		if err != nil {
			t.Fatalf("manifestSigningPayload: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("payload changed with timestamps or signature annotations:\n got %s\nwant %s", got, want)
		}
	})

	t.Run("binds the reference and the other annotations", func(t *testing.T) {
		other, err := manifestSigningPayload("apps/web:v2", base())
		if err != nil {
			t.Fatalf("manifestSigningPayload: %v", err)
		}
		if bytes.Equal(other, want) {
			t.Error("payload does not bind the reference")
		}
		m := base()
		m.Annotations["org.example.owner"] = "attacker"
		changed, err := manifestSigningPayload("apps/web:v1", m)
		if err != nil {
			t.Fatalf("manifestSigningPayload: %v", err)
		}
		if bytes.Equal(changed, want) {
			t.Error("payload does not cover caller annotations")
		}
	})
}

func TestWithoutSignatureAnnotations(t *testing.T) {
	if got := withoutSignatureAnnotations(nil); got != nil {
		t.Errorf("withoutSignatureAnnotations(nil) = %v, want nil", got)
	}
	onlySignature := map[string]string{ManifestAnnotationSigned: "true", ManifestAnnotationSignature: "c2ln"}
	if got := withoutSignatureAnnotations(onlySignature); got != nil {
		t.Errorf("only signature annotations: got %v, want nil", got)
	}
	in := map[string]string{ManifestAnnotationSigningKeyID: "k", ManifestAnnotationEncrypted: "true"}
	got := withoutSignatureAnnotations(in)
	if len(got) != 1 || got[ManifestAnnotationEncrypted] != "true" {
		t.Errorf("mixed annotations: got %v, want only the encrypted annotation", got)
	}
	if _, ok := in[ManifestAnnotationSigningKeyID]; !ok {
		t.Error("withoutSignatureAnnotations modified its input")
	}
}
