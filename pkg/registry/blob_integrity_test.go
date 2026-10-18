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
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// integrityImage builds an image whose layer and config digests are the
// SHA-256 of their bytes, as an honest client sends them.
func integrityImage(layerContent, config []byte) *Image {
	layerDigest := sha256Digest(layerContent)
	const layerType = "application/vnd.oci.image.layer.v1.tar"
	return &Image{
		Manifest: &ImageManifest{
			SchemaVersion: 2,
			MediaType:     "application/vnd.oci.image.manifest.v1+json",
			Config: Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    sha256Digest(config),
				Size:      int64(len(config)),
			},
			Layers: []Descriptor{{MediaType: layerType, Digest: layerDigest, Size: int64(len(layerContent))}},
		},
		Config: config,
		Layers: []Layer{{Digest: layerDigest, MediaType: layerType, Size: int64(len(layerContent)), Content: layerContent}},
	}
}

func newEncryptingRegistry(t *testing.T) *Registry {
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
	reg, err := NewRegistry(validTestConfig(), testLogger(), WithStorage(storage), WithEncryptor(enc))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	return reg
}

// newTestSigner builds a manifest signer on a PKCS#8 key store rooted at
// dir, the way the daemon's newRegistrySigner does.
func newTestSigner(t *testing.T, dir string) *ManifestSigner {
	t.Helper()
	storage, err := xkmssdk.NewFileStorageBackend(dir)
	if err != nil {
		t.Fatalf("NewFileStorageBackend: %v", err)
	}
	keys, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
		KeyStorage:         storage,
		AllowPlaintextKeys: true,
	})
	if err != nil {
		t.Fatalf("NewPKCS8Backend: %v", err)
	}
	signer, err := NewManifestSigner(keys)
	if err != nil {
		t.Fatalf("NewManifestSigner: %v", err)
	}
	return signer
}

// newSigningRegistry builds a registry on in-memory storage that signs
// manifests with signer; a nil signer builds one that cannot sign.
func newSigningRegistry(t *testing.T, signer *ManifestSigner) *Registry {
	t.Helper()
	storage, err := NewQuicBaaSStorage(newMockStorageClient())
	if err != nil {
		t.Fatalf("NewQuicBaaSStorage: %v", err)
	}
	opts := []RegistryOption{WithStorage(storage), WithVersion("v1.2.3")}
	if signer != nil {
		opts = append(opts, WithSigner(signer))
	}
	reg, err := NewRegistry(validTestConfig(), testLogger(), opts...)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	return reg
}

func TestRegistryPull_SignedImageReturnsItsBlobs(t *testing.T) {
	ctx := context.Background()
	reg := newSigningRegistry(t, newTestSigner(t, t.TempDir()))
	image := integrityImage([]byte("layer bytes"), []byte(`{"architecture":"amd64"}`))
	if err := reg.Push(ctx, "apps/web:v1", image, PushOptions{SignImage: true}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	got, err := reg.Pull(ctx, "apps/web:v1", PullOptions{VerifySignature: true})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if string(got.Config) != `{"architecture":"amd64"}` {
		t.Errorf("config = %q", got.Config)
	}
	if len(got.Layers) != 1 || string(got.Layers[0].Content) != "layer bytes" {
		t.Errorf("layers = %+v", got.Layers)
	}
}

// RC 5611: a signed manifest names its blobs by digest, so a stored blob
// replaced underneath it must not come back from a verified pull.
func TestRegistryPull_RefusesReplacedBlobUnderSignedManifest(t *testing.T) {
	tests := []struct {
		name   string
		digest func(*Image) string
	}{
		{"layer", func(img *Image) string { return img.Layers[0].Digest }},
		{"config", func(img *Image) string { return img.Manifest.Config.Digest }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			reg := newSigningRegistry(t, newTestSigner(t, t.TempDir()))
			image := integrityImage([]byte("layer bytes"), []byte("config bytes"))
			if err := reg.Push(ctx, "apps/web:v1", image, PushOptions{SignImage: true}); err != nil {
				t.Fatalf("Push: %v", err)
			}
			digest := tt.digest(image)
			if err := reg.storage.StoreBlob(ctx, digest, []byte("attacker bytes")); err != nil {
				t.Fatalf("StoreBlob: %v", err)
			}

			_, err := reg.Pull(ctx, "apps/web:v1", PullOptions{VerifySignature: true})

			var mismatch ErrDigestMismatch
			if !errors.As(err, &mismatch) {
				t.Fatalf("Pull error = %v, want ErrDigestMismatch", err)
			}
			if mismatch.Expected != digest || mismatch.Actual != sha256Digest([]byte("attacker bytes")) {
				t.Errorf("mismatch = %+v", mismatch)
			}
		})
	}
}

func TestRegistryPull_RefusesReplacedEncryptedLayer(t *testing.T) {
	ctx := context.Background()
	reg := newEncryptingRegistry(t)
	victim := integrityImage([]byte("victim layer"), []byte("cfg"))
	if err := reg.Push(ctx, "apps/victim:v1", victim, PushOptions{Encrypt: true}); err != nil {
		t.Fatalf("Push victim: %v", err)
	}
	other := integrityImage([]byte("other layer"), []byte("cfg"))
	if err := reg.Push(ctx, "apps/other:v1", other, PushOptions{Encrypt: true}); err != nil {
		t.Fatalf("Push other: %v", err)
	}
	// Move the other image's envelope under the victim's layer digest: it
	// decrypts, but to bytes the victim's manifest does not name.
	envelope, err := reg.storage.GetBlob(ctx, other.Layers[0].Digest)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if err := reg.storage.StoreBlob(ctx, victim.Layers[0].Digest, envelope); err != nil {
		t.Fatalf("StoreBlob: %v", err)
	}

	_, err = reg.Pull(ctx, "apps/victim:v1", PullOptions{})

	var mismatch ErrDigestMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("Pull error = %v, want ErrDigestMismatch", err)
	}
}

func TestRegistryPush_RefusesContentNotMatchingItsDigest(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*Image)
	}{
		{"layer", func(img *Image) { img.Layers[0].Content = []byte("swapped layer") }},
		{"config", func(img *Image) { img.Config = []byte("swapped config") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			reg := newTestRegistry(t)
			image := integrityImage([]byte("layer bytes"), []byte("config bytes"))
			tt.tamper(image)

			err := reg.Push(ctx, "apps/web:v1", image, PushOptions{})

			var mismatch ErrDigestMismatch
			if !errors.As(err, &mismatch) {
				t.Fatalf("Push error = %v, want ErrDigestMismatch", err)
			}
			for _, digest := range []string{image.Layers[0].Digest, image.Manifest.Config.Digest} {
				if exists, err := reg.storage.BlobExists(ctx, digest); err != nil || exists {
					t.Errorf("blob %s stored after a refused push (exists=%v, err=%v)", digest, exists, err)
				}
			}
			if exists, err := reg.storage.ManifestExists(ctx, "apps/web:v1"); err != nil || exists {
				t.Errorf("manifest stored after a refused push (exists=%v, err=%v)", exists, err)
			}
		})
	}
}

func TestRegistryPush_RefusesOverwritingAStoredBlob(t *testing.T) {
	ctx := context.Background()
	reg := newEncryptingRegistry(t)
	encrypted := integrityImage([]byte("shared layer"), []byte("cfg"))
	if err := reg.Push(ctx, "apps/sealed:v1", encrypted, PushOptions{Encrypt: true}); err != nil {
		t.Fatalf("Push encrypted: %v", err)
	}
	envelope, err := reg.storage.GetBlob(ctx, encrypted.Layers[0].Digest)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}

	// The same layer pushed in plaintext would replace the stored envelope.
	plain := integrityImage([]byte("shared layer"), []byte("cfg"))
	err = reg.Push(ctx, "apps/plain:v1", plain, PushOptions{})

	var conflict ErrBlobConflict
	if !errors.As(err, &conflict) || conflict.Digest != plain.Layers[0].Digest {
		t.Fatalf("Push error = %v, want ErrBlobConflict for %s", err, plain.Layers[0].Digest)
	}
	stored, err := reg.storage.GetBlob(ctx, encrypted.Layers[0].Digest)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if !bytes.Equal(stored, envelope) {
		t.Fatal("a refused push replaced the stored blob")
	}
	if _, err := reg.Pull(ctx, "apps/sealed:v1", PullOptions{}); err != nil {
		t.Fatalf("Pull of the first image after the refused push: %v", err)
	}
}

func TestRegistryPush_RepushOfStoredContentSucceeds(t *testing.T) {
	tests := []struct {
		name string
		reg  func(*testing.T) *Registry
		opts PushOptions
	}{
		{"plaintext", newTestRegistry, PushOptions{AllowOverwrite: true}},
		{"encrypted", newEncryptingRegistry, PushOptions{AllowOverwrite: true, Encrypt: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			reg := tt.reg(t)
			for i := range 2 {
				image := integrityImage([]byte("layer bytes"), []byte("config bytes"))
				if err := reg.Push(ctx, "apps/web:v1", image, tt.opts); err != nil {
					t.Fatalf("Push %d: %v", i, err)
				}
			}
			got, err := reg.Pull(ctx, "apps/web:v1", PullOptions{})
			if err != nil {
				t.Fatalf("Pull: %v", err)
			}
			if len(got.Layers) != 1 || string(got.Layers[0].Content) != "layer bytes" {
				t.Errorf("layers = %+v", got.Layers)
			}
		})
	}
}

func TestRegistryPutBlob_VerifiesContent(t *testing.T) {
	ctx := context.Background()
	reg := newTestRegistry(t)
	content := []byte("layer bytes")

	var mismatch ErrDigestMismatch
	if err := reg.PutBlob(ctx, sha256Digest([]byte("other")), content); !errors.As(err, &mismatch) {
		t.Fatalf("PutBlob with a wrong digest = %v, want ErrDigestMismatch", err)
	}
	if err := reg.PutBlob(ctx, sha256Digest(content), content); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	if err := reg.PutBlob(ctx, sha256Digest(content), content); err != nil {
		t.Fatalf("PutBlob of the same content again: %v", err)
	}
}

func TestVerifyBlobDigest(t *testing.T) {
	content := []byte("blob")
	sum := sha512.Sum512(content)
	tests := []struct {
		name    string
		digest  string
		wantErr error
	}{
		{"sha256", sha256Digest(content), nil},
		{"sha512", "sha512:" + hex.EncodeToString(sum[:]), nil},
		{"wrong hash", sha256Digest([]byte("other")), ErrDigestMismatch{}},
		{"unsupported algorithm", "md5:" + repeat64("a"), ErrInvalidDigest{}},
		{"no algorithm", repeat64("a"), ErrInvalidDigest{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyBlobDigest(tt.digest, content)
			switch tt.wantErr.(type) {
			case nil:
				if err != nil {
					t.Fatalf("verifyBlobDigest = %v, want nil", err)
				}
			case ErrDigestMismatch:
				var mismatch ErrDigestMismatch
				if !errors.As(err, &mismatch) {
					t.Fatalf("verifyBlobDigest = %v, want ErrDigestMismatch", err)
				}
			case ErrInvalidDigest:
				var invalid ErrInvalidDigest
				if !errors.As(err, &invalid) {
					t.Fatalf("verifyBlobDigest = %v, want ErrInvalidDigest", err)
				}
			}
		})
	}
}
