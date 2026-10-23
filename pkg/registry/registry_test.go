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
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// testLogger returns a logger for tests
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Only log errors during tests
	}))
}

// validTestConfig returns a valid test configuration
func validTestConfig() RegistryConfig {
	cfg := DefaultRegistryConfig()
	cfg.TLS.Enabled = false // Disable TLS for tests
	cfg.Storage.Encrypted = false
	return cfg
}

// newTestRegistry constructs a Registry backed by an in-memory mock
// QuicBaaSStorageClient so Push/Pull/Delete/List exercise the real
// storage code path instead of returning ErrStorageNotConfigured.
// Used by the post-Phase-5 tests; the older tests that intentionally
// run without storage continue to call NewRegistry directly to
// exercise the unconfigured branch.
func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	storage, err := NewQuicBaaSStorage(newMockStorageClient())
	if err != nil {
		t.Fatalf("NewQuicBaaSStorage: %v", err)
	}
	reg, err := NewRegistry(validTestConfig(), testLogger(), WithStorage(storage))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	return reg
}

func TestNewRegistry(t *testing.T) {
	tests := []struct {
		name        string
		config      RegistryConfig
		logger      *slog.Logger
		expectError bool
	}{
		{
			name:        "valid config",
			config:      validTestConfig(),
			logger:      testLogger(),
			expectError: false,
		},
		{
			name:        "valid config nil logger",
			config:      validTestConfig(),
			logger:      nil, // Should use default logger
			expectError: false,
		},
		{
			name: "invalid config empty listen addr",
			config: func() RegistryConfig {
				cfg := validTestConfig()
				cfg.ListenAddr = ""
				return cfg
			}(),
			logger:      testLogger(),
			expectError: true,
		},
		{
			name: "invalid config zero timeout",
			config: func() RegistryConfig {
				cfg := validTestConfig()
				cfg.ReadTimeout = 0
				return cfg
			}(),
			logger:      testLogger(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, err := NewRegistry(tt.config, tt.logger)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if reg == nil {
				t.Error("expected non-nil registry")
				return
			}

			// Verify registry is initialized
			if !reg.initialized.Load() {
				t.Error("registry should be initialized")
			}

			// Cleanup
			if err := reg.Close(); err != nil {
				t.Errorf("failed to close registry: %v", err)
			}
		})
	}
}

func TestRegistryPush(t *testing.T) {
	reg := newTestRegistry(t)

	tests := []struct {
		name        string
		ref         string
		image       *Image
		opts        PushOptions
		expectError error
	}{
		{
			name: "valid push",
			ref:  "myrepo/myimage:v1",
			image: &Image{
				Manifest: &ImageManifest{Layers: []Descriptor{{Digest: "sha256:" + repeat64("c"), Size: 5}}},
				Layers:   []Layer{{Digest: "sha256:" + repeat64("c"), Size: 5, Content: []byte("layer")}},
			},
			opts:        PushOptions{},
			expectError: nil,
		},
		{
			name:        "no layers",
			ref:         "myrepo/myimage:v2",
			image:       &Image{Manifest: &ImageManifest{}},
			opts:        PushOptions{},
			expectError: ErrImageEmpty{},
		},
		{
			name:        "empty reference",
			ref:         "",
			image:       &Image{},
			opts:        PushOptions{},
			expectError: ErrInvalidImageRef{},
		},
		{
			name:        "invalid reference uppercase",
			ref:         "MyRepo/MyImage:v1",
			image:       &Image{},
			opts:        PushOptions{},
			expectError: ErrInvalidImageRef{},
		},
		{
			name:        "nil image",
			ref:         "myrepo/myimage:v1",
			image:       nil,
			opts:        PushOptions{},
			expectError: ErrInvalidManifest{},
		},
		{
			name:        "reference too long",
			ref:         string(make([]byte, 300)),
			image:       &Image{},
			opts:        PushOptions{},
			expectError: ErrInvalidImageRef{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := reg.Push(ctx, tt.ref, tt.image, tt.opts)

			if tt.expectError == nil && err != nil {
				t.Fatalf("expected success, got: %v", err)
			}
			if tt.expectError != nil {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				// Check error type matches
				switch tt.expectError.(type) {
				case ErrInvalidImageRef:
					var target ErrInvalidImageRef
					if !errors.As(err, &target) {
						t.Errorf("expected ErrInvalidImageRef, got: %T", err)
					}
				case ErrInvalidManifest:
					var target ErrInvalidManifest
					if !errors.As(err, &target) {
						t.Errorf("expected ErrInvalidManifest, got: %T", err)
					}
				case ErrImageEmpty:
					var target ErrImageEmpty
					if !errors.As(err, &target) {
						t.Errorf("expected ErrImageEmpty, got: %T", err)
					}
				}
			}
		})
	}
}

func TestRegistryPushContextCancellation(t *testing.T) {
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = reg.Push(ctx, "myrepo/myimage:v1", &Image{Manifest: &ImageManifest{}}, PushOptions{})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestRegistryPull(t *testing.T) {
	reg := newTestRegistry(t)

	tests := []struct {
		name        string
		ref         string
		opts        PullOptions
		expectError error
	}{
		{
			name:        "image not found",
			ref:         "myrepo/myimage:v1",
			opts:        PullOptions{},
			expectError: ErrImageNotFound{},
		},
		{
			name:        "empty reference",
			ref:         "",
			opts:        PullOptions{},
			expectError: ErrInvalidImageRef{},
		},
		{
			name:        "invalid reference",
			ref:         "INVALID:tag",
			opts:        PullOptions{},
			expectError: ErrInvalidImageRef{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := reg.Pull(ctx, tt.ref, tt.opts)

			if err == nil {
				t.Error("expected error but got nil")
				return
			}

			switch tt.expectError.(type) {
			case ErrInvalidImageRef:
				var target ErrInvalidImageRef
				if !errors.As(err, &target) {
					t.Errorf("expected ErrInvalidImageRef, got: %T", err)
				}
			case ErrImageNotFound:
				var target ErrImageNotFound
				if !errors.As(err, &target) {
					t.Errorf("expected ErrImageNotFound, got: %T", err)
				}
			}
		})
	}
}

func TestRegistryPullContextCancellation(t *testing.T) {
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = reg.Pull(ctx, "myrepo/myimage:v1", PullOptions{})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestRegistryDelete(t *testing.T) {
	reg := newTestRegistry(t)

	tests := []struct {
		name        string
		ref         string
		expectError error
	}{
		{
			name:        "image not found",
			ref:         "myrepo/myimage:v1",
			expectError: ErrImageNotFound{},
		},
		{
			name:        "empty reference",
			ref:         "",
			expectError: ErrInvalidImageRef{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := reg.Delete(ctx, tt.ref)

			if err == nil {
				t.Error("expected error but got nil")
				return
			}

			switch tt.expectError.(type) {
			case ErrInvalidImageRef:
				var target ErrInvalidImageRef
				if !errors.As(err, &target) {
					t.Errorf("expected ErrInvalidImageRef, got: %T", err)
				}
			case ErrImageNotFound:
				var target ErrImageNotFound
				if !errors.As(err, &target) {
					t.Errorf("expected ErrImageNotFound, got: %T", err)
				}
			}
		})
	}
}

func TestRegistryList(t *testing.T) {
	reg := newTestRegistry(t)

	ctx := context.Background()
	manifests, err := reg.List(ctx, RegistryListOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(manifests) != 0 {
		t.Errorf("expected empty list, got %d items", len(manifests))
	}
}

// TestRegistryPushPullRoundTrip exercises the full Push -> List ->
// Pull -> Delete lifecycle against the in-memory storage. This is the
// production-path test that replaces the pre-Phase-5 stub-as-spec
// tests.
func TestRegistryPushPullRoundTrip(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()

	const ref = "myrepo/myimage:v1"
	layer := Layer{
		Digest:    "sha256:" + repeat64("a"),
		MediaType: "application/vnd.oci.image.layer.v1.tar",
		Size:      11,
		Content:   []byte("hello world"),
	}
	configBlob := []byte(`{"architecture":"amd64"}`)
	manifest := &ImageManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Config: Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    "sha256:" + repeat64("b"),
			Size:      int64(len(configBlob)),
		},
		Layers: []Descriptor{{
			MediaType: layer.MediaType,
			Digest:    layer.Digest,
			Size:      layer.Size,
		}},
	}
	image := &Image{Manifest: manifest, Config: configBlob, Layers: []Layer{layer}}

	if err := reg.Push(ctx, ref, image, PushOptions{}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	// Second push without AllowOverwrite must fail.
	if err := reg.Push(ctx, ref, image, PushOptions{}); err == nil {
		t.Fatal("expected ErrImageAlreadyExists on second push without overwrite")
	}

	// List should include the just-pushed manifest.
	list, err := reg.List(ctx, RegistryListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Reference != ref {
		t.Fatalf("List = %+v, want one manifest at %q", list, ref)
	}

	// Pull should round-trip the blob bytes.
	got, err := reg.Pull(ctx, ref, PullOptions{})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if string(got.Config) != string(configBlob) {
		t.Errorf("config mismatch: got %q want %q", got.Config, configBlob)
	}
	if len(got.Layers) != 1 || string(got.Layers[0].Content) != string(layer.Content) {
		t.Errorf("layer mismatch: got %+v", got.Layers)
	}

	// Delete + verify gone.
	if err := reg.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := reg.Pull(ctx, ref, PullOptions{}); err == nil {
		t.Error("expected error after delete")
	}
	if err := reg.Delete(ctx, ref); err == nil {
		t.Error("expected ErrImageNotFound on second delete")
	}
}

// TestRegistryPush_Encrypted asserts the Encrypt opt is refused while
// encryption is deferred. This prevents the surface from silently
// landing unencrypted blobs when the caller asked for encryption.
func TestRegistryPush_Encrypted(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()
	err := reg.Push(ctx, "myrepo/x:v1", &Image{Manifest: &ImageManifest{}}, PushOptions{Encrypt: true})
	if err == nil {
		t.Fatal("expected ErrEncryptionNotConfigured")
	}
	var enc ErrEncryptionNotConfigured
	if !errors.As(err, &enc) {
		t.Errorf("expected ErrEncryptionNotConfigured, got %T: %v", err, err)
	}
}

// TestRegistry_UnconfiguredStorage exercises the failure path when
// no storage was wired at construction. The Registry is a real
// boot-time misconfiguration sentinel here, not a silent no-op.
func TestRegistry_UnconfiguredStorage(t *testing.T) {
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	defer func() { _ = reg.Close() }()
	ctx := context.Background()
	if err := reg.Push(ctx, "x/y:1", &Image{Manifest: &ImageManifest{}}, PushOptions{}); err == nil {
		t.Error("expected ErrStorageNotConfigured from Push")
	}
	if _, err := reg.Pull(ctx, "x/y:1", PullOptions{}); err == nil {
		t.Error("expected ErrStorageNotConfigured from Pull")
	}
	if err := reg.Delete(ctx, "x/y:1"); err == nil {
		t.Error("expected ErrStorageNotConfigured from Delete")
	}
	if _, err := reg.List(ctx, RegistryListOptions{}); err == nil {
		t.Error("expected ErrStorageNotConfigured from List")
	}
}

func repeat64(c string) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = c[0]
	}
	return string(out)
}

// TestRegistry_EncryptedRoundTrip exercises the full lifecycle of an
// encrypted push: encrypted layer bytes land in storage, plaintext is
// never visible, and Pull transparently decrypts. The unencrypted
// content must come back byte-for-byte.
func TestRegistry_EncryptedRoundTrip(t *testing.T) {
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

	ctx := context.Background()
	plaintext := []byte("secret payload that must survive a round trip")
	digest := "sha256:" + repeat64("f")
	image := &Image{
		Manifest: &ImageManifest{
			SchemaVersion: 2,
			MediaType:     "application/vnd.oci.image.manifest.v1+json",
			Config: Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    "sha256:" + repeat64("0"),
				Size:      4,
			},
			Layers: []Descriptor{{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    digest,
				Size:      int64(len(plaintext)),
			}},
		},
		Config: []byte("cfg!"),
		Layers: []Layer{{
			Digest:    digest,
			MediaType: "application/vnd.oci.image.layer.v1.tar",
			Size:      int64(len(plaintext)),
			Content:   plaintext,
		}},
	}

	ref := "encrypted/img:v1"
	if err := reg.Push(ctx, ref, image, PushOptions{Encrypt: true}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	// Confirm what landed on disk is NOT the plaintext.
	storedBlob, err := storage.GetBlob(ctx, digest)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if string(storedBlob) == string(plaintext) {
		t.Fatal("encrypted push left plaintext in storage")
	}

	got, err := reg.Pull(ctx, ref, PullOptions{})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(got.Layers) != 1 || string(got.Layers[0].Content) != string(plaintext) {
		t.Errorf("encrypted round-trip lost plaintext: got %q want %q",
			got.Layers[0].Content, plaintext)
	}

	// Manifest annotations must record the encryption choice.
	manifest, err := storage.GetManifest(ctx, ref)
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if manifest.Annotations[ManifestAnnotationEncrypted] != "true" {
		t.Errorf("expected encrypted annotation, got %v", manifest.Annotations)
	}
}

// TestRegistry_EncryptedPushWithoutEncryptor verifies the refusal
// branch still works when the encryptor option is omitted.
func TestRegistry_EncryptedPushWithoutEncryptor(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()
	err := reg.Push(ctx, "no-enc/img:v1", &Image{Manifest: &ImageManifest{}}, PushOptions{Encrypt: true})
	if err == nil {
		t.Fatal("expected ErrEncryptionNotConfigured")
	}
	var enc ErrEncryptionNotConfigured
	if !errors.As(err, &enc) {
		t.Errorf("expected ErrEncryptionNotConfigured, got %T: %v", err, err)
	}
}

// TestRegistry_DeleteGCsOrphanBlobs verifies that Delete reclaims
// blob storage for layers no longer referenced by any surviving
// manifest, and that layers shared between images survive deletion
// of one of the sharing images.
func TestRegistry_DeleteGCsOrphanBlobs(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()

	mkImage := func(layerDigest, contentSuffix string) *Image {
		return &Image{
			Manifest: &ImageManifest{
				SchemaVersion: 2,
				MediaType:     "application/vnd.oci.image.manifest.v1+json",
				Config: Descriptor{
					Digest: "sha256:" + repeat64("c"),
					Size:   4,
				},
				Layers: []Descriptor{{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    layerDigest,
					Size:      int64(len("hello" + contentSuffix)),
				}},
			},
			Config: []byte("cfg!"),
			Layers: []Layer{{
				Digest:    layerDigest,
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Size:      int64(len("hello" + contentSuffix)),
				Content:   []byte("hello" + contentSuffix),
			}},
		}
	}

	uniqueLayer := "sha256:" + repeat64("d")
	sharedLayer := "sha256:" + repeat64("e")

	// Image A: unique layer only.
	if err := reg.Push(ctx, "img-a:v1", mkImage(uniqueLayer, "A"), PushOptions{}); err != nil {
		t.Fatalf("push A: %v", err)
	}
	// Image B + C: both reference the shared layer.
	if err := reg.Push(ctx, "img-b:v1", mkImage(sharedLayer, "shared"), PushOptions{}); err != nil {
		t.Fatalf("push B: %v", err)
	}
	if err := reg.Push(ctx, "img-c:v1", mkImage(sharedLayer, "shared"), PushOptions{}); err != nil {
		t.Fatalf("push C: %v", err)
	}

	// Delete A: its unique layer should be GC'd.
	if err := reg.Delete(ctx, "img-a:v1"); err != nil {
		t.Fatalf("delete A: %v", err)
	}
	if exists, _ := reg.storage.BlobExists(ctx, uniqueLayer); exists {
		t.Errorf("uniqueLayer should be GC'd after deleting its only referent")
	}
	if exists, _ := reg.storage.BlobExists(ctx, sharedLayer); !exists {
		t.Errorf("sharedLayer should survive A's delete (B and C still reference it)")
	}

	// Delete B: shared layer should still survive (C references it).
	if err := reg.Delete(ctx, "img-b:v1"); err != nil {
		t.Fatalf("delete B: %v", err)
	}
	if exists, _ := reg.storage.BlobExists(ctx, sharedLayer); !exists {
		t.Errorf("sharedLayer should survive B's delete (C still references it)")
	}

	// Delete C: now the shared layer is orphaned and should be GC'd.
	if err := reg.Delete(ctx, "img-c:v1"); err != nil {
		t.Fatalf("delete C: %v", err)
	}
	if exists, _ := reg.storage.BlobExists(ctx, sharedLayer); exists {
		t.Errorf("sharedLayer should be GC'd after all referencing images are deleted")
	}
}

func TestRegistryVerifyClient(t *testing.T) {
	tests := []struct {
		name               string
		requireAttestation bool
		attestation        *AttestationEvidence
		allowedAIKs        []string
		requiredPCRs       map[int][]byte
		quoteMaxAge        time.Duration
		expectError        bool
		expectedErrorType  interface{}
	}{
		{
			name:               "attestation not required",
			requireAttestation: false,
			attestation:        nil,
			expectError:        false,
		},
		{
			name:               "attestation required but nil",
			requireAttestation: true,
			attestation:        nil,
			expectError:        true,
			expectedErrorType:  ErrAttestationRequired{},
		},
		{
			name:               "attestation required and valid",
			requireAttestation: true,
			attestation: &AttestationEvidence{
				ClientID:  "client-1",
				AIK:       []byte("aik-1-bytes-here"),
				Timestamp: time.Now(),
				PCRs:      map[int][]byte{},
			},
			quoteMaxAge: 10 * time.Minute,
			expectError: false,
		},
		{
			name:               "quote expired",
			requireAttestation: true,
			attestation: &AttestationEvidence{
				ClientID:  "client-1",
				AIK:       []byte("aik-1-bytes"),
				Timestamp: time.Now().Add(-1 * time.Hour), // Old timestamp
			},
			quoteMaxAge:       10 * time.Minute,
			expectError:       true,
			expectedErrorType: ErrInvalidQuote{},
		},
		{
			name:               "PCR mismatch",
			requireAttestation: true,
			attestation: &AttestationEvidence{
				ClientID:  "client-1",
				AIK:       []byte("aik-1-bytes"),
				Timestamp: time.Now(),
				PCRs:      map[int][]byte{7: {0x01, 0x02, 0x03}},
			},
			requiredPCRs:      map[int][]byte{7: {0x04, 0x05, 0x06}},
			quoteMaxAge:       10 * time.Minute,
			expectError:       true,
			expectedErrorType: ErrPCRMismatch{},
		},
		{
			name:               "PCR missing",
			requireAttestation: true,
			attestation: &AttestationEvidence{
				ClientID:  "client-1",
				AIK:       []byte("aik-1-bytes"),
				Timestamp: time.Now(),
				PCRs:      map[int][]byte{}, // PCR 7 missing
			},
			requiredPCRs:      map[int][]byte{7: {0x01, 0x02, 0x03}},
			quoteMaxAge:       10 * time.Minute,
			expectError:       true,
			expectedErrorType: ErrPCRMismatch{},
		},
		{
			name:               "PCR match",
			requireAttestation: true,
			attestation: &AttestationEvidence{
				ClientID:  "client-1",
				AIK:       []byte("aik-1-bytes"),
				Timestamp: time.Now(),
				PCRs:      map[int][]byte{7: {0x01, 0x02, 0x03}},
			},
			requiredPCRs: map[int][]byte{7: {0x01, 0x02, 0x03}},
			quoteMaxAge:  10 * time.Minute,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfig()
			cfg.Attestation.RequireAttestation = tt.requireAttestation
			cfg.Attestation.AllowedAIKs = tt.allowedAIKs
			cfg.Attestation.RequiredPCRs = tt.requiredPCRs
			if tt.quoteMaxAge > 0 {
				cfg.Attestation.QuoteMaxAge = tt.quoteMaxAge
			}

			reg, err := NewRegistry(cfg, testLogger())
			if err != nil {
				t.Fatalf("failed to create registry: %v", err)
			}
			defer func() { _ = reg.Close() }()

			ctx := context.Background()
			err = reg.VerifyClient(ctx, tt.attestation)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				switch tt.expectedErrorType.(type) {
				case ErrAttestationRequired:
					var target ErrAttestationRequired
					if !errors.As(err, &target) {
						t.Errorf("expected ErrAttestationRequired, got: %T (%v)", err, err)
					}
				case ErrAIKNotAllowed:
					var target ErrAIKNotAllowed
					if !errors.As(err, &target) {
						t.Errorf("expected ErrAIKNotAllowed, got: %T (%v)", err, err)
					}
				case ErrInvalidQuote:
					var target ErrInvalidQuote
					if !errors.As(err, &target) {
						t.Errorf("expected ErrInvalidQuote, got: %T (%v)", err, err)
					}
				case ErrPCRMismatch:
					var target ErrPCRMismatch
					if !errors.As(err, &target) {
						t.Errorf("expected ErrPCRMismatch, got: %T (%v)", err, err)
					}
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRegistrySessionManagement(t *testing.T) {
	cfg := validTestConfig()
	cfg.Attestation.RequireAttestation = true
	cfg.Attestation.CacheSessionDuration = 1 * time.Hour

	reg, err := NewRegistry(cfg, testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	// Verify a client
	attestation := &AttestationEvidence{
		ClientID:  "client-1",
		AIK:       []byte("aik-1-bytes-here-long"),
		Timestamp: time.Now(),
		PCRs:      map[int][]byte{},
	}

	ctx := context.Background()
	if err := reg.VerifyClient(ctx, attestation); err != nil {
		t.Fatalf("failed to verify client: %v", err)
	}

	// Session should exist
	session, ok := reg.GetSession("client-1")
	if !ok {
		t.Error("expected session to exist")
	}
	if session.ClientID != "client-1" {
		t.Errorf("expected client ID 'client-1', got: %s", session.ClientID)
	}

	// Invalidate session
	reg.InvalidateSession("client-1")

	// Session should not exist
	_, ok = reg.GetSession("client-1")
	if ok {
		t.Error("expected session to be invalidated")
	}
}

func TestRegistrySessionExpiration(t *testing.T) {
	cfg := validTestConfig()
	cfg.Attestation.RequireAttestation = true
	cfg.Attestation.CacheSessionDuration = time.Minute

	reg, err := NewRegistry(cfg, testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	reg.now = func() time.Time { return current }

	// Verify a client
	attestation := &AttestationEvidence{
		ClientID:  "client-1",
		AIK:       []byte("aik-1-bytes-here"),
		Timestamp: current,
		PCRs:      map[int][]byte{},
	}

	ctx := context.Background()
	if err := reg.VerifyClient(ctx, attestation); err != nil {
		t.Fatalf("failed to verify client: %v", err)
	}

	// Still valid at exactly the session duration: expiry is strictly after
	// ValidUntil.
	current = current.Add(time.Minute)
	session, ok := reg.GetSession("client-1")
	if !ok {
		t.Fatal("expected session to be valid at exactly its duration")
	}
	if !session.ValidUntil.Equal(current) {
		t.Errorf("ValidUntil = %v, want %v", session.ValidUntil, current)
	}

	// Expired one tick later, and evicted on that read.
	current = current.Add(time.Nanosecond)
	if _, ok := reg.GetSession("client-1"); ok {
		t.Error("expected session to be expired")
	}
	if _, ok := reg.sessions.Load("client-1"); ok {
		t.Error("expected expired session to be evicted")
	}
}

func TestRegistryEncryptImage(t *testing.T) {
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	tests := []struct {
		name        string
		ref         string
		keyID       string
		expectError bool
	}{
		{
			name:        "image not found",
			ref:         "myrepo/myimage:v1",
			keyID:       "my-key",
			expectError: true,
		},
		{
			name:        "empty reference",
			ref:         "",
			keyID:       "my-key",
			expectError: true,
		},
		{
			name:        "empty key ID",
			ref:         "myrepo/myimage:v1",
			keyID:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := reg.EncryptImage(ctx, tt.ref, tt.keyID)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRegistryDecryptImage(t *testing.T) {
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	tests := []struct {
		name        string
		ref         string
		expectError bool
	}{
		{
			name:        "image not found",
			ref:         "myrepo/myimage:v1",
			expectError: true,
		},
		{
			name:        "empty reference",
			ref:         "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := reg.DecryptImage(ctx, tt.ref)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRegistryClose(t *testing.T) {
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// First close should succeed
	if err := reg.Close(); err != nil {
		t.Errorf("first close failed: %v", err)
	}

	// Second close should return error
	err = reg.Close()
	var target ErrRegistryClosed
	if !errors.As(err, &target) {
		t.Errorf("expected ErrRegistryClosed, got: %T (%v)", err, err)
	}
}

func TestRegistryOperationsAfterClose(t *testing.T) {
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	if err := reg.Close(); err != nil {
		t.Fatalf("failed to close registry: %v", err)
	}

	ctx := context.Background()

	// All operations should fail
	var target ErrRegistryClosed

	err = reg.Push(ctx, "test:latest", &Image{}, PushOptions{})
	if !errors.As(err, &target) {
		t.Errorf("Push: expected ErrRegistryClosed, got: %T", err)
	}

	_, err = reg.Pull(ctx, "test:latest", PullOptions{})
	if !errors.As(err, &target) {
		t.Errorf("Pull: expected ErrRegistryClosed, got: %T", err)
	}

	err = reg.Delete(ctx, "test:latest")
	if !errors.As(err, &target) {
		t.Errorf("Delete: expected ErrRegistryClosed, got: %T", err)
	}

	_, err = reg.List(ctx, RegistryListOptions{})
	if !errors.As(err, &target) {
		t.Errorf("List: expected ErrRegistryClosed, got: %T", err)
	}

	err = reg.VerifyClient(ctx, &AttestationEvidence{})
	if !errors.As(err, &target) {
		t.Errorf("VerifyClient: expected ErrRegistryClosed, got: %T", err)
	}

	err = reg.EncryptImage(ctx, "test:latest", "key")
	if !errors.As(err, &target) {
		t.Errorf("EncryptImage: expected ErrRegistryClosed, got: %T", err)
	}

	_, err = reg.DecryptImage(ctx, "test:latest")
	if !errors.As(err, &target) {
		t.Errorf("DecryptImage: expected ErrRegistryClosed, got: %T", err)
	}
}

func TestValidateImageRef(t *testing.T) {
	tests := []struct {
		name        string
		ref         string
		expectError bool
	}{
		{"simple name", "alpine", false},
		{"with tag", "alpine:latest", false},
		{"with repository", "myrepo/myimage", false},
		{"with repository and tag", "myrepo/myimage:v1.2.3", false},
		{"with digest", "myrepo/myimage@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd", false},
		{"with registry", "registry.example.com/myrepo/myimage:v1", false},
		{"with port", "localhost:5000/myimage:v1", false},
		{"empty", "", true},
		{"too long", string(make([]byte, 300)), true},
		{"uppercase", "MyRepo/MyImage:v1", true},
		{"special chars", "my-repo/my_image:v1", false},
		{"dots in name", "my.repo/my.image:v1", false},
		// OCI distribution-spec repository and tag grammar.
		{"double underscore separator", "my__repo/image:v1", false},
		{"hyphen run separator", "my---repo/image:v1", false},
		{"triple underscore separator", "my___repo/image:v1", true},
		{"trailing separator", "myrepo-/image:v1", true},
		{"integration name", "grpc-1792717075-push-basic-20261023005754-333050821:v1", false},
		{"mixed-case integration name", "gRPC-1792717075-push-basic-20261023005754-333050821:v1", true},
		{"128-char tag", "alpine:" + strings.Repeat("a", 128), false},
		{"129-char tag", "alpine:" + strings.Repeat("a", 129), true},
		{"tag starting with dot", "alpine:.v1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateImageRef(tt.ref)
			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRegistryConcurrentOperations(t *testing.T) {
	cfg := validTestConfig()
	cfg.MaxConcurrentPulls = 10
	cfg.MaxConcurrentPushes = 10

	reg, err := NewRegistry(cfg, testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	var wg sync.WaitGroup
	ctx := context.Background()

	// Start multiple concurrent pulls and pushes
	for i := 0; i < 20; i++ {
		wg.Add(2)

		go func(idx int) {
			defer wg.Done()
			_, _ = reg.Pull(ctx, "test:latest", PullOptions{})
		}(i)

		go func(idx int) {
			defer wg.Done()
			_ = reg.Push(ctx, "test:latest", &Image{Manifest: &ImageManifest{}}, PushOptions{})
		}(i)
	}

	wg.Wait()
}

// Ensure TrustedRegistry interface is properly implemented
func TestInterfaceImplementation(t *testing.T) {
	var _ TrustedRegistry = (*Registry)(nil)
}

func TestImageStructure(t *testing.T) {
	image := &Image{
		Manifest: &ImageManifest{
			SchemaVersion: 2,
			MediaType:     "application/vnd.oci.image.manifest.v1+json",
			Reference:     "myrepo/myimage:v1",
			Config: Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    "sha256:config123",
				Size:      512,
			},
			Layers: []Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
					Digest:    "sha256:layer1",
					Size:      2048,
				},
			},
		},
		Layers: []Layer{
			{
				Digest:    "sha256:layer1",
				Size:      2048,
				MediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
				Content:   []byte("layer data"),
			},
		},
		Config: []byte("config data"),
	}

	if image.Manifest.SchemaVersion != 2 {
		t.Errorf("unexpected schema version: %d", image.Manifest.SchemaVersion)
	}

	if len(image.Layers) != 1 {
		t.Errorf("unexpected number of layers: %d", len(image.Layers))
	}
}

func TestAttestationEvidenceStructure(t *testing.T) {
	evidence := &AttestationEvidence{
		Quote:     []byte("quote data"),
		Signature: []byte("signature data"),
		PCRs: map[int][]byte{
			0:  make([]byte, 32),
			7:  make([]byte, 32),
			14: make([]byte, 32),
		},
		AIK:       []byte("aikfingerprint"),
		Nonce:     []byte("nonce"),
		Timestamp: time.Now(),
		ClientID:  "client-123",
	}

	if evidence.ClientID != "client-123" {
		t.Errorf("unexpected client ID: %s", evidence.ClientID)
	}

	if len(evidence.PCRs) != 3 {
		t.Errorf("unexpected number of PCRs: %d", len(evidence.PCRs))
	}
}

func TestPushOptionsStructure(t *testing.T) {
	opts := PushOptions{
		Encrypt:        true,
		KeyID:          "my-key",
		AllowOverwrite: true,
		SignImage:      true,
		SigningKeyID:   "signing-key",
		Annotations: map[string]string{
			"author":  "test",
			"version": "1.0",
		},
		Timeout: 30 * time.Second,
	}

	if !opts.Encrypt {
		t.Error("expected Encrypt to be true")
	}

	if opts.KeyID != "my-key" {
		t.Errorf("unexpected KeyID: %s", opts.KeyID)
	}

	if len(opts.Annotations) != 2 {
		t.Errorf("unexpected annotations count: %d", len(opts.Annotations))
	}
}

func TestPullOptionsStructure(t *testing.T) {
	opts := PullOptions{
		DecryptIfEncrypted: true,
		VerifySignature:    true,
		Platform:           "linux/amd64",
		Timeout:            30 * time.Second,
	}

	if !opts.DecryptIfEncrypted {
		t.Error("expected DecryptIfEncrypted to be true")
	}

	if opts.Platform != "linux/amd64" {
		t.Errorf("unexpected platform: %s", opts.Platform)
	}
}

func TestRegistryListOptionsStructure(t *testing.T) {
	opts := RegistryListOptions{
		Repository:       "myrepo",
		TagPrefix:        "v1",
		Limit:            100,
		Offset:           50,
		IncludeEncrypted: true,
		SortBy:           "created_at",
		SortDesc:         true,
	}

	if opts.Repository != "myrepo" {
		t.Errorf("unexpected repository: %s", opts.Repository)
	}

	if opts.Limit != 100 {
		t.Errorf("unexpected limit: %d", opts.Limit)
	}
}

func TestRegistrySessionViewStructure(t *testing.T) {
	session := &RegistrySessionView{
		ClientID:    "client-1",
		AIK:         "aik-fingerprint",
		PCRs:        map[int][]byte{7: {1, 2, 3}},
		ValidUntil:  time.Now().Add(1 * time.Hour),
		Permissions: []string{"pull", "push"},
	}

	if session.ClientID != "client-1" {
		t.Errorf("unexpected client ID: %s", session.ClientID)
	}

	if len(session.Permissions) != 2 {
		t.Errorf("unexpected permissions count: %d", len(session.Permissions))
	}
}
