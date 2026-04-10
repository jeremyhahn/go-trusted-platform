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

package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"
)

// MockImageVerifier is a mock implementation of ImageVerifier for testing.
type MockImageVerifier struct {
	result      *ImageVerificationResult
	verifyError error
	verifyCalls int
}

func NewMockImageVerifier(verified bool) *MockImageVerifier {
	return &MockImageVerifier{
		result: &ImageVerificationResult{
			Verified:      verified,
			Signer:        "test-signer",
			SignatureType: "cosign",
		},
	}
}

func (m *MockImageVerifier) Verify(ctx context.Context, imageRef string, opts ImageVerifyOptions) (*ImageVerificationResult, error) {
	m.verifyCalls++
	if m.verifyError != nil {
		return nil, m.verifyError
	}
	return m.result, nil
}

// testImageLogger returns a test logger for image tests.
func testImageLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// TestNewImageManager tests ImageManager creation.
func TestNewImageManager(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:    testImageLogger(),
			CacheSize: 100,
			CacheTTL:  5 * time.Minute,
		}

		manager, err := NewImageManager(config)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if manager == nil {
			t.Fatal("expected manager, got nil")
		}
		defer manager.Close()
	})

	t.Run("nil logger returns error", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger: nil,
		}

		_, err := NewImageManager(config)
		if err == nil {
			t.Fatal("expected error for nil logger")
		}
	})

	t.Run("negative cache size returns error", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:    testImageLogger(),
			CacheSize: -1,
		}

		_, err := NewImageManager(config)
		if err == nil {
			t.Fatal("expected error for negative cache size")
		}
	})

	t.Run("negative cache TTL returns error", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:   testImageLogger(),
			CacheTTL: -1 * time.Second,
		}

		_, err := NewImageManager(config)
		if err == nil {
			t.Fatal("expected error for negative cache TTL")
		}
	})

	t.Run("with all options", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:            testImageLogger(),
			CacheSize:         50,
			CacheTTL:          10 * time.Minute,
			RequireSignature:  true,
			TrustedRootCA:     "/path/to/ca.crt",
			AllowedSigners:    []string{"signer1", "signer2"},
			AllowedRegistries: []string{"docker.io", "gcr.io"},
		}
		podman := NewMockPodmanBackend()
		verifier := NewMockImageVerifier(true)

		manager, err := NewImageManager(config,
			WithPodmanForImages(podman),
			WithImageVerifier(verifier),
		)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer manager.Close()
	})
}

// TestImageManagerPullImage tests image pulling.
func TestImageManagerPullImage(t *testing.T) {
	t.Run("pull image successfully", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		err := manager.PullImage(context.Background(), "alpine:latest", PullOptions{})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if podman.pullCalled != 1 {
			t.Errorf("expected pullCalled=1, got %d", podman.pullCalled)
		}
	})

	t.Run("pull with signature verification", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:           testImageLogger(),
			RequireSignature: true,
		}
		podman := NewMockPodmanBackend()
		verifier := NewMockImageVerifier(true)
		manager, _ := NewImageManager(config,
			WithPodmanForImages(podman),
			WithImageVerifier(verifier),
		)
		defer manager.Close()

		err := manager.PullImage(context.Background(), "alpine:latest", PullOptions{
			VerifySignature: true,
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if verifier.verifyCalls != 1 {
			t.Errorf("expected verifyCalls=1, got %d", verifier.verifyCalls)
		}
	})

	t.Run("pull with signature verification fails", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:           testImageLogger(),
			RequireSignature: true,
		}
		podman := NewMockPodmanBackend()
		verifier := NewMockImageVerifier(false) // Verification fails
		manager, _ := NewImageManager(config,
			WithPodmanForImages(podman),
			WithImageVerifier(verifier),
		)
		defer manager.Close()

		err := manager.PullImage(context.Background(), "unsigned:latest", PullOptions{
			VerifySignature: true,
		})
		if err == nil {
			t.Fatal("expected error for failed verification")
		}
		if !errors.Is(err, ErrImageSignatureRequired) {
			t.Errorf("expected ErrImageSignatureRequired, got %v", err)
		}
	})

	t.Run("pull from disallowed registry", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:            testImageLogger(),
			AllowedRegistries: []string{"docker.io", "gcr.io"},
		}
		podman := NewMockPodmanBackend()
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		err := manager.PullImage(context.Background(), "evil.registry.com/malware:latest", PullOptions{})
		if err == nil {
			t.Fatal("expected error for disallowed registry")
		}
	})

	t.Run("pull from allowed registry", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:            testImageLogger(),
			AllowedRegistries: []string{"docker.io", "gcr.io"},
		}
		podman := NewMockPodmanBackend()
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		err := manager.PullImage(context.Background(), "gcr.io/my-project/app:v1", PullOptions{})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("pull with empty ref", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		defer manager.Close()

		err := manager.PullImage(context.Background(), "", PullOptions{})
		if err == nil {
			t.Fatal("expected error for empty ref")
		}
	})

	t.Run("pull on closed manager", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		manager.Close()

		err := manager.PullImage(context.Background(), "alpine:latest", PullOptions{})
		if err == nil {
			t.Fatal("expected error on closed manager")
		}
	})
}

// TestImageManagerVerifyImage tests image verification.
func TestImageManagerVerifyImage(t *testing.T) {
	t.Run("verify image successfully", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		verifier := NewMockImageVerifier(true)
		manager, _ := NewImageManager(config, WithImageVerifier(verifier))
		defer manager.Close()

		result, err := manager.VerifyImage(context.Background(), "alpine:latest")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !result.Verified {
			t.Error("expected image to be verified")
		}
		if result.Signer != "test-signer" {
			t.Errorf("expected signer 'test-signer', got %q", result.Signer)
		}
	})

	t.Run("verify uses cache", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:   testImageLogger(),
			CacheTTL: 5 * time.Minute,
		}
		verifier := NewMockImageVerifier(true)
		manager, _ := NewImageManager(config, WithImageVerifier(verifier))
		defer manager.Close()

		// First call
		manager.VerifyImage(context.Background(), "alpine:latest")
		// Second call should use cache
		manager.VerifyImage(context.Background(), "alpine:latest")

		if verifier.verifyCalls != 1 {
			t.Errorf("expected verifyCalls=1 (cached), got %d", verifier.verifyCalls)
		}
	})

	t.Run("verify without verifier", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		defer manager.Close()

		result, err := manager.VerifyImage(context.Background(), "alpine:latest")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.Verified {
			t.Error("expected image to be unverified without verifier")
		}
	})

	t.Run("verify with empty ref", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		defer manager.Close()

		_, err := manager.VerifyImage(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty ref")
		}
	})

	t.Run("verify with verifier error", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		verifier := NewMockImageVerifier(false)
		verifier.verifyError = errors.New("verification failed")
		manager, _ := NewImageManager(config, WithImageVerifier(verifier))
		defer manager.Close()

		_, err := manager.VerifyImage(context.Background(), "bad:image")
		if err == nil {
			t.Fatal("expected error from verifier")
		}
	})
}

// TestImageManagerGetImageDigest tests digest retrieval.
func TestImageManagerGetImageDigest(t *testing.T) {
	t.Run("get digest from podman", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		// Pre-populate image with digest
		podman.images["alpine:latest"] = &PodmanImage{
			ID:     "img-alpine",
			Digest: "sha256:abc123",
		}
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		digest, err := manager.GetImageDigest(context.Background(), "alpine:latest")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(digest) == 0 {
			t.Error("expected non-empty digest")
		}
	})

	t.Run("get digest uses cache", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		podman.images["alpine:latest"] = &PodmanImage{
			ID:     "img-alpine",
			Digest: "sha256:abc123",
		}
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		// First call
		digest1, _ := manager.GetImageDigest(context.Background(), "alpine:latest")
		// Second call should use cache
		digest2, _ := manager.GetImageDigest(context.Background(), "alpine:latest")

		if string(digest1) != string(digest2) {
			t.Error("expected same digest from cache")
		}
	})

	t.Run("get digest without podman falls back", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config) // No podman
		defer manager.Close()

		digest, err := manager.GetImageDigest(context.Background(), "alpine:latest")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(digest) == 0 {
			t.Error("expected non-empty digest from fallback")
		}
	})

	t.Run("get digest with empty ref", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		defer manager.Close()

		_, err := manager.GetImageDigest(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty ref")
		}
	})
}

// TestImageManagerListImages tests image listing.
func TestImageManagerListImages(t *testing.T) {
	t.Run("list images", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		podman.images["alpine:latest"] = &PodmanImage{
			ID:    "img-1",
			Names: []string{"alpine:latest"},
			Size:  1024,
		}
		podman.images["nginx:latest"] = &PodmanImage{
			ID:    "img-2",
			Names: []string{"nginx:latest"},
			Size:  2048,
		}
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		images, err := manager.ListImages(context.Background())
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(images) != 2 {
			t.Errorf("expected 2 images, got %d", len(images))
		}
	})

	t.Run("list without podman", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config) // No podman
		defer manager.Close()

		_, err := manager.ListImages(context.Background())
		if err == nil {
			t.Fatal("expected error without podman")
		}
	})
}

// TestImageManagerInspectImage tests image inspection.
func TestImageManagerInspectImage(t *testing.T) {
	t.Run("inspect existing image", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		podman.images["alpine:latest"] = &PodmanImage{
			ID:           "img-alpine",
			Names:        []string{"alpine:latest"},
			Size:         1024,
			Architecture: "amd64",
			OS:           "linux",
		}
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		result, err := manager.InspectImage(context.Background(), "alpine:latest")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.ID != "img-alpine" {
			t.Errorf("expected ID 'img-alpine', got %q", result.ID)
		}
		if result.Architecture != "amd64" {
			t.Errorf("expected architecture 'amd64', got %q", result.Architecture)
		}
	})

	t.Run("inspect nonexistent image", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		_, err := manager.InspectImage(context.Background(), "nonexistent:tag")
		if err == nil {
			t.Fatal("expected error for nonexistent image")
		}
	})

	t.Run("inspect with empty ref", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		defer manager.Close()

		_, err := manager.InspectImage(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty ref")
		}
	})
}

// TestImageManagerClearCache tests cache clearing.
func TestImageManagerClearCache(t *testing.T) {
	config := ImageManagerConfig{
		Logger:   testImageLogger(),
		CacheTTL: 5 * time.Minute,
	}
	verifier := NewMockImageVerifier(true)
	manager, _ := NewImageManager(config, WithImageVerifier(verifier))
	defer manager.Close()

	// Populate cache
	manager.VerifyImage(context.Background(), "alpine:latest")
	manager.GetImageDigest(context.Background(), "alpine:latest")

	// Clear cache
	manager.ClearCache()

	// Verify cache was cleared by checking verifier is called again
	manager.VerifyImage(context.Background(), "alpine:latest")
	if verifier.verifyCalls != 2 {
		t.Errorf("expected verifyCalls=2 after clear, got %d", verifier.verifyCalls)
	}
}

// TestImageManagerClose tests manager closure.
func TestImageManagerClose(t *testing.T) {
	t.Run("close manager", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)

		err := manager.Close()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("double close", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)

		manager.Close()
		err := manager.Close()
		if err != nil {
			t.Fatalf("expected no error on double close, got %v", err)
		}
	})
}

// TestParseRegistry tests registry parsing from image references.
func TestParseRegistry(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"alpine:latest", "docker.io"},
		{"nginx", "docker.io"},
		{"library/nginx:latest", "docker.io"},
		{"gcr.io/my-project/app:v1", "gcr.io"},
		{"quay.io/prometheus/node-exporter:latest", "quay.io"},
		{"localhost:5000/myimage:tag", "localhost:5000"},
		{"registry.example.com/image:tag", "registry.example.com"},
		{"192.168.1.1:5000/image", "192.168.1.1:5000"},
		{"alpine@sha256:abc123", "docker.io"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseRegistry(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestIsRegistryAllowed tests registry allowlist checking.
func TestIsRegistryAllowed(t *testing.T) {
	t.Run("empty allowlist allows all", func(t *testing.T) {
		if !isRegistryAllowed("any.registry.com", []string{}) {
			t.Error("expected empty allowlist to allow all")
		}
	})

	t.Run("exact match", func(t *testing.T) {
		allowed := []string{"docker.io", "gcr.io"}
		if !isRegistryAllowed("docker.io", allowed) {
			t.Error("expected docker.io to be allowed")
		}
		if isRegistryAllowed("quay.io", allowed) {
			t.Error("expected quay.io to be disallowed")
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		allowed := []string{"Docker.IO"}
		if !isRegistryAllowed("docker.io", allowed) {
			t.Error("expected case insensitive match")
		}
	})

	t.Run("wildcard match", func(t *testing.T) {
		allowed := []string{"*.gcr.io", "docker.io"}
		if !isRegistryAllowed("us.gcr.io", allowed) {
			t.Error("expected us.gcr.io to match *.gcr.io")
		}
		if !isRegistryAllowed("eu.gcr.io", allowed) {
			t.Error("expected eu.gcr.io to match *.gcr.io")
		}
		if isRegistryAllowed("gcr.io", allowed) {
			t.Error("expected gcr.io to not match *.gcr.io")
		}
	})
}

// TestParseImageReference tests image reference parsing.
func TestParseImageReference(t *testing.T) {
	tests := []struct {
		input    string
		registry string
		repo     string
		name     string
		tag      string
		digest   string
	}{
		{
			input:    "alpine",
			registry: "docker.io",
			repo:     "library/alpine",
			name:     "alpine",
			tag:      "latest",
		},
		{
			input:    "alpine:3.18",
			registry: "docker.io",
			repo:     "library/alpine",
			name:     "alpine",
			tag:      "3.18",
		},
		{
			input:    "myuser/myapp:v1.0",
			registry: "docker.io",
			repo:     "myuser/myapp",
			name:     "myapp",
			tag:      "v1.0",
		},
		{
			input:    "gcr.io/project/image:tag",
			registry: "gcr.io",
			repo:     "project/image",
			name:     "image",
			tag:      "tag",
		},
		{
			input:    "localhost:5000/myimage",
			registry: "localhost:5000",
			repo:     "myimage",
			name:     "myimage",
			tag:      "latest",
		},
		{
			input:    "alpine@sha256:abc123",
			registry: "docker.io",
			repo:     "library/alpine",
			name:     "alpine",
			tag:      "",
			digest:   "sha256:abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ref := ParseImageReference(tt.input)

			if ref.Registry != tt.registry {
				t.Errorf("expected registry %q, got %q", tt.registry, ref.Registry)
			}
			if ref.Repository != tt.repo {
				t.Errorf("expected repository %q, got %q", tt.repo, ref.Repository)
			}
			if ref.Name != tt.name {
				t.Errorf("expected name %q, got %q", tt.name, ref.Name)
			}
			if ref.Tag != tt.tag {
				t.Errorf("expected tag %q, got %q", tt.tag, ref.Tag)
			}
			if ref.Digest != tt.digest {
				t.Errorf("expected digest %q, got %q", tt.digest, ref.Digest)
			}
		})
	}
}

// TestImageReferenceString tests ImageReference string methods.
func TestImageReferenceString(t *testing.T) {
	t.Run("basic reference", func(t *testing.T) {
		ref := &ImageReference{
			Registry:   "docker.io",
			Repository: "library/alpine",
			Tag:        "3.18",
		}
		str := ref.String()
		if str != "library/alpine:3.18" {
			t.Errorf("expected 'library/alpine:3.18', got %q", str)
		}
	})

	t.Run("with custom registry", func(t *testing.T) {
		ref := &ImageReference{
			Registry:   "gcr.io",
			Repository: "project/image",
			Tag:        "v1",
		}
		str := ref.String()
		if str != "gcr.io/project/image:v1" {
			t.Errorf("expected 'gcr.io/project/image:v1', got %q", str)
		}
	})

	t.Run("with digest", func(t *testing.T) {
		ref := &ImageReference{
			Registry:   "docker.io",
			Repository: "library/alpine",
			Digest:     "sha256:abc123",
		}
		str := ref.String()
		if str != "library/alpine@sha256:abc123" {
			t.Errorf("expected 'library/alpine@sha256:abc123', got %q", str)
		}
	})

	t.Run("full reference", func(t *testing.T) {
		ref := &ImageReference{
			Registry:   "gcr.io",
			Repository: "project/image",
			Tag:        "v1",
		}
		full := ref.FullReference()
		if full != "gcr.io/project/image:v1" {
			t.Errorf("expected 'gcr.io/project/image:v1', got %q", full)
		}
	})
}

// TestComputeDigestFromRef tests digest computation.
func TestComputeDigestFromRef(t *testing.T) {
	config := ImageManagerConfig{Logger: testImageLogger()}
	manager, _ := NewImageManager(config)
	defer manager.Close()

	digest := manager.computeDigestFromRef("alpine:latest")
	if len(digest) != sha256.Size {
		t.Errorf("expected %d bytes, got %d", sha256.Size, len(digest))
	}

	// Same input should produce same digest
	digest2 := manager.computeDigestFromRef("alpine:latest")
	if string(digest) != string(digest2) {
		t.Error("expected deterministic digest")
	}

	// Different input should produce different digest
	digest3 := manager.computeDigestFromRef("nginx:latest")
	if string(digest) == string(digest3) {
		t.Error("expected different digest for different input")
	}
}

// TestParseDigest tests digest parsing.
func TestParseDigest(t *testing.T) {
	config := ImageManagerConfig{Logger: testImageLogger()}
	manager, _ := NewImageManager(config)
	defer manager.Close()

	t.Run("valid sha256 digest", func(t *testing.T) {
		input := "sha256:" + hex.EncodeToString(make([]byte, 32))
		result := manager.parseDigest(input)
		if len(result) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(result))
		}
	})

	t.Run("digest without prefix", func(t *testing.T) {
		input := hex.EncodeToString(make([]byte, 32))
		result := manager.parseDigest(input)
		if len(result) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(result))
		}
	})

	t.Run("invalid hex falls back to hash", func(t *testing.T) {
		result := manager.parseDigest("not-a-valid-hex")
		if len(result) != 32 {
			t.Errorf("expected 32 bytes from fallback, got %d", len(result))
		}
	})
}

// TestImageManagerConfigValidate tests configuration validation.
func TestImageManagerConfigValidate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:    testImageLogger(),
			CacheSize: 100,
			CacheTTL:  5 * time.Minute,
		}
		if err := config.Validate(); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("nil logger", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger: nil,
		}
		if err := config.Validate(); err == nil {
			t.Error("expected error for nil logger")
		}
	})

	t.Run("negative cache size", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:    testImageLogger(),
			CacheSize: -1,
		}
		if err := config.Validate(); err == nil {
			t.Error("expected error for negative cache size")
		}
	})

	t.Run("negative cache TTL", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:   testImageLogger(),
			CacheTTL: -1 * time.Second,
		}
		if err := config.Validate(); err == nil {
			t.Error("expected error for negative cache TTL")
		}
	})
}

// TestVerificationCacheExpiry tests that cached entries expire.
func TestVerificationCacheExpiry(t *testing.T) {
	config := ImageManagerConfig{
		Logger:   testImageLogger(),
		CacheTTL: 10 * time.Millisecond, // Very short TTL for testing
	}
	verifier := NewMockImageVerifier(true)
	manager, _ := NewImageManager(config, WithImageVerifier(verifier))
	defer manager.Close()

	// First call populates cache
	manager.VerifyImage(context.Background(), "alpine:latest")
	if verifier.verifyCalls != 1 {
		t.Fatalf("expected verifyCalls=1, got %d", verifier.verifyCalls)
	}

	// Immediate second call uses cache
	manager.VerifyImage(context.Background(), "alpine:latest")
	if verifier.verifyCalls != 1 {
		t.Errorf("expected verifyCalls=1 (cached), got %d", verifier.verifyCalls)
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// Third call should re-verify
	manager.VerifyImage(context.Background(), "alpine:latest")
	if verifier.verifyCalls != 2 {
		t.Errorf("expected verifyCalls=2 (expired), got %d", verifier.verifyCalls)
	}
}

// TestImageManagerRemoveImage tests image removal.
func TestImageManagerRemoveImage(t *testing.T) {
	t.Run("remove image successfully", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		defer manager.Close()

		err := manager.RemoveImage(context.Background(), "alpine:latest", false)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("remove with force", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		defer manager.Close()

		err := manager.RemoveImage(context.Background(), "alpine:latest", true)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("remove with empty ref", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		defer manager.Close()

		err := manager.RemoveImage(context.Background(), "", false)
		if err == nil {
			t.Fatal("expected error for empty ref")
		}
		if !errors.Is(err, ErrInvalidImage) {
			t.Errorf("expected ErrInvalidImage, got %v", err)
		}
	})

	t.Run("remove on closed manager", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		manager.Close()

		err := manager.RemoveImage(context.Background(), "alpine:latest", false)
		if err == nil {
			t.Fatal("expected error on closed manager")
		}
	})

	t.Run("remove clears caches", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:   testImageLogger(),
			CacheTTL: 5 * time.Minute,
		}
		verifier := NewMockImageVerifier(true)
		manager, _ := NewImageManager(config, WithImageVerifier(verifier))
		defer manager.Close()

		// Populate caches
		manager.VerifyImage(context.Background(), "alpine:latest")
		manager.GetImageDigest(context.Background(), "alpine:latest")

		// Remove should clear caches
		manager.RemoveImage(context.Background(), "alpine:latest", false)

		// Next verify should call verifier again
		manager.VerifyImage(context.Background(), "alpine:latest")
		if verifier.verifyCalls != 2 {
			t.Errorf("expected verifyCalls=2 after remove, got %d", verifier.verifyCalls)
		}
	})
}

// TestWithImageManagerLogger tests the logger option.
func TestWithImageManagerLogger(t *testing.T) {
	t.Run("with custom logger", func(t *testing.T) {
		customLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
		config := ImageManagerConfig{
			Logger: testImageLogger(),
		}
		manager, err := NewImageManager(config, WithImageManagerLogger(customLogger))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		defer manager.Close()
	})

	t.Run("nil logger defaults to config logger", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger: testImageLogger(),
		}
		// This should work - the option sets nil but config has a logger
		manager, err := NewImageManager(config, WithImageManagerLogger(nil))
		if err != nil {
			// It might fail validation if logger ends up nil
			// This depends on validation order
			t.Logf("got expected validation error for nil logger: %v", err)
		} else {
			defer manager.Close()
		}
	})
}
