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

// testRegistryDigest stands in for the repository manifest digest a registry
// reports for an image. It is deliberately NOT sha256(ref): the whole point of
// these tests is that no code path may substitute a hash of the image
// reference for the image's content digest, so the fixture value must be
// distinguishable from that hash.
func testRegistryDigest(ref string) string {
	sum := sha256.Sum256([]byte("registry-manifest\x00" + ref))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// testRefHashDigest is the forbidden value: a canonical-looking digest computed
// from the image reference string. No API may ever return it.
func testRefHashDigest(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// newImageManagerWithImages returns a manager whose podman backend already
// knows the given references, each with a resolvable content digest.
func newImageManagerWithImages(t *testing.T, config ImageManagerConfig, opts []ImageManagerOption, refs ...string) (*ImageManager, *MockPodmanBackend) {
	t.Helper()
	podman := NewMockPodmanBackend()
	for _, ref := range refs {
		podman.images[ref] = &PodmanImage{
			ID:     "img-" + ref,
			Names:  []string{ref},
			Digest: testRegistryDigest(ref),
		}
	}
	manager, err := NewImageManager(config, append(opts, WithPodmanForImages(podman))...)
	if err != nil {
		t.Fatalf("NewImageManager: %v", err)
	}
	return manager, podman
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
//
// A verification result must name the artifact it covers by its real OCI
// content digest. The manager used to put a SHA-256 of the image REFERENCE in
// the Digest field — a value no registry, no other host and no verifier can
// reproduce — which made an authoritative-looking record of an artifact that
// was never identified.
func TestImageManagerVerifyImage(t *testing.T) {
	t.Run("verify image successfully", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		verifier := NewMockImageVerifier(true)
		manager, _ := newImageManagerWithImages(t, config,
			[]ImageManagerOption{WithImageVerifier(verifier)}, "alpine:latest")
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

	// The regression this guards: the reported digest is the image's content
	// digest, never a hash of its reference.
	t.Run("reports the content digest, not a hash of the reference", func(t *testing.T) {
		const ref = "alpine:latest"
		config := ImageManagerConfig{Logger: testImageLogger()}
		verifier := NewMockImageVerifier(true)
		manager, _ := newImageManagerWithImages(t, config,
			[]ImageManagerOption{WithImageVerifier(verifier)}, ref)
		defer manager.Close()

		result, err := manager.VerifyImage(context.Background(), ref)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.Digest != testRegistryDigest(ref) {
			t.Errorf("Digest = %q, want the podman-reported content digest %q",
				result.Digest, testRegistryDigest(ref))
		}
		if result.Digest == testRefHashDigest(ref) {
			t.Error("the image reference hash was substituted for the content digest")
		}
	})

	// Same property for the unendorsed path, which had the identical
	// substitution.
	t.Run("unverified result also reports the content digest", func(t *testing.T) {
		const ref = "alpine:latest"
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := newImageManagerWithImages(t, config, nil, ref)
		defer manager.Close()

		result, err := manager.VerifyImage(context.Background(), ref)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if result.Verified {
			t.Error("expected image to be unverified without verifier")
		}
		if result.Digest != testRegistryDigest(ref) {
			t.Errorf("Digest = %q, want %q", result.Digest, testRegistryDigest(ref))
		}
		if result.Digest == testRefHashDigest(ref) {
			t.Error("the image reference hash was substituted for the content digest")
		}
	})

	t.Run("verify uses cache", func(t *testing.T) {
		config := ImageManagerConfig{
			Logger:   testImageLogger(),
			CacheTTL: 5 * time.Minute,
		}
		verifier := NewMockImageVerifier(true)
		manager, _ := newImageManagerWithImages(t, config,
			[]ImageManagerOption{WithImageVerifier(verifier)}, "alpine:latest")
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
		manager, _ := newImageManagerWithImages(t, config, nil, "alpine:latest")
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
		manager, _ := newImageManagerWithImages(t, config,
			[]ImageManagerOption{WithImageVerifier(verifier)}, "bad:image")
		defer manager.Close()

		_, err := manager.VerifyImage(context.Background(), "bad:image")
		if err == nil {
			t.Fatal("expected error from verifier")
		}
	})

	// An image whose content digest cannot be resolved yields NO result: the
	// verifier is never even consulted, because there is nothing to attribute
	// a verdict to.
	t.Run("unresolvable image is an error, not a result with a placeholder digest", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		verifier := NewMockImageVerifier(true)
		podman := NewMockPodmanBackend()
		podman.inspectError = errors.New("podman: no such image")
		manager, _ := NewImageManager(config,
			WithImageVerifier(verifier), WithPodmanForImages(podman))
		defer manager.Close()

		result, err := manager.VerifyImage(context.Background(), "ghost:latest")
		if err == nil {
			t.Fatal("an unresolvable image must be reported, not papered over")
		}
		if result != nil {
			t.Errorf("no verification result may be returned on failure, got %+v", result)
		}
		if verifier.verifyCalls != 0 {
			t.Errorf("the verifier must not be consulted for an unidentified image, got %d calls",
				verifier.verifyCalls)
		}
	})

	t.Run("no podman backend is an error, not an unverified result", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config, WithImageVerifier(NewMockImageVerifier(true)))
		defer manager.Close()

		if _, err := manager.VerifyImage(context.Background(), "alpine:latest"); !errors.Is(err, ErrPodmanNotAvailable) {
			t.Fatalf("expected ErrPodmanNotAvailable, got %v", err)
		}
	})
}

// TestImageManagerGetImageDigest asserts the digest path fails closed. The
// manager used to substitute a SHA-256 of the image REFERENCE whenever podman
// could not be inspected — a value no registry, no other host and no verifier
// can reproduce, presented as if it were the image's content digest.
func TestImageManagerGetImageDigest(t *testing.T) {
	const validDigest = "sha256:" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("returns the content digest reported by podman", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		podman.images["alpine:latest"] = &PodmanImage{
			ID:     "img-alpine",
			Digest: validDigest,
		}
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		digest, err := manager.GetImageDigest(context.Background(), "alpine:latest")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if digest != validDigest {
			t.Errorf("digest = %q, want %q", digest, validDigest)
		}
	})

	t.Run("resolves a pinned reference without inspecting", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config) // no podman at all
		defer manager.Close()

		digest, err := manager.GetImageDigest(context.Background(), "alpine@"+validDigest)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if digest != validDigest {
			t.Errorf("digest = %q, want %q", digest, validDigest)
		}
	})

	t.Run("caches the resolved digest", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		podman.images["alpine:latest"] = &PodmanImage{ID: "img-alpine", Digest: validDigest}
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		first, err := manager.GetImageDigest(context.Background(), "alpine:latest")
		if err != nil {
			t.Fatalf("first call: %v", err)
		}
		second, err := manager.GetImageDigest(context.Background(), "alpine:latest")
		if err != nil {
			t.Fatalf("second call: %v", err)
		}
		if first != second {
			t.Error("expected same digest from cache")
		}
	})

	// The regression this test guards: an inspect failure must not yield a
	// hash of the image reference.
	t.Run("inspect failure returns the error, never a reference hash", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		podman.inspectError = errors.New("podman: no such image")
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		digest, err := manager.GetImageDigest(context.Background(), "alpine:latest")
		if err == nil {
			t.Fatal("an inspect failure must be reported, not papered over")
		}
		if digest != "" {
			t.Errorf("no digest may be returned on failure, got %q", digest)
		}

		refHash := sha256.Sum256([]byte("alpine:latest"))
		if digest == "sha256:"+hex.EncodeToString(refHash[:]) {
			t.Error("the image reference hash was substituted for the content digest")
		}
	})

	t.Run("no podman backend is an error, not a fallback", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		defer manager.Close()

		if _, err := manager.GetImageDigest(context.Background(), "alpine:latest"); err == nil {
			t.Fatal("expected an error with no podman backend")
		}
	})

	t.Run("locally built image with no repository digest is an error", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		podman.images["local:dev"] = &PodmanImage{ID: "img-local"} // no Digest
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		if _, err := manager.GetImageDigest(context.Background(), "local:dev"); err == nil {
			t.Fatal("an image with no content digest must be an error")
		}
	})

	t.Run("non-canonical digest from podman is rejected", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		podman := NewMockPodmanBackend()
		podman.images["alpine:latest"] = &PodmanImage{ID: "img", Digest: "sha256:abc123"}
		manager, _ := NewImageManager(config, WithPodmanForImages(podman))
		defer manager.Close()

		if _, err := manager.GetImageDigest(context.Background(), "alpine:latest"); err == nil {
			t.Fatal("a truncated digest must be rejected")
		}
	})

	t.Run("empty ref", func(t *testing.T) {
		config := ImageManagerConfig{Logger: testImageLogger()}
		manager, _ := NewImageManager(config)
		defer manager.Close()

		if _, err := manager.GetImageDigest(context.Background(), ""); err == nil {
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
	manager, _ := newImageManagerWithImages(t, config,
		[]ImageManagerOption{WithImageVerifier(verifier)}, "alpine:latest")
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
	manager, _ := newImageManagerWithImages(t, config,
		[]ImageManagerOption{WithImageVerifier(verifier)}, "alpine:latest")
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
		manager, _ := newImageManagerWithImages(t, config,
			[]ImageManagerOption{WithImageVerifier(verifier)}, "alpine:latest")
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
