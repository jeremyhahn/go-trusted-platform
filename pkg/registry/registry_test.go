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
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	tests := []struct {
		name        string
		ref         string
		image       *Image
		opts        PushOptions
		expectError error
	}{
		{
			name:        "valid push",
			ref:         "myrepo/myimage:v1",
			image:       &Image{Manifest: &ImageManifest{}},
			opts:        PushOptions{},
			expectError: nil,
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
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

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
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

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
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	ctx := context.Background()
	manifests, err := reg.List(ctx, RegistryListOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Empty registry should return empty list
	if len(manifests) != 0 {
		t.Errorf("expected empty list, got %d items", len(manifests))
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
	cfg.Attestation.CacheSessionDuration = 1 * time.Millisecond // Very short duration

	reg, err := NewRegistry(cfg, testLogger())
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	defer func() { _ = reg.Close() }()

	// Verify a client
	attestation := &AttestationEvidence{
		ClientID:  "client-1",
		AIK:       []byte("aik-1-bytes-here"),
		Timestamp: time.Now(),
		PCRs:      map[int][]byte{},
	}

	ctx := context.Background()
	if err := reg.VerifyClient(ctx, attestation); err != nil {
		t.Fatalf("failed to verify client: %v", err)
	}

	// Wait for session to expire
	time.Sleep(10 * time.Millisecond)

	// Session should be expired
	_, ok := reg.GetSession("client-1")
	if ok {
		t.Error("expected session to be expired")
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
