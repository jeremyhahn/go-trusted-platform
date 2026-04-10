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

package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// =============================================================================
// Data Key Operations Tests
// =============================================================================

func TestMCPServiceProvider_KMSGenerateDataKey_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.KMSGenerateDataKey(ctx, &mcp.KMSGenerateDataKeyRequest{
		KeyID:     "test-kek",
		Algorithm: "aes-256-gcm",
	})

	if err == nil {
		t.Error("expected error for nil crypto service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_KMSGenerateDataKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.KMSGenerateDataKey(ctx, &mcp.KMSGenerateDataKeyRequest{
		KeyID: "", // missing key ID
	})

	if err == nil {
		t.Error("expected error for missing key_id")
	}
}

func TestMCPServiceProvider_KMSGenerateWrappedDataKey_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.KMSGenerateWrappedDataKey(ctx, &mcp.KMSGenerateWrappedDataKeyRequest{
		KeyID:     "test-kek",
		Algorithm: "aes-256-gcm",
	})

	if err == nil {
		t.Error("expected error for nil crypto service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_KMSGenerateWrappedDataKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.KMSGenerateWrappedDataKey(ctx, &mcp.KMSGenerateWrappedDataKeyRequest{
		KeyID: "", // missing key ID
	})

	if err == nil {
		t.Error("expected error for missing key_id")
	}
}

func TestBuildDataKeyAttributes(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"aes-128-gcm", "aes-128-gcm", false},
		{"AES-128-GCM uppercase", "AES-128-GCM", false},
		{"aes-192-gcm", "aes-192-gcm", false},
		{"aes-256-gcm", "aes-256-gcm", false},
		{"aes256", "aes256", false},
		{"chacha20-poly1305", "chacha20-poly1305", false},
		{"xchacha20-poly1305", "xchacha20-poly1305", false},
		{"invalid algorithm", "invalid", true},
		{"empty algorithm", "", true},
		{"des (unsupported)", "des", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := buildDataKeyAttributes(tt.algorithm)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				if _, ok := err.(ErrKMSInvalidAlgorithm); !ok {
					t.Errorf("expected ErrKMSInvalidAlgorithm, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if attrs == nil {
					t.Error("expected attributes, got nil")
				}
			}
		})
	}
}

func TestErrKMSDataKeyGenerationFailed(t *testing.T) {
	cause := ErrKMSKeyNotFound{KeyID: "test-key"}
	err := ErrKMSDataKeyGenerationFailed{
		KeyID: "test-kek",
		Cause: cause,
	}

	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
	if !strings.Contains(msg, "test-kek") {
		t.Errorf("expected error message to contain key ID, got: %s", msg)
	}

	// Test Unwrap
	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("expected Unwrap to return cause, got %v", unwrapped)
	}
}

func TestPlatformServiceProvider_KMSGenerateDataKey(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.KMSGenerateDataKey(ctx, &mcp.KMSGenerateDataKeyRequest{
		KeyID: "test-key",
	})

	if err == nil {
		t.Error("expected error for nil services")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestPlatformServiceProvider_KMSGenerateWrappedDataKey(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.KMSGenerateWrappedDataKey(ctx, &mcp.KMSGenerateWrappedDataKeyRequest{
		KeyID: "test-key",
	})

	if err == nil {
		t.Error("expected error for nil services")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}
