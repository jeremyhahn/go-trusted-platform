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
	"testing"
	"time"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestParseDeviceIDFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		{
			name:    "valid ID",
			input:   "123",
			want:    123,
			wantErr: false,
		},
		{
			name:    "zero",
			input:   "0",
			want:    0,
			wantErr: false,
		},
		{
			name:    "large number",
			input:   "9999999999",
			want:    9999999999,
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "non-numeric",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "mixed",
			input:   "123abc",
			wantErr: true,
		},
		{
			name:    "negative",
			input:   "-1",
			wantErr: true,
		},
		{
			name:    "decimal",
			input:   "123.45",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDeviceIDFromString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if _, ok := err.(ErrInvalidDeviceID); !ok {
					t.Errorf("expected ErrInvalidDeviceID, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("parseDeviceIDFromString(%q) = %d, want %d", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestParseUint64(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		{"valid", "42", 42, false},
		{"zero", "0", 0, false},
		{"empty", "", 0, true},
		{"letter", "a", 0, true},
		{"space", " ", 0, true},
		{"leading_space", " 123", 0, true},
		{"max_safe", "18446744073709551615", 18446744073709551615, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUint64(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("parseUint64(%q) = %d, want %d", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestNormalizeKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ECDSA-P256 uppercase", "ECDSA-P256", "ECDSA-P256"},
		{"ecdsa-p256 lowercase", "ecdsa-p256", "ECDSA-P256"},
		{"P256 short", "P256", "ECDSA-P256"},
		{"p256 short lowercase", "p256", "ECDSA-P256"},
		{"ECDSA-P384 uppercase", "ECDSA-P384", "ECDSA-P384"},
		{"ecdsa-p384 lowercase", "ecdsa-p384", "ECDSA-P384"},
		{"P384 short", "P384", "ECDSA-P384"},
		{"p384 short lowercase", "p384", "ECDSA-P384"},
		{"RSA-2048 uppercase", "RSA-2048", "RSA-2048"},
		{"rsa-2048 lowercase", "rsa-2048", "RSA-2048"},
		{"RSA2048 no hyphen", "RSA2048", "RSA-2048"},
		{"rsa2048 no hyphen lowercase", "rsa2048", "RSA-2048"},
		{"RSA-3072 uppercase", "RSA-3072", "RSA-3072"},
		{"rsa-3072 lowercase", "rsa-3072", "RSA-3072"},
		{"RSA3072 no hyphen", "RSA3072", "RSA-3072"},
		{"rsa3072 no hyphen lowercase", "rsa3072", "RSA-3072"},
		// Unknown algorithms default to ECDSA-P256
		{"unknown", "unknown", "ECDSA-P256"},
		{"empty", "", "ECDSA-P256"},
		{"RSA alone", "RSA", "ECDSA-P256"}, // Not matched, defaults to P256
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeKeyAlgorithm(tt.input)
			if got != tt.want {
				t.Errorf("normalizeKeyAlgorithm(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseKMSKeyUsage(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    baasservice.KeyUsage
		wantErr bool
	}{
		{"encrypt", "encrypt", baasservice.KeyUsageEncrypt, false},
		{"Encrypt", "Encrypt", baasservice.KeyUsageEncrypt, false},
		{"ENCRYPT", "ENCRYPT", baasservice.KeyUsageEncrypt, false},
		{"decrypt", "decrypt", baasservice.KeyUsageDecrypt, false},
		{"sign", "sign", baasservice.KeyUsageSign, false},
		{"verify", "verify", baasservice.KeyUsageVerify, false},
		{"wrap", "wrap", baasservice.KeyUsageWrapKey, false},
		{"unwrap", "unwrap", baasservice.KeyUsageWrapKey, false},
		{"derive", "derive", baasservice.KeyUsageDeriveKey, false},
		{"generate_mac", "generate_mac", baasservice.KeyUsageGenerateMAC, false},
		{"verify_mac", "verify_mac", baasservice.KeyUsageVerifyMAC, false},
		{"with_spaces", "  sign  ", baasservice.KeyUsageSign, false},
		{"invalid", "invalid_usage", baasservice.KeyUsageEncrypt, true},
		{"empty", "", baasservice.KeyUsageEncrypt, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKMSKeyUsage(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				if _, ok := err.(ErrKMSInvalidKeyUsage); !ok {
					t.Errorf("expected ErrKMSInvalidKeyUsage, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("parseKMSKeyUsage(%q) = %v, want %v", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestParseHashAlgorithm(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  baasservice.HashAlgorithm
	}{
		{"SHA256", "SHA256", baasservice.HashAlgSHA256},
		{"SHA-256", "SHA-256", baasservice.HashAlgSHA256},
		{"sha256", "sha256", baasservice.HashAlgSHA256},
		{"SHA384", "SHA384", baasservice.HashAlgSHA384},
		{"SHA-384", "SHA-384", baasservice.HashAlgSHA384},
		{"SHA512", "SHA512", baasservice.HashAlgSHA512},
		{"SHA-512", "SHA-512", baasservice.HashAlgSHA512},
		{"unknown", "unknown", baasservice.HashAlgSHA256},
		{"empty", "", baasservice.HashAlgSHA256},
		{"with_spaces", "  SHA384  ", baasservice.HashAlgSHA384},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHashAlgorithm(tt.input)
			if got != tt.want {
				t.Errorf("parseHashAlgorithm(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildKeyAttributes(t *testing.T) {
	tests := []struct {
		name    string
		req     *mcp.KMSCreateKeyRequest
		wantErr bool
	}{
		{name: "AES128", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "AES128"}, wantErr: false},
		{name: "AES-128-GCM", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "AES-128-GCM"}, wantErr: false},
		{name: "AES256", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "AES256"}, wantErr: false},
		{name: "AES-256-GCM", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "AES-256-GCM"}, wantErr: false},
		{name: "CHACHA20", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "CHACHA20"}, wantErr: false},
		{name: "RSA", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "RSA"}, wantErr: false},
		{name: "RSA2048", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "RSA2048"}, wantErr: false},
		{name: "ECDSA", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "ECDSA"}, wantErr: false},
		{name: "ED25519", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "ED25519"}, wantErr: false},
		{name: "invalid", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "INVALID"}, wantErr: true},
		{name: "empty", req: &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: ""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := buildKeyAttributes(tt.req)
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
					t.Error("expected non-nil attrs")
				}
				if attrs != nil && attrs.CN != tt.req.Name {
					t.Errorf("attrs.CN = %q, want %q", attrs.CN, tt.req.Name)
				}
			}
		})
	}
}

func TestUserToMap(t *testing.T) {
	now := time.Now()
	lastLogin := now

	tests := []struct {
		name string
		user *sdkiam.User
	}{
		{
			name: "minimal user",
			user: &sdkiam.User{ID: "user-123", TenantID: "tenant-456", Email: "test@example.com"},
		},
		{
			name: "user with name",
			user: &sdkiam.User{ID: "user-123", TenantID: "tenant-456", Email: "test@example.com", DisplayName: "Test User"},
		},
		{
			name: "user with roles",
			user: &sdkiam.User{ID: "user-123", TenantID: "tenant-456", Email: "test@example.com", Roles: []string{"admin", "user"}},
		},
		{
			name: "user with timestamps",
			user: &sdkiam.User{ID: "user-123", TenantID: "tenant-456", Email: "test@example.com", CreatedAt: now, UpdatedAt: now, LastLoginAt: &lastLogin},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sdkUserToMap(tt.user)

			if got["id"] != tt.user.ID {
				t.Errorf("id = %v, want %v", got["id"], tt.user.ID)
			}
			if got["tenant_id"] != tt.user.TenantID {
				t.Errorf("tenant_id = %v, want %v", got["tenant_id"], tt.user.TenantID)
			}
			if got["email"] != tt.user.Email {
				t.Errorf("email = %v, want %v", got["email"], tt.user.Email)
			}
		})
	}
}

func TestRoleToMap(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		role *sdkiam.Role
	}{
		{name: "minimal role", role: &sdkiam.Role{ID: "role-123", TenantID: "tenant-456"}},
		{name: "role with name", role: &sdkiam.Role{ID: "role-123", TenantID: "tenant-456", Name: "Admin"}},
		{name: "role with timestamps", role: &sdkiam.Role{ID: "role-123", TenantID: "tenant-456", CreatedAt: now, UpdatedAt: now}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sdkRoleToMap(tt.role)
			if got["id"] != tt.role.ID {
				t.Errorf("id = %v, want %v", got["id"], tt.role.ID)
			}
			if got["tenant_id"] != tt.role.TenantID {
				t.Errorf("tenant_id = %v, want %v", got["tenant_id"], tt.role.TenantID)
			}
		})
	}
}

// =============================================================================
// MCPServiceProvider Tests
// =============================================================================

func TestNewMCPServiceProvider(t *testing.T) {
	t.Run("creates provider with nil config", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})
		if provider == nil {
			t.Fatal("expected non-nil provider")
		}
		if provider.logger == nil {
			t.Error("expected non-nil logger")
		}
	})

	t.Run("creates provider with custom logger", func(t *testing.T) {
		logger := slog.Default()
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{Logger: logger})
		if provider == nil {
			t.Fatal("expected non-nil provider")
		}
		if provider.logger != logger {
			t.Error("expected custom logger to be used")
		}
	})
}

func TestMCPServiceProvider_VTPMOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("VTPMCreate returns error", func(t *testing.T) {
		_, err := provider.VTPMCreate(ctx, "test", "RSA")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("VTPMDelete returns error", func(t *testing.T) {
		err := provider.VTPMDelete(ctx, "test")
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("VTPMList returns error", func(t *testing.T) {
		_, err := provider.VTPMList(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestMCPServiceProvider_DNSOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("DNSAddRecord returns error", func(t *testing.T) {
		err := provider.DNSAddRecord(ctx, "test.example.com", "A", "192.168.1.1", 300)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("DNSDeleteRecord returns error", func(t *testing.T) {
		err := provider.DNSDeleteRecord(ctx, "test.example.com", "A")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestMCPServiceProvider_DeviceOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("DeviceRegister returns error", func(t *testing.T) {
		_, err := provider.DeviceRegister(ctx, &mcp.DeviceRegisterRequest{Model: "device1", Serial: "server"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("DeviceGet returns error", func(t *testing.T) {
		_, err := provider.DeviceGet(ctx, "1")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestMCPServiceProvider_SDNOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("SDNGetPortState returns error", func(t *testing.T) {
		_, err := provider.SDNGetPortState(ctx, "br0", "eth0")
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("SDNListBridges returns error", func(t *testing.T) {
		_, err := provider.SDNListBridges(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestMCPServiceProvider_HealthOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("Health returns error", func(t *testing.T) {
		_, err := provider.Health(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("Liveness returns error", func(t *testing.T) {
		_, err := provider.Liveness(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("Readiness returns error", func(t *testing.T) {
		_, err := provider.Readiness(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestMCPServiceProvider_CAOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("CAInfo returns error", func(t *testing.T) {
		_, err := provider.CAInfo(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("CAIssue returns error", func(t *testing.T) {
		_, err := provider.CAIssue(ctx, &mcp.CAIssueRequest{CommonName: "test.example.com"})
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestMCPServiceProvider_IAMOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("IAMCreateUser returns error", func(t *testing.T) {
		_, err := provider.IAMCreateUser(ctx, &mcp.IAMCreateUserRequest{TenantID: "tenant1", Email: "test@example.com"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("IAMDeleteUser returns error", func(t *testing.T) {
		err := provider.IAMDeleteUser(ctx, "tenant1", "user1")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestMCPServiceProvider_KMSOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("KMSCreateKey returns error", func(t *testing.T) {
		_, err := provider.KMSCreateKey(ctx, &mcp.KMSCreateKeyRequest{Name: "test-key", Algorithm: "AES256"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("KMSDeleteKey returns error", func(t *testing.T) {
		err := provider.KMSDeleteKey(ctx, "key1")
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("KMSEncrypt returns error", func(t *testing.T) {
		_, err := provider.KMSEncrypt(ctx, &mcp.KMSEncryptRequest{KeyID: "key1", Plaintext: []byte("data")})
		if err == nil {
			t.Error("expected error")
		}
	})

	// KMSGenerateRandom uses crypto/rand directly, so it works without the KMS service
	t.Run("KMSGenerateRandom succeeds without service", func(t *testing.T) {
		result, err := provider.KMSGenerateRandom(ctx, 32)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(result) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(result))
		}
	})

	t.Run("KMSGenerateRandom validates zero bytes", func(t *testing.T) {
		_, err := provider.KMSGenerateRandom(ctx, 0)
		if err == nil {
			t.Error("expected error for 0 bytes")
		}
	})

	t.Run("KMSGenerateRandom validates negative bytes", func(t *testing.T) {
		_, err := provider.KMSGenerateRandom(ctx, -1)
		if err == nil {
			t.Error("expected error for negative bytes")
		}
	})

	t.Run("KMSGenerateRandom validates max bytes", func(t *testing.T) {
		_, err := provider.KMSGenerateRandom(ctx, 2000)
		if err == nil {
			t.Error("expected error for too many bytes")
		}
	})
}
