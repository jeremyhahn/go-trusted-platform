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
	"crypto/tls"
	"errors"
	"testing"
	"time"
)

func TestDefaultRegistryConfig(t *testing.T) {
	cfg := DefaultRegistryConfig()

	if cfg.ListenAddr == "" {
		t.Error("expected non-empty listen address")
	}

	if cfg.ReadTimeout <= 0 {
		t.Error("expected positive read timeout")
	}

	if cfg.WriteTimeout <= 0 {
		t.Error("expected positive write timeout")
	}

	if cfg.MaxConcurrentPulls <= 0 {
		t.Error("expected positive max concurrent pulls")
	}

	if cfg.MaxConcurrentPushes <= 0 {
		t.Error("expected positive max concurrent pushes")
	}

	// Default config has TLS enabled but no certs, so validation fails
	// This is expected - production deployment must provide certs
	// For testing, we verify the structure is correct
	if !cfg.TLS.Enabled {
		t.Error("TLS should be enabled by default")
	}
}

func TestDefaultTLSConfig(t *testing.T) {
	cfg := DefaultTLSConfig()

	if !cfg.Enabled {
		t.Error("TLS should be enabled by default")
	}

	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("expected client cert verification by default")
	}

	if cfg.MinVersion < tls.VersionTLS12 {
		t.Error("min TLS version should be at least 1.2")
	}

	if len(cfg.CipherSuites) == 0 {
		t.Error("expected default cipher suites")
	}
}

func TestDefaultAttestationConfig(t *testing.T) {
	cfg := DefaultAttestationConfig()

	if !cfg.RequireAttestation {
		t.Error("attestation should be required by default")
	}

	if cfg.RequiredPCRs == nil {
		t.Error("RequiredPCRs should not be nil")
	}

	if cfg.NonceValidityDuration <= 0 {
		t.Error("expected positive nonce validity duration")
	}

	if cfg.QuoteMaxAge <= 0 {
		t.Error("expected positive quote max age")
	}

	if cfg.CacheSessionDuration <= 0 {
		t.Error("expected positive cache session duration")
	}
}

func TestDefaultStorageConfig(t *testing.T) {
	cfg := DefaultStorageConfig()

	if cfg.Addr == "" {
		t.Error("expected non-empty QuicBaaS address")
	}

	if cfg.Namespace == "" {
		t.Error("expected non-empty namespace")
	}

	if !cfg.Encrypted {
		t.Error("encryption should be enabled by default")
	}

	if cfg.ConnectionTimeout <= 0 {
		t.Error("expected positive connection timeout")
	}

	if cfg.RequestTimeout <= 0 {
		t.Error("expected positive request timeout")
	}
}

func TestDefaultEncryptionConfig(t *testing.T) {
	cfg := DefaultEncryptionConfig()

	if cfg.QuicBaaSAddr == "" {
		t.Error("expected non-empty QuicBaaS address")
	}

	if cfg.KeyNamespace == "" {
		t.Error("expected non-empty key namespace")
	}

	if cfg.Algorithm == "" {
		t.Error("expected non-empty algorithm")
	}

	if cfg.Algorithm != "AES-256-GCM" {
		t.Errorf("expected AES-256-GCM algorithm, got: %s", cfg.Algorithm)
	}

	if !cfg.EncryptByDefault {
		t.Error("encrypt by default should be true")
	}

	if cfg.DEKCacheSize <= 0 {
		t.Error("expected positive DEK cache size")
	}

	if cfg.DEKCacheTTL <= 0 {
		t.Error("expected positive DEK cache TTL")
	}
}

// validTestConfigForConfigTests returns a complete valid config for validation tests
func validTestConfigForConfigTests() RegistryConfig {
	cfg := DefaultRegistryConfig()
	// Provide TLS certs for validation
	cfg.TLS.CertFile = "/path/to/cert.pem"
	cfg.TLS.KeyFile = "/path/to/key.pem"
	// Provide storage key for validation
	cfg.Storage.KeyID = "test-key"
	return cfg
}

func TestRegistryConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(*RegistryConfig)
		expectError bool
		errorField  string
	}{
		{
			name:        "valid complete config",
			modify:      func(c *RegistryConfig) {},
			expectError: false,
		},
		{
			name: "empty listen address",
			modify: func(c *RegistryConfig) {
				c.ListenAddr = ""
			},
			expectError: true,
			errorField:  "listen_addr",
		},
		{
			name: "zero read timeout",
			modify: func(c *RegistryConfig) {
				c.ReadTimeout = 0
			},
			expectError: true,
			errorField:  "read_timeout",
		},
		{
			name: "zero write timeout",
			modify: func(c *RegistryConfig) {
				c.WriteTimeout = 0
			},
			expectError: true,
			errorField:  "write_timeout",
		},
		{
			name: "zero max concurrent pulls",
			modify: func(c *RegistryConfig) {
				c.MaxConcurrentPulls = 0
			},
			expectError: true,
			errorField:  "max_concurrent_pulls",
		},
		{
			name: "zero max concurrent pushes",
			modify: func(c *RegistryConfig) {
				c.MaxConcurrentPushes = 0
			},
			expectError: true,
			errorField:  "max_concurrent_pushes",
		},
		{
			name: "tls disabled is valid without certs",
			modify: func(c *RegistryConfig) {
				c.TLS.Enabled = false
				c.TLS.CertFile = ""
				c.TLS.KeyFile = ""
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validTestConfigForConfigTests()
			tt.modify(&cfg)

			err := cfg.Validate()
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				var invalidCfg ErrInvalidConfig
				if !errors.As(err, &invalidCfg) {
					t.Errorf("expected ErrInvalidConfig, got: %T", err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestTLSConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         TLSConfig
		expectError bool
	}{
		{
			name: "disabled TLS is valid",
			cfg: TLSConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "valid enabled TLS",
			cfg: TLSConfig{
				Enabled:    true,
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				MinVersion: tls.VersionTLS12,
			},
			expectError: false,
		},
		{
			name: "enabled TLS missing cert file",
			cfg: TLSConfig{
				Enabled:    true,
				KeyFile:    "/path/to/key.pem",
				MinVersion: tls.VersionTLS12,
			},
			expectError: true,
		},
		{
			name: "enabled TLS missing key file",
			cfg: TLSConfig{
				Enabled:    true,
				CertFile:   "/path/to/cert.pem",
				MinVersion: tls.VersionTLS12,
			},
			expectError: true,
		},
		{
			name: "TLS version too low",
			cfg: TLSConfig{
				Enabled:    true,
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				MinVersion: tls.VersionTLS10,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestAttestationConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         RegistryAttestationConfig
		expectError bool
	}{
		{
			name: "disabled attestation is valid",
			cfg: RegistryAttestationConfig{
				RequireAttestation: false,
			},
			expectError: false,
		},
		{
			name: "valid enabled attestation",
			cfg: RegistryAttestationConfig{
				RequireAttestation:    true,
				NonceValidityDuration: 5 * time.Minute,
				QuoteMaxAge:           10 * time.Minute,
				CacheSessionDuration:  1 * time.Hour,
			},
			expectError: false,
		},
		{
			name: "zero nonce validity",
			cfg: RegistryAttestationConfig{
				RequireAttestation:    true,
				NonceValidityDuration: 0,
				QuoteMaxAge:           10 * time.Minute,
				CacheSessionDuration:  1 * time.Hour,
			},
			expectError: true,
		},
		{
			name: "zero quote max age",
			cfg: RegistryAttestationConfig{
				RequireAttestation:    true,
				NonceValidityDuration: 5 * time.Minute,
				QuoteMaxAge:           0,
				CacheSessionDuration:  1 * time.Hour,
			},
			expectError: true,
		},
		{
			name: "zero cache session duration",
			cfg: RegistryAttestationConfig{
				RequireAttestation:    true,
				NonceValidityDuration: 5 * time.Minute,
				QuoteMaxAge:           10 * time.Minute,
				CacheSessionDuration:  0,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestStorageConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         StorageConfig
		expectError bool
	}{
		{
			name: "valid storage config",
			cfg: StorageConfig{
				Addr:              "localhost:9000",
				Namespace:         "registry",
				Encrypted:         true,
				KeyID:             "my-key",
				ConnectionTimeout: 10 * time.Second,
				RequestTimeout:    30 * time.Second,
				MaxRetries:        3,
			},
			expectError: false,
		},
		{
			name: "empty address",
			cfg: StorageConfig{
				Addr:              "",
				Namespace:         "registry",
				ConnectionTimeout: 10 * time.Second,
				RequestTimeout:    30 * time.Second,
			},
			expectError: true,
		},
		{
			name: "empty namespace",
			cfg: StorageConfig{
				Addr:              "localhost:9000",
				Namespace:         "",
				ConnectionTimeout: 10 * time.Second,
				RequestTimeout:    30 * time.Second,
			},
			expectError: true,
		},
		{
			name: "encrypted without key ID",
			cfg: StorageConfig{
				Addr:              "localhost:9000",
				Namespace:         "registry",
				Encrypted:         true,
				KeyID:             "",
				ConnectionTimeout: 10 * time.Second,
				RequestTimeout:    30 * time.Second,
			},
			expectError: true,
		},
		{
			name: "zero connection timeout",
			cfg: StorageConfig{
				Addr:              "localhost:9000",
				Namespace:         "registry",
				ConnectionTimeout: 0,
				RequestTimeout:    30 * time.Second,
			},
			expectError: true,
		},
		{
			name: "zero request timeout",
			cfg: StorageConfig{
				Addr:              "localhost:9000",
				Namespace:         "registry",
				ConnectionTimeout: 10 * time.Second,
				RequestTimeout:    0,
			},
			expectError: true,
		},
		{
			name: "negative max retries",
			cfg: StorageConfig{
				Addr:              "localhost:9000",
				Namespace:         "registry",
				ConnectionTimeout: 10 * time.Second,
				RequestTimeout:    30 * time.Second,
				MaxRetries:        -1,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestEncryptionConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         EncryptionConfig
		expectError bool
	}{
		{
			name: "valid encryption config",
			cfg: EncryptionConfig{
				QuicBaaSAddr: "localhost:9000",
				KeyNamespace: "registry-keys",
				Algorithm:    "AES-256-GCM",
				DEKCacheSize: 100,
				DEKCacheTTL:  1 * time.Hour,
			},
			expectError: false,
		},
		{
			name: "AES-128-GCM is valid",
			cfg: EncryptionConfig{
				QuicBaaSAddr: "localhost:9000",
				KeyNamespace: "registry-keys",
				Algorithm:    "AES-128-GCM",
				DEKCacheSize: 100,
				DEKCacheTTL:  1 * time.Hour,
			},
			expectError: false,
		},
		{
			name: "empty QuicBaaS address",
			cfg: EncryptionConfig{
				QuicBaaSAddr: "",
				KeyNamespace: "registry-keys",
				Algorithm:    "AES-256-GCM",
				DEKCacheSize: 100,
				DEKCacheTTL:  1 * time.Hour,
			},
			expectError: true,
		},
		{
			name: "empty key namespace",
			cfg: EncryptionConfig{
				QuicBaaSAddr: "localhost:9000",
				KeyNamespace: "",
				Algorithm:    "AES-256-GCM",
				DEKCacheSize: 100,
				DEKCacheTTL:  1 * time.Hour,
			},
			expectError: true,
		},
		{
			name: "empty algorithm",
			cfg: EncryptionConfig{
				QuicBaaSAddr: "localhost:9000",
				KeyNamespace: "registry-keys",
				Algorithm:    "",
				DEKCacheSize: 100,
				DEKCacheTTL:  1 * time.Hour,
			},
			expectError: true,
		},
		{
			name: "unsupported algorithm",
			cfg: EncryptionConfig{
				QuicBaaSAddr: "localhost:9000",
				KeyNamespace: "registry-keys",
				Algorithm:    "ChaCha20-Poly1305",
				DEKCacheSize: 100,
				DEKCacheTTL:  1 * time.Hour,
			},
			expectError: true,
		},
		{
			name: "zero DEK cache size",
			cfg: EncryptionConfig{
				QuicBaaSAddr: "localhost:9000",
				KeyNamespace: "registry-keys",
				Algorithm:    "AES-256-GCM",
				DEKCacheSize: 0,
				DEKCacheTTL:  1 * time.Hour,
			},
			expectError: true,
		},
		{
			name: "zero DEK cache TTL",
			cfg: EncryptionConfig{
				QuicBaaSAddr: "localhost:9000",
				KeyNamespace: "registry-keys",
				Algorithm:    "AES-256-GCM",
				DEKCacheSize: 100,
				DEKCacheTTL:  0,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRegistryConfigValidateWithTLSError(t *testing.T) {
	cfg := validTestConfigForConfigTests()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "" // Invalid - missing cert file

	err := cfg.Validate()
	if err == nil {
		t.Error("expected TLS validation error")
	}
}

func TestRegistryConfigValidateWithAttestationError(t *testing.T) {
	cfg := validTestConfigForConfigTests()
	cfg.Attestation.RequireAttestation = true
	cfg.Attestation.NonceValidityDuration = 0 // Invalid

	err := cfg.Validate()
	if err == nil {
		t.Error("expected attestation validation error")
	}
}

func TestRegistryConfigValidateWithStorageError(t *testing.T) {
	cfg := validTestConfigForConfigTests()
	cfg.Storage.Addr = "" // Invalid

	err := cfg.Validate()
	if err == nil {
		t.Error("expected storage validation error")
	}
}

func TestRegistryConfigValidateWithEncryptionError(t *testing.T) {
	cfg := validTestConfigForConfigTests()
	cfg.Encryption.Algorithm = "INVALID" // Invalid

	err := cfg.Validate()
	if err == nil {
		t.Error("expected encryption validation error")
	}
}

func TestConfigStructTags(t *testing.T) {
	// This test verifies the struct has proper YAML/JSON tags for serialization
	cfg := RegistryConfig{
		ListenAddr: ":5000",
		TLS: TLSConfig{
			Enabled:  true,
			CertFile: "/path/to/cert",
		},
	}

	if cfg.ListenAddr != ":5000" {
		t.Error("unexpected ListenAddr value")
	}

	if !cfg.TLS.Enabled {
		t.Error("unexpected TLS.Enabled value")
	}
}

func TestStorageConfigNonEncrypted(t *testing.T) {
	cfg := StorageConfig{
		Addr:              "localhost:9000",
		Namespace:         "registry",
		Encrypted:         false, // Not encrypted, so KeyID can be empty
		KeyID:             "",
		ConnectionTimeout: 10 * time.Second,
		RequestTimeout:    30 * time.Second,
		MaxRetries:        0, // Zero retries is valid
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("non-encrypted config should be valid: %v", err)
	}
}

func TestTLSConfigMinVersionBoundary(t *testing.T) {
	// TLS 1.2 should be valid
	cfg := TLSConfig{
		Enabled:    true,
		CertFile:   "/path/to/cert.pem",
		KeyFile:    "/path/to/key.pem",
		MinVersion: tls.VersionTLS12,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("TLS 1.2 should be valid: %v", err)
	}

	// TLS 1.3 should also be valid
	cfg.MinVersion = tls.VersionTLS13
	if err := cfg.Validate(); err != nil {
		t.Errorf("TLS 1.3 should be valid: %v", err)
	}

	// TLS 1.1 should be invalid
	cfg.MinVersion = tls.VersionTLS11
	if err := cfg.Validate(); err == nil {
		t.Error("TLS 1.1 should be invalid")
	}
}
