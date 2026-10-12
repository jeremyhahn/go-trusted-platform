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

package quicwire

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestDefaultClientConfig(t *testing.T) {
	serverAddr := "localhost:9444"
	config := DefaultClientConfig(serverAddr)

	if config == nil {
		t.Fatal("DefaultClientConfig returned nil")
	}

	if config.ServerAddr != serverAddr {
		t.Errorf("expected ServerAddr '%s', got '%s'", serverAddr, config.ServerAddr)
	}

	if config.Timeout != 10*time.Second {
		t.Errorf("expected Timeout 10s, got %v", config.Timeout)
	}

	if config.MaxIdleTimeout != 30*time.Second {
		t.Errorf("expected MaxIdleTimeout 30s, got %v", config.MaxIdleTimeout)
	}

	if len(config.NextProtos) != 1 || config.NextProtos[0] != "platform-quic" {
		t.Errorf("expected NextProtos ['platform-quic'], got %v", config.NextProtos)
	}
}

func TestClientConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      *ClientConfig
		expectError bool
		errorField  string
	}{
		{
			name: "valid config",
			config: &ClientConfig{
				ServerAddr: "localhost:9444",
				Timeout:    10 * time.Second,
			},
			expectError: false,
		},
		{
			name: "empty server address",
			config: &ClientConfig{
				ServerAddr: "",
				Timeout:    10 * time.Second,
			},
			expectError: true,
			errorField:  "ServerAddr",
		},
		{
			name: "zero timeout gets default",
			config: &ClientConfig{
				ServerAddr: "localhost:9444",
				Timeout:    0,
			},
			expectError: false,
		},
		{
			name: "negative timeout gets default",
			config: &ClientConfig{
				ServerAddr: "localhost:9444",
				Timeout:    -1 * time.Second,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}

				invalidConfigErr, ok := err.(ErrInvalidConfig)
				if !ok {
					t.Errorf("expected ErrInvalidConfig, got %T", err)
					return
				}

				if invalidConfigErr.Field != tt.errorField {
					t.Errorf("expected error field '%s', got '%s'", tt.errorField, invalidConfigErr.Field)
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestClientConfigValidateDefaultsTimeout(t *testing.T) {
	config := &ClientConfig{
		ServerAddr: "localhost:9444",
		Timeout:    0,
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.Timeout != 10*time.Second {
		t.Errorf("expected Timeout to default to 10s, got %v", config.Timeout)
	}
}

func TestDefaultClientConfigWithEmptyAddress(t *testing.T) {
	config := DefaultClientConfig("")

	if config.ServerAddr != "" {
		t.Errorf("expected empty ServerAddr, got '%s'", config.ServerAddr)
	}

	// Validate should fail
	err := config.Validate()
	if err == nil {
		t.Error("expected validation error for empty ServerAddr")
	}
}

func TestDefaultClientConfigWithValidAddress(t *testing.T) {
	testAddrs := []string{
		"localhost:9444",
		"127.0.0.1:9444",
		"192.168.1.1:9444",
		"example.com:9444",
		"[::1]:9444",
	}

	for _, addr := range testAddrs {
		t.Run(addr, func(t *testing.T) {
			config := DefaultClientConfig(addr)

			if config.ServerAddr != addr {
				t.Errorf("expected ServerAddr '%s', got '%s'", addr, config.ServerAddr)
			}

			err := config.Validate()
			if err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestClientConfigRootCAs_SetPool(t *testing.T) {
	// A pool set on ClientConfig must be passed into the fallback tls.Config
	// constructed by NewClient when no TLSConfig is provided. This test
	// verifies the field exists and is preserved by DefaultClientConfig round-trip.
	pool := x509.NewCertPool()
	cfg := DefaultClientConfig("localhost:9444")
	cfg.RootCAs = pool

	if cfg.RootCAs != pool {
		t.Error("RootCAs must be preserved on ClientConfig")
	}
}

func TestClientConfigRootCAs_NilIsSystemRoots(t *testing.T) {
	// DefaultClientConfig must leave RootCAs nil so system roots are used
	// in the absence of an explicit pool.
	cfg := DefaultClientConfig("localhost:9444")
	if cfg.RootCAs != nil {
		t.Error("DefaultClientConfig must not set RootCAs (must use system roots by default)")
	}
}
