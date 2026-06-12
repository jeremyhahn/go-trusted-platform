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

//go:build codec_msgpack

package quic

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestDefaultServerConfig(t *testing.T) {
	config := DefaultServerConfig()

	if config == nil {
		t.Fatal("DefaultServerConfig returned nil")
	}

	if config.ListenAddr != "0.0.0.0:9444" {
		t.Errorf("expected ListenAddr '0.0.0.0:9444', got '%s'", config.ListenAddr)
	}

	if config.MaxStreams != 1000 {
		t.Errorf("expected MaxStreams 1000, got %d", config.MaxStreams)
	}

	if config.MaxIdleTimeout != 30*time.Second {
		t.Errorf("expected MaxIdleTimeout 30s, got %v", config.MaxIdleTimeout)
	}

	if config.MaxIncomingStreams != 1000 {
		t.Errorf("expected MaxIncomingStreams 1000, got %d", config.MaxIncomingStreams)
	}

	if config.MaxIncomingUniStreams != 100 {
		t.Errorf("expected MaxIncomingUniStreams 100, got %d", config.MaxIncomingUniStreams)
	}

	if config.KeepAlivePeriod != 15*time.Second {
		t.Errorf("expected KeepAlivePeriod 15s, got %v", config.KeepAlivePeriod)
	}

	if config.HandshakeIdleTimeout != 5*time.Second {
		t.Errorf("expected HandshakeIdleTimeout 5s, got %v", config.HandshakeIdleTimeout)
	}

	if config.MaxReceiveBufferSize != 1*1024*1024 {
		t.Errorf("expected MaxReceiveBufferSize 1MB, got %d", config.MaxReceiveBufferSize)
	}

	if config.InitialStreamReceiveWindow != 512*1024 {
		t.Errorf("expected InitialStreamReceiveWindow 512KB, got %d", config.InitialStreamReceiveWindow)
	}

	if config.MaxStreamReceiveWindow != 6*1024*1024 {
		t.Errorf("expected MaxStreamReceiveWindow 6MB, got %d", config.MaxStreamReceiveWindow)
	}

	if !config.EnableMetrics {
		t.Error("expected EnableMetrics to be true")
	}
}

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

func TestServerConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      *ServerConfig
		expectError bool
		errorField  string
	}{
		{
			name: "valid config",
			config: &ServerConfig{
				ListenAddr: "0.0.0.0:9444",
				TLSConfig:  &tls.Config{},
				MaxStreams: 100,
			},
			expectError: false,
		},
		{
			name: "empty listen address",
			config: &ServerConfig{
				ListenAddr: "",
				TLSConfig:  &tls.Config{},
			},
			expectError: true,
			errorField:  "ListenAddr",
		},
		{
			name: "nil TLS config",
			config: &ServerConfig{
				ListenAddr: "0.0.0.0:9444",
				TLSConfig:  nil,
			},
			expectError: true,
			errorField:  "TLSConfig",
		},
		{
			name: "zero max streams gets default",
			config: &ServerConfig{
				ListenAddr: "0.0.0.0:9444",
				TLSConfig:  &tls.Config{},
				MaxStreams: 0,
			},
			expectError: false,
		},
		{
			name: "negative max streams gets default",
			config: &ServerConfig{
				ListenAddr: "0.0.0.0:9444",
				TLSConfig:  &tls.Config{},
				MaxStreams: -1,
			},
			expectError: false,
		},
		{
			name: "zero max idle timeout gets default",
			config: &ServerConfig{
				ListenAddr:     "0.0.0.0:9444",
				TLSConfig:      &tls.Config{},
				MaxIdleTimeout: 0,
			},
			expectError: false,
		},
		{
			name: "negative max idle timeout gets default",
			config: &ServerConfig{
				ListenAddr:     "0.0.0.0:9444",
				TLSConfig:      &tls.Config{},
				MaxIdleTimeout: -1 * time.Second,
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
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestServerConfigValidateDefaultsMaxStreams(t *testing.T) {
	config := &ServerConfig{
		ListenAddr: "0.0.0.0:9444",
		TLSConfig:  &tls.Config{},
		MaxStreams: 0,
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.MaxStreams != 1000 {
		t.Errorf("expected MaxStreams to default to 1000, got %d", config.MaxStreams)
	}
}

func TestServerConfigValidateDefaultsMaxIdleTimeout(t *testing.T) {
	config := &ServerConfig{
		ListenAddr:     "0.0.0.0:9444",
		TLSConfig:      &tls.Config{},
		MaxIdleTimeout: 0,
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.MaxIdleTimeout != 30*time.Second {
		t.Errorf("expected MaxIdleTimeout to default to 30s, got %v", config.MaxIdleTimeout)
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
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
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

func TestGenerateSelfSignedTLSConfig(t *testing.T) {
	tlsConfig, err := GenerateSelfSignedTLSConfig()
	if err != nil {
		t.Fatalf("GenerateSelfSignedTLSConfig failed: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("GenerateSelfSignedTLSConfig returned nil config")
	}

	// Verify TLS 1.3 is required
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion TLS 1.3, got %d", tlsConfig.MinVersion)
	}

	// Verify ALPN protocol is set
	if len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "platform-quic" {
		t.Errorf("expected NextProtos ['platform-quic'], got %v", tlsConfig.NextProtos)
	}

	// Verify certificate is present
	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}

	cert := tlsConfig.Certificates[0]

	// Verify certificate chain is present
	if len(cert.Certificate) != 1 {
		t.Errorf("expected 1 certificate in chain, got %d", len(cert.Certificate))
	}

	// Verify private key is present
	if cert.PrivateKey == nil {
		t.Error("expected private key to be set")
	}
}

func TestGenerateSelfSignedTLSConfigMultipleCalls(t *testing.T) {
	// Generate two configs and ensure they have different certificates
	config1, err1 := GenerateSelfSignedTLSConfig()
	if err1 != nil {
		t.Fatalf("first GenerateSelfSignedTLSConfig failed: %v", err1)
	}

	config2, err2 := GenerateSelfSignedTLSConfig()
	if err2 != nil {
		t.Fatalf("second GenerateSelfSignedTLSConfig failed: %v", err2)
	}

	// Each call should generate a unique certificate (different serial numbers)
	cert1 := config1.Certificates[0].Certificate[0]
	cert2 := config2.Certificates[0].Certificate[0]

	// Compare raw certificate bytes - they should differ
	if len(cert1) == len(cert2) {
		match := true
		for i := range cert1 {
			if cert1[i] != cert2[i] {
				match = false
				break
			}
		}
		if match {
			t.Error("expected different certificates for multiple calls")
		}
	}
}

func TestDefaultServerConfigWithTLS(t *testing.T) {
	config, err := DefaultServerConfigWithTLS()
	if err != nil {
		t.Fatalf("DefaultServerConfigWithTLS failed: %v", err)
	}

	if config == nil {
		t.Fatal("DefaultServerConfigWithTLS returned nil config")
	}

	// Verify default values are set
	if config.ListenAddr != "0.0.0.0:9444" {
		t.Errorf("expected ListenAddr '0.0.0.0:9444', got '%s'", config.ListenAddr)
	}

	if config.MaxStreams != 1000 {
		t.Errorf("expected MaxStreams 1000, got %d", config.MaxStreams)
	}

	// Verify TLS config is set
	if config.TLSConfig == nil {
		t.Fatal("expected TLSConfig to be set")
	}

	// Verify the config validates successfully
	if err := config.Validate(); err != nil {
		t.Errorf("config validation failed: %v", err)
	}
}

func TestDefaultServerConfigWithTLSValidation(t *testing.T) {
	config, err := DefaultServerConfigWithTLS()
	if err != nil {
		t.Fatalf("DefaultServerConfigWithTLS failed: %v", err)
	}

	// The returned config should pass validation
	if err := config.Validate(); err != nil {
		t.Errorf("expected valid config, got validation error: %v", err)
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
