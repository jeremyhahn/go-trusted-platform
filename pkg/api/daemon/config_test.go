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
	"net"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

func TestDefaultConfig(t *testing.T) {
	t.Run("returns valid configuration", func(t *testing.T) {
		config := DefaultConfig()

		if config == nil {
			t.Fatal("DefaultConfig() returned nil")
		}

		if config.SocketPath == "" {
			t.Error("SocketPath should not be empty")
		}

		if config.SocketGroup == "" {
			t.Error("SocketGroup should not be empty")
		}

		if config.SocketMode == 0 {
			t.Error("SocketMode should not be zero")
		}

		if config.ShutdownTimeout <= 0 {
			t.Error("ShutdownTimeout should be positive")
		}

		if config.Services == nil {
			t.Error("Services map should not be nil")
		}
	})

	t.Run("has expected defaults", func(t *testing.T) {
		config := DefaultConfig()

		expectedSocketPath := "/run/platformd.sock"
		if config.SocketPath != expectedSocketPath {
			t.Errorf("SocketPath = %q, want %q", config.SocketPath, expectedSocketPath)
		}

		expectedGroup := "trusted-platform"
		if config.SocketGroup != expectedGroup {
			t.Errorf("SocketGroup = %q, want %q", config.SocketGroup, expectedGroup)
		}

		expectedMode := os.FileMode(0660)
		if config.SocketMode != expectedMode {
			t.Errorf("SocketMode = %o, want %o", config.SocketMode, expectedMode)
		}

		expectedTimeout := 30 * time.Second
		if config.ShutdownTimeout != expectedTimeout {
			t.Errorf("ShutdownTimeout = %v, want %v", config.ShutdownTimeout, expectedTimeout)
		}

		if !config.EnableMetrics {
			t.Error("EnableMetrics should be true by default")
		}

		if !config.EnableEvents {
			t.Error("EnableEvents should be true by default")
		}
	})

	t.Run("has expected services", func(t *testing.T) {
		config := DefaultConfig()

		expectedServices := []string{"tpm", "sdn", "compute", "dns", "acme", "webservice", "attestation"}
		for _, svc := range expectedServices {
			if _, exists := config.Services[svc]; !exists {
				t.Errorf("expected service %q to exist in default config", svc)
			}
		}
	})

	t.Run("tpm service has correct defaults", func(t *testing.T) {
		config := DefaultConfig()

		tpm, exists := config.Services["tpm"]
		if !exists {
			t.Fatal("tpm service should exist")
		}

		if !tpm.Enabled {
			t.Error("tpm service should be enabled")
		}

		if !tpm.AutoStart {
			t.Error("tpm service should have AutoStart enabled")
		}

		if tpm.Timeout != 10*time.Second {
			t.Errorf("tpm timeout = %v, want %v", tpm.Timeout, 10*time.Second)
		}

		if tpm.MaxRetries != 3 {
			t.Errorf("tpm MaxRetries = %d, want %d", tpm.MaxRetries, 3)
		}
	})
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid default config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "valid custom config",
			config: &Config{
				SocketPath:      "/tmp/test.sock",
				SocketGroup:     "test-group",
				SocketMode:      0600,
				ShutdownTimeout: 15 * time.Second,
				EnableMetrics:   true,
				EnableEvents:    true,
				Services: map[string]ServiceConfig{
					"test": {
						Enabled:    true,
						AutoStart:  false,
						Timeout:    5 * time.Second,
						MaxRetries: 2,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty socket path",
			config: &Config{
				SocketPath:      "",
				ShutdownTimeout: 10 * time.Second,
				Services:        map[string]ServiceConfig{},
			},
			wantErr: true,
			errMsg:  "socket path cannot be empty",
		},
		{
			name: "zero shutdown timeout",
			config: &Config{
				SocketPath:      "/tmp/test.sock",
				ShutdownTimeout: 0,
				Services:        map[string]ServiceConfig{},
			},
			wantErr: true,
			errMsg:  "shutdown timeout must be positive",
		},
		{
			name: "negative shutdown timeout",
			config: &Config{
				SocketPath:      "/tmp/test.sock",
				ShutdownTimeout: -5 * time.Second,
				Services:        map[string]ServiceConfig{},
			},
			wantErr: true,
			errMsg:  "shutdown timeout must be positive",
		},
		{
			name: "service with zero timeout",
			config: &Config{
				SocketPath:      "/tmp/test.sock",
				ShutdownTimeout: 10 * time.Second,
				Services: map[string]ServiceConfig{
					"invalid": {
						Enabled:    true,
						AutoStart:  false,
						Timeout:    0,
						MaxRetries: 3,
					},
				},
			},
			wantErr: true,
			errMsg:  "service invalid timeout must be positive",
		},
		{
			name: "service with negative timeout",
			config: &Config{
				SocketPath:      "/tmp/test.sock",
				ShutdownTimeout: 10 * time.Second,
				Services: map[string]ServiceConfig{
					"test": {
						Enabled:    true,
						AutoStart:  false,
						Timeout:    -5 * time.Second,
						MaxRetries: 3,
					},
				},
			},
			wantErr: true,
			errMsg:  "service test timeout must be positive",
		},
		{
			name: "service with negative max retries",
			config: &Config{
				SocketPath:      "/tmp/test.sock",
				ShutdownTimeout: 10 * time.Second,
				Services: map[string]ServiceConfig{
					"test": {
						Enabled:    true,
						AutoStart:  false,
						Timeout:    5 * time.Second,
						MaxRetries: -1,
					},
				},
			},
			wantErr: true,
			errMsg:  "service test max retries cannot be negative",
		},
		{
			name: "service with zero max retries is valid",
			config: &Config{
				SocketPath:      "/tmp/test.sock",
				ShutdownTimeout: 10 * time.Second,
				Services: map[string]ServiceConfig{
					"test": {
						Enabled:    true,
						AutoStart:  false,
						Timeout:    5 * time.Second,
						MaxRetries: 0,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple services with one invalid",
			config: &Config{
				SocketPath:      "/tmp/test.sock",
				ShutdownTimeout: 10 * time.Second,
				Services: map[string]ServiceConfig{
					"valid": {
						Enabled:    true,
						AutoStart:  false,
						Timeout:    5 * time.Second,
						MaxRetries: 3,
					},
					"invalid": {
						Enabled:    true,
						AutoStart:  false,
						Timeout:    0,
						MaxRetries: 3,
					},
				},
			},
			wantErr: true,
			errMsg:  "service invalid timeout must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Error("Validate() expected error but got nil")
					return
				}

				if tt.errMsg != "" {
					errInvalid, ok := err.(ErrInvalidConfig)
					if !ok {
						t.Errorf("expected ErrInvalidConfig, got %T", err)
						return
					}
					if errInvalid.Reason != tt.errMsg {
						t.Errorf("error message = %q, want %q", errInvalid.Reason, tt.errMsg)
					}
				}
			} else if err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestServiceConfig(t *testing.T) {
	t.Run("all fields are settable", func(t *testing.T) {
		config := ServiceConfig{
			Enabled:    true,
			AutoStart:  true,
			Timeout:    15 * time.Second,
			MaxRetries: 5,
		}

		if !config.Enabled {
			t.Error("Enabled should be true")
		}

		if !config.AutoStart {
			t.Error("AutoStart should be true")
		}

		if config.Timeout != 15*time.Second {
			t.Errorf("Timeout = %v, want %v", config.Timeout, 15*time.Second)
		}

		if config.MaxRetries != 5 {
			t.Errorf("MaxRetries = %d, want %d", config.MaxRetries, 5)
		}
	})

	t.Run("zero value is valid struct", func(t *testing.T) {
		var config ServiceConfig

		if config.Enabled {
			t.Error("zero value Enabled should be false")
		}

		if config.AutoStart {
			t.Error("zero value AutoStart should be false")
		}

		if config.Timeout != 0 {
			t.Error("zero value Timeout should be 0")
		}

		if config.MaxRetries != 0 {
			t.Error("zero value MaxRetries should be 0")
		}
	})
}

func TestConfig_Fields(t *testing.T) {
	t.Run("all fields are accessible", func(t *testing.T) {
		config := &Config{
			SocketPath:      "/test/socket.sock",
			SocketGroup:     "test-group",
			SocketMode:      0600,
			ShutdownTimeout: 20 * time.Second,
			EnableMetrics:   false,
			EnableEvents:    false,
			Services:        make(map[string]ServiceConfig),
		}

		if config.SocketPath != "/test/socket.sock" {
			t.Errorf("SocketPath mismatch")
		}

		if config.SocketGroup != "test-group" {
			t.Errorf("SocketGroup mismatch")
		}

		if config.SocketMode != 0600 {
			t.Errorf("SocketMode mismatch")
		}

		if config.ShutdownTimeout != 20*time.Second {
			t.Errorf("ShutdownTimeout mismatch")
		}

		if config.EnableMetrics {
			t.Error("EnableMetrics should be false")
		}

		if config.EnableEvents {
			t.Error("EnableEvents should be false")
		}

		if config.Services == nil {
			t.Error("Services should not be nil")
		}
	})
}

// TestDefaultConfig_ListenAddressesAreLoopback pins the defaults layer of
// the 2026-08-26 ruling (#93, #552): no transport reaches an interface
// unless the resolved `daemon:` section says so.
func TestDefaultConfig_ListenAddressesAreLoopback(t *testing.T) {
	config := DefaultConfig()
	for name, addr := range map[string]string{
		"grpc": config.GRPCListenAddr,
		"quic": config.QUICListenAddr,
		"rest": config.RESTListenAddr,
		"mcp":  config.MCPConfig.HTTPAddr,
	} {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("%s: %q is not host:port: %v", name, addr, err)
		}
		if host != "127.0.0.1" {
			t.Errorf("%s: default host = %q, want loopback", name, host)
		}
		if port == "" || port == "0" {
			t.Errorf("%s: default port = %q, want a canonical port", name, port)
		}
	}
}

// The library defaults are the platformd serve defaults; a second copy of
// the numbers drifted once (QUIC defaulted to 11443 here, 9444 in serve).
func TestDefaultConfig_ListenAddressesMatchTheDaemonListenerDefaults(t *testing.T) {
	config := DefaultConfig()
	listeners := tpconfig.DefaultDaemonListeners()
	for name, tc := range map[string]struct{ got, want string }{
		"grpc": {config.GRPCListenAddr, listeners.GRPC.Address()},
		"quic": {config.QUICListenAddr, listeners.QUIC.Address()},
		"rest": {config.RESTListenAddr, listeners.REST.Address()},
		"mcp":  {config.MCPConfig.HTTPAddr, listeners.MCP.Address()},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: default listen address = %q, want %q", name, tc.got, tc.want)
		}
	}
}

// The daemon and the MCP server package each carry a default MCP listen
// address; both must be the canonical 9445 so an embedded consumer that
// skips `serve` reaches the same listener (#301).
func TestDefaultMCPConfig_AgreesWithMCPServerDefault(t *testing.T) {
	const want = "127.0.0.1:9445"
	if got := DefaultMCPConfig().HTTPAddr; got != want {
		t.Errorf("daemon default MCP HTTPAddr = %q, want %q", got, want)
	}
	if got := mcp.DefaultConfig().HTTPAddr; got != want {
		t.Errorf("mcp default HTTPAddr = %q, want %q", got, want)
	}
	if DefaultMCPConfig().HTTPAddr != mcp.DefaultConfig().HTTPAddr {
		t.Error("daemon and mcp default HTTPAddr disagree")
	}
}
