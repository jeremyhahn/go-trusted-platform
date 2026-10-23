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

package platform

import (
	"crypto/tls"
	"errors"
	"testing"
	"time"
)

func TestNewOptions(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		opts := NewOptions()

		if opts.UnixSocket != DefaultUnixSocket {
			t.Errorf("UnixSocket = %q, want %q", opts.UnixSocket, DefaultUnixSocket)
		}
		if opts.Timeout != DefaultTimeout {
			t.Errorf("Timeout = %v, want %v", opts.Timeout, DefaultTimeout)
		}
		if opts.MaxMessageSize != DefaultMaxMessageSize {
			t.Errorf("MaxMessageSize = %d, want %d", opts.MaxMessageSize, DefaultMaxMessageSize)
		}
		if opts.GRPCAddr != "" {
			t.Errorf("GRPCAddr should be empty by default, got %q", opts.GRPCAddr)
		}
		if opts.RESTAddr != "" {
			t.Errorf("RESTAddr should be empty by default, got %q", opts.RESTAddr)
		}
		if opts.QUICAddr != "" {
			t.Errorf("QUICAddr should be empty by default, got %q", opts.QUICAddr)
		}
		if opts.MCPAddr != "" {
			t.Errorf("MCPAddr should be empty by default, got %q", opts.MCPAddr)
		}
	})

	t.Run("default values have nil embedded services", func(t *testing.T) {
		opts := NewOptions()

		if opts.EmbeddedServices != nil {
			t.Error("EmbeddedServices should be nil by default")
		}
		if opts.HasEmbeddedServices() {
			t.Error("HasEmbeddedServices() should return false by default")
		}
	})

	t.Run("with functional options", func(t *testing.T) {
		opts := NewOptions(
			WithUnixSocket("/custom/socket.sock"),
			WithGRPCAddr("localhost:10443"),
			WithRESTAddr("localhost:8443"),
			WithQUICAddr("localhost:9444"),
			WithMCPAddr("localhost:9445"),
			WithTimeout(10*time.Second),
			WithMaxMessageSize(8*1024*1024),
			WithPreferredProtocol(ProtocolGRPC),
			WithOnlyProtocol(ProtocolGRPC),
		)

		if opts.UnixSocket != "/custom/socket.sock" {
			t.Errorf("UnixSocket = %q, want %q", opts.UnixSocket, "/custom/socket.sock")
		}
		if opts.GRPCAddr != "localhost:10443" {
			t.Errorf("GRPCAddr = %q, want %q", opts.GRPCAddr, "localhost:10443")
		}
		if opts.RESTAddr != "localhost:8443" {
			t.Errorf("RESTAddr = %q, want %q", opts.RESTAddr, "localhost:8443")
		}
		if opts.QUICAddr != "localhost:9444" {
			t.Errorf("QUICAddr = %q, want %q", opts.QUICAddr, "localhost:9444")
		}
		if opts.MCPAddr != "localhost:9445" {
			t.Errorf("MCPAddr = %q, want %q", opts.MCPAddr, "localhost:9445")
		}
		if opts.Timeout != 10*time.Second {
			t.Errorf("Timeout = %v, want %v", opts.Timeout, 10*time.Second)
		}
		if opts.MaxMessageSize != 8*1024*1024 {
			t.Errorf("MaxMessageSize = %d, want %d", opts.MaxMessageSize, 8*1024*1024)
		}
		if opts.PreferredProtocol != ProtocolGRPC {
			t.Errorf("PreferredProtocol = %v, want %v", opts.PreferredProtocol, ProtocolGRPC)
		}
		if opts.OnlyProtocol != ProtocolGRPC {
			t.Errorf("OnlyProtocol = %v, want %v", opts.OnlyProtocol, ProtocolGRPC)
		}
	})

	t.Run("with TLS config", func(t *testing.T) {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
		opts := NewOptions(WithTLSConfig(tlsConfig))

		if opts.TLSConfig != tlsConfig {
			t.Error("TLSConfig was not set correctly")
		}
	})
}

func TestWithEmbeddedServices(t *testing.T) {
	t.Run("sets non-nil value", func(t *testing.T) {
		registry := &struct{ Name string }{Name: "test-registry"}
		opts := NewOptions(WithEmbeddedServices(registry))

		if opts.EmbeddedServices == nil {
			t.Error("EmbeddedServices should not be nil after WithEmbeddedServices")
		}
		if opts.EmbeddedServices != registry {
			t.Error("EmbeddedServices should be the exact registry value passed in")
		}
	})

	t.Run("sets nil value", func(t *testing.T) {
		opts := NewOptions(WithEmbeddedServices(nil))

		if opts.EmbeddedServices != nil {
			t.Error("EmbeddedServices should be nil when WithEmbeddedServices(nil) is used")
		}
	})

	t.Run("overrides previous value", func(t *testing.T) {
		first := &struct{ ID int }{ID: 1}
		second := &struct{ ID int }{ID: 2}
		opts := NewOptions(
			WithEmbeddedServices(first),
			WithEmbeddedServices(second),
		)

		if opts.EmbeddedServices != second {
			t.Error("EmbeddedServices should be overridden by the last WithEmbeddedServices call")
		}
	})
}

func TestOptions_ClientTLSConfig(t *testing.T) {
	t.Run("defaults to TLS 1.3 when no config is set", func(t *testing.T) {
		cfg := NewOptions().ClientTLSConfig()

		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
		}
	})

	t.Run("clones the caller config and raises the minimum version", func(t *testing.T) {
		callerCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "original"}
		opts := NewOptions(WithTLSConfig(callerCfg))

		cfg := opts.ClientTLSConfig()

		if cfg == callerCfg {
			t.Fatal("ClientTLSConfig() must return a clone, not the caller's config")
		}
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
		}
		if callerCfg.MinVersion != tls.VersionTLS12 {
			t.Error("ClientTLSConfig() must not modify the caller's config")
		}
		if cfg.ServerName != "original" {
			t.Errorf("ServerName = %q, want %q", cfg.ServerName, "original")
		}
	})

	t.Run("TLSServerName overrides the server name", func(t *testing.T) {
		opts := NewOptions(
			WithTLSConfig(&tls.Config{ServerName: "original"}),
			WithTLSServerName("platform.example"),
		)

		if got := opts.ClientTLSConfig().ServerName; got != "platform.example" {
			t.Errorf("ServerName = %q, want %q", got, "platform.example")
		}
	})
}

func TestOptions_CredentialOptions(t *testing.T) {
	t.Run("empty when nothing is set", func(t *testing.T) {
		if got := NewOptions().CredentialOptions(); len(got) != 0 {
			t.Errorf("CredentialOptions() = %v, want none", got)
		}
	})

	t.Run("names every option that is set", func(t *testing.T) {
		opts := NewOptions(
			WithBearerToken("token"),
			WithTLSConfig(&tls.Config{}),
			WithTLSServerName("platform.example"),
		)

		got := opts.CredentialOptions()
		want := []string{"BearerToken", "TLSConfig", "TLSServerName"}
		if len(got) != len(want) {
			t.Fatalf("CredentialOptions() = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("CredentialOptions()[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})
}

func TestOptions_HasEmbeddedServices(t *testing.T) {
	t.Run("returns true when set", func(t *testing.T) {
		opts := NewOptions(WithEmbeddedServices(&struct{}{}))

		if !opts.HasEmbeddedServices() {
			t.Error("HasEmbeddedServices() should return true when EmbeddedServices is set")
		}
	})

	t.Run("returns false when nil", func(t *testing.T) {
		opts := NewOptions()

		if opts.HasEmbeddedServices() {
			t.Error("HasEmbeddedServices() should return false when EmbeddedServices is nil")
		}
	})

	t.Run("returns false after setting nil", func(t *testing.T) {
		opts := NewOptions(WithEmbeddedServices(nil))

		if opts.HasEmbeddedServices() {
			t.Error("HasEmbeddedServices() should return false when WithEmbeddedServices(nil) is used")
		}
	})

	t.Run("returns true with string value", func(t *testing.T) {
		// EmbeddedServices is interface{}, verify it works with any non-nil type
		opts := &Options{EmbeddedServices: "non-nil-value"}

		if !opts.HasEmbeddedServices() {
			t.Error("HasEmbeddedServices() should return true for any non-nil interface{} value")
		}
	})
}

func TestOptions_Validate(t *testing.T) {
	t.Run("valid options", func(t *testing.T) {
		opts := NewOptions()
		if err := opts.Validate(); err != nil {
			t.Errorf("Validate() returned error for valid options: %v", err)
		}
	})

	t.Run("valid with all protocols set", func(t *testing.T) {
		opts := NewOptions(
			WithPreferredProtocol(ProtocolGRPC),
			WithOnlyProtocol(ProtocolUnix),
		)
		if err := opts.Validate(); err != nil {
			t.Errorf("Validate() returned error for valid options: %v", err)
		}
	})

	t.Run("valid with embedded protocol", func(t *testing.T) {
		opts := NewOptions(
			WithOnlyProtocol(ProtocolEmbedded),
			WithEmbeddedServices(&struct{}{}),
		)
		if err := opts.Validate(); err != nil {
			t.Errorf("Validate() returned error for valid embedded options: %v", err)
		}
	})

	t.Run("valid with preferred embedded protocol", func(t *testing.T) {
		opts := NewOptions(
			WithPreferredProtocol(ProtocolEmbedded),
			WithEmbeddedServices(&struct{}{}),
		)
		if err := opts.Validate(); err != nil {
			t.Errorf("Validate() returned error for valid preferred embedded options: %v", err)
		}
	})

	t.Run("invalid OnlyProtocol", func(t *testing.T) {
		opts := NewOptions()
		opts.OnlyProtocol = Protocol(99)

		err := opts.Validate()
		if err == nil {
			t.Error("Validate() should return error for invalid OnlyProtocol")
		}

		var invalidErr ErrInvalidOptions
		if !errors.As(err, &invalidErr) {
			t.Error("error should be ErrInvalidOptions")
		}
		if invalidErr.Field != "OnlyProtocol" {
			t.Errorf("Field = %q, want %q", invalidErr.Field, "OnlyProtocol")
		}
	})

	t.Run("invalid PreferredProtocol", func(t *testing.T) {
		opts := NewOptions()
		opts.PreferredProtocol = Protocol(99)

		err := opts.Validate()
		if err == nil {
			t.Error("Validate() should return error for invalid PreferredProtocol")
		}

		var invalidErr ErrInvalidOptions
		if !errors.As(err, &invalidErr) {
			t.Error("error should be ErrInvalidOptions")
		}
		if invalidErr.Field != "PreferredProtocol" {
			t.Errorf("Field = %q, want %q", invalidErr.Field, "PreferredProtocol")
		}
	})

	t.Run("negative timeout", func(t *testing.T) {
		opts := NewOptions()
		opts.Timeout = -1 * time.Second

		err := opts.Validate()
		if err == nil {
			t.Error("Validate() should return error for negative Timeout")
		}

		var invalidErr ErrInvalidOptions
		if !errors.As(err, &invalidErr) {
			t.Error("error should be ErrInvalidOptions")
		}
		if invalidErr.Field != "Timeout" {
			t.Errorf("Field = %q, want %q", invalidErr.Field, "Timeout")
		}
	})

	t.Run("negative max message size", func(t *testing.T) {
		opts := NewOptions()
		opts.MaxMessageSize = -1

		err := opts.Validate()
		if err == nil {
			t.Error("Validate() should return error for negative MaxMessageSize")
		}

		var invalidErr ErrInvalidOptions
		if !errors.As(err, &invalidErr) {
			t.Error("error should be ErrInvalidOptions")
		}
		if invalidErr.Field != "MaxMessageSize" {
			t.Errorf("Field = %q, want %q", invalidErr.Field, "MaxMessageSize")
		}
	})
}

func TestOptions_GetTimeout(t *testing.T) {
	t.Run("returns set value", func(t *testing.T) {
		opts := NewOptions(WithTimeout(10 * time.Second))
		if got := opts.GetTimeout(); got != 10*time.Second {
			t.Errorf("GetTimeout() = %v, want %v", got, 10*time.Second)
		}
	})

	t.Run("returns default when zero", func(t *testing.T) {
		opts := &Options{Timeout: 0}
		if got := opts.GetTimeout(); got != DefaultTimeout {
			t.Errorf("GetTimeout() = %v, want %v", got, DefaultTimeout)
		}
	})
}

func TestOptions_GetMaxMessageSize(t *testing.T) {
	t.Run("returns set value", func(t *testing.T) {
		opts := NewOptions(WithMaxMessageSize(8 * 1024 * 1024))
		if got := opts.GetMaxMessageSize(); got != 8*1024*1024 {
			t.Errorf("GetMaxMessageSize() = %d, want %d", got, 8*1024*1024)
		}
	})

	t.Run("returns default when zero", func(t *testing.T) {
		opts := &Options{MaxMessageSize: 0}
		if got := opts.GetMaxMessageSize(); got != DefaultMaxMessageSize {
			t.Errorf("GetMaxMessageSize() = %d, want %d", got, DefaultMaxMessageSize)
		}
	})
}

func TestOptions_HasMethods(t *testing.T) {
	t.Run("HasUnixSocket", func(t *testing.T) {
		opts := NewOptions()
		if !opts.HasUnixSocket() {
			t.Error("HasUnixSocket() should return true with default socket")
		}

		opts.UnixSocket = ""
		if opts.HasUnixSocket() {
			t.Error("HasUnixSocket() should return false with empty socket")
		}
	})

	t.Run("HasGRPCAddr", func(t *testing.T) {
		opts := NewOptions()
		if opts.HasGRPCAddr() {
			t.Error("HasGRPCAddr() should return false by default")
		}

		opts.GRPCAddr = "localhost:10443"
		if !opts.HasGRPCAddr() {
			t.Error("HasGRPCAddr() should return true when set")
		}
	})

	t.Run("HasRESTAddr", func(t *testing.T) {
		opts := NewOptions()
		if opts.HasRESTAddr() {
			t.Error("HasRESTAddr() should return false by default")
		}

		opts.RESTAddr = "localhost:8443"
		if !opts.HasRESTAddr() {
			t.Error("HasRESTAddr() should return true when set")
		}
	})

	t.Run("HasQUICAddr", func(t *testing.T) {
		opts := NewOptions()
		if opts.HasQUICAddr() {
			t.Error("HasQUICAddr() should return false by default")
		}

		opts.QUICAddr = "localhost:9444"
		if !opts.HasQUICAddr() {
			t.Error("HasQUICAddr() should return true when set")
		}
	})

	t.Run("HasMCPAddr", func(t *testing.T) {
		opts := NewOptions()
		if opts.HasMCPAddr() {
			t.Error("HasMCPAddr() should return false by default")
		}

		opts.MCPAddr = "localhost:9445"
		if !opts.HasMCPAddr() {
			t.Error("HasMCPAddr() should return true when set")
		}
	})

	t.Run("HasEmbeddedServices", func(t *testing.T) {
		opts := NewOptions()
		if opts.HasEmbeddedServices() {
			t.Error("HasEmbeddedServices() should return false by default")
		}

		opts.EmbeddedServices = &struct{}{}
		if !opts.HasEmbeddedServices() {
			t.Error("HasEmbeddedServices() should return true when set")
		}
	})
}

func TestDefaultConstants(t *testing.T) {
	t.Run("DefaultTimeout", func(t *testing.T) {
		if DefaultTimeout != 5*time.Second {
			t.Errorf("DefaultTimeout = %v, want %v", DefaultTimeout, 5*time.Second)
		}
	})

	t.Run("DefaultUnixSocket", func(t *testing.T) {
		if DefaultUnixSocket != "/run/platformd.sock" {
			t.Errorf("DefaultUnixSocket = %q, want %q", DefaultUnixSocket, "/run/platformd.sock")
		}
	})

	t.Run("DefaultGRPCPort", func(t *testing.T) {
		if DefaultGRPCPort != "10443" {
			t.Errorf("DefaultGRPCPort = %q, want %q", DefaultGRPCPort, "10443")
		}
	})

	t.Run("DefaultRESTPort", func(t *testing.T) {
		if DefaultRESTPort != "8443" {
			t.Errorf("DefaultRESTPort = %q, want %q", DefaultRESTPort, "8443")
		}
	})

	t.Run("DefaultQUICPort", func(t *testing.T) {
		if DefaultQUICPort != "9444" {
			t.Errorf("DefaultQUICPort = %q, want %q", DefaultQUICPort, "9444")
		}
	})

	t.Run("DefaultMCPPort", func(t *testing.T) {
		if DefaultMCPPort != "9445" {
			t.Errorf("DefaultMCPPort = %q, want %q", DefaultMCPPort, "9445")
		}
	})

	t.Run("DefaultMaxMessageSize", func(t *testing.T) {
		expectedSize := 4 * 1024 * 1024
		if DefaultMaxMessageSize != expectedSize {
			t.Errorf("DefaultMaxMessageSize = %d, want %d", DefaultMaxMessageSize, expectedSize)
		}
	})
}
