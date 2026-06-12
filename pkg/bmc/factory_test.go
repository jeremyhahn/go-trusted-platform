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

package bmc

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"
)

// --- DefaultClientFactory Tests ---

func TestDefaultClientFactory_IPMI(t *testing.T) {
	factory := NewDefaultClientFactory(slog.Default())

	t.Run("creates IPMI client", func(t *testing.T) {
		cfg := &Config{
			Address:  "192.168.1.100",
			Port:     623,
			Username: "admin",
			Password: "secret",
			Protocol: ProtocolIPMI,
		}
		client, err := factory.NewClient(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}
		if _, ok := client.(*ipmiClient); !ok {
			t.Errorf("expected *ipmiClient, got %T", client)
		}
		if err := client.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		client, err := factory.NewClient(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
		var target ErrNilConfig
		if !errors.As(err, &target) {
			t.Errorf("expected ErrNilConfig, got %T: %v", err, err)
		}
		if client != nil {
			t.Error("expected nil client on error")
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		cfg := &Config{
			Port:     623,
			Protocol: ProtocolIPMI,
		}
		client, err := factory.NewClient(cfg)
		if err == nil {
			t.Fatal("expected error for missing address")
		}
		var target ErrInvalidConfig
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
		}
		if client != nil {
			t.Error("expected nil client on error")
		}
	})
}

func TestDefaultClientFactory_Redfish(t *testing.T) {
	factory := NewDefaultClientFactory(slog.Default())

	t.Run("creates Redfish client", func(t *testing.T) {
		cfg := &Config{
			Address:  "192.168.1.100",
			Port:     443,
			Username: "admin",
			Password: "secret",
			Protocol: ProtocolRedfish,
			TLS:      &fakeTLSProvider{cfg: &tls.Config{MinVersion: tls.VersionTLS12}},
		}
		client, err := factory.NewClient(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}
		if _, ok := client.(*redfishClient); !ok {
			t.Errorf("expected *redfishClient, got %T", client)
		}
		if err := client.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}
	})

	t.Run("default protocol defaults to IPMI", func(t *testing.T) {
		cfg := &Config{
			Address:  "192.168.1.100",
			Port:     623,
			Username: "admin",
			Password: "secret",
			Protocol: ProtocolIPMI,
		}
		client, err := factory.NewClient(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := client.(*ipmiClient); !ok {
			t.Errorf("expected *ipmiClient for default protocol, got %T", client)
		}
		client.Close()
	})
}

// --- RedfishClientFactory Tests ---

func TestRedfishClientFactory_NewClient(t *testing.T) {
	factory := NewRedfishClientFactory(slog.Default())

	t.Run("valid config", func(t *testing.T) {
		cfg := &Config{
			Address:  "192.168.1.100",
			Port:     443,
			Username: "admin",
			Password: "secret",
			Protocol: ProtocolRedfish,
			TLS:      &fakeTLSProvider{cfg: &tls.Config{MinVersion: tls.VersionTLS12}},
		}
		client, err := factory.NewClient(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}
		if _, ok := client.(*redfishClient); !ok {
			t.Errorf("expected *redfishClient, got %T", client)
		}
		if err := client.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		client, err := factory.NewClient(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
		var target ErrNilConfig
		if !errors.As(err, &target) {
			t.Errorf("expected ErrNilConfig, got %T: %v", err, err)
		}
		if client != nil {
			t.Error("expected nil client on error")
		}
	})

	t.Run("invalid config missing address", func(t *testing.T) {
		cfg := &Config{
			Port:     443,
			Protocol: ProtocolRedfish,
		}
		client, err := factory.NewClient(cfg)
		if err == nil {
			t.Fatal("expected error for invalid config")
		}
		var target ErrInvalidConfig
		if !errors.As(err, &target) {
			t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
		}
		if client != nil {
			t.Error("expected nil client on error")
		}
	})
}

// --- Config Tests ---

func TestDefaultRedfishConfig(t *testing.T) {
	cfg := DefaultRedfishConfig()
	if cfg.Port != 443 {
		t.Errorf("Port = %d, want 443", cfg.Port)
	}
	if cfg.Protocol != ProtocolRedfish {
		t.Errorf("Protocol = %q, want %q", cfg.Protocol, ProtocolRedfish)
	}
	// TLS is nil by default: provider-or-system-roots contract.
	if cfg.TLS != nil {
		t.Error("TLS provider should be nil in the default config")
	}
}
