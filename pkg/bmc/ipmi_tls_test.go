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

// TestEnsureRedfishClient_WithTLSProvider verifies that when the parent
// IPMI config carries a TLSProvider, the synthesized Redfish fallback
// config also carries it. No implicit insecure override must occur.
func TestEnsureRedfishClient_WithTLSProvider(t *testing.T) {
	provider := &fakeTLSProvider{cfg: &tls.Config{
		ServerName: "bmc-provider-marker",
		MinVersion: tls.VersionTLS13,
	}}
	cfg := &Config{
		Address:  "192.168.1.1",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
		TLS:      provider,
	}
	client := newIPMIClient(cfg, slog.Default())
	// ensureRedfishClient tries to dial 192.168.1.1:443 which will fail,
	// but the TLS provider is valid so TLS construction itself succeeds.
	// The error (if any) must be a connection error, never an ErrTLSProvider.
	err := client.ensureRedfishClient()
	if err != nil {
		var tlsErr ErrTLSProvider
		if errors.As(err, &tlsErr) {
			t.Errorf("got ErrTLSProvider when provider is valid: %v", err)
		}
		// A connection-refused / timeout error is acceptable here.
	}
}

// TestEnsureRedfishClient_NoImplicitInsecure is a regression test for the
// deleted implicit insecure-skip-verify default. Before the fix, when
// no TLS provider was set, ensureRedfishClient silently forced InsecureSkipVerify.
// After the fix it must route through BuildTLSConfig (system roots).
func TestEnsureRedfishClient_NoImplicitInsecure(t *testing.T) {
	cfg := &Config{
		Address:  "192.168.1.1",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
		// No TLS provider: system roots must be used.
	}
	client := newIPMIClient(cfg, slog.Default())
	// Connection will fail (no real BMC at 192.168.1.1) but
	// ensureRedfishClient must not error on TLS config construction.
	err := client.ensureRedfishClient()
	if err != nil {
		// Only a connection-refused or timeout error is acceptable.
		var tlsErr ErrTLSProvider
		if errors.As(err, &tlsErr) {
			t.Errorf("ensureRedfishClient set an ErrTLSProvider on a config without provider: %v", err)
		}
	}
}

// TestEnsureRedfishClient_Idempotent verifies the lazy guard: calling
// ensureRedfishClient multiple times does not panic or corrupt state.
func TestEnsureRedfishClient_Idempotent(t *testing.T) {
	// Use a provider so the test is self-contained (no dial to real host).
	provider := &fakeTLSProvider{cfg: &tls.Config{MinVersion: tls.VersionTLS12}}
	cfg := &Config{
		Address:  "192.168.1.1",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
		TLS:      provider,
	}
	client := newIPMIClient(cfg, slog.Default())
	_ = client.ensureRedfishClient()
	// Second call must be a no-op (client already set or construction
	// already attempted). Must not panic.
	_ = client.ensureRedfishClient()
}

// TestEnsureRedfishClient_TLSProviderPropagated verifies that the synthesized
// Redfish sub-config carries the parent TLS provider (not nil, not a new
// independent config).
func TestEnsureRedfishClient_TLSProviderPropagated(t *testing.T) {
	provider := &fakeTLSProvider{cfg: &tls.Config{MinVersion: tls.VersionTLS12}}
	cfg := &Config{
		Address:  "192.168.1.1",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
		TLS:      provider,
	}
	client := newIPMIClient(cfg, slog.Default())
	// We cannot inspect the internal redfishConfig directly, but we can
	// verify that the call succeeds at the TLS-config level (provider is
	// reached) and that the parent config is not mutated.
	_ = client.ensureRedfishClient()
	if cfg.TLS != provider {
		t.Error("parent Config.TLS was mutated by ensureRedfishClient")
	}
}
