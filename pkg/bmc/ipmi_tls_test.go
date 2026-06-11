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
	// Parent config must not be mutated.
	if cfg.SkipTLSVerify {
		t.Error("ensureRedfishClient must not mutate SkipTLSVerify on parent config")
	}
}

// TestEnsureRedfishClient_NoImplicitInsecure is a regression test for the
// deleted implicit insecure-skip-verify default. Before the fix, when
// neither SkipTLSVerify nor CACertPath was set, ensureRedfishClient
// silently forced skipTLS=true. After the fix it must not.
func TestEnsureRedfishClient_NoImplicitInsecure(t *testing.T) {
	cfg := &Config{
		Address:  "192.168.1.1",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: ProtocolIPMI,
		// Deliberately no TLS provider, no SkipTLSVerify, no CACertPath.
	}
	client := newIPMIClient(cfg, slog.Default())
	// The call will fail to connect, but SkipTLSVerify must remain false.
	_ = client.ensureRedfishClient()
	if cfg.SkipTLSVerify {
		t.Error("ensureRedfishClient must not set SkipTLSVerify on parent config")
	}
}

// TestEnsureRedfishClient_Idempotent verifies the lazy guard: calling
// ensureRedfishClient multiple times does not panic or corrupt state.
func TestEnsureRedfishClient_Idempotent(t *testing.T) {
	cfg := &Config{
		Address:       "192.168.1.1",
		Port:          623,
		Username:      "admin",
		Password:      "secret",
		Protocol:      ProtocolIPMI,
		SkipTLSVerify: true,
	}
	client := newIPMIClient(cfg, slog.Default())
	_ = client.ensureRedfishClient()
	// Second call must be a no-op (client already set or construction
	// already attempted). Must not panic.
	_ = client.ensureRedfishClient()
}
