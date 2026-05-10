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

package mcp

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// phase35CombinedProvider embeds both mockServiceProvider (satisfies the full
// ServiceProvider interface) and phase35StubProvider (satisfies
// Phase35Provider). This lets the tool registry route Phase 3.5 tools through
// the optional-interface path while still constructing cleanly.
//
// Because both types implement different methods, there is no collision in
// the method set.
type phase35CombinedProvider struct {
	*mockServiceProvider
	*phase35StubProvider
}

// Compile-time assertions.
var (
	_ ServiceProvider = (*phase35CombinedProvider)(nil)
	_ Phase35Provider = (*phase35CombinedProvider)(nil)
)

// TestToolRegistry_ExecuteTool_Phase35_RoutesToProvider verifies the central
// ExecuteTool entry point correctly dispatches Phase 3.5 tools to the
// provider when the ServiceProvider also satisfies Phase35Provider.
func TestToolRegistry_ExecuteTool_Phase35_RoutesToProvider(t *testing.T) {
	stub := &phase35StubProvider{}
	svc := &phase35CombinedProvider{
		mockServiceProvider: newMockServiceProvider(),
		phase35StubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	// Status tool.
	result, err := registry.ExecuteTool(ctx, "platform_ceremony_status", nil)
	if err != nil {
		t.Fatalf("platform_ceremony_status: %v", err)
	}
	if result == nil {
		t.Error("result should not be nil")
	}
	if stub.lastCall != "ceremony_status" {
		t.Errorf("wrong stub method invoked: %q", stub.lastCall)
	}

	// LUKS enroll TPM: args should flow through to the stub.
	if _, err := registry.ExecuteTool(ctx, "platform_luks_enroll_tpm", map[string]interface{}{
		"device": "/dev/sda", "existing_passphrase": "x",
	}); err != nil {
		t.Fatalf("platform_luks_enroll_tpm: %v", err)
	}
	if stub.lastCall != "luks_enroll_tpm" {
		t.Errorf("wrong stub method invoked: %q", stub.lastCall)
	}

	// FIDO2 authenticate.
	if _, err := registry.ExecuteTool(ctx, "platform_fido2_authenticate", map[string]interface{}{
		"credential_id": "c",
	}); err != nil {
		t.Fatalf("platform_fido2_authenticate: %v", err)
	}
	if stub.lastCall != "fido2_authenticate" {
		t.Errorf("wrong stub method invoked: %q", stub.lastCall)
	}
}

// TestToolRegistry_ExecuteTool_Phase35_NoProvider verifies Phase 3.5 tools
// return ErrPhase35NotConfigured when the ServiceProvider does not satisfy
// Phase35Provider.
func TestToolRegistry_ExecuteTool_Phase35_NoProvider(t *testing.T) {
	// Plain mockServiceProvider does NOT satisfy Phase35Provider.
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	for _, name := range phase35ExpectedTools {
		_, err := registry.ExecuteTool(ctx, name, nil)
		if err == nil {
			t.Errorf("tool %s: expected error, got nil", name)
		}
	}
}
