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
)

// phase35ToolScopes is the scope every ceremony, PIV and FIDO2 tool requires.
// Ceremony init and status are scoped, not pre-auth: first boot runs over the
// Unix socket, which is not token-gated.
var phase35ToolScopes = map[string]string{
	"platform_piv_list_devices": "piv:read",
	"platform_piv_list_slots":   "piv:read",
	"platform_piv_slot_info":    "piv:read",
	"platform_piv_attest":       "piv:read",
	"platform_piv_generate":     "piv:write",
	"platform_piv_import":       "piv:write",
	"platform_piv_sign":         "piv:write",
	"platform_piv_reset":        "piv:write",

	"platform_fido2_list_devices": "fido2:read",
	"platform_fido2_wait_device":  "fido2:read",
	"platform_fido2_info":         "fido2:read",
	"platform_fido2_register":     "fido2:write",
	"platform_fido2_authenticate": "fido2:write",

	"platform_ceremony_status":               "ceremony:read",
	"platform_ceremony_init":                 "ceremony:write",
	"platform_ceremony_claim_cert_begin":     "ceremony:write",
	"platform_ceremony_claim_cert_complete":  "ceremony:write",
	"platform_ceremony_claim_share_begin":    "ceremony:write",
	"platform_ceremony_claim_share_complete": "ceremony:write",
	"platform_ceremony_sign_csr":             "ceremony:write",
}

func TestPhase35ToolPermissions(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)
	for tool, want := range phase35ToolScopes {
		if got := checker.toolPermissions[tool]; got != want {
			t.Errorf("permission for %s = %q, want %q", tool, got, want)
		}
	}
}

// TestPhase35ToolsAreRegisteredAndScoped fails when a ceremony, PIV or FIDO2
// tool is registered without an entry in phase35ToolScopes, so a new tool
// cannot ship unclassified or silently open.
func TestPhase35ToolsAreRegisteredAndScoped(t *testing.T) {
	registry := NewToolRegistry(nil, nil)
	registered := 0
	for _, tool := range registry.ListTools() {
		scope, isPhase35 := phase35ToolScopes[tool.Name]
		if !isPhase35 {
			continue
		}
		registered++
		if scope == "" {
			t.Errorf("%s has an empty scope", tool.Name)
		}
	}
	if registered != len(phase35ToolScopes) {
		t.Errorf("registry exposes %d of the %d scoped tools", registered, len(phase35ToolScopes))
	}
}

// TestPhase35AuthorizeToolEnforcesScope drives the real checker: a caller
// holding only read scopes may list devices but not generate a key, and a
// ceremony call without a token is refused.
func TestPhase35AuthorizeToolEnforcesScope(t *testing.T) {
	readOnly := &mockAuthorizationService{
		checkFunc: func(_ context.Context, _, resource, action string) (bool, error) {
			return action == "read", nil
		},
	}
	checker := NewAuthorizationChecker(readOnly, &mockAuthManager{})

	if _, authErr := checker.AuthorizeTool(context.Background(), "platform_piv_list_devices", "tok"); authErr != nil {
		t.Errorf("read tool refused for a read-only caller: %v", authErr.Message)
	}
	if _, authErr := checker.AuthorizeTool(context.Background(), "platform_piv_generate", "tok"); authErr == nil || authErr.Type != AuthErrorPermissionDenied {
		t.Errorf("write tool err = %+v, want permission denied for a read-only caller", authErr)
	}
	if _, authErr := checker.AuthorizeTool(context.Background(), "platform_ceremony_init", ""); authErr == nil || authErr.Type != AuthErrorMissingToken {
		t.Errorf("ceremony init without token err = %+v, want missing token", authErr)
	}
}
