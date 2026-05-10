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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Test fixtures
// =============================================================================

// invitationStubProvider is a minimal InvitationProvider that records the
// last invoked method so tests can assert dispatch.
type invitationStubProvider struct {
	lastCall string
	// Optional error to inject from any handler.
	err error
}

func (s *invitationStubProvider) CreateInvitation(_ context.Context, tenantID, email, role string, invitedByID uint64, expiresInSeconds int64) (interface{}, error) {
	s.lastCall = "create:" + tenantID + ":" + email + ":" + role
	if s.err != nil {
		return nil, s.err
	}
	return map[string]interface{}{
		"tenant_id":     tenantID,
		"email":         email,
		"role":          role,
		"invited_by_id": invitedByID,
		"expires_in":    expiresInSeconds,
	}, nil
}

func (s *invitationStubProvider) GetInvitation(_ context.Context, invitationID uint64) (interface{}, error) {
	s.lastCall = "get"
	if s.err != nil {
		return nil, s.err
	}
	return map[string]interface{}{"invitation_id": invitationID}, nil
}

func (s *invitationStubProvider) GetInvitationByToken(_ context.Context, token string) (interface{}, error) {
	s.lastCall = "get_by_token:" + token
	if s.err != nil {
		return nil, s.err
	}
	return map[string]interface{}{"token": token}, nil
}

func (s *invitationStubProvider) ListInvitations(_ context.Context, tenantID string, pendingOnly bool) (interface{}, error) {
	s.lastCall = "list:" + tenantID
	if pendingOnly {
		s.lastCall += ":pending"
	}
	if s.err != nil {
		return nil, s.err
	}
	return map[string]interface{}{
		"tenant_id":    tenantID,
		"pending_only": pendingOnly,
		"invitations":  []map[string]interface{}{},
	}, nil
}

func (s *invitationStubProvider) RevokeInvitation(_ context.Context, invitationID, revokerID uint64) (interface{}, error) {
	s.lastCall = "revoke"
	if s.err != nil {
		return nil, s.err
	}
	return map[string]interface{}{
		"invitation_id": invitationID,
		"revoker_id":    revokerID,
	}, nil
}

func (s *invitationStubProvider) AcceptInvitation(_ context.Context, token string, userID uint64) (interface{}, error) {
	s.lastCall = "accept:" + token
	if s.err != nil {
		return nil, s.err
	}
	return map[string]interface{}{
		"token":   token,
		"user_id": userID,
	}, nil
}

func (s *invitationStubProvider) DeleteInvitation(_ context.Context, invitationID uint64) (interface{}, error) {
	s.lastCall = "delete"
	if s.err != nil {
		return nil, s.err
	}
	return map[string]interface{}{
		"invitation_id": invitationID,
		"deleted":       true,
	}, nil
}

// invitationCombinedProvider satisfies both ServiceProvider (via mockServiceProvider)
// and InvitationProvider (via invitationStubProvider). The two types contribute
// disjoint method sets so embedding is collision-free.
type invitationCombinedProvider struct {
	*mockServiceProvider
	*invitationStubProvider
}

// Compile-time assertions: combined provider satisfies both interfaces.
var (
	_ ServiceProvider    = (*invitationCombinedProvider)(nil)
	_ InvitationProvider = (*invitationCombinedProvider)(nil)
)

// =============================================================================
// Tests
// =============================================================================

// TestToolRegistry_ExecuteTool_Invitation_RoutesToProvider verifies that
// the ExecuteTool dispatcher routes platform_invitation_* tools through
// the optional InvitationProvider interface.
func TestToolRegistry_ExecuteTool_Invitation_RoutesToProvider(t *testing.T) {
	stub := &invitationStubProvider{}
	svc := &invitationCombinedProvider{
		mockServiceProvider:    newMockServiceProvider(),
		invitationStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	cases := []struct {
		name     string
		args     map[string]interface{}
		wantCall string
	}{
		{
			name: "platform_invitation_create",
			args: map[string]interface{}{
				"tenant_id":          "tenant-1",
				"email":              "alice@example.com",
				"role":               "member",
				"invited_by_id":      99,
				"expires_in_seconds": 3600,
			},
			wantCall: "create:tenant-1:alice@example.com:member",
		},
		{
			name:     "platform_invitation_get",
			args:     map[string]interface{}{"invitation_id": 42},
			wantCall: "get",
		},
		{
			name:     "platform_invitation_get_by_token",
			args:     map[string]interface{}{"token": "tok-abc"},
			wantCall: "get_by_token:tok-abc",
		},
		{
			name:     "platform_invitation_list",
			args:     map[string]interface{}{"tenant_id": "tenant-1"},
			wantCall: "list:tenant-1",
		},
		{
			name:     "platform_invitation_list",
			args:     map[string]interface{}{"tenant_id": "tenant-1", "pending_only": true},
			wantCall: "list:tenant-1:pending",
		},
		{
			name:     "platform_invitation_revoke",
			args:     map[string]interface{}{"invitation_id": 42, "revoker_id": 99},
			wantCall: "revoke",
		},
		{
			name:     "platform_invitation_accept",
			args:     map[string]interface{}{"token": "tok-xyz", "user_id": 7},
			wantCall: "accept:tok-xyz",
		},
		{
			name:     "platform_invitation_delete",
			args:     map[string]interface{}{"invitation_id": 42},
			wantCall: "delete",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+":"+tc.wantCall, func(t *testing.T) {
			result, err := registry.ExecuteTool(ctx, tc.name, tc.args)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tc.name, err)
			}
			if result == nil {
				t.Errorf("%s: result should not be nil", tc.name)
			}
			if stub.lastCall != tc.wantCall {
				t.Errorf("%s: lastCall = %q, want %q", tc.name, stub.lastCall, tc.wantCall)
			}
		})
	}
}

// TestToolRegistry_ExecuteTool_Invitation_NoProvider verifies that
// invitation tools return ErrInvitationNotConfigured when the
// ServiceProvider does not also satisfy InvitationProvider.
func TestToolRegistry_ExecuteTool_Invitation_NoProvider(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	tools := []struct {
		name string
		args map[string]interface{}
	}{
		{
			name: "platform_invitation_create",
			args: map[string]interface{}{
				"tenant_id":     "t",
				"email":         "a@b",
				"role":          "member",
				"invited_by_id": 1,
			},
		},
		{name: "platform_invitation_get", args: map[string]interface{}{"invitation_id": 1}},
		{name: "platform_invitation_get_by_token", args: map[string]interface{}{"token": "t"}},
		{name: "platform_invitation_list", args: map[string]interface{}{"tenant_id": "t"}},
		{name: "platform_invitation_revoke", args: map[string]interface{}{"invitation_id": 1, "revoker_id": 2}},
		{name: "platform_invitation_accept", args: map[string]interface{}{"token": "t", "user_id": 1}},
		{name: "platform_invitation_delete", args: map[string]interface{}{"invitation_id": 1}},
	}
	for _, tc := range tools {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, tc.name, tc.args)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !errors.Is(err, ErrInvitationNotConfigured) {
				t.Errorf("%s: expected ErrInvitationNotConfigured, got %v", tc.name, err)
			}
		})
	}
}

// TestToolRegistry_ExecuteTool_Invitation_MissingArgs verifies argument
// validation errors for each invitation tool.
func TestToolRegistry_ExecuteTool_Invitation_MissingArgs(t *testing.T) {
	stub := &invitationStubProvider{}
	svc := &invitationCombinedProvider{
		mockServiceProvider:    newMockServiceProvider(),
		invitationStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	cases := []struct {
		name    string
		tool    string
		args    map[string]interface{}
		wantErr error
	}{
		// create
		{name: "create_missing_tenant", tool: "platform_invitation_create",
			args:    map[string]interface{}{"email": "a@b", "role": "r", "invited_by_id": 1},
			wantErr: ErrInvitationTenantIDRequired},
		{name: "create_missing_email", tool: "platform_invitation_create",
			args:    map[string]interface{}{"tenant_id": "t", "role": "r", "invited_by_id": 1},
			wantErr: ErrInvitationEmailRequired},
		{name: "create_missing_role", tool: "platform_invitation_create",
			args:    map[string]interface{}{"tenant_id": "t", "email": "a@b", "invited_by_id": 1},
			wantErr: ErrInvitationRoleRequired},
		{name: "create_missing_invited_by_id", tool: "platform_invitation_create",
			args:    map[string]interface{}{"tenant_id": "t", "email": "a@b", "role": "r"},
			wantErr: ErrInvitationInvitedByIDRequired},

		// get
		{name: "get_missing_id", tool: "platform_invitation_get",
			args: map[string]interface{}{}, wantErr: ErrInvitationIDRequired},

		// get_by_token
		{name: "get_by_token_missing_token", tool: "platform_invitation_get_by_token",
			args: map[string]interface{}{}, wantErr: ErrInvitationTokenRequired},

		// list
		{name: "list_missing_tenant", tool: "platform_invitation_list",
			args: map[string]interface{}{}, wantErr: ErrInvitationTenantIDRequired},

		// revoke
		{name: "revoke_missing_id", tool: "platform_invitation_revoke",
			args: map[string]interface{}{"revoker_id": 1}, wantErr: ErrInvitationIDRequired},
		{name: "revoke_missing_revoker", tool: "platform_invitation_revoke",
			args: map[string]interface{}{"invitation_id": 1}, wantErr: ErrInvitationRevokerIDRequired},

		// accept
		{name: "accept_missing_token", tool: "platform_invitation_accept",
			args: map[string]interface{}{"user_id": 1}, wantErr: ErrInvitationTokenRequired},
		{name: "accept_missing_user", tool: "platform_invitation_accept",
			args: map[string]interface{}{"token": "t"}, wantErr: ErrInvitationUserIDRequired},

		// delete
		{name: "delete_missing_id", tool: "platform_invitation_delete",
			args: map[string]interface{}{}, wantErr: ErrInvitationIDRequired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registry.ExecuteTool(ctx, tc.tool, tc.args)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestToolRegistry_ExecuteTool_Invitation_PropagatesProviderError verifies
// that errors returned from the InvitationProvider are surfaced to the
// caller verbatim.
func TestToolRegistry_ExecuteTool_Invitation_PropagatesProviderError(t *testing.T) {
	sentinel := errors.New("backend boom")
	stub := &invitationStubProvider{err: sentinel}
	svc := &invitationCombinedProvider{
		mockServiceProvider:    newMockServiceProvider(),
		invitationStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	args := map[string]interface{}{
		"tenant_id":     "t",
		"email":         "a@b",
		"role":          "r",
		"invited_by_id": 1,
	}
	_, err := registry.ExecuteTool(ctx, "platform_invitation_create", args)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

// TestToolRegistry_InvitationToolsRegistered verifies all
// platform_invitation_* tool definitions are registered and listable.
func TestToolRegistry_InvitationToolsRegistered(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	expected := []string{
		"platform_invitation_create",
		"platform_invitation_get",
		"platform_invitation_get_by_token",
		"platform_invitation_list",
		"platform_invitation_revoke",
		"platform_invitation_accept",
		"platform_invitation_delete",
	}
	tools := registry.ListTools()
	got := make(map[string]struct{}, len(tools))
	for _, td := range tools {
		got[td.Name] = struct{}{}
	}
	for _, name := range expected {
		if _, ok := got[name]; !ok {
			t.Errorf("missing registered tool: %s", name)
		}
	}
}

// TestDispatchInvitationTool_NotHandled verifies that the dispatcher
// returns handled=false for unknown tool names so the caller can fall
// through to other dispatchers.
func TestDispatchInvitationTool_NotHandled(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	result, handled, err := registry.dispatchInvitationTool(context.Background(), "platform_unknown_tool", nil)
	if handled {
		t.Fatalf("expected handled=false, got true")
	}
	if result != nil {
		t.Errorf("expected nil result, got %v", result)
	}
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// TestInvitationProvider_NilWhenNotImplemented verifies that the
// invitationProvider helper returns nil when the underlying
// ServiceProvider does not satisfy InvitationProvider.
func TestInvitationProvider_NilWhenNotImplemented(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	if p := registry.invitationProvider(); p != nil {
		t.Errorf("expected nil InvitationProvider, got %T", p)
	}
}

// TestInvitationProvider_PresentWhenImplemented verifies the helper
// returns the underlying provider when the ServiceProvider implements
// InvitationProvider.
func TestInvitationProvider_PresentWhenImplemented(t *testing.T) {
	stub := &invitationStubProvider{}
	svc := &invitationCombinedProvider{
		mockServiceProvider:    newMockServiceProvider(),
		invitationStubProvider: stub,
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	if p := registry.invitationProvider(); p == nil {
		t.Fatalf("expected non-nil InvitationProvider")
	}
}
