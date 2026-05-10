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
	"context"
	"time"

	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// =============================================================================
// MCP Invitation bridge
// =============================================================================
//
// MCPServiceProvider implements mcp.InvitationProvider by delegating to the
// same platform.service.InvitationServicer that powers the gRPC
// InvitationServiceServer. This keeps the MCP and gRPC surfaces in lockstep:
// AI/LLM clients calling platform_invitation_create hit the exact same code
// path as a gRPC CreateInvitation RPC.

// ErrInvitationNotConfigured indicates that no invitation servicer is wired
// into the MCPServiceProvider. Callers should treat this the same way the
// gRPC InvitationService treats a nil servicer (FailedPrecondition).
type ErrInvitationNotConfigured struct{}

// Error returns a human-readable description of the error.
func (ErrInvitationNotConfigured) Error() string {
	return "invitation service not configured"
}

// SetInvitationService injects the invitation service after construction.
// The daemon wires the same InvitationServicer that powers the gRPC
// InvitationServiceServer so the MCP and gRPC surfaces stay in lockstep.
func (p *MCPServiceProvider) SetInvitationService(svc platformservice.InvitationServicer) {
	p.invitationService = svc
}

// =============================================================================
// CRUD
// =============================================================================

// CreateInvitation creates a new invitation for a user to join a tenant.
// expiresInSeconds <= 0 lets the platform service apply its default
// expiry (7 days at the time of writing).
func (p *MCPServiceProvider) CreateInvitation(
	ctx context.Context,
	tenantID, email, role string,
	invitedByID uint64,
	expiresInSeconds int64,
) (interface{}, error) {
	if p.invitationService == nil {
		return nil, ErrInvitationNotConfigured{}
	}
	req := &platformservice.CreateInvitationRequest{
		TenantID:    tenantID,
		Email:       email,
		Role:        role,
		InvitedByID: invitedByID,
	}
	if expiresInSeconds > 0 {
		req.ExpiresIn = time.Duration(expiresInSeconds) * time.Second
	}
	inv, err := p.invitationService.Create(ctx, req)
	if err != nil {
		return nil, err
	}
	return invitationJSON(inv), nil
}

// GetInvitation retrieves an invitation by its ID.
func (p *MCPServiceProvider) GetInvitation(ctx context.Context, invitationID uint64) (interface{}, error) {
	if p.invitationService == nil {
		return nil, ErrInvitationNotConfigured{}
	}
	inv, err := p.invitationService.GetByID(ctx, invitationID)
	if err != nil {
		return nil, err
	}
	return invitationJSON(inv), nil
}

// GetInvitationByToken retrieves an invitation by its secure token.
func (p *MCPServiceProvider) GetInvitationByToken(ctx context.Context, token string) (interface{}, error) {
	if p.invitationService == nil {
		return nil, ErrInvitationNotConfigured{}
	}
	inv, err := p.invitationService.GetByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return invitationJSON(inv), nil
}

// ListInvitations lists invitations for a tenant. When pendingOnly is
// true, only invitations in the pending state are returned.
func (p *MCPServiceProvider) ListInvitations(ctx context.Context, tenantID string, pendingOnly bool) (interface{}, error) {
	if p.invitationService == nil {
		return nil, ErrInvitationNotConfigured{}
	}
	var (
		invs []*entities.Invitation
		err  error
	)
	if pendingOnly {
		invs, err = p.invitationService.ListPendingByTenant(ctx, tenantID)
	} else {
		invs, err = p.invitationService.ListByTenant(ctx, tenantID)
	}
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, len(invs))
	for i, inv := range invs {
		out[i] = invitationJSON(inv)
	}
	return map[string]interface{}{
		"tenant_id":    tenantID,
		"pending_only": pendingOnly,
		"total":        len(out),
		"invitations":  out,
	}, nil
}

// RevokeInvitation revokes a pending invitation.
func (p *MCPServiceProvider) RevokeInvitation(ctx context.Context, invitationID, revokerID uint64) (interface{}, error) {
	if p.invitationService == nil {
		return nil, ErrInvitationNotConfigured{}
	}
	if err := p.invitationService.Revoke(ctx, invitationID, revokerID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"invitation_id": invitationID,
		"revoker_id":    revokerID,
		"status":        string(entities.InvitationStatusRevoked),
	}, nil
}

// AcceptInvitation marks an invitation as accepted by the given user.
// On success, the updated invitation is read back so MCP clients see
// the new status and accepted_at timestamp without an additional RPC.
func (p *MCPServiceProvider) AcceptInvitation(ctx context.Context, token string, userID uint64) (interface{}, error) {
	if p.invitationService == nil {
		return nil, ErrInvitationNotConfigured{}
	}
	if err := p.invitationService.Accept(ctx, token, userID); err != nil {
		return nil, err
	}
	inv, err := p.invitationService.GetByToken(ctx, token)
	if err != nil {
		// Accept succeeded but read-back failed — surface a partial
		// success rather than masking the original Accept outcome.
		return map[string]interface{}{
			"token":   token,
			"user_id": userID,
			"status":  string(entities.InvitationStatusAccepted),
		}, nil
	}
	result := invitationJSON(inv)
	result["user_id"] = userID
	return result, nil
}

// DeleteInvitation permanently removes an invitation.
func (p *MCPServiceProvider) DeleteInvitation(ctx context.Context, invitationID uint64) (interface{}, error) {
	if p.invitationService == nil {
		return nil, ErrInvitationNotConfigured{}
	}
	if err := p.invitationService.Delete(ctx, invitationID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"invitation_id": invitationID,
		"deleted":       true,
	}, nil
}

// =============================================================================
// Helpers
// =============================================================================

// invitationJSON renders an *entities.Invitation as a JSON-friendly map.
// Mirrors the proto Invitation message field set so MCP clients see the
// same shape that gRPC clients already know.
func invitationJSON(inv *entities.Invitation) map[string]interface{} {
	if inv == nil {
		return nil
	}
	out := map[string]interface{}{
		"id":            inv.ID,
		"token":         inv.Token,
		"tenant_id":     inv.TenantID,
		"email":         inv.Email,
		"role":          inv.Role,
		"status":        string(inv.Status),
		"invited_by_id": inv.InvitedByID,
		"expires_at":    inv.ExpiresAt.UTC().Format(time.RFC3339),
		"created_at":    inv.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":    inv.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if inv.AcceptedAt != nil {
		out["accepted_at"] = inv.AcceptedAt.UTC().Format(time.RFC3339)
	}
	return out
}
