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
	"errors"
	"testing"
	"time"

	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// =============================================================================
// Fake InvitationServicer
// =============================================================================

// fakeInvitationServicer is a fully in-memory test double that satisfies
// platformservice.InvitationServicer. It records the last call so tests
// can assert delegation.
type fakeInvitationServicer struct {
	createCalls  int
	createReq    *platformservice.CreateInvitationRequest
	createResult *entities.Invitation
	createErr    error

	getByIDCalls  int
	getByIDID     uint64
	getByIDResult *entities.Invitation
	getByIDErr    error

	getByTokenCalls  int
	getByTokenToken  string
	getByTokenResult *entities.Invitation
	getByTokenErr    error

	listCalls   int
	listTenant  string
	listResult  []*entities.Invitation
	listErr     error
	listPending bool

	revokeCalls    int
	revokeID       uint64
	revokeRevoker  uint64
	revokeReturned error

	acceptCalls    int
	acceptToken    string
	acceptUser     uint64
	acceptReturned error

	deleteCalls    int
	deleteID       uint64
	deleteReturned error

	cleanupCalls    int
	cleanupResult   int
	cleanupReturned error
}

func (f *fakeInvitationServicer) Create(_ context.Context, req *platformservice.CreateInvitationRequest) (*entities.Invitation, error) {
	f.createCalls++
	f.createReq = req
	return f.createResult, f.createErr
}

func (f *fakeInvitationServicer) GetByID(_ context.Context, id uint64) (*entities.Invitation, error) {
	f.getByIDCalls++
	f.getByIDID = id
	return f.getByIDResult, f.getByIDErr
}

func (f *fakeInvitationServicer) GetByToken(_ context.Context, token string) (*entities.Invitation, error) {
	f.getByTokenCalls++
	f.getByTokenToken = token
	return f.getByTokenResult, f.getByTokenErr
}

func (f *fakeInvitationServicer) Accept(_ context.Context, token string, userID uint64) error {
	f.acceptCalls++
	f.acceptToken = token
	f.acceptUser = userID
	return f.acceptReturned
}

func (f *fakeInvitationServicer) Revoke(_ context.Context, id, revokerID uint64) error {
	f.revokeCalls++
	f.revokeID = id
	f.revokeRevoker = revokerID
	return f.revokeReturned
}

func (f *fakeInvitationServicer) ListByTenant(_ context.Context, tenantID string) ([]*entities.Invitation, error) {
	f.listCalls++
	f.listTenant = tenantID
	f.listPending = false
	return f.listResult, f.listErr
}

func (f *fakeInvitationServicer) ListPendingByTenant(_ context.Context, tenantID string) ([]*entities.Invitation, error) {
	f.listCalls++
	f.listTenant = tenantID
	f.listPending = true
	return f.listResult, f.listErr
}

func (f *fakeInvitationServicer) CleanupExpired(_ context.Context) (int, error) {
	f.cleanupCalls++
	return f.cleanupResult, f.cleanupReturned
}

func (f *fakeInvitationServicer) Delete(_ context.Context, id uint64) error {
	f.deleteCalls++
	f.deleteID = id
	return f.deleteReturned
}

// Compile-time assertion.
var _ platformservice.InvitationServicer = (*fakeInvitationServicer)(nil)

// =============================================================================
// Helpers
// =============================================================================

func newTestInvitation() *entities.Invitation {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return &entities.Invitation{
		ID:          42,
		Token:       "tok-1",
		TenantID:    "tenant-1",
		Email:       "alice@example.com",
		Role:        "member",
		Status:      entities.InvitationStatusPending,
		InvitedByID: 99,
		ExpiresAt:   now.Add(7 * 24 * time.Hour),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func newProviderWithInvitation(svc platformservice.InvitationServicer) *MCPServiceProvider {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	p.SetInvitationService(svc)
	return p
}

// =============================================================================
// Not configured
// =============================================================================

// TestMCPProvider_Invitation_NotConfigured verifies that every invitation
// method returns ErrInvitationNotConfigured when no servicer is wired.
func TestMCPProvider_Invitation_NotConfigured(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	ctx := context.Background()

	cases := []struct {
		name string
		call func() (interface{}, error)
	}{
		{"Create", func() (interface{}, error) {
			return p.CreateInvitation(ctx, "t", "a@b", "r", 1, 0)
		}},
		{"Get", func() (interface{}, error) {
			return p.GetInvitation(ctx, 1)
		}},
		{"GetByToken", func() (interface{}, error) {
			return p.GetInvitationByToken(ctx, "tok")
		}},
		{"List", func() (interface{}, error) {
			return p.ListInvitations(ctx, "t", false)
		}},
		{"Revoke", func() (interface{}, error) {
			return p.RevokeInvitation(ctx, 1, 2)
		}},
		{"Accept", func() (interface{}, error) {
			return p.AcceptInvitation(ctx, "tok", 1)
		}},
		{"Delete", func() (interface{}, error) {
			return p.DeleteInvitation(ctx, 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.call()
			if result != nil {
				t.Errorf("expected nil result, got %v", result)
			}
			var notConfigured ErrInvitationNotConfigured
			if !errors.As(err, &notConfigured) {
				t.Errorf("expected ErrInvitationNotConfigured, got %v", err)
			}
			if err.Error() != "invitation service not configured" {
				t.Errorf("unexpected error string: %q", err.Error())
			}
		})
	}
}

// =============================================================================
// Create
// =============================================================================

func TestMCPProvider_CreateInvitation_DelegatesAndShapes(t *testing.T) {
	inv := newTestInvitation()
	fake := &fakeInvitationServicer{createResult: inv}
	p := newProviderWithInvitation(fake)

	got, err := p.CreateInvitation(context.Background(), "tenant-1", "alice@example.com", "member", 99, 3600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", fake.createCalls)
	}
	if fake.createReq == nil {
		t.Fatalf("expected create request to be captured")
	}
	if fake.createReq.TenantID != "tenant-1" {
		t.Errorf("tenant_id = %q", fake.createReq.TenantID)
	}
	if fake.createReq.Email != "alice@example.com" {
		t.Errorf("email = %q", fake.createReq.Email)
	}
	if fake.createReq.Role != "member" {
		t.Errorf("role = %q", fake.createReq.Role)
	}
	if fake.createReq.InvitedByID != 99 {
		t.Errorf("invited_by_id = %d", fake.createReq.InvitedByID)
	}
	if fake.createReq.ExpiresIn != time.Hour {
		t.Errorf("expires_in = %v, want 1h", fake.createReq.ExpiresIn)
	}

	m, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", got)
	}
	if m["id"].(uint64) != 42 {
		t.Errorf("id = %v", m["id"])
	}
	if m["token"].(string) != "tok-1" {
		t.Errorf("token = %v", m["token"])
	}
	if m["status"].(string) != "pending" {
		t.Errorf("status = %v", m["status"])
	}
}

func TestMCPProvider_CreateInvitation_DefaultExpiry(t *testing.T) {
	fake := &fakeInvitationServicer{createResult: newTestInvitation()}
	p := newProviderWithInvitation(fake)

	_, err := p.CreateInvitation(context.Background(), "t", "a@b", "r", 1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.createReq.ExpiresIn != 0 {
		t.Errorf("expected zero ExpiresIn so platform applies default, got %v", fake.createReq.ExpiresIn)
	}
}

func TestMCPProvider_CreateInvitation_ServicerError(t *testing.T) {
	sentinel := errors.New("backend down")
	fake := &fakeInvitationServicer{createErr: sentinel}
	p := newProviderWithInvitation(fake)

	_, err := p.CreateInvitation(context.Background(), "t", "a@b", "r", 1, 0)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

// =============================================================================
// Get / GetByToken
// =============================================================================

func TestMCPProvider_GetInvitation_Delegates(t *testing.T) {
	fake := &fakeInvitationServicer{getByIDResult: newTestInvitation()}
	p := newProviderWithInvitation(fake)

	got, err := p.GetInvitation(context.Background(), 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.getByIDID != 42 {
		t.Errorf("id = %d", fake.getByIDID)
	}
	if got.(map[string]interface{})["email"].(string) != "alice@example.com" {
		t.Errorf("email mismatch")
	}
}

func TestMCPProvider_GetInvitation_Error(t *testing.T) {
	sentinel := errors.New("not found")
	fake := &fakeInvitationServicer{getByIDErr: sentinel}
	p := newProviderWithInvitation(fake)

	_, err := p.GetInvitation(context.Background(), 42)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

func TestMCPProvider_GetInvitationByToken_Delegates(t *testing.T) {
	fake := &fakeInvitationServicer{getByTokenResult: newTestInvitation()}
	p := newProviderWithInvitation(fake)

	got, err := p.GetInvitationByToken(context.Background(), "tok-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.getByTokenToken != "tok-1" {
		t.Errorf("token = %q", fake.getByTokenToken)
	}
	if got.(map[string]interface{})["token"].(string) != "tok-1" {
		t.Errorf("token mismatch in response")
	}
}

func TestMCPProvider_GetInvitationByToken_Error(t *testing.T) {
	sentinel := errors.New("nope")
	fake := &fakeInvitationServicer{getByTokenErr: sentinel}
	p := newProviderWithInvitation(fake)

	_, err := p.GetInvitationByToken(context.Background(), "tok")
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

// =============================================================================
// List
// =============================================================================

func TestMCPProvider_ListInvitations_AllAndPending(t *testing.T) {
	inv := newTestInvitation()
	fake := &fakeInvitationServicer{listResult: []*entities.Invitation{inv}}
	p := newProviderWithInvitation(fake)

	got, err := p.ListInvitations(context.Background(), "tenant-1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.listPending {
		t.Errorf("expected listAll, got listPending")
	}
	m := got.(map[string]interface{})
	if m["total"].(int) != 1 {
		t.Errorf("total = %v", m["total"])
	}
	if m["pending_only"].(bool) != false {
		t.Errorf("pending_only should be false")
	}

	got, err = p.ListInvitations(context.Background(), "tenant-1", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fake.listPending {
		t.Errorf("expected listPending, got listAll")
	}
	m = got.(map[string]interface{})
	if m["pending_only"].(bool) != true {
		t.Errorf("pending_only should be true")
	}
}

func TestMCPProvider_ListInvitations_Error(t *testing.T) {
	sentinel := errors.New("db down")
	fake := &fakeInvitationServicer{listErr: sentinel}
	p := newProviderWithInvitation(fake)

	_, err := p.ListInvitations(context.Background(), "t", false)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

// =============================================================================
// Revoke / Delete
// =============================================================================

func TestMCPProvider_RevokeInvitation_Delegates(t *testing.T) {
	fake := &fakeInvitationServicer{}
	p := newProviderWithInvitation(fake)

	got, err := p.RevokeInvitation(context.Background(), 42, 99)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.revokeID != 42 || fake.revokeRevoker != 99 {
		t.Errorf("ids mismatch: %d %d", fake.revokeID, fake.revokeRevoker)
	}
	m := got.(map[string]interface{})
	if m["status"].(string) != "revoked" {
		t.Errorf("status = %v", m["status"])
	}
}

func TestMCPProvider_RevokeInvitation_Error(t *testing.T) {
	sentinel := errors.New("nope")
	fake := &fakeInvitationServicer{revokeReturned: sentinel}
	p := newProviderWithInvitation(fake)

	_, err := p.RevokeInvitation(context.Background(), 1, 2)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

func TestMCPProvider_DeleteInvitation_Delegates(t *testing.T) {
	fake := &fakeInvitationServicer{}
	p := newProviderWithInvitation(fake)

	got, err := p.DeleteInvitation(context.Background(), 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.deleteID != 42 {
		t.Errorf("id = %d", fake.deleteID)
	}
	m := got.(map[string]interface{})
	if m["deleted"].(bool) != true {
		t.Errorf("deleted should be true")
	}
}

func TestMCPProvider_DeleteInvitation_Error(t *testing.T) {
	sentinel := errors.New("nope")
	fake := &fakeInvitationServicer{deleteReturned: sentinel}
	p := newProviderWithInvitation(fake)

	_, err := p.DeleteInvitation(context.Background(), 1)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

// =============================================================================
// Accept
// =============================================================================

func TestMCPProvider_AcceptInvitation_Delegates(t *testing.T) {
	inv := newTestInvitation()
	now := time.Now().UTC()
	inv.Status = entities.InvitationStatusAccepted
	inv.AcceptedAt = &now
	fake := &fakeInvitationServicer{getByTokenResult: inv}
	p := newProviderWithInvitation(fake)

	got, err := p.AcceptInvitation(context.Background(), "tok-1", 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.acceptCalls != 1 || fake.acceptToken != "tok-1" || fake.acceptUser != 7 {
		t.Errorf("delegation mismatch: %d %q %d", fake.acceptCalls, fake.acceptToken, fake.acceptUser)
	}
	m := got.(map[string]interface{})
	if m["status"].(string) != "accepted" {
		t.Errorf("status = %v", m["status"])
	}
	if m["user_id"].(uint64) != 7 {
		t.Errorf("user_id = %v", m["user_id"])
	}
	if _, ok := m["accepted_at"]; !ok {
		t.Errorf("accepted_at field expected on response")
	}
}

func TestMCPProvider_AcceptInvitation_AcceptError(t *testing.T) {
	sentinel := errors.New("expired")
	fake := &fakeInvitationServicer{acceptReturned: sentinel}
	p := newProviderWithInvitation(fake)

	_, err := p.AcceptInvitation(context.Background(), "tok", 1)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

// TestMCPProvider_AcceptInvitation_ReadbackFailure verifies that when
// Accept succeeds but the read-back GetByToken fails, the response
// still reports success rather than masking the original outcome.
func TestMCPProvider_AcceptInvitation_ReadbackFailure(t *testing.T) {
	fake := &fakeInvitationServicer{getByTokenErr: errors.New("disk hiccup")}
	p := newProviderWithInvitation(fake)

	got, err := p.AcceptInvitation(context.Background(), "tok-1", 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := got.(map[string]interface{})
	if m["status"].(string) != "accepted" {
		t.Errorf("status = %v", m["status"])
	}
	if m["token"].(string) != "tok-1" {
		t.Errorf("token = %v", m["token"])
	}
	if m["user_id"].(uint64) != 7 {
		t.Errorf("user_id = %v", m["user_id"])
	}
}

// =============================================================================
// Helpers
// =============================================================================

// TestInvitationJSON_Nil verifies the rendering helper returns nil on
// nil input rather than a partial map.
func TestInvitationJSON_Nil(t *testing.T) {
	if invitationJSON(nil) != nil {
		t.Errorf("expected nil for nil input")
	}
}

// TestInvitationJSON_PendingNoAcceptedAt verifies the optional
// accepted_at field is omitted for invitations that have not been
// accepted yet.
func TestInvitationJSON_PendingNoAcceptedAt(t *testing.T) {
	inv := newTestInvitation()
	m := invitationJSON(inv)
	if _, ok := m["accepted_at"]; ok {
		t.Errorf("accepted_at should be omitted for pending invitations")
	}
	if m["status"].(string) != "pending" {
		t.Errorf("status = %v", m["status"])
	}
}

// TestInvitationJSON_AcceptedHasTimestamp verifies accepted invitations
// surface the accepted_at timestamp in RFC3339 form.
func TestInvitationJSON_AcceptedHasTimestamp(t *testing.T) {
	inv := newTestInvitation()
	t0 := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	inv.Status = entities.InvitationStatusAccepted
	inv.AcceptedAt = &t0
	m := invitationJSON(inv)
	got, ok := m["accepted_at"].(string)
	if !ok {
		t.Fatalf("accepted_at missing or wrong type: %T", m["accepted_at"])
	}
	if got != "2026-04-01T12:00:00Z" {
		t.Errorf("accepted_at = %q", got)
	}
}

// TestSetInvitationService verifies the setter swaps the underlying
// servicer at runtime.
func TestSetInvitationService(t *testing.T) {
	first := &fakeInvitationServicer{}
	second := &fakeInvitationServicer{}
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{InvitationService: first})

	if _, err := p.GetInvitation(context.Background(), 1); err != nil {
		t.Fatalf("first call err: %v", err)
	}
	if first.getByIDCalls != 1 {
		t.Fatalf("expected first to be called once")
	}
	p.SetInvitationService(second)
	if _, err := p.GetInvitation(context.Background(), 2); err != nil {
		t.Fatalf("second call err: %v", err)
	}
	if second.getByIDCalls != 1 {
		t.Errorf("expected second to be called after SetInvitationService")
	}
	if first.getByIDCalls != 1 {
		t.Errorf("first should not be called after override")
	}
}
