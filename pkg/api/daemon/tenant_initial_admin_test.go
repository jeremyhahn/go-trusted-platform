package daemon

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeInitialAdminInviter records the request the tenant gRPC server hands
// to the owner-minting path.
type fakeInitialAdminInviter struct {
	calls int
	got   *platformservice.CreateInvitationRequest
}

func (f *fakeInitialAdminInviter) CreateInitialAdmin(
	_ context.Context,
	req *platformservice.CreateInvitationRequest,
) (*entities.Invitation, error) {
	f.calls++
	f.got = req
	now := time.Now()
	return &entities.Invitation{
		ID:        1,
		Token:     "token-1",
		TenantID:  req.TenantID,
		Email:     req.Email,
		Role:      "owner",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// The daemon hands the registry's invitation service to the tenant server
// by a type assertion; this keeps the concrete service on the capability.
var _ initialAdminInviter = (*platformservice.InvitationService)(nil)

const initialAdminSystemTenant = "system"

func newInitialAdminServer(inviter initialAdminInviter) *TenantGRPCServer {
	s := NewTenantGRPCServer()
	s.SetSystemTenant(initialAdminSystemTenant)
	if inviter != nil {
		s.SetInitialAdminInviter(inviter)
	}
	return s
}

func TestTenantGRPCServer_CreateInitialAdminInvitation_SystemTenantOnly(t *testing.T) {
	fake := &fakeInitialAdminInviter{}
	s := newInitialAdminServer(fake)
	req := &platformv1.CreateInitialAdminInvitationRequest{
		TenantId: "tenant-a",
		Email:    "owner@example.com",
	}

	_, err := s.CreateInitialAdminInvitation(tokenCallerContext("tenant-a"), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("own-tenant caller: got %v, want PermissionDenied", err)
	}
	if fake.calls != 0 {
		t.Fatalf("own-tenant caller reached the inviter %d times", fake.calls)
	}

	resp, err := s.CreateInitialAdminInvitation(tokenCallerContext(initialAdminSystemTenant), req)
	if err != nil {
		t.Fatalf("system tenant: %v", err)
	}
	if resp.GetInvitation().GetTenantId() != "tenant-a" {
		t.Fatalf("invitation tenant = %q, want tenant-a", resp.GetInvitation().GetTenantId())
	}
	if fake.calls != 1 || fake.got.TenantID != "tenant-a" || fake.got.Email != "owner@example.com" {
		t.Fatalf("inviter saw calls=%d req=%+v", fake.calls, fake.got)
	}
}

func TestTenantGRPCServer_CreateInitialAdminInvitation_RequiresEmail(t *testing.T) {
	fake := &fakeInitialAdminInviter{}
	s := newInitialAdminServer(fake)
	_, err := s.CreateInitialAdminInvitation(tokenCallerContext(initialAdminSystemTenant),
		&platformv1.CreateInitialAdminInvitationRequest{TenantId: "tenant-a"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v, want InvalidArgument", err)
	}
	if fake.calls != 0 {
		t.Fatalf("inviter called without an email")
	}
}

func TestTenantGRPCServer_CreateInitialAdminInvitation_NoInviter(t *testing.T) {
	s := newInitialAdminServer(nil)
	_, err := s.CreateInitialAdminInvitation(tokenCallerContext(initialAdminSystemTenant),
		&platformv1.CreateInitialAdminInvitationRequest{TenantId: "tenant-a", Email: "owner@example.com"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", err)
	}
}
