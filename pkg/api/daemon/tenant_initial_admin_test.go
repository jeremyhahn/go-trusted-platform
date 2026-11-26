package daemon

import (
	"context"
	"testing"
	"time"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	webiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
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

// systemAdminCallerContext is a system-tenant platform-token caller whose
// token subject is the given user id.
func systemAdminCallerContext(subject string) context.Context {
	return grpcapi.ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{
		TenantID: initialAdminSystemTenant,
		Subject:  subject,
	})
}

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

	resp, err := s.CreateInitialAdminInvitation(systemAdminCallerContext("42"), req)
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

// The invitation service refuses an empty role and a zero inviter, so the
// handler must supply the tenant owner role and the caller's user id.
func TestCreateInitialAdminInvitation_SendsOwnerRoleAndInviter(t *testing.T) {
	fake := &fakeInitialAdminInviter{}
	s := newInitialAdminServer(fake)
	_, err := s.CreateInitialAdminInvitation(systemAdminCallerContext("42"),
		&platformv1.CreateInitialAdminInvitationRequest{TenantId: "tenant-a", Email: "owner@example.com"})
	if err != nil {
		t.Fatalf("system tenant: %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("inviter calls = %d, want 1", fake.calls)
	}
	if fake.got.Role != platformservice.DefaultTenantOwnerRole {
		t.Fatalf("role = %q, want %q", fake.got.Role, platformservice.DefaultTenantOwnerRole)
	}
	if fake.got.InvitedByID != 42 {
		t.Fatalf("invited_by = %d, want 42", fake.got.InvitedByID)
	}
}

func TestCreateInitialAdminInvitation_NoNumericCallerIDIsRefused(t *testing.T) {
	for _, subject := range []string{"", "alice", "0"} {
		fake := &fakeInitialAdminInviter{}
		s := newInitialAdminServer(fake)
		_, err := s.CreateInitialAdminInvitation(systemAdminCallerContext(subject),
			&platformv1.CreateInitialAdminInvitationRequest{TenantId: "tenant-a", Email: "owner@example.com"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("subject %q: got %v, want FailedPrecondition", subject, err)
		}
		if fake.calls != 0 {
			t.Fatalf("subject %q reached the inviter %d times", subject, fake.calls)
		}
	}
}

// TestCreateInitialAdminInvitation_RESTIdentityRecordsInviter pins that the
// webservice REST identity (a verified platform token or an IAM session)
// reaches callerUserID, so a system-tenant admin calling over REST is
// recorded as the inviter rather than refused with FailedPrecondition.
func TestCreateInitialAdminInvitation_RESTIdentityRecordsInviter(t *testing.T) {
	cases := map[string]context.Context{
		"platform token": webiam.SetAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{
			TenantID: initialAdminSystemTenant,
			Subject:  "42",
		}),
		"iam session": webiam.SetSessionInContext(context.Background(),
			webiam.NewIAMSession(&iamsdk.User{ID: "42", TenantID: initialAdminSystemTenant})),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &fakeInitialAdminInviter{}
			s := newInitialAdminServer(fake)
			_, err := s.CreateInitialAdminInvitation(ctx,
				&platformv1.CreateInitialAdminInvitationRequest{TenantId: "tenant-a", Email: "owner@example.com"})
			if status.Code(err) == codes.FailedPrecondition {
				t.Fatalf("REST caller refused as having no user id: %v", err)
			}
			if err != nil {
				t.Fatalf("REST caller: %v", err)
			}
			if fake.got.InvitedByID != 42 {
				t.Fatalf("invited_by = %d, want 42", fake.got.InvitedByID)
			}
		})
	}
}
