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
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
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
	cfg := tenant.DefaultConfig()
	cfg.EnableDEKIsolation = false
	mgr, err := tenant.NewManager(&tenant.ManagerConfig{
		IAMTenantClient: newMockIAMClientForServer(),
		IAMRoleClient:   newMockIAMClientForServer(),
		Config:          cfg,
	})
	if err != nil {
		panic(err)
	}
	if _, err := mgr.CreateTenant(context.Background(), &tenant.CreateTenantRequest{Name: initialAdminTenantName}); err != nil {
		panic(err)
	}
	s.SetManager(mgr)
	if inviter != nil {
		s.SetInitialAdminInviter(inviter)
	}
	return s
}

// initialAdminTenantName names the one tenant newInitialAdminServer creates.
const initialAdminTenantName = "tenant-a"

// initialAdminTenantID is the stored id of the tenant newInitialAdminServer
// creates: an owner invitation names an existing tenant (#2362).
func initialAdminTenantID(s *TenantGRPCServer) string {
	entity, err := s.manager.GetTenantByName(context.Background(), initialAdminTenantName)
	if err != nil {
		panic(err)
	}
	return entity.ID
}

// TestCreateInitialAdminInvitation_UnknownTenantIsNotFound: an owner
// invitation for a tenant that does not exist answers NotFound and stores
// nothing (#2362).
func TestCreateInitialAdminInvitation_UnknownTenantIsNotFound(t *testing.T) {
	fake := &fakeInitialAdminInviter{}
	s := newInitialAdminServer(fake)
	_, err := s.CreateInitialAdminInvitation(systemAdminCallerContext("42"),
		&platformv1.CreateInitialAdminInvitationRequest{TenantId: "no-such-tenant", Email: "owner@example.com"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown tenant: code = %v (%v), want NotFound", status.Code(err), err)
	}
	if fake.calls != 0 {
		t.Fatalf("inviter calls = %d, want 0", fake.calls)
	}
}

func TestTenantGRPCServer_CreateInitialAdminInvitation_SystemTenantOnly(t *testing.T) {
	fake := &fakeInitialAdminInviter{}
	s := newInitialAdminServer(fake)
	req := &platformv1.CreateInitialAdminInvitationRequest{
		TenantId: initialAdminTenantID(s),
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
	if resp.GetInvitation().GetTenantId() != initialAdminTenantID(s) {
		t.Fatalf("invitation tenant = %q, want %q", resp.GetInvitation().GetTenantId(), initialAdminTenantID(s))
	}
	if fake.calls != 1 || fake.got.TenantID != initialAdminTenantID(s) || fake.got.Email != "owner@example.com" {
		t.Fatalf("inviter saw calls=%d req=%+v", fake.calls, fake.got)
	}
}

func TestTenantGRPCServer_CreateInitialAdminInvitation_RequiresEmail(t *testing.T) {
	fake := &fakeInitialAdminInviter{}
	s := newInitialAdminServer(fake)
	_, err := s.CreateInitialAdminInvitation(tokenCallerContext(initialAdminSystemTenant),
		&platformv1.CreateInitialAdminInvitationRequest{TenantId: initialAdminTenantID(s)})
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
		&platformv1.CreateInitialAdminInvitationRequest{TenantId: initialAdminTenantID(s), Email: "owner@example.com"})
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
		&platformv1.CreateInitialAdminInvitationRequest{TenantId: initialAdminTenantID(s), Email: "owner@example.com"})
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
			&platformv1.CreateInitialAdminInvitationRequest{TenantId: initialAdminTenantID(s), Email: "owner@example.com"})
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
				&platformv1.CreateInitialAdminInvitationRequest{TenantId: initialAdminTenantID(s), Email: "owner@example.com"})
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

// fakeInviterResolver maps a login email to a stored IAM user, as the
// platform user service does.
type fakeInviterResolver struct {
	users map[string]*entities.User
	calls int
}

func (f *fakeInviterResolver) GetByEmail(_ context.Context, email string) (*entities.User, error) {
	f.calls++
	if u, ok := f.users[email]; ok {
		return u, nil
	}
	return nil, platformservice.ErrUserNotFound{Email: email}
}

const initialAdminInviterEmail = "admin@example.com"

func newResolvingInitialAdminServer(inviter initialAdminInviter) (*TenantGRPCServer, *fakeInviterResolver) {
	s := newInitialAdminServer(inviter)
	r := &fakeInviterResolver{users: map[string]*entities.User{
		initialAdminInviterEmail: {ID: 7, Email: initialAdminInviterEmail},
	}}
	s.SetInviterResolver(r)
	return s, r
}

// A real session keeps the login name (email) as the subject and an mTLS
// identity carries the certificate email, so neither is a decimal user id.
// Each resolves to the stored IAM user before the inviter is recorded.
func TestCreateInitialAdminInvitation_EmailSubjectResolvesInviter(t *testing.T) {
	cases := map[string]context.Context{
		"platform token": systemAdminCallerContext(initialAdminInviterEmail),
		"webiam platform token": webiam.SetAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{
			TenantID: initialAdminSystemTenant,
			Subject:  initialAdminInviterEmail,
		}),
		"webiam session": webiam.SetSessionInContext(context.Background(),
			webiam.NewIAMSession(&iamsdk.User{ID: initialAdminInviterEmail, Email: initialAdminInviterEmail, TenantID: initialAdminSystemTenant})),
		"mtls identity": context.WithValue(context.Background(), ContextKeyIdentity, &auth.Identity{
			ID:       initialAdminInviterEmail,
			TenantID: initialAdminSystemTenant,
			Email:    initialAdminInviterEmail,
			Name:     "Admin",
		}),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &fakeInitialAdminInviter{}
			s, _ := newResolvingInitialAdminServer(fake)
			_, err := s.CreateInitialAdminInvitation(ctx,
				&platformv1.CreateInitialAdminInvitationRequest{TenantId: initialAdminTenantID(s), Email: "owner@example.com"})
			if err != nil {
				t.Fatalf("email caller: %v", err)
			}
			if fake.got == nil || fake.got.InvitedByID != 7 {
				t.Fatalf("invited_by = %+v, want 7", fake.got)
			}
		})
	}
}

func TestCreateInitialAdminInvitation_UnknownEmailIsRefused(t *testing.T) {
	fake := &fakeInitialAdminInviter{}
	s, r := newResolvingInitialAdminServer(fake)
	_, err := s.CreateInitialAdminInvitation(systemAdminCallerContext("stranger@example.com"),
		&platformv1.CreateInitialAdminInvitationRequest{TenantId: initialAdminTenantID(s), Email: "owner@example.com"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", err)
	}
	if fake.calls != 0 {
		t.Fatalf("unknown caller reached the inviter %d times", fake.calls)
	}
	if r.calls == 0 {
		t.Fatalf("the resolver was not consulted")
	}
}

// failingInviterResolver answers every lookup with err.
type failingInviterResolver struct {
	err   error
	calls int
}

func (f *failingInviterResolver) GetByEmail(_ context.Context, _ string) (*entities.User, error) {
	f.calls++
	return nil, f.err
}

// An IAM user whose canonical id is not a positive decimal cannot be
// recorded as the inviter: the RPC refuses it FailedPrecondition (#2362).
func TestCreateInitialAdminInvitation_UnusableInviterIDIsFailedPrecondition(t *testing.T) {
	fake := &fakeInitialAdminInviter{}
	s := newInitialAdminServer(fake)
	r := &failingInviterResolver{err: ErrInviterIDNotUsable{ID: "usr-abc"}}
	s.SetInviterResolver(r)
	_, err := s.CreateInitialAdminInvitation(systemAdminCallerContext(initialAdminInviterEmail),
		&platformv1.CreateInitialAdminInvitationRequest{TenantId: initialAdminTenantID(s), Email: "owner@example.com"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", err)
	}
	if fake.calls != 0 {
		t.Fatalf("an unusable inviter id reached the inviter %d times", fake.calls)
	}
	if r.calls == 0 {
		t.Fatalf("the resolver was not consulted")
	}
}

// A numeric subject is already the user id and needs no lookup.
func TestCreateInitialAdminInvitation_NumericSubjectSkipsResolver(t *testing.T) {
	fake := &fakeInitialAdminInviter{}
	s, r := newResolvingInitialAdminServer(fake)
	if _, err := s.CreateInitialAdminInvitation(systemAdminCallerContext("42"),
		&platformv1.CreateInitialAdminInvitationRequest{TenantId: initialAdminTenantID(s), Email: "owner@example.com"}); err != nil {
		t.Fatalf("numeric caller: %v", err)
	}
	if fake.got.InvitedByID != 42 || r.calls != 0 {
		t.Fatalf("invited_by = %d, resolver calls = %d; want 42, 0", fake.got.InvitedByID, r.calls)
	}
}
