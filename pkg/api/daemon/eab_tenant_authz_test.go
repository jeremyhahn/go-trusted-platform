package daemon

import (
	"context"
	"testing"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newEABTwoTenantFixture seeds one credential for tenant-a and one for
// tenant-b, with "system" as the platform tenant.
func newEABTwoTenantFixture(t *testing.T) (*EABGRPCService, *fakeEABService, *eab.Credential, *eab.Credential) {
	t.Helper()
	service, svc, _ := newEABGRPCFixture()
	service.SetSystemTenant("system")
	credA, err := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("seed tenant-a: %v", err)
	}
	credB, err := svc.Generate(context.Background(), eab.GenerateParams{ProfileID: 1, TenantID: "tenant-b"})
	if err != nil {
		t.Fatalf("seed tenant-b: %v", err)
	}
	return service, svc, credA, credB
}

func requireEABCode(t *testing.T, what string, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("%s: code = %v (err %v), want %v", what, got, err, want)
	}
}

func listedEABTenants(t *testing.T, service *EABGRPCService, ctx context.Context) map[string]int {
	t.Helper()
	resp, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{})
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	tenants := map[string]int{}
	for _, cred := range resp.GetCredentials() {
		tenants[cred.GetTenantId()]++
	}
	return tenants
}

func requireEABUntouched(t *testing.T, svc *fakeEABService, id uint64) {
	t.Helper()
	cred, ok := svc.byID[id]
	if !ok {
		t.Fatalf("credential %d was deleted", id)
	}
	if cred.Status != eab.StatusActive {
		t.Fatalf("credential %d status = %v, want active", id, cred.Status)
	}
}

func TestEABGRPCService_TenantBoundCallerSeesOnlyItsTenant(t *testing.T) {
	service, svc, credA, credB := newEABTwoTenantFixture(t)
	ctx := tokenCallerContext("tenant-a")

	tenants := listedEABTenants(t, service, ctx)
	if tenants["tenant-a"] != 1 || len(tenants) != 1 {
		t.Fatalf("unfiltered list = %v, want only tenant-a", tenants)
	}
	_, err := service.ListCredentials(ctx, &platformv1.ListEABCredentialsRequest{TenantId: "tenant-b"})
	requireEABCode(t, "list tenant-b", err, codes.PermissionDenied)

	// Another tenant's credential: every read, secret delivery and mutation is refused.
	_, err = service.GetCredential(ctx, &platformv1.GetEABCredentialRequest{CredentialId: credB.ID})
	requireEABCode(t, "get tenant-b", err, codes.PermissionDenied)
	_, err = service.GetCredentialByKeyID(ctx, &platformv1.GetEABCredentialByKeyIDRequest{KeyId: credB.KeyID})
	requireEABCode(t, "get by key tenant-b", err, codes.PermissionDenied)
	_, err = service.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{CredentialId: credB.ID})
	requireEABCode(t, "qr tenant-b", err, codes.PermissionDenied)
	_, err = service.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{CredentialId: credB.ID})
	requireEABCode(t, "url tenant-b", err, codes.PermissionDenied)
	_, err = service.RevokeCredential(ctx, &platformv1.RevokeEABCredentialRequest{CredentialId: credB.ID})
	requireEABCode(t, "revoke tenant-b", err, codes.PermissionDenied)
	_, err = service.DeleteCredential(ctx, &platformv1.DeleteEABCredentialRequest{CredentialId: credB.ID})
	requireEABCode(t, "delete tenant-b", err, codes.PermissionDenied)
	_, err = service.MarkCredentialUsed(ctx, &platformv1.MarkEABCredentialUsedRequest{CredentialId: credB.ID})
	requireEABCode(t, "mark used tenant-b", err, codes.PermissionDenied)
	requireEABUntouched(t, svc, credB.ID)

	// The caller's own credential: the same calls succeed.
	if _, err := service.GetCredential(ctx, &platformv1.GetEABCredentialRequest{CredentialId: credA.ID}); err != nil {
		t.Fatalf("get tenant-a: %v", err)
	}
	if _, err := service.GetCredentialByKeyID(ctx, &platformv1.GetEABCredentialByKeyIDRequest{KeyId: credA.KeyID}); err != nil {
		t.Fatalf("get by key tenant-a: %v", err)
	}
	if _, err := service.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{CredentialId: credA.ID}); err != nil {
		t.Fatalf("qr tenant-a: %v", err)
	}
	if _, err := service.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{CredentialId: credA.ID}); err != nil {
		t.Fatalf("url tenant-a: %v", err)
	}
	if _, err := service.MarkCredentialUsed(ctx, &platformv1.MarkEABCredentialUsedRequest{CredentialId: credA.ID}); err != nil {
		t.Fatalf("mark used tenant-a: %v", err)
	}
	if _, err := service.RevokeCredential(ctx, &platformv1.RevokeEABCredentialRequest{CredentialId: credA.ID}); err != nil {
		t.Fatalf("revoke tenant-a: %v", err)
	}
	if _, err := service.DeleteCredential(ctx, &platformv1.DeleteEABCredentialRequest{CredentialId: credA.ID}); err != nil {
		t.Fatalf("delete tenant-a: %v", err)
	}

	// Create: another tenant is refused; no tenant means the caller's own.
	_, err = service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: "tenant-b"})
	requireEABCode(t, "create tenant-b", err, codes.PermissionDenied)
	if _, err := service.CreateCredential(ctx, &platformv1.CreateEABCredentialRequest{ProfileId: 1}); err != nil {
		t.Fatalf("create own tenant: %v", err)
	}
	if svc.lastGenerate.TenantID != "tenant-a" {
		t.Fatalf("created for tenant %q, want tenant-a", svc.lastGenerate.TenantID)
	}

	// Cleanup: another tenant is refused; no tenant never runs the store-wide cleanup.
	_, err = service.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{TenantId: "tenant-b"})
	requireEABCode(t, "cleanup tenant-b", err, codes.PermissionDenied)
	svc.cleanupCount = 99
	resp, err := service.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{})
	if err != nil {
		t.Fatalf("cleanup own tenant: %v", err)
	}
	if resp.GetDeletedCount() == 99 {
		t.Fatal("a tenant-bound cleanup ran the store-wide cleanup")
	}
	requireEABUntouched(t, svc, credB.ID)
}

func TestEABGRPCService_RESTSessionTenantIsEnforced(t *testing.T) {
	service, svc, _, credB := newEABTwoTenantFixture(t)
	ctx := iammw.SetSessionInContext(context.Background(),
		iammw.NewIAMSession(&sdkiam.User{TenantID: "tenant-a"}))

	tenants := listedEABTenants(t, service, ctx)
	if tenants["tenant-a"] != 1 || len(tenants) != 1 {
		t.Fatalf("unfiltered list = %v, want only tenant-a", tenants)
	}
	_, err := service.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{CredentialId: credB.ID})
	requireEABCode(t, "url tenant-b", err, codes.PermissionDenied)
	_, err = service.DeleteCredential(ctx, &platformv1.DeleteEABCredentialRequest{CredentialId: credB.ID})
	requireEABCode(t, "delete tenant-b", err, codes.PermissionDenied)
	requireEABUntouched(t, svc, credB.ID)
}

func TestEABGRPCService_SystemTenantAndOperatorSeeEveryTenant(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"system tenant": tokenCallerContext("system"),
		"operator":      context.Background(),
	} {
		t.Run(name, func(t *testing.T) {
			service, _, _, credB := newEABTwoTenantFixture(t)
			tenants := listedEABTenants(t, service, ctx)
			if tenants["tenant-a"] != 1 || tenants["tenant-b"] != 1 {
				t.Fatalf("unfiltered list = %v, want both tenants", tenants)
			}
			if _, err := service.GetCredential(ctx, &platformv1.GetEABCredentialRequest{CredentialId: credB.ID}); err != nil {
				t.Fatalf("get tenant-b: %v", err)
			}
		})
	}
}

func TestEABCallerTenantScope(t *testing.T) {
	cases := []struct {
		name      string
		system    string
		caller    string
		bound     bool
		requested string
		want      string
		refused   bool
	}{
		{name: "unbound keeps the request", system: "system", requested: "tenant-b", want: "tenant-b"},
		{name: "unbound with no request", system: "system", want: ""},
		{name: "bound empty caller refused", system: "system", bound: true, requested: "tenant-a", refused: true},
		{name: "bound empty caller no request refused", system: "system", bound: true, refused: true},
		{name: "empty system tenant and empty caller refused", bound: true, refused: true},
		{name: "system tenant keeps the request", system: "system", caller: "system", bound: true, requested: "tenant-b", want: "tenant-b"},
		{name: "system tenant with no request", system: "system", caller: "system", bound: true, want: ""},
		{name: "empty system tenant makes no caller system", caller: "tenant-a", bound: true, requested: "tenant-b", refused: true},
		{name: "tenant with no request gets its own", system: "system", caller: "tenant-a", bound: true, want: "tenant-a"},
		{name: "tenant asking for its own", system: "system", caller: "tenant-a", bound: true, requested: "tenant-a", want: "tenant-a"},
		{name: "tenant asking for another refused", system: "system", caller: "tenant-a", bound: true, requested: "tenant-b", refused: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := eabTenantScope(tc.system, tc.caller, tc.bound, tc.requested)
			if tc.refused {
				var forbidden ErrIAMTenantForbidden
				if !errorAsIAMTenantForbidden(err, &forbidden) {
					t.Fatalf("err = %v, want ErrIAMTenantForbidden", err)
				}
				if forbidden.Requested != tc.requested {
					t.Fatalf("Requested = %q, want %q", forbidden.Requested, tc.requested)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("scope = %q, want %q", got, tc.want)
			}
		})
	}
}

func errorAsIAMTenantForbidden(err error, target *ErrIAMTenantForbidden) bool {
	forbidden, ok := err.(ErrIAMTenantForbidden)
	if ok {
		*target = forbidden
	}
	return ok
}
