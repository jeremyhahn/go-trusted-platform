package daemon

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A QUIC local JWT on the legacy validator path stays bound to its tenant:
// its own tenant is allowed, another tenant is refused.
func TestCallerTenant_QUICLegacyPrincipalBound(t *testing.T) {
	ctx := quic.ContextWithLegacyPrincipal(context.Background(), &platformtoken.AuthorizedContext{TenantID: "tenant-a"})

	tenant, bound := callerTenant(ctx)
	if !bound || tenant != "tenant-a" {
		t.Fatalf("callerTenant = %q, %v; want tenant-a, true", tenant, bound)
	}
	if err := authorizeIAMTenant(ctx, nil, "tenant-a"); err != nil {
		t.Fatalf("own tenant must be allowed: %v", err)
	}
	err := authorizeIAMTenant(ctx, nil, "tenant-b")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another tenant must be PermissionDenied, got %v", err)
	}
}
