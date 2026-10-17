package helpers

import (
	"context"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EnsureIAMTenant creates the IAM tenant tenantID through client, which must
// act as the unbound operator, and deletes it when the test ends. A tenant
// that already exists is left in place and not deleted.
func EnsureIAMTenant(t *testing.T, ctx context.Context, client platformv1.PlatformIAMServiceClient, tenantID string) {
	t.Helper()

	_, err := client.CreateTenant(ctx, &platformv1.CreateIAMTenantRequest{Id: tenantID, Name: tenantID})
	if status.Code(err) == codes.AlreadyExists {
		return
	}
	if err != nil {
		t.Fatalf("the unbound operator creates IAM tenant %q: %v", tenantID, err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := client.DeleteTenant(cleanupCtx, &platformv1.DeleteIAMTenantRequest{TenantId: tenantID}); err != nil {
			t.Errorf("delete IAM tenant %q: %v", tenantID, err)
		}
	})
}
