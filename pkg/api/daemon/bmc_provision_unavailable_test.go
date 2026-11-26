package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestNew_BMCProvisioningStaysUnavailableWithoutInstallCompletion pins
// that a stock daemon does not wire the bare metal orchestrator. The
// orchestrator waits for an install-completion event that nothing in
// production sends, so a wired workflow would hang in installing until
// its timeout and leave the ISO mounted. Until an authenticated
// completion event exists, Provision and ProvisionStatus answer
// Unavailable on gRPC and 503 on REST, even with a device profile store.
func TestNew_BMCProvisioningStaysUnavailableWithoutInstallCompletion(t *testing.T) {
	config := testConfig(filepath.Join(t.TempDir(), "d.sock"))
	config.DeviceProfileService = newRealTemplateServices(t).profiles

	d, err := New(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		if d != nil && d.grpcServer != nil {
			d.grpcServer.Stop()
		}
	})
	require.NotNil(t, d.bmcGRPCService, "the BMC gRPC service is registered")
	require.NotNil(t, d.BMCRestHandler(), "the BMC REST handler is built")

	ctx := context.Background()
	_, err = d.bmcGRPCService.Provision(ctx, &platformv1.BMCProvisionRequest{ProfileId: 1})
	require.Error(t, err)
	require.Equal(t, codes.Unavailable, status.Code(err), "gRPC Provision: %v", err)

	_, err = d.bmcGRPCService.ProvisionStatus(ctx, &platformv1.BMCProvisionStatusRequest{ProfileId: 1})
	require.Error(t, err)
	require.Equal(t, codes.Unavailable, status.Code(err), "gRPC ProvisionStatus: %v", err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/bmc/1/provision", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"profileID": "1"})
	rec := httptest.NewRecorder()
	d.BMCRestHandler().Provision(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "REST Provision: %s", rec.Body.String())
}
