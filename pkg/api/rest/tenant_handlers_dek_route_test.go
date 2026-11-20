package rest

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTenantRoutes_DEKStatusPaths checks that the daemon tenant router
// answers the SDK's GET /api/v1/tenants/{id}/dek as well as the older
// /dek/status, both with the DEK status handler behind the same guard.
func TestTenantRoutes_DEKStatusPaths(t *testing.T) {
	status := serveTenant(t, tenantAuthzRouter(t), tenantAToken, http.MethodGet,
		fmt.Sprintf("/api/v1/tenants/%s/dek/status", tenantAID), nil)
	require.NotContains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, status.Code, "dek/status: %s", status.Body.String())

	dek := serveTenant(t, tenantAuthzRouter(t), tenantAToken, http.MethodGet,
		fmt.Sprintf("/api/v1/tenants/%s/dek", tenantAID), nil)
	require.NotContains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, dek.Code, "dek: %s", dek.Body.String())

	assert.Equal(t, status.Code, dek.Code)
	assert.JSONEq(t, status.Body.String(), dek.Body.String())

	other := serveTenant(t, tenantAuthzRouter(t), tenantAToken, http.MethodGet,
		fmt.Sprintf("/api/v1/tenants/%s/dek", tenantBID), nil)
	assert.Equal(t, http.StatusForbidden, other.Code, "another tenant: %s", other.Body.String())
}
