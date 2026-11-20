package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTenantRoutes_DEKStatusPaths checks that the daemon tenant router
// answers the SDK's GET /api/v1/tenants/{id}/dek as well as the older
// /dek/status, both with the DEK status handler behind the same guard.
func TestTenantRoutes_DEKStatusPaths(t *testing.T) {
	// One router, so both paths read the same mock DEK and timestamps.
	router := tenantAuthzRouter(t)
	status := serveTenant(t, router, tenantAToken, http.MethodGet,
		fmt.Sprintf("/api/v1/tenants/%s/dek/status", tenantAID), nil)
	require.NotContains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, status.Code, "dek/status: %s", status.Body.String())

	dek := serveTenant(t, router, tenantAToken, http.MethodGet,
		fmt.Sprintf("/api/v1/tenants/%s/dek", tenantAID), nil)
	require.NotContains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, dek.Code, "dek: %s", dek.Body.String())

	assert.Equal(t, status.Code, dek.Code)
	assert.Equal(t, dekStatusWithoutTimes(t, status.Body.Bytes()), dekStatusWithoutTimes(t, dek.Body.Bytes()))

	other := serveTenant(t, router, tenantAToken, http.MethodGet,
		fmt.Sprintf("/api/v1/tenants/%s/dek", tenantBID), nil)
	assert.Equal(t, http.StatusForbidden, other.Code, "another tenant: %s", other.Body.String())
}

// dekStatusWithoutTimes decodes a DEK status body and drops the *_at and
// timestamp fields, which are stamped afresh on every call.
func dekStatusWithoutTimes(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	for k := range out {
		if strings.HasSuffix(k, "_at") || k == "timestamp" {
			delete(out, k)
		}
	}
	return out
}
