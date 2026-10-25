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

package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

// webUIRoutes are concrete requests the WebUI sends. Path-derived IDs are
// placeholders: the route only has to match, the handler may reject them.
// TestRoutes_WebUIRequestsMatchARoute matches each one against the built
// router, which the template-level golden in route_existence_test.go does
// not do: a template can survive while its variable's pattern stops
// accepting the IDs the console really sends.
var webUIRoutes = []struct{ method, path string }{
	// Compute
	{http.MethodGet, "/api/v1/compute/vms"},
	{http.MethodGet, "/api/v1/compute/vms/test-id"},
	{http.MethodGet, "/api/v1/compute/vms/test-id/metrics"},
	{http.MethodGet, "/api/v1/compute/vms/test-id/snapshots"},
	{http.MethodGet, "/api/v1/compute/containers"},
	{http.MethodGet, "/api/v1/compute/containers/test-id"},
	{http.MethodGet, "/api/v1/compute/containers/test-id/metrics"},
	// TPM
	{http.MethodGet, "/api/v1/tpm/info"},
	{http.MethodGet, "/api/v1/tpm/ek"},
	{http.MethodGet, "/api/v1/tpm/ek/certificate"},
	{http.MethodGet, "/api/v1/tpm/srk"},
	{http.MethodGet, "/api/v1/tpm/ak"},
	{http.MethodGet, "/api/v1/tpm/eventlog"},
	{http.MethodGet, "/api/v1/tpm/pcrs"},
	{http.MethodGet, "/api/v1/tpm/nvram/0x1c00002"},
	// IDevID
	{http.MethodGet, "/api/v1/idevid"},
	{http.MethodGet, "/api/v1/idevid/exists"},
	{http.MethodGet, "/api/v1/idevid/certificate"},
	{http.MethodGet, "/api/v1/idevid/iak"},
	{http.MethodGet, "/api/v1/idevid/iak/exists"},
	{http.MethodGet, "/api/v1/idevid/iak/certificate"},
	{http.MethodGet, "/api/v1/idevid/attributes"},
	// Attestation
	{http.MethodGet, "/api/v1/attestation/manifests"},
	// Tenants
	{http.MethodGet, "/api/v1/tenants"},
	{http.MethodGet, "/api/v1/tenants/by-name/test"},
	{http.MethodGet, "/api/v1/tenants/test-tenant-id"},
	{http.MethodGet, "/api/v1/tenants/test-tenant-id/quotas"},
	{http.MethodGet, "/api/v1/tenants/test-tenant-id/usage"},
	{http.MethodGet, "/api/v1/tenants/test-tenant-id/dek"},
	{http.MethodGet, "/api/v1/tenants/test-tenant-id/barrier"},
	// Invitations
	{http.MethodGet, "/api/v1/invitations"},
	{http.MethodGet, "/api/v1/invitations/123"},
	{http.MethodGet, "/api/v1/invitations/token/test-token"},
	// EAB
	{http.MethodGet, "/api/v1/eab/credentials"},
	{http.MethodGet, "/api/v1/eab/credentials/123"},
	{http.MethodGet, "/api/v1/eab/credentials/key/test-key"},
	{http.MethodGet, "/api/v1/eab/credentials/123/qrcode"},
	{http.MethodGet, "/api/v1/eab/credentials/123/url"},
	// Gateway
	{http.MethodGet, "/api/v1/gateway/status"},
	{http.MethodGet, "/api/v1/gateway/bgp/status"},
	{http.MethodGet, "/api/v1/gateway/bgp/peers"},
	{http.MethodGet, "/api/v1/gateway/bgp/prefixes"},
	{http.MethodGet, "/api/v1/gateway/ipam/pools"},
	{http.MethodGet, "/api/v1/gateway/ipam/allocations"},
	// Overlay
	{http.MethodGet, "/api/v1/overlay/status"},
	{http.MethodGet, "/api/v1/overlay/vteps"},
	{http.MethodGet, "/api/v1/overlay/vteps/test-node"},
	{http.MethodGet, "/api/v1/overlay/vnis"},
	{http.MethodGet, "/api/v1/overlay/tunnels"},
	{http.MethodGet, "/api/v1/overlay/macs"},
	// PXE
	{http.MethodGet, "/api/v1/pxe/status"},
	{http.MethodGet, "/api/v1/pxe/devices"},
	{http.MethodGet, "/api/v1/pxe/devices/test-device"},
	{http.MethodGet, "/api/v1/pxe/devices/mac/00:00:00:00:00:00"},
	{http.MethodGet, "/api/v1/pxe/devices/test-device/events"},
	// Pre-existing routes that must still resolve
	{http.MethodGet, "/api/v1/iam/tenants"},
	{http.MethodGet, "/api/v1/kms/keys"},
	{http.MethodGet, "/api/v1/sdn/bridges"},
	{http.MethodGet, "/api/v1/dns/zones"},
	{http.MethodGet, "/api/v1/platform/health"},
	{http.MethodGet, "/api/v1/devices"},
	{http.MethodGet, "/api/v1/ca/info"},
}

func TestRoutes_WebUIRequestsMatchARoute(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	for _, r := range webUIRoutes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			var match mux.RouteMatch
			req := httptest.NewRequest(r.method, r.path, nil)
			assert.Truef(t, router.Match(req, &match), "%s %s matches no route", r.method, r.path)
			assert.NoErrorf(t, match.MatchErr, "%s %s: %v", r.method, r.path, match.MatchErr)
		})
	}
}

// TestRoutes_NoRouteInventory pins the removal of GET /endpoints (#551): the
// route walked the mux and handed any caller every registered template,
// gated paths included, with no credential.
func TestRoutes_NoRouteInventory(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	var match mux.RouteMatch
	req := httptest.NewRequest(http.MethodGet, "/endpoints", nil)
	assert.False(t, router.Match(req, &match), "GET /endpoints is routed again")
}
