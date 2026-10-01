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

package rest

import (
	"net/http"
	"testing"
)

// TestNAT64Status_ResolvesToTheServedRoute pins the NAT64 status route.
//
// mapGRPCMethodToREST never fails: an unmapped method falls back to
// POST /api/v1/<service>/<method>, so a forgotten entry produces
// POST /api/v1/gateway/getnat64status — a path nothing routes — and the
// SDK reports a 404 that is indistinguishable from a gateway running no
// translator. The route is on the /sdn/gateway prefix
// (pkg/api/rest/gateway_nat64_handlers.go), which the fallback cannot
// derive, so only an explicit mapping can be correct here (#601).
func TestNAT64Status_ResolvesToTheServedRoute(t *testing.T) {
	const method = "/platform.v1.GatewayService/GetNAT64Status"

	path, httpMethod := mapGRPCMethodToREST(method)

	if want := "/api/v1/sdn/gateway/nat64/status"; path != want {
		t.Errorf("NAT64 status path = %q, want %q (the fallback would give /api/v1/gateway/getnat64status, which nothing serves)", path, want)
	}
	if httpMethod != http.MethodGet {
		t.Errorf("NAT64 status HTTP method = %q, want %q", httpMethod, http.MethodGet)
	}
}
