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

package daemon

import (
	"net/http"
	"testing"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// DaemonRouteTableWithKMS exists for the daemon_test package: it returns the
// router of the daemon's full REST route table (daemonRouteTableWithKMS) with
// kms behind the webservice KMS router. The KMS routes run behind the catalog
// scope guard, so the route-table tests carry a token with every KMS scope:
// the integration adapter test (rest_kms_adapter_route_test.go) keeps
// reaching the handler.
func DaemonRouteTableWithKMS(t *testing.T, kms kmsclient.Client) http.Handler {
	s, _ := daemonRouteTableWithKMS(t, kmsScopedGuard(), kms)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer t")
		s.Router().ServeHTTP(w, r)
	})
}

// kmsScopedGuard returns a scope guard whose token carries every KMS and
// secrets scope the gRPC catalog names.
func kmsScopedGuard() *restapi.ScopeGuard {
	return restapi.NewScopeGuard(scopedTokenValidator{scopes: []string{
		"kms:read", "kms:write", "kms:delete",
		"secrets:read", "secrets:write", "secrets:list", "secrets:delete",
	}, tenant: testPlatformTenantID}, nil, nil)
}

// testPlatformTenantID is the platform tenant the KMS route fixtures
// authorize as, so the tenant-bound KMS routes reach their handlers.
const testPlatformTenantID = "platform"
