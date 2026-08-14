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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestNTPMethodsMapToTheServerRoutes pins the REST wire contract against the
// routes registered by pkg/webservice/v1/rest/ntp and pkg/api/rest. A drift
// here makes `platformctl --protocol rest ntp ...` 404 at runtime.
func TestNTPMethodsMapToTheServerRoutes(t *testing.T) {
	cases := map[string]struct {
		path   string
		method string
	}{
		platformv1.NTPService_GetStatus_FullMethodName:   {"/api/v1/ntp/status", http.MethodGet},
		platformv1.NTPService_ListSources_FullMethodName: {"/api/v1/ntp/sources", http.MethodGet},
		platformv1.NTPService_Step_FullMethodName:        {"/api/v1/ntp/step", http.MethodPost},
	}

	for method, want := range cases {
		t.Run(method, func(t *testing.T) {
			path, httpMethod := mapGRPCMethodToREST(method)
			if path != want.path || httpMethod != want.method {
				t.Fatalf("mapping = %s %s, want %s %s", httpMethod, path, want.method, want.path)
			}
		})
	}
}

// TestNTPMethodsAreNotLeftToTheHeuristic guards against relying on the
// method-name fallback, which would derive /api/v1/ntp/getstatus and 404.
func TestNTPMethodsAreNotLeftToTheHeuristic(t *testing.T) {
	for _, method := range []string{
		platformv1.NTPService_GetStatus_FullMethodName,
		platformv1.NTPService_ListSources_FullMethodName,
		platformv1.NTPService_Step_FullMethodName,
	} {
		if _, ok := grpcMethodToRESTMap[method]; !ok {
			t.Fatalf("%s is missing from grpcMethodToRESTMap", method)
		}
	}
}
