// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package kms

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// pathVars fills every path variable the KMS router declares.
var pathVars = strings.NewReplacer(
	"{name}", "k1",
	"{path:.+}", "app/db",
	"{version}", "1",
)

// TestUnwiredKMS_EveryRouteIsUnavailable walks every route the router
// registers with no SDK client wired and expects 503 from each, as
// docs/kms/api.md §7 maps "KMS not wired into the daemon".
func TestUnwiredKMS_EveryRouteIsUnavailable(t *testing.T) {
	logger := logging.DefaultLogger()
	parent := mux.NewRouter()
	NewKMSRouter(logger, nil, nil, nil, nil, response.NewResponseWriter(logger, nil)).RegisterRoutes(parent)

	routes := 0
	err := parent.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		for _, method := range methods {
			target := pathVars.Replace(tmpl)
			routes++
			t.Run(method+" "+tmpl, func(t *testing.T) {
				w := httptest.NewRecorder()
				req := httptest.NewRequest(method, target, strings.NewReader(`{}`))
				parent.ServeHTTP(w, req)
				if w.Code != http.StatusServiceUnavailable {
					t.Fatalf("status = %d, want 503 (body: %s)", w.Code, w.Body.String())
				}
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk routes: %v", err)
	}
	if routes == 0 {
		t.Fatal("router registered no routes")
	}
}
