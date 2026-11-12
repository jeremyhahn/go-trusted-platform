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
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBMCRoutes_MountedOnConsoleAndGated pins that the console listener
// serves the BMC surface the dashboard calls (#1720), and that every BMC
// route refuses a request carrying no credential: the routes are remote
// power, boot and media control of the host.
func TestBMCRoutes_MountedOnConsoleAndGated(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	walked := map[string]bool{}
	for _, route := range testutil.WalkRoutes(t, router) {
		walked[route] = true
	}

	const base = "/api/v1/bmc/{profileID:[0-9]+}"
	want := []string{
		"GET " + base + "/users",
		"POST " + base + "/users",
		"DELETE " + base + "/users/{slot:[0-9]+}",
		"PUT " + base + "/users/{slot:[0-9]+}/password",
		"PUT " + base + "/users/{slot:[0-9]+}/privilege",
		"POST " + base + "/enroll",
		"POST " + base + "/cert/restore",
		"GET " + base + "/cert",
		"PUT " + base + "/cert",
	}
	for _, route := range want {
		require.True(t, walked[route], "the console route table lacks %s", route)
		method, template := splitRoute(route)
		code := probe(router, method, template)
		assert.True(t, denied(code),
			"%s answered %d to a request carrying no credential", route, code)
	}
}

// TestBMCRoutes_NilHandlerMountsNothing pins the skip: a daemon without a
// BMC service builds no /bmc route on the console.
func TestBMCRoutes_NilHandlerMountsNothing(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry := &testHandlerRegistry{
		tokenHandler:   &anonymousAuth{},
		responseWriter: respWriter,
	}
	v1 := NewRouter(logger, nil, nil, nil, registry, respWriter).(*Router)
	r := mux.NewRouter()
	v1.router = r

	v1.bmcRoutes()

	for _, route := range testutil.WalkRoutes(t, r) {
		assert.False(t, strings.Contains(route, "/bmc"),
			"a nil BMC handler still built %s", route)
	}
}
