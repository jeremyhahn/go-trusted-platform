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
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
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

// recordingBMCHandler records which BMC operation a request reached, so a
// test can prove a refused caller reached none.
type recordingBMCHandler struct {
	stubBMCHandler
	reached []string
}

func (h *recordingBMCHandler) hit(name string, w http.ResponseWriter) {
	h.reached = append(h.reached, name)
	w.WriteHeader(http.StatusOK)
}

func (h *recordingBMCHandler) ListUsers(w http.ResponseWriter, _ *http.Request) {
	h.hit("ListUsers", w)
}

func (h *recordingBMCHandler) CreateUser(w http.ResponseWriter, _ *http.Request) {
	h.hit("CreateUser", w)
}

func (h *recordingBMCHandler) DeleteUser(w http.ResponseWriter, _ *http.Request) {
	h.hit("DeleteUser", w)
}

func (h *recordingBMCHandler) SetUserPassword(w http.ResponseWriter, _ *http.Request) {
	h.hit("SetUserPassword", w)
}

func (h *recordingBMCHandler) SetUserPrivilege(w http.ResponseWriter, _ *http.Request) {
	h.hit("SetUserPrivilege", w)
}

func (h *recordingBMCHandler) PowerAction(w http.ResponseWriter, _ *http.Request) {
	h.hit("PowerAction", w)
}

// tenantProfiles answers Get with a profile owned by the mapped tenant.
type tenantProfiles struct {
	stubDeviceProfileService
	owners map[uint64]string
}

func (p *tenantProfiles) Get(_ context.Context, id uint64) (*entities.DeviceProfile, error) {
	owner, ok := p.owners[id]
	if !ok {
		return nil, errors.New("profile not found")
	}
	return &entities.DeviceProfile{ID: id, TenantID: owner}, nil
}

// bmcTenantProbes are the BMC operations that change or power off another
// machine: profile 7 belongs to tenant-b, profile 9 to no tenant.
var bmcTenantProbes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/bmc/7/users"},
	{http.MethodPost, "/api/v1/bmc/7/users"},
	{http.MethodDelete, "/api/v1/bmc/7/users/3"},
	{http.MethodPut, "/api/v1/bmc/7/users/3/password"},
	{http.MethodPut, "/api/v1/bmc/7/users/3/privilege"},
	{http.MethodPost, "/api/v1/bmc/7/power"},
	{http.MethodGet, "/api/v1/bmc/9/users"},
	{http.MethodGet, "/api/v1/bmc/404/users"},
}

func newBMCTenantRouter(t *testing.T, tenantID string) (*mux.Router, *recordingBMCHandler) {
	t.Helper()
	h := &recordingBMCHandler{}
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler:         &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: tenantID},
		bmcHandler:           h,
		deviceProfileService: &tenantProfiles{owners: map[uint64]string{7: "tenant-b", 9: ""}},
	})
	return router, h
}

// TestBMCRoutes_DenyAnAdminOfAnotherTenant is the Codex P1 on #1730: the
// admin gate alone let a tenant-a administrator drive tenant-b's BMC with
// the daemon's stored credentials. The profile's owner must be the caller's
// tenant, and the refusal must come before any BMC operation.
func TestBMCRoutes_DenyAnAdminOfAnotherTenant(t *testing.T) {
	router, h := newBMCTenantRouter(t, "tenant-a")
	for _, tc := range bmcTenantProbes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, probe(router, tc.method, tc.path),
				"an admin of tenant-a reached a BMC it does not own")
		})
	}
	assert.Empty(t, h.reached, "a refused caller reached a BMC operation")
}

// TestBMCRoutes_AdmitTheOwnerAndTheSystemTenant: the profile's own tenant
// reaches its BMC, and the system tenant, the control plane, reaches any.
func TestBMCRoutes_AdmitTheOwnerAndTheSystemTenant(t *testing.T) {
	owner, ownerHits := newBMCTenantRouter(t, "tenant-b")
	assert.Equal(t, http.StatusOK, probe(owner, http.MethodGet, "/api/v1/bmc/7/users"))
	assert.Equal(t, http.StatusOK, probe(owner, http.MethodPost, "/api/v1/bmc/7/power"))
	assert.Equal(t, []string{"ListUsers", "PowerAction"}, ownerHits.reached)

	system, systemHits := newBMCTenantRouter(t, "system")
	assert.Equal(t, http.StatusOK, probe(system, http.MethodDelete, "/api/v1/bmc/7/users/3"))
	assert.Equal(t, http.StatusOK, probe(system, http.MethodGet, "/api/v1/bmc/9/users"))
	assert.Equal(t, []string{"DeleteUser", "ListUsers"}, systemHits.reached)
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
