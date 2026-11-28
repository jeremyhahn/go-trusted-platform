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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
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

// probeBMC is probe with a well-formed power body on the power route: the
// power route decodes its body to pick the action scope, so an empty body
// answers 400 before the tenant check this file asserts.
func probeBMC(router *mux.Router, method, template string) int {
	if strings.HasSuffix(template, "/power") {
		return serve(router, httptest.NewRequest(method, testutil.ConcreteFor(template),
			strings.NewReader(`{"action":"on"}`)))
	}
	return probe(router, method, template)
}

// TestBMCRoutes_DenyAnAdminOfAnotherTenant is the Codex P1 on #1730: the
// admin gate alone let a tenant-a administrator drive tenant-b's BMC with
// the daemon's stored credentials. The profile's owner must be the caller's
// tenant, and the refusal must come before any BMC operation.
func TestBMCRoutes_DenyAnAdminOfAnotherTenant(t *testing.T) {
	router, h := newBMCTenantRouter(t, "tenant-a")
	for _, tc := range bmcTenantProbes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, probeBMC(router, tc.method, tc.path),
				"an admin of tenant-a reached a BMC it does not own")
		})
	}
	assert.Empty(t, h.reached, "a refused caller reached a BMC operation")
}

// TestBMCRoutes_AdmitTheOwnerAndTheSystemTenant: the profile's own tenant
// reaches its BMC, and the system tenant, the control plane, reaches any.
func TestBMCRoutes_AdmitTheOwnerAndTheSystemTenant(t *testing.T) {
	// The mounted BMC routes are system-tenant only: the profile owner
	// tenant-b is refused and reaches nothing.
	owner, ownerHits := newBMCTenantRouter(t, "tenant-b")
	assert.Equal(t, http.StatusForbidden, probe(owner, http.MethodGet, "/api/v1/bmc/7/users"))
	assert.Equal(t, http.StatusForbidden, probeBMC(owner, http.MethodPost, "/api/v1/bmc/7/power"))
	assert.Empty(t, ownerHits.reached)

	// The system tenant is admitted once its session carries the BMC scopes.
	systemHits := &recordingBMCHandler{}
	system := newBMCScopedRouter(t, systemHits, allBMCScopes)
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

// bmcScopeProbes pairs every BMC console route except POST power with the
// gRPC RPC it mirrors (#2021 Codex round 4): the REST route must take the
// same operation scope as its gRPC twin under platform-token auth.
var bmcScopeProbes = []struct {
	method, path, rpc string
}{
	{http.MethodGet, "/api/v1/bmc/7/power", "PowerStatus"},
	{http.MethodPost, "/api/v1/bmc/7/boot-device", "SetBootDevice"},
	{http.MethodGet, "/api/v1/bmc/7/boot-device", "GetBootDevice"},
	{http.MethodPost, "/api/v1/bmc/7/virtual-media", "MountISO"},
	{http.MethodDelete, "/api/v1/bmc/7/virtual-media", "UnmountISO"},
	{http.MethodGet, "/api/v1/bmc/7/virtual-media", "VirtualMediaStatus"},
	{http.MethodGet, "/api/v1/bmc/7/sensors", "GetSensors"},
	{http.MethodGet, "/api/v1/bmc/7/system-info", "GetSystemInfo"},
	{http.MethodPost, "/api/v1/bmc/7/provision", "Provision"},
	{http.MethodGet, "/api/v1/bmc/7/provision", "ProvisionStatus"},
	{http.MethodPost, "/api/v1/bmc/7/enroll", "EnrollBMC"},
	{http.MethodPost, "/api/v1/bmc/7/cert/restore", "RestoreFactoryCert"},
	{http.MethodGet, "/api/v1/bmc/7/cert", "GetWebCertificate"},
	{http.MethodPut, "/api/v1/bmc/7/cert", "ReplaceWebCertificate"},
	{http.MethodGet, "/api/v1/bmc/7/users", "ListUsers"},
	{http.MethodPost, "/api/v1/bmc/7/users", "CreateUser"},
	{http.MethodDelete, "/api/v1/bmc/7/users/3", "DeleteUser"},
	{http.MethodPut, "/api/v1/bmc/7/users/3/password", "SetUserPassword"},
	{http.MethodPut, "/api/v1/bmc/7/users/3/privilege", "SetUserPrivilege"},
}

var allBMCScopes = []string{"bmc:read", "bmc:write", "bmc:power", "bmc:media", "bmc:admin"}

func newBMCScopedRouter(t *testing.T, handler bmc.RestHandler, scopes []string) *mux.Router {
	t.Helper()
	return newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler: &scopedSessionAuth{
			sessionAuth: sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"},
			scopes:      scopes,
		},
		bmcHandler:           handler,
		deviceProfileService: &tenantProfiles{owners: map[uint64]string{7: "tenant-b", 9: ""}},
	})
}

func bmcRPCScope(t *testing.T, rpc string) string {
	t.Helper()
	scope := grpcapi.ScopeForMethod("/platform.v1.BMCService/" + rpc)
	require.NotEmpty(t, scope, "no gRPC scope for %s", rpc)
	return scope
}

// TestBMCRoutes_RefuseAnAdminWithoutTheRPCScope pins that an admin token
// holding every BMC scope but the one the gRPC twin needs is refused before
// the handler runs.
func TestBMCRoutes_RefuseAnAdminWithoutTheRPCScope(t *testing.T) {
	for _, p := range bmcScopeProbes {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			scope := bmcRPCScope(t, p.rpc)
			granted := slices.DeleteFunc(slices.Clone(allBMCScopes), func(s string) bool { return s == scope })
			h := &recordingBMCHandler{}
			router := newBMCScopedRouter(t, h, granted)
			code := serve(router, httptest.NewRequest(p.method, p.path, nil))
			assert.Equal(t, http.StatusForbidden, code)
			assert.Empty(t, h.reached)
		})
	}
}

// TestBMCRoutes_AdmitAnAdminWithTheRPCScope pins that the gRPC twin's scope
// alone is enough to reach the handler.
func TestBMCRoutes_AdmitAnAdminWithTheRPCScope(t *testing.T) {
	for _, p := range bmcScopeProbes {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			scope := bmcRPCScope(t, p.rpc)
			router := newBMCScopedRouter(t, &recordingBMCHandler{}, []string{scope})
			code := serve(router, httptest.NewRequest(p.method, p.path, nil))
			assert.NotEqual(t, http.StatusForbidden, code)
		})
	}
}

// actionRecordingBMCHandler decodes the power request the way the real
// handler does and records the action it saw.
type actionRecordingBMCHandler struct {
	recordingBMCHandler
	actions []string
}

func (h *actionRecordingBMCHandler) PowerAction(w http.ResponseWriter, r *http.Request) {
	var req bmc.PowerActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	h.actions = append(h.actions, req.Action)
	w.WriteHeader(http.StatusOK)
}

// TestBMCRoutes_PowerActionTakesTheActionScope pins that POST power takes
// bmc:write for "on" (PowerOn) and bmc:power for off/reset/cycle, and that
// the body still reaches the handler intact after the scope check read it.
func TestBMCRoutes_PowerActionTakesTheActionScope(t *testing.T) {
	cases := []struct {
		scope, action string
		want          int
	}{
		{"bmc:write", "on", http.StatusOK},
		{"bmc:write", "off", http.StatusForbidden},
		{"bmc:write", "reset", http.StatusForbidden},
		{"bmc:write", "cycle", http.StatusForbidden},
		{"bmc:power", "off", http.StatusOK},
		{"bmc:power", "cycle", http.StatusOK},
		{"bmc:read", "on", http.StatusForbidden},
		{"bmc:power", "on", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.scope+" "+tc.action, func(t *testing.T) {
			h := &actionRecordingBMCHandler{}
			router := newBMCScopedRouter(t, h, []string{tc.scope})
			code := serve(router, httptest.NewRequest(http.MethodPost, "/api/v1/bmc/7/power",
				strings.NewReader(`{"action":"`+tc.action+`"}`)))
			require.Equal(t, tc.want, code)
			if tc.want == http.StatusOK {
				assert.Equal(t, []string{tc.action}, h.actions)
			} else {
				assert.Empty(t, h.actions)
			}
		})
	}
}

// The handler decodes only the first JSON object of the body, so a trailing
// object must not make the scope check read the body differently: an "on"
// followed by more data is still a power-on and takes bmc:write.
func TestBMCRoutes_PowerActionTrailingJSONTakesTheWriteScope(t *testing.T) {
	cases := []struct {
		scope string
		want  int
	}{
		// The canonical decoder refuses a trailing JSON value with 400
		// whichever scope the session holds; no action reaches the handler.
		{"bmc:power", http.StatusBadRequest},
		{"bmc:write", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.scope, func(t *testing.T) {
			h := &actionRecordingBMCHandler{}
			router := newBMCScopedRouter(t, h, []string{tc.scope})
			code := serve(router, httptest.NewRequest(http.MethodPost, "/api/v1/bmc/7/power",
				strings.NewReader(`{"action":"on"}{}`)))
			require.Equal(t, tc.want, code)
			if tc.want == http.StatusOK {
				assert.Equal(t, []string{"on"}, h.actions)
			} else {
				assert.Empty(t, h.actions)
			}
		})
	}
}
