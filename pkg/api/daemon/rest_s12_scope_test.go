package daemon

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
)

// s12BMCHandler answers every BMC route with the name of the handler method
// that served it, so a test can tell the guard let the request through to
// the handler the route has always served. PowerAction decodes its body as
// the real handler does and echoes the action it read.
type s12BMCHandler struct{ bmcwebsvc.RestHandler }

func s12Reached(w http.ResponseWriter, name string) {
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, "reached:"+name); err != nil {
		slog.Default().Error("s12 fake BMC handler could not write", "error", err)
	}
}

func (s12BMCHandler) PowerAction(w http.ResponseWriter, r *http.Request) {
	var req bmcwebsvc.PowerActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "handler could not decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	s12Reached(w, "PowerAction:"+req.Action)
}

func (s12BMCHandler) PowerStatus(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "PowerStatus")
}
func (s12BMCHandler) SetBootDevice(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "SetBootDevice")
}
func (s12BMCHandler) GetBootDevice(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "GetBootDevice")
}
func (s12BMCHandler) MountISO(w http.ResponseWriter, _ *http.Request) { s12Reached(w, "MountISO") }
func (s12BMCHandler) UnmountISO(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "UnmountISO")
}
func (s12BMCHandler) VirtualMediaStatus(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "VirtualMediaStatus")
}
func (s12BMCHandler) GetSensors(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "GetSensors")
}
func (s12BMCHandler) GetSystemInfo(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "GetSystemInfo")
}
func (s12BMCHandler) Provision(w http.ResponseWriter, _ *http.Request) { s12Reached(w, "Provision") }
func (s12BMCHandler) ProvisionStatus(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "ProvisionStatus")
}
func (s12BMCHandler) EnrollBMC(w http.ResponseWriter, _ *http.Request) { s12Reached(w, "EnrollBMC") }
func (s12BMCHandler) RestoreBMC(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "RestoreBMC")
}
func (s12BMCHandler) GetWebCertificate(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "GetWebCertificate")
}
func (s12BMCHandler) ReplaceWebCertificate(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "ReplaceWebCertificate")
}
func (s12BMCHandler) ListUsers(w http.ResponseWriter, _ *http.Request) { s12Reached(w, "ListUsers") }
func (s12BMCHandler) CreateUser(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "CreateUser")
}
func (s12BMCHandler) DeleteUser(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "DeleteUser")
}
func (s12BMCHandler) SetUserPassword(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "SetUserPassword")
}
func (s12BMCHandler) SetUserPrivilege(w http.ResponseWriter, _ *http.Request) {
	s12Reached(w, "SetUserPrivilege")
}

// s12RouteScopes is every BMC route whose rpc does not depend on the body,
// with the handler it serves and the scope the gRPC catalog gives its rpc.
// The route is the exact template restRouteTemplate returns, regexes and all.
var s12RouteScopes = []struct {
	method, route, path, handler, scope string
}{
	{http.MethodGet, "/api/v1/bmc/{profileID:[0-9]+}/power", "/api/v1/bmc/1/power", "PowerStatus", "bmc:read"},
	{http.MethodGet, "/api/v1/bmc/{profileID:[0-9]+}/boot-device", "/api/v1/bmc/1/boot-device", "GetBootDevice", "bmc:read"},
	{http.MethodPost, "/api/v1/bmc/{profileID:[0-9]+}/boot-device", "/api/v1/bmc/1/boot-device", "SetBootDevice", "bmc:write"},
	{http.MethodGet, "/api/v1/bmc/{profileID:[0-9]+}/virtual-media", "/api/v1/bmc/1/virtual-media", "VirtualMediaStatus", "bmc:read"},
	{http.MethodPost, "/api/v1/bmc/{profileID:[0-9]+}/virtual-media", "/api/v1/bmc/1/virtual-media", "MountISO", "bmc:media"},
	{http.MethodDelete, "/api/v1/bmc/{profileID:[0-9]+}/virtual-media", "/api/v1/bmc/1/virtual-media", "UnmountISO", "bmc:media"},
	{http.MethodGet, "/api/v1/bmc/{profileID:[0-9]+}/sensors", "/api/v1/bmc/1/sensors", "GetSensors", "bmc:read"},
	{http.MethodGet, "/api/v1/bmc/{profileID:[0-9]+}/system-info", "/api/v1/bmc/1/system-info", "GetSystemInfo", "bmc:read"},
	{http.MethodGet, "/api/v1/bmc/{profileID:[0-9]+}/provision", "/api/v1/bmc/1/provision", "ProvisionStatus", "bmc:read"},
	{http.MethodPost, "/api/v1/bmc/{profileID:[0-9]+}/provision", "/api/v1/bmc/1/provision", "Provision", "bmc:admin"},
	{http.MethodPost, "/api/v1/bmc/{profileID:[0-9]+}/enroll", "/api/v1/bmc/1/enroll", "EnrollBMC", "bmc:admin"},
	{http.MethodGet, "/api/v1/bmc/{profileID:[0-9]+}/cert", "/api/v1/bmc/1/cert", "GetWebCertificate", "bmc:read"},
	{http.MethodPut, "/api/v1/bmc/{profileID:[0-9]+}/cert", "/api/v1/bmc/1/cert", "ReplaceWebCertificate", "bmc:admin"},
	{http.MethodPost, "/api/v1/bmc/{profileID:[0-9]+}/cert/restore", "/api/v1/bmc/1/cert/restore", "RestoreBMC", "bmc:admin"},
	{http.MethodGet, "/api/v1/bmc/{profileID:[0-9]+}/users", "/api/v1/bmc/1/users", "ListUsers", "bmc:read"},
	{http.MethodPost, "/api/v1/bmc/{profileID:[0-9]+}/users", "/api/v1/bmc/1/users", "CreateUser", "bmc:admin"},
	{http.MethodDelete, "/api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}", "/api/v1/bmc/1/users/3", "DeleteUser", "bmc:admin"},
	{http.MethodPut, "/api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/password", "/api/v1/bmc/1/users/3/password", "SetUserPassword", "bmc:admin"},
	{http.MethodPut, "/api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/privilege", "/api/v1/bmc/1/users/3/privilege", "SetUserPrivilege", "bmc:admin"},
}

const s12PowerRoute = "/api/v1/bmc/{profileID:[0-9]+}/power"

// s12PowerActions is the scope each power action needs: PowerOn is a write,
// the other three are the stronger power scope.
var s12PowerActions = []struct{ action, scope string }{
	{"on", "bmc:write"},
	{"off", "bmc:power"},
	{"reset", "bmc:power"},
	{"cycle", "bmc:power"},
}

func s12ServePower(s *RESTServer, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bmc/1/power", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, req)
	return recorder
}

func TestS12REST_EveryRouteNeedsItsCatalogScope(t *testing.T) {
	s := newRESTServerWithS6(t)
	mounted := testWalkHandlers(t, s.router)
	for _, tc := range s12RouteScopes {
		name := tc.method + " " + tc.route
		assert.Contains(t, mounted, name, "the route template is the catalogRouteRPCs key")
		scope, err := catalogRouteScope(tc.method, tc.route)
		require.NoError(t, err, name)
		assert.Equal(t, tc.scope, scope, name)

		assert.Equal(t, http.StatusUnauthorized, serveIAM(s, tc.method, tc.path, "").Code, name)

		recorder := serveIAM(s, tc.method, tc.path, "dns-reader")
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		recorder = serveIAM(s, tc.method, tc.path, "except:"+tc.scope)
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		recorder = serveIAM(s, tc.method, tc.path, "only:"+tc.scope)
		assert.Equal(t, http.StatusOK, recorder.Code, name)
		assert.Equal(t, "reached:"+tc.handler, recorder.Body.String(), name)
	}
}

func TestS12REST_PowerActionNeedsTheScopeOfItsRPC(t *testing.T) {
	s := newRESTServerWithS6(t)
	assert.Contains(t, testWalkHandlers(t, s.router), http.MethodPost+" "+s12PowerRoute)

	_, err := catalogRouteScope(http.MethodPost, s12PowerRoute)
	var unscoped ErrRESTRouteUnscoped
	require.ErrorAs(t, err, &unscoped, "the power route has no scope without its body")

	for _, tc := range s12PowerActions {
		body := `{"action":"` + tc.action + `"}`
		assert.Equal(t, http.StatusUnauthorized, s12ServePower(s, "", body).Code, tc.action)

		recorder := s12ServePower(s, "except:"+tc.scope, body)
		assert.Equal(t, http.StatusForbidden, recorder.Code, tc.action)
		assert.Contains(t, recorder.Body.String(), tc.scope, tc.action)

		recorder = s12ServePower(s, "only:"+tc.scope, body)
		assert.Equal(t, http.StatusOK, recorder.Code, tc.action)
		assert.Equal(t, "reached:PowerAction:"+tc.action, recorder.Body.String(), "the handler decodes the body unchanged")
	}

	// bmc write is PowerOn's scope; it is never enough to power off, reset
	// or cycle.
	for _, action := range []string{"off", "reset", "cycle"} {
		recorder := s12ServePower(s, "only:bmc:write", `{"action":"`+action+`"}`)
		assert.Equal(t, http.StatusForbidden, recorder.Code, action)
		assert.Contains(t, recorder.Body.String(), "bmc:power", action)
	}
}

func TestS12REST_PowerActionWithoutAKnownActionIsRefused(t *testing.T) {
	s := newRESTServerWithS6(t)
	overLimit := `{"action":"on","pad":"` + strings.Repeat("x", bmcPowerActionBodyLimit) + `"}`
	refused := map[string]string{
		"empty body":      "",
		"missing action":  `{}`,
		"empty action":    `{"action":""}`,
		"unknown action":  `{"action":"hibernate"}`,
		"wrong case":      `{"action":"OFF"}`,
		"not JSON":        `action=off`,
		"action not text": `{"action":1}`,
		"over the limit":  overLimit,
	}
	for name, body := range refused {
		// Even a caller holding every BMC scope is refused: no scope can be
		// chosen, and the guard never falls back to one.
		recorder := s12ServePower(s, s6OperatorToken, body)
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), "BMC power action", name)
		assert.NotContains(t, recorder.Body.String(), "reached:", name)
	}

	within := `{"action":"off","pad":"` + strings.Repeat("x", bmcPowerActionBodyLimit-40) + `"}`
	recorder := s12ServePower(s, "only:bmc:power", within)
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "reached:PowerAction:off", recorder.Body.String())
}

func TestBMCPowerActionRPC_RefusesARequestWithoutABody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bmc/1/power", nil)
	req.Body = nil
	_, err := bmcPowerActionRPC(httptest.NewRecorder(), req)
	var unscoped ErrBMCPowerActionUnscoped
	require.ErrorAs(t, err, &unscoped)
}

func TestS12SetBMCHandler_RefusesANilGuard(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	err := s.SetBMCHandler(s12BMCHandler{}, nil)
	var unavailable ErrBMCRESTUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.Empty(t, testWalkHandlers(t, s.router))
	assert.Nil(t, s.bmcHandler)
}

func TestS12SetBMCHandler_NilHandlerMountsNothing(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	require.NoError(t, s.SetBMCHandler(nil, s6RESTGuard()))
	assert.Empty(t, testWalkHandlers(t, s.router))
}
