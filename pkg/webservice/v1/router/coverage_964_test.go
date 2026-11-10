package router

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cov964BMCHandler is a bmc.RestHandler that records which handler method
// served a request, together with the path variables mux extracted.
type cov964BMCHandler struct {
	called  []string
	vars    map[string]string
	enroll  bool
	restore bool
}

func (h *cov964BMCHandler) record(name string, w http.ResponseWriter, r *http.Request) {
	h.called = append(h.called, name)
	h.vars = mux.Vars(r)
	w.WriteHeader(http.StatusOK)
}

func (h *cov964BMCHandler) PowerAction(w http.ResponseWriter, r *http.Request) {
	h.record("PowerAction", w, r)
}

func (h *cov964BMCHandler) PowerStatus(w http.ResponseWriter, r *http.Request) {
	h.record("PowerStatus", w, r)
}

func (h *cov964BMCHandler) SetBootDevice(w http.ResponseWriter, r *http.Request) {
	h.record("SetBootDevice", w, r)
}

func (h *cov964BMCHandler) GetBootDevice(w http.ResponseWriter, r *http.Request) {
	h.record("GetBootDevice", w, r)
}

func (h *cov964BMCHandler) MountISO(w http.ResponseWriter, r *http.Request) {
	h.record("MountISO", w, r)
}

func (h *cov964BMCHandler) UnmountISO(w http.ResponseWriter, r *http.Request) {
	h.record("UnmountISO", w, r)
}

func (h *cov964BMCHandler) VirtualMediaStatus(w http.ResponseWriter, r *http.Request) {
	h.record("VirtualMediaStatus", w, r)
}

func (h *cov964BMCHandler) GetSensors(w http.ResponseWriter, r *http.Request) {
	h.record("GetSensors", w, r)
}

func (h *cov964BMCHandler) GetSystemInfo(w http.ResponseWriter, r *http.Request) {
	h.record("GetSystemInfo", w, r)
}

func (h *cov964BMCHandler) Provision(w http.ResponseWriter, r *http.Request) {
	h.record("Provision", w, r)
}

func (h *cov964BMCHandler) ProvisionStatus(w http.ResponseWriter, r *http.Request) {
	h.record("ProvisionStatus", w, r)
}

func (h *cov964BMCHandler) GetWebCertificate(w http.ResponseWriter, r *http.Request) {
	h.record("GetWebCertificate", w, r)
}

func (h *cov964BMCHandler) ReplaceWebCertificate(w http.ResponseWriter, r *http.Request) {
	h.record("ReplaceWebCertificate", w, r)
}

func (h *cov964BMCHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	h.record("ListUsers", w, r)
}

func (h *cov964BMCHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	h.record("CreateUser", w, r)
}

func (h *cov964BMCHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	h.record("DeleteUser", w, r)
}

func (h *cov964BMCHandler) SetUserPassword(w http.ResponseWriter, r *http.Request) {
	h.record("SetUserPassword", w, r)
}

func (h *cov964BMCHandler) SetUserPrivilege(w http.ResponseWriter, r *http.Request) {
	h.record("SetUserPrivilege", w, r)
}

func (h *cov964BMCHandler) EnrollBMC(w http.ResponseWriter, r *http.Request) {
	h.record("EnrollBMC", w, r)
}

func (h *cov964BMCHandler) SetEnroller(bmc.BMCEnrollerServicer, bmc.ProfileLookup) {
	h.enroll = true
}

func (h *cov964BMCHandler) RestoreBMC(w http.ResponseWriter, r *http.Request) {
	h.record("RestoreBMC", w, r)
}

func (h *cov964BMCHandler) SetRestorer(bmc.BMCRestorerServicer, bmc.ProfileLookup) {
	h.restore = true
}

// cov964BMCMux mounts the BMC router on its own test mux only; production
// keeps it behind the auth gate.
func cov964BMCMux(t *testing.T) (*mux.Router, *cov964BMCHandler) {
	t.Helper()
	handler := &cov964BMCHandler{}
	bmcRouter := NewBMCRouter(handler)
	require.IsType(t, &BMCRouter{}, bmcRouter)
	muxRouter := mux.NewRouter()
	bmcRouter.RegisterRoutes(muxRouter)
	return muxRouter, handler
}

func cov964Serve(muxRouter *mux.Router, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestCov964BMCRouter_RoutesDispatchToHandler(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
		slot   string
	}{
		{http.MethodPost, "/bmc/7/power", "PowerAction", ""},
		{http.MethodGet, "/bmc/7/power", "PowerStatus", ""},
		{http.MethodPost, "/bmc/7/boot-device", "SetBootDevice", ""},
		{http.MethodGet, "/bmc/7/boot-device", "GetBootDevice", ""},
		{http.MethodPost, "/bmc/7/virtual-media", "MountISO", ""},
		{http.MethodDelete, "/bmc/7/virtual-media", "UnmountISO", ""},
		{http.MethodGet, "/bmc/7/virtual-media", "VirtualMediaStatus", ""},
		{http.MethodGet, "/bmc/7/sensors", "GetSensors", ""},
		{http.MethodGet, "/bmc/7/system-info", "GetSystemInfo", ""},
		{http.MethodPost, "/bmc/7/provision", "Provision", ""},
		{http.MethodGet, "/bmc/7/provision", "ProvisionStatus", ""},
		{http.MethodGet, "/bmc/7/cert", "GetWebCertificate", ""},
		{http.MethodPut, "/bmc/7/cert", "ReplaceWebCertificate", ""},
		{http.MethodGet, "/bmc/7/users", "ListUsers", ""},
		{http.MethodPost, "/bmc/7/users", "CreateUser", ""},
		{http.MethodDelete, "/bmc/7/users/3", "DeleteUser", "3"},
		{http.MethodPut, "/bmc/7/users/3/password", "SetUserPassword", "3"},
		{http.MethodPut, "/bmc/7/users/3/privilege", "SetUserPrivilege", "3"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			muxRouter, handler := cov964BMCMux(t)

			rec := cov964Serve(muxRouter, tt.method, tt.path)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, []string{tt.want}, handler.called)
			assert.Equal(t, "7", handler.vars["profileID"])
			if tt.slot != "" {
				assert.Equal(t, tt.slot, handler.vars["slot"])
			}
		})
	}
}

func TestCov964BMCRouter_RejectsWrongMethodAndBadPath(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		status int
	}{
		{"power patch", http.MethodPatch, "/bmc/7/power", http.StatusMethodNotAllowed},
		{"boot-device delete", http.MethodDelete, "/bmc/7/boot-device", http.StatusMethodNotAllowed},
		{"virtual-media put", http.MethodPut, "/bmc/7/virtual-media", http.StatusMethodNotAllowed},
		{"sensors post", http.MethodPost, "/bmc/7/sensors", http.StatusMethodNotAllowed},
		{"system-info post", http.MethodPost, "/bmc/7/system-info", http.StatusMethodNotAllowed},
		{"provision delete", http.MethodDelete, "/bmc/7/provision", http.StatusMethodNotAllowed},
		{"cert post", http.MethodPost, "/bmc/7/cert", http.StatusMethodNotAllowed},
		{"users delete", http.MethodDelete, "/bmc/7/users", http.StatusMethodNotAllowed},
		{"user slot get", http.MethodGet, "/bmc/7/users/3", http.StatusMethodNotAllowed},
		{"password get", http.MethodGet, "/bmc/7/users/3/password", http.StatusMethodNotAllowed},
		{"privilege post", http.MethodPost, "/bmc/7/users/3/privilege", http.StatusMethodNotAllowed},
		{"non-numeric profile", http.MethodGet, "/bmc/abc/power", http.StatusNotFound},
		{"non-numeric slot", http.MethodDelete, "/bmc/7/users/admin", http.StatusNotFound},
		{"enroll not mounted", http.MethodPost, "/bmc/7/enroll", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			muxRouter, handler := cov964BMCMux(t)

			rec := cov964Serve(muxRouter, tt.method, tt.path)

			assert.Equal(t, tt.status, rec.Code)
			assert.Empty(t, handler.called)
		})
	}
}

func TestCov964NewSystemRouter_WiresMiddlewareAndRoutes(t *testing.T) {
	mockAuth := &MockAuthMiddleware{}
	mockJWT := &MockJsonWebTokenMiddleware{}

	got := NewSystemRouter(nil, nil, nil, nil, mockJWT, mockAuth, mux.NewRouter(), nil, nil)

	sysRouter, ok := got.(*SystemRouter)
	require.True(t, ok)
	assert.Same(t, mockAuth, sysRouter.authMiddleware)
	assert.Same(t, mockJWT, sysRouter.jwtMiddleware)
	assert.IsType(t, &system.Handler{}, sysRouter.systemRestHandler)

	muxRouter := mux.NewRouter()
	got.RegisterRoutes(muxRouter)

	var paths []string
	err := muxRouter.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, tmplErr := route.GetPathTemplate()
		if tmplErr != nil {
			return tmplErr
		}
		paths = append(paths, tmpl)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(paths)
	assert.Equal(t, []string{"/certificate", "/config", "/events/{page}", "/pubkey", "/status"}, paths)
	mockAuth.AssertExpectations(t)
	mockJWT.AssertExpectations(t)
}
