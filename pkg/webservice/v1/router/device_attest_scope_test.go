// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package router

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// grantingValidator accepts any bearer token and grants a fixed scope set,
// so a test controls exactly what the caller may do.
type grantingValidator struct {
	scopes []string
}

func (v grantingValidator) Validate(context.Context, string, string, string, string) (*platformtoken.AuthorizedContext, error) {
	return &platformtoken.AuthorizedContext{Subject: "operator", TenantID: "t1", Scopes: v.scopes}, nil
}

// attestOK answers the attestation and lifecycle routes with 200, standing
// in for the real handlers so a test sees only whether the scope check let
// it through.
type attestOK struct{}

func (attestOK) HandleDisable(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (attestOK) HandleEnable(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (attestOK) HandleAttestDevice(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (attestOK) HandleRecordAttestCert(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// newAttestMux mounts the attestation routes behind the platform token
// middleware granting scopes, as router.go wires them.
func newAttestMux(t *testing.T, scopes ...string) http.Handler {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mw, err := iammw.NewPlatformTokenMiddleware(logger, response.NewResponseWriter(logger, nil),
		grantingValidator{scopes: scopes}, iammw.PlatformTokenConfig{AllowBearer: true})
	require.NoError(t, err)

	deviceRouter, err := NewDeviceRouter(&MockMTLSMiddleware{}, nil,
		&MockDeviceCRUDHandler{}, &MockTemplateCRUDHandler{}, nil, attestOK{})
	require.NoError(t, err)
	deviceRouter.SetAttestCertHandler(attestOK{})
	deviceRouter.SetLifecycleHandler(attestOK{})
	deviceRouter.SetScopeAuthorizer(mw)
	m := mux.NewRouter()
	deviceRouter.RegisterRoutes(m)
	return mw.Handler(m)
}

// attestRoutes are the device writes the webservice scope-checks: the two
// attestation routes and the two lifecycle transitions (#250).
var attestRoutes = map[string]string{
	"AttestDevice":          "/devices/7/attest",
	"RecordAttestationCert": "/devices/7/attest-cert/record",
	"DisableDevice":         "/devices/7/disable",
	"EnableDevice":          "/devices/7/enable",
}

func postAttest(handler http.Handler, path string) int {
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set(iammw.AuthorizationHeader, iammw.BearerPrefix+"t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

func TestDeviceRouter_AttestRoutes_RefuseAReadOnlyToken(t *testing.T) {
	handler := newAttestMux(t, "device:read")
	for name, path := range attestRoutes {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, postAttest(handler, path),
				"a device:read token must not reach a device write")
		})
	}
}

func TestDeviceRouter_AttestRoutes_AllowDeviceWrite(t *testing.T) {
	handler := newAttestMux(t, "device:write")
	for name, path := range attestRoutes {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, http.StatusOK, postAttest(handler, path))
		})
	}
}

// TestDeviceRouter_AttestRoutes_RoleGateAloneWithoutScopes pins the legacy
// JWT path: with no scope authorizer the routes are left to the admin role
// gate instead of refusing every request.
func TestDeviceRouter_AttestRoutes_RoleGateAloneWithoutScopes(t *testing.T) {
	deviceRouter, err := NewDeviceRouter(&MockMTLSMiddleware{}, nil,
		&MockDeviceCRUDHandler{}, &MockTemplateCRUDHandler{}, nil, attestOK{})
	require.NoError(t, err)
	deviceRouter.SetAttestCertHandler(attestOK{})
	deviceRouter.SetLifecycleHandler(attestOK{})
	m := mux.NewRouter()
	deviceRouter.RegisterRoutes(m)
	for name, path := range attestRoutes {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, http.StatusOK, postAttest(m, path))
		})
	}
}
