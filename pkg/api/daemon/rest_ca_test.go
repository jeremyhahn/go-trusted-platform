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

//go:build codec_msgpack

package daemon

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// The mock CA is fakeRESTCA (rest_ca_fake_test.go).

// =============================================================================
// Tests
// =============================================================================

func TestRESTServer_SetCAHandlers_Nil(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	// Calling SetCAHandlers with nil should be a no-op (must not panic).
	server.SetCAHandlers(nil, nil)

	// /api/v1/ca/info should NOT be registered when CA is nil.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code, "CA routes should not be registered when CA is nil")
}

func TestRESTServer_SetCAHandlers_RegistersRoutes(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	server.SetCAHandlers(&fakeRESTCA{}, nil)

	// /api/v1/ca/info should now be registered. The handler will respond
	// (status will be 200 because the fake CA reports IsInitialized=true).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusNotFound, w.Code, "CA routes should be registered after SetCAHandlers")
}

func TestRESTServer_SetCAHandlers_AllRoutesRegistered(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)

	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)

	server.SetCAHandlers(&fakeRESTCA{}, nil)

	// Walk the router and verify every CA route is present. We can't
	// distinguish handler-returned 404 from router 404 by status code, so
	// inspect the route table directly. Each route is identified by its
	// (method, path-template) tuple.
	expected := map[string]string{
		"GET /api/v1/ca/info":                         "",
		"GET /api/v1/ca/certificates":                 "",
		"POST /api/v1/ca/certificates":                "",
		"POST /api/v1/ca/sign-csr":                    "",
		"GET /api/v1/ca/certificates/{serial}":        "",
		"DELETE /api/v1/ca/certificates/{serial}":     "",
		"POST /api/v1/ca/certificates/{serial}/renew": "",
		"POST /api/v1/ca/certificates/verify":         "",
		"GET /api/v1/ca/crl":                          "",
		"GET /api/v1/ca/bundle":                       "",
	}
	found := map[string]bool{}
	registered := map[string]bool{}
	walkErr := server.router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		for _, m := range methods {
			key := m + " " + tmpl
			registered[key] = true
			if _, ok := expected[key]; ok {
				found[key] = true
			}
		}
		return nil
	})
	require.NoError(t, walkErr)

	for key := range expected {
		assert.Truef(t, found[key], "route %q must be registered", key)
	}
	// Revocation moved to DELETE /api/v1/ca/certificates/{serial}
	// under certs:revoke; the old POST route must not come back.
	assert.False(t, registered["POST /api/v1/ca/certificates/{serial}/revoke"],
		"the retired POST revoke route must not be registered")
}

// tokenScopeGuard is the daemon's REST guard with tokens as its only
// credential; a nil validator stays a nil TokenAuthorizer, as in
// newRESTScopeGuard.
func tokenScopeGuard(tokens *platformTokenValidator) *restapi.ScopeGuard {
	if tokens == nil {
		return restapi.NewScopeGuard(nil, nil, nil)
	}
	return restapi.NewScopeGuard(tokens, nil, nil)
}

// signCSRStatus posts an empty sign-csr request, with bearer when it is set,
// to a REST server whose CA handlers are authorized by tokens.
func signCSRStatus(t *testing.T, tokens *platformTokenValidator, bearer string) int {
	t.Helper()
	config := DefaultConfig()
	service, err := NewService(config)
	require.NoError(t, err)
	server, err := NewRESTServer(config, service, slog.Default())
	require.NoError(t, err)
	server.SetCAHandlers(&fakeRESTCA{}, tokenScopeGuard(tokens))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/sign-csr", strings.NewReader(`{"csr_pem":"x"}`))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	return w.Code
}

// Without the platform-token validator nobody can hold ca:sign-csr, so the
// daemon's REST sign-csr refuses every bearer as unauthenticated.
func TestRESTServer_SetCAHandlers_SignCSRWithoutAValidator(t *testing.T) {
	t.Parallel()
	assert.Equal(t, http.StatusUnauthorized, signCSRStatus(t, nil, "token"))
}

// With the validator wired, sign-csr asks for a bearer token, and a token
// the validator refuses (here: a bearer without its required DPoP proof)
// is unauthenticated.
func TestRESTServer_SetCAHandlers_SignCSRUsesTheValidator(t *testing.T) {
	t.Parallel()
	assert.Equal(t, http.StatusUnauthorized, signCSRStatus(t, &platformTokenValidator{}, ""))
	assert.Equal(t, http.StatusUnauthorized, signCSRStatus(t, &platformTokenValidator{}, "token"))
}

// issueSubCAOverREST posts a subordinate CA issue request with pathLen 0 to
// the daemon's REST CA routes over ca, as a caller holding certs:generate.
func issueSubCAOverREST(t *testing.T, ca *configurableMockCA) (int, restapi.CAErrorResponse) {
	t.Helper()
	router := mux.NewRouter()
	guard := restapi.NewScopeGuard(tokenScopes{"op": {"certs:generate"}}, nil, nil)
	restapi.NewCAHandlers(restapi.NewCAAuthorityAdapter(ca), nil, nil).WithScopeGuard(guard).RegisterRoutes(router)

	body := `{"request":{"subject":{"common_name":"sub-ca.example.com"},"key_algorithm":"KEY_ALGORITHM_ECDSA_P256","store_type":"software","is_ca":true,"max_path_len":0}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer op")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var resp restapi.CAErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), "body %s", w.Body.String())
	return w.Code, resp
}

// A subordinate CA the issuer's path length forbids answers 400 with the
// refusal's message.
func TestRESTServer_CAIssue_PathLenRefusalIs400(t *testing.T) {
	t.Parallel()
	code, resp := issueSubCAOverREST(t, &configurableMockCA{issuedCert: createTestCertificate(t), caCertificate: pathLenZeroIssuer()})

	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, pathLenZeroRefusal(), resp.Error)
}

// A CA fault on a subordinate CA request stays a 500.
func TestRESTServer_CAIssue_CAFaultIs500(t *testing.T) {
	t.Parallel()
	code, _ := issueSubCAOverREST(t, &configurableMockCA{issueCertErr: errors.New("hsm offline")})

	assert.Equal(t, http.StatusInternalServerError, code)
}
