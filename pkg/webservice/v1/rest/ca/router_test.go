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

package ca

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newTestRouter creates a mux.Router with the /api/v1 subrouter to match
// production setup in webserver_v1.go, and registers BOTH halves of the CA
// surface on it — the public routes and the protected ones — exactly as
// v1Router.caRoutes does. Tests that care which half a route belongs to
// register the halves separately instead.
func newTestRouter(caRouter *CARouter) *mux.Router {
	router := mux.NewRouter()
	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	caRouter.RegisterPublicRoutes(apiRouter)
	caRouter.RegisterRoutes(apiRouter)
	return router
}

// registeredPaths returns the set of "METHOD /path" strings a single
// registration method installs, so a test can assert the public/protected
// split by its actual effect on the route table rather than by reading the
// source.
func registeredPaths(register func(*mux.Router)) map[string]bool {
	router := mux.NewRouter()
	register(router.PathPrefix("/api/v1").Subrouter())

	out := map[string]bool{}
	_ = router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		for _, m := range methods {
			out[m+" "+path] = true
		}
		return nil
	})
	return out
}

// =============================================================================
// NewCARouter Tests
// =============================================================================

func TestNewCARouter(t *testing.T) {
	t.Run("creates router with all dependencies", func(t *testing.T) {
		logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
		mockCA := &mockCertificateAuthority{}
		writer := &mockHttpWriter{}

		router := NewCARouter(logger, mockCA, writer)

		require.NotNil(t, router)
		assert.NotNil(t, router.handlers)
	})

	t.Run("creates router with nil CA", func(t *testing.T) {
		logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
		writer := &mockHttpWriter{}

		router := NewCARouter(logger, nil, writer)

		require.NotNil(t, router)
		assert.NotNil(t, router.handlers)
	})
}

// =============================================================================
// RegisterRoutes Tests
// =============================================================================

func TestRegisterRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	// Test that all routes are registered correctly
	tests := []struct {
		name   string
		method string
		path   string
	}{
		// CA Info routes
		{"get CA info", http.MethodGet, "/api/v1/ca/info"},

		// Certificate routes
		{"list certificates", http.MethodGet, "/api/v1/ca/certificates"},
		{"issue certificate", http.MethodPost, "/api/v1/ca/certificates"},
		{"get certificate", http.MethodGet, "/api/v1/ca/certificates/abc123"},
		{"revoke certificate", http.MethodDelete, "/api/v1/ca/certificates/abc123"},

		// Bundle routes
		{"get bundle", http.MethodGet, "/api/v1/ca/bundle"},

		// Bootstrap routes
		{"get bootstrap bundle", http.MethodGet, "/api/v1/ca/bootstrap"},

		// CRL routes
		{"get CRL", http.MethodGet, "/api/v1/ca/crl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched, "route should match: %s %s", tt.method, tt.path)
		})
	}
}

// =============================================================================
// Info Routes Tests
// =============================================================================

func TestInfoRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	t.Run("GET /info route registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		require.True(t, matched)
	})

	t.Run("POST /info route not registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/info", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		// Should not match (method not allowed)
		assert.False(t, matched || match.MatchErr == nil)
	})
}

// =============================================================================
// Certificate Routes Tests
// =============================================================================

func TestCertificateRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	tests := []struct {
		name         string
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			name:   "list certificates",
			method: http.MethodGet,
			path:   "/api/v1/ca/certificates",
		},
		{
			name:   "issue certificate",
			method: http.MethodPost,
			path:   "/api/v1/ca/certificates",
		},
		{
			name:         "get certificate by serial",
			method:       http.MethodGet,
			path:         "/api/v1/ca/certificates/abc123def456",
			expectedVars: map[string]string{"serial": "abc123def456"},
		},
		{
			name:         "revoke certificate by serial",
			method:       http.MethodDelete,
			path:         "/api/v1/ca/certificates/abc123def456",
			expectedVars: map[string]string{"serial": "abc123def456"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched, "route should match: %s %s", tt.method, tt.path)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestCertificateRoutes_SerialWithSpecialCharacters(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	tests := []struct {
		name   string
		serial string
	}{
		{"hex serial", "0123456789abcdef"},
		{"uppercase hex", "ABCDEF0123456789"},
		{"mixed case", "AbCdEf0123456789"},
		{"long serial", "000102030405060708090a0b0c0d0e0f"},
		{"short serial", "01"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates/"+tt.serial, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)
			assert.Equal(t, tt.serial, match.Vars["serial"])
		})
	}
}

// =============================================================================
// Bundle Routes Tests
// =============================================================================

func TestBundleRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	t.Run("GET /bundle route registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		require.True(t, matched)
	})

	t.Run("POST /bundle route not registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/bundle", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		assert.False(t, matched || match.MatchErr == nil)
	})
}

// =============================================================================
// CRL Routes Tests
// =============================================================================

func TestCRLRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	t.Run("GET /crl route registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/crl", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		require.True(t, matched)
	})

	t.Run("POST /crl route not registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/crl", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		assert.False(t, matched || match.MatchErr == nil)
	})
}

// =============================================================================
// Method Not Allowed Tests
// =============================================================================

func TestRoutes_MethodNotAllowed(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"PATCH on info", http.MethodPatch, "/api/v1/ca/info"},
		{"PUT on info", http.MethodPut, "/api/v1/ca/info"},
		{"DELETE on info", http.MethodDelete, "/api/v1/ca/info"},
		{"PATCH on certificates", http.MethodPatch, "/api/v1/ca/certificates"},
		{"PUT on certificates collection", http.MethodPut, "/api/v1/ca/certificates"},
		{"POST on bundle", http.MethodPost, "/api/v1/ca/bundle"},
		{"DELETE on bundle", http.MethodDelete, "/api/v1/ca/bundle"},
		{"POST on crl", http.MethodPost, "/api/v1/ca/crl"},
		{"DELETE on crl", http.MethodDelete, "/api/v1/ca/crl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			// These methods should not match
			assert.False(t, matched || match.MatchErr == nil,
				"unexpected method %s should not match for %s", tt.method, tt.path)
		})
	}
}

// =============================================================================
// Not Found Tests
// =============================================================================

func TestRoutes_NotFound(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"non-existent resource", http.MethodGet, "/api/v1/ca/nonexistent"},
		{"missing version", http.MethodGet, "/api/ca/info"},
		{"wrong version", http.MethodGet, "/api/v2/ca/info"},
		{"incomplete path", http.MethodGet, "/api/v1/ca"},
		{"different API", http.MethodGet, "/api/v1/other/info"},
		{"no API prefix", http.MethodGet, "/ca/info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.False(t, matched, "non-existent path should not match: %s", tt.path)
		})
	}
}

// =============================================================================
// Base Path Tests
// =============================================================================

func TestBasePath_Constant(t *testing.T) {
	assert.Equal(t, "/ca", basePath)
}

// =============================================================================
// Subrouter Isolation Tests
// =============================================================================

func TestRoutes_SubrouterIsolation(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := mux.NewRouter()
	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	caRouter.RegisterPublicRoutes(apiRouter)
	caRouter.RegisterRoutes(apiRouter)

	// Add a different route to ensure CA routes don't interfere
	router.HandleFunc("/api/v1/other", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)

	// Verify both CA and other routes work
	t.Run("CA route works", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		assert.True(t, matched)
	})

	t.Run("other route works", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/other", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		assert.True(t, matched)
	})
}

// =============================================================================
// Handler Execution Tests
// =============================================================================

func TestRoutes_HandlerExecution(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{
		initialized: true,
		rootCert:    createTestRootCertificate(),
	}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	t.Run("GET /info handler executes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
	})

	t.Run("GET /certificates handler executes", func(t *testing.T) {
		mockCA.certStore = &mockCertStore{}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates", nil)
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, writer.lastStatus)
	})
}

// =============================================================================
// Query Parameter Tests
// =============================================================================

func TestRoutes_WithQueryParameters(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{
		initialized: true,
		rootCert:    createTestRootCertificate(),
		certStore:   &mockCertStore{},
	}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	tests := []struct {
		name string
		path string
	}{
		{"certificates with limit", "/api/v1/ca/certificates?limit=10"},
		{"certificates with cursor", "/api/v1/ca/certificates?cursor=abc123"},
		{"certificates with both", "/api/v1/ca/certificates?limit=50&cursor=xyz"},
		{"certificate with include_pem", "/api/v1/ca/certificates/abc123?include_pem=true"},
		{"bundle with store_type", "/api/v1/ca/bundle?store_type=software"},
		{"bundle with algorithm", "/api/v1/ca/bundle?algorithm=ECDSA"},
		{"bundle with both", "/api/v1/ca/bundle?store_type=tpm2&algorithm=RSA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched, "route with query params should match: %s", tt.path)
		})
	}
}

// =============================================================================
// Route Order Priority Tests
// =============================================================================

func TestRoutes_OrderPriority(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	// The specific certificate route should match, not be interpreted as a collection action
	t.Run("specific serial route matches correctly", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates/specific-serial", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		require.True(t, matched)
		assert.Equal(t, "specific-serial", match.Vars["serial"])
	})

	// Collection routes should not have serial var
	t.Run("collection route has no serial var", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificates", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		require.True(t, matched)
		_, hasSerial := match.Vars["serial"]
		assert.False(t, hasSerial, "collection route should not have serial variable")
	})
}

// =============================================================================
// Multiple Registrations Test
// =============================================================================

func TestRoutes_MultipleRegistrations(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	// Create a second router on different base
	router2 := newTestRouter(caRouter)

	t.Run("first router still works", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
		var match mux.RouteMatch
		matched := router.Match(req, &match)
		assert.True(t, matched)
	})

	t.Run("second router also works", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
		var match mux.RouteMatch
		matched := router2.Match(req, &match)
		assert.True(t, matched)
	})
}

// =============================================================================
// Content Type Headers Test
// =============================================================================

func TestRoutes_AcceptsContentTypes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	mockCA := &mockCertificateAuthority{
		initialized: true,
		rootCert:    createTestRootCertificate(),
	}
	writer := &mockHttpWriter{}

	caRouter := NewCARouter(logger, mockCA, writer)
	router := newTestRouter(caRouter)

	contentTypes := []string{
		"application/json",
		"application/yaml",
		"text/json",
		"text/yaml",
	}

	for _, ct := range contentTypes {
		t.Run("accepts "+ct, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/info", nil)
			req.Header.Set("Accept", ct)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			// Should not return 406 Not Acceptable
			assert.NotEqual(t, http.StatusNotAcceptable, rec.Code)
		})
	}
}

// =============================================================================
// Public / protected split (issue #165)
// =============================================================================

// TestRegisterRoutes_RegistersOnlyTheProtectedHalf pins the half of the CA
// surface that must sit behind the caller's gate. If a route moves out of
// this method it silently becomes reachable without a credential, which is
// the defect #165 exists to close, so the assertion is exact in both
// directions: these routes and no others.
func TestRegisterRoutes_RegistersOnlyTheProtectedHalf(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	caRouter := NewCARouter(logger, &mockCertificateAuthority{}, &mockHttpWriter{})

	got := registeredPaths(caRouter.RegisterRoutes)

	want := map[string]bool{
		"POST /api/v1/ca/certificates":            true,
		"GET /api/v1/ca/certificates":             true,
		"GET /api/v1/ca/certificates/{serial}":    true,
		"DELETE /api/v1/ca/certificates/{serial}": true,
	}
	assert.Equal(t, want, got,
		"the protected CA half must be exactly issuance, revocation and the issued-certificate inventory")
}

// TestRegisterPublicRoutes_RegistersOnlyTheUnauthenticatedHalf pins the
// half that must stay reachable without a credential. A privileged route
// added here would be published to anonymous callers, so this asserts the
// exact set too — and, together with the protected assertion above, that
// the two halves do not overlap.
func TestRegisterPublicRoutes_RegistersOnlyTheUnauthenticatedHalf(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	caRouter := NewCARouter(logger, &mockCertificateAuthority{}, &mockHttpWriter{})

	got := registeredPaths(caRouter.RegisterPublicRoutes)

	want := map[string]bool{
		"GET /api/v1/ca/info":         true,
		"GET /api/v1/ca/root":         true,
		"GET /api/v1/ca/intermediate": true,
		"GET /api/v1/ca/bundle":       true,
		"GET /api/v1/ca/bootstrap":    true,
		"GET /api/v1/ca/crl":          true,
	}
	assert.Equal(t, want, got,
		"the public CA half must be exactly the CA's own chain, the CRL and the trust-bootstrap fetch")

	for route := range got {
		assert.True(t, strings.HasPrefix(route, "GET "),
			"a public CA route may not mutate CA state: %s", route)
	}
}

// TestRegisterRoutes_HalvesAreDisjointAndCoverTheSurface proves the split
// lost nothing: together the two methods register every route the CA had
// before it was divided, and no route appears in both.
func TestRegisterRoutes_HalvesAreDisjointAndCoverTheSurface(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	caRouter := NewCARouter(logger, &mockCertificateAuthority{}, &mockHttpWriter{})

	protected := registeredPaths(caRouter.RegisterRoutes)
	public := registeredPaths(caRouter.RegisterPublicRoutes)

	for route := range protected {
		assert.False(t, public[route], "route is in both halves: %s", route)
	}

	union := map[string]bool{}
	for route := range protected {
		union[route] = true
	}
	for route := range public {
		union[route] = true
	}
	assert.Equal(t, registeredPaths(func(r *mux.Router) {
		caRouter.RegisterPublicRoutes(r)
		caRouter.RegisterRoutes(r)
	}), union, "the two halves must cover the whole CA surface")
	assert.Len(t, union, 10)
}
