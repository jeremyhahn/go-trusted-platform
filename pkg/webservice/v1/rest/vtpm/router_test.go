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

package vtpm

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

func TestNewVTPMRouter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := &mockVTPMService{}
	writer := &mockHttpWriter{}

	router := NewVTPMRouter(logger, service, writer)

	require.NotNil(t, router)
	assert.NotNil(t, router.handlers)
}

func TestVTPMRouter_RegisterRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := &mockVTPMService{}
	writer := &mockHttpWriter{}

	vtpmRouter := NewVTPMRouter(logger, service, writer)
	muxRouter := mux.NewRouter()

	// Should not panic
	vtpmRouter.RegisterRoutes(muxRouter)

	// Verify that routes are registered by checking that the router can match them
	testCases := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/vtpm/bundles"},
		{"GET", "/api/v1/vtpm/bundles"},
		{"GET", "/api/v1/vtpm/bundles/test-id"},
		{"DELETE", "/api/v1/vtpm/bundles/test-id"},
		{"GET", "/api/v1/vtpm/bundles/test-id/export"},
		{"POST", "/api/v1/vtpm/bundles/import"},
		{"POST", "/api/v1/vtpm/bundles/test-id/validate"},
		{"GET", "/api/v1/vtpm/bundles/test-id/path"},
		{"GET", "/api/v1/vtpm/bundles/test-id/tpm-socket"},
		{"GET", "/api/v1/vtpm/bundles/test-id/nvram"},
		{"POST", "/api/v1/vtpm/templates"},
		{"GET", "/api/v1/vtpm/templates"},
		{"GET", "/api/v1/vtpm/templates/test-id"},
		{"DELETE", "/api/v1/vtpm/templates/test-id"},
		{"POST", "/api/v1/vtpm/templates/test-id/clone"},
	}

	for _, tc := range testCases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			match := &mux.RouteMatch{}
			matched := muxRouter.Match(req, match)
			assert.True(t, matched, "Route should be registered: %s %s", tc.method, tc.path)
		})
	}
}

func TestVTPMRouter_BundleRoutes_Functional(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)

	bundle := createTestBundle("test-bundle")
	service := &mockVTPMService{
		getBundleFn: func(ctx context.Context, id string) (*vtpm.Bundle, error) {
			return bundle, nil
		},
	}
	writer := &mockHttpWriter{}

	vtpmRouter := NewVTPMRouter(logger, service, writer)
	muxRouter := mux.NewRouter()
	vtpmRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle", nil)
	rec := httptest.NewRecorder()

	muxRouter.ServeHTTP(rec, req)

	// Route was matched (not 404)
	assert.NotEqual(t, http.StatusNotFound, rec.Code, "Route should be matched")
}

func TestVTPMRouter_TemplateRoutes_Functional(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)

	template := createTestTemplate("test-template")
	service := &mockVTPMService{
		getTemplateFn: func(ctx context.Context, id string) (*vtpm.Template, error) {
			return template, nil
		},
	}
	writer := &mockHttpWriter{}

	vtpmRouter := NewVTPMRouter(logger, service, writer)
	muxRouter := mux.NewRouter()
	vtpmRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/templates/test-template", nil)
	rec := httptest.NewRecorder()

	muxRouter.ServeHTTP(rec, req)

	// Route was matched (not 404)
	assert.NotEqual(t, http.StatusNotFound, rec.Code, "Route should be matched")
}

func TestVTPMRouter_UnregisteredRoute_Returns404(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := &mockVTPMService{}
	writer := &mockHttpWriter{}

	vtpmRouter := NewVTPMRouter(logger, service, writer)
	muxRouter := mux.NewRouter()
	vtpmRouter.RegisterRoutes(muxRouter)

	// Test that unregistered routes return 404
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/nonexistent", nil)
	rec := httptest.NewRecorder()

	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestVTPMRouter_WrongMethod_ReturnsNotFound(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	service := &mockVTPMService{}
	writer := &mockHttpWriter{}

	vtpmRouter := NewVTPMRouter(logger, service, writer)
	muxRouter := mux.NewRouter()
	vtpmRouter.RegisterRoutes(muxRouter)

	// Mux returns 404 for unmatched method on a registered path by default
	// (unless MethodNotAllowedHandler is configured). This tests that behavior.
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/vtpm/bundles", nil)
	rec := httptest.NewRecorder()

	muxRouter.ServeHTTP(rec, req)

	// PATCH is not registered, so it should not match any route
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestVTPMRouter_ListBundles_Functional(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)

	bundles := []*vtpm.Bundle{createTestBundle("b1"), createTestBundle("b2")}
	service := &mockVTPMService{
		listBundlesFn: func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
			return bundles, nil
		},
	}
	writer := &mockHttpWriter{}

	vtpmRouter := NewVTPMRouter(logger, service, writer)
	muxRouter := mux.NewRouter()
	vtpmRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles", nil)
	rec := httptest.NewRecorder()

	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestVTPMRouter_ListTemplates_Functional(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)

	templates := []*vtpm.Template{createTestTemplate("t1"), createTestTemplate("t2")}
	service := &mockVTPMService{
		listTemplatesFn: func(ctx context.Context) ([]*vtpm.Template, error) {
			return templates, nil
		},
	}
	writer := &mockHttpWriter{}

	vtpmRouter := NewVTPMRouter(logger, service, writer)
	muxRouter := mux.NewRouter()
	vtpmRouter.RegisterRoutes(muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/templates", nil)
	rec := httptest.NewRecorder()

	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
