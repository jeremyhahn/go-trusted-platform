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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

func serveJavaScriptSDKBody(service vtpm.VTPMService, path, body string) *httptest.ResponseRecorder {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	router := mux.NewRouter()
	NewVTPMRouter(logger, service, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestCreateBundle_JavaScriptSDKBody feeds the body the JavaScript SDK's
// createBundle sends (sdk/javascript/src/services/vtpm-service.ts).
func TestCreateBundle_JavaScriptSDKBody(t *testing.T) {
	var got *vtpm.CreateBundleOptions
	service := &mockVTPMService{
		createBundleFn: func(_ context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
			got = opts
			return createTestBundle("b1"), nil
		},
	}

	rec := serveJavaScriptSDKBody(service, "/api/v1/vtpm/bundles",
		`{"mode":"pre-assigned","hostname":"h1","ek_algorithm":"ECC","secure_boot_enabled":true,`+
			`"labels":{"env":"prod"},"template_id":"t1","device_profile_id":9}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, got)
	assert.Equal(t, vtpm.BundleModePreAssigned, got.Mode)
	assert.Equal(t, vtpm.EKAlgorithmECC, got.EKAlgorithm)
	assert.Equal(t, "h1", got.Hostname)
	assert.True(t, got.SecureBootEnabled)
	assert.Equal(t, map[string]string{"env": "prod"}, got.Labels)
	assert.Equal(t, "t1", got.TemplateID)
	assert.Equal(t, uint64(9), got.DeviceProfileID)
}

// TestCreateBundle_NestedOptionsBodyIsRefused pins why the SDK flattens the
// body: the {options:{...}} shape it used to send is refused before the service.
func TestCreateBundle_NestedOptionsBodyIsRefused(t *testing.T) {
	called := false
	service := &mockVTPMService{
		createBundleFn: func(_ context.Context, _ *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
			called = true
			return createTestBundle("b1"), nil
		},
	}

	rec := serveJavaScriptSDKBody(service, "/api/v1/vtpm/bundles",
		`{"options":{"mode":"PRE_ASSIGNED","hostname":"h1","ekAlgorithm":"ECC"}}`)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.False(t, called, "the service ran on a refused body")
}

// TestCreateTemplate_JavaScriptSDKBody feeds the body createTemplate sends.
func TestCreateTemplate_JavaScriptSDKBody(t *testing.T) {
	var got *vtpm.CreateTemplateOptions
	service := &mockVTPMService{
		createTemplateFn: func(_ context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
			got = opts
			return &vtpm.Template{ID: opts.ID}, nil
		},
	}

	rec := serveJavaScriptSDKBody(service, "/api/v1/vtpm/templates",
		`{"id":"t1","description":"base","ek_algorithm":"RSA","secure_boot_enabled":false}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, got)
	assert.Equal(t, "t1", got.ID)
	assert.Equal(t, "base", got.Description)
	assert.Equal(t, vtpm.EKAlgorithmRSA, got.EKAlgorithm)
}
