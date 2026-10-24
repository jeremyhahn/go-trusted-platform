package rest

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// listTemplatesFailingVTPM fails ListTemplates; the shared mock has no
// error hook for it.
type listTemplatesFailingVTPM struct {
	*mockVTPMService
	err error
}

func (s *listTemplatesFailingVTPM) ListTemplates(context.Context) ([]*vtpm.Template, error) {
	return nil, s.err
}

func serveVTPM(router *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func vtpmErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var errResp ErrorResponse
	decodeResponse(t, rec.Body, &errResp)
	assert.Equal(t, rec.Code, errResp.Code, "the body code mirrors the HTTP status")
	return errResp.Error
}

// The router never yields an empty {id}, so every ID-scoped handler is
// driven directly to prove it refuses before reaching the service.
func TestVTPMAPIRest_EmptyID(t *testing.T) {
	h, _ := setupVTPMTestHandler(newMockVTPMService())
	bundleHandlers := map[string]http.HandlerFunc{
		"get":        h.handleGetBundle,
		"delete":     h.handleDeleteBundle,
		"start":      h.handleStartBundle,
		"stop":       h.handleStopBundle,
		"state":      h.handleGetBundleState,
		"validate":   h.handleValidateBundle,
		"path":       h.handleGetBundlePath,
		"tpm-socket": h.handleGetTPMSocketPath,
		"nvram":      h.handleGetNVRAMPath,
		"quote":      h.handleQuote,
		"read pcr":   h.handleReadPCR,
		"extend pcr": h.handleExtendPCR,
		"seal":       h.handleSeal,
		"unseal":     h.handleUnseal,
		"export":     h.handleExportBundle,
	}
	templateHandlers := map[string]http.HandlerFunc{
		"get template":    h.handleGetTemplate,
		"delete template": h.handleDeleteTemplate,
		"clone template":  h.handleCloneTemplate,
	}

	run := func(handlers map[string]http.HandlerFunc, want error) {
		for name, handle := range handlers {
			t.Run(name, func(t *testing.T) {
				req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)),
					map[string]string{"id": "", "index": "0"})
				rec := httptest.NewRecorder()
				handle(rec, req)
				require.Equal(t, http.StatusBadRequest, rec.Code)
				assert.Equal(t, want.Error(), vtpmErrorMessage(t, rec))
			})
		}
	}
	run(bundleHandlers, ErrInvalidBundleID{})
	run(templateHandlers, ErrInvalidTemplateID{})
}

func TestVTPMAPIRest_MalformedBody(t *testing.T) {
	paths := map[string]string{
		"quote":           "/api/v1/vtpm/bundles/b1/quote",
		"extend pcr":      "/api/v1/vtpm/bundles/b1/pcr/7/extend",
		"seal":            "/api/v1/vtpm/bundles/b1/seal",
		"unseal":          "/api/v1/vtpm/bundles/b1/unseal",
		"create template": "/api/v1/vtpm/templates",
		"clone template":  "/api/v1/vtpm/templates/t1/clone",
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			svc := newMockVTPMService()
			svc.addTestBundle("b1", "host-1", true)
			_, router := setupVTPMTestHandler(svc)

			rec := serveVTPM(router, http.MethodPost, path, `{"data":`)

			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, ErrInvalidRequestBody{Reason: "unexpected EOF"}.Error(), vtpmErrorMessage(t, rec))
		})
	}
}

func TestVTPMAPIRest_ExtendPCRNonNumericIndex(t *testing.T) {
	svc := newMockVTPMService()
	svc.addTestBundle("b1", "host-1", true)
	_, router := setupVTPMTestHandler(svc)

	rec := serveVTPM(router, http.MethodPost, "/api/v1/vtpm/bundles/b1/pcr/seven/extend", `{"data":"AA=="}`)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, ErrVTPMInvalidPCRIndex{Index: -1}.Error(), vtpmErrorMessage(t, rec))
}

// A service failure is reported with its operation name and the status
// writeVTPMError assigns to the typed cause.
func TestVTPMAPIRest_ServiceErrors(t *testing.T) {
	cause := vtpm.ErrVTPMNotRunning{BundleID: "b1"}
	cases := []struct {
		name      string
		operation string
		setErr    func(m *mockVTPMService)
		method    string
		path      string
		body      string
	}{
		{"list bundles", "list", func(m *mockVTPMService) { m.listBundlesErr = cause }, http.MethodGet, "/api/v1/vtpm/bundles", ""},
		{"extend pcr", "extend_pcr", func(m *mockVTPMService) { m.extendPCRErr = cause }, http.MethodPost, "/api/v1/vtpm/bundles/b1/pcr/7/extend", `{"data":"AA=="}`},
		{"seal", "seal", func(m *mockVTPMService) { m.sealErr = cause }, http.MethodPost, "/api/v1/vtpm/bundles/b1/seal", `{"data":"AA=="}`},
		{"unseal", "unseal", func(m *mockVTPMService) { m.unsealErr = cause }, http.MethodPost, "/api/v1/vtpm/bundles/b1/unseal", `{"sealed_data":"AA=="}`},
		{"create template", "create_template", func(m *mockVTPMService) { m.createTemplateErr = cause }, http.MethodPost, "/api/v1/vtpm/templates", `{"id":"t1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newMockVTPMService()
			svc.addTestBundle("b1", "host-1", true)
			tc.setErr(svc)
			_, router := setupVTPMTestHandler(svc)

			rec := serveVTPM(router, tc.method, tc.path, tc.body)

			require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
			assert.Equal(t, ErrVTPMOperationFailed{Operation: tc.operation, Cause: cause}.Error(), vtpmErrorMessage(t, rec))
		})
	}
}

func TestVTPMAPIRest_ListTemplatesError(t *testing.T) {
	cause := errors.New("template store offline")
	h := NewVTPMHandlers(&listTemplatesFailingVTPM{mockVTPMService: newMockVTPMService(), err: cause}, slog.Default())
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	rec := serveVTPM(router, http.MethodGet, "/api/v1/vtpm/templates", "")

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, ErrVTPMOperationFailed{Operation: "list_templates", Cause: cause}.Error(), vtpmErrorMessage(t, rec))
}

func TestVTPMAPIRest_WriteVTPMErrorStatus(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{vtpm.ErrBundleNotFound{ID: "b"}, http.StatusNotFound},
		{vtpm.ErrBundleAlreadyExists{ID: "b"}, http.StatusConflict},
		{vtpm.ErrTemplateNotFound{ID: "t"}, http.StatusNotFound},
		{vtpm.ErrTemplateAlreadyExists{ID: "t"}, http.StatusConflict},
		{vtpm.ErrInvalidConfig{Field: "f", Reason: "r"}, http.StatusBadRequest},
		{vtpm.ErrInvalidEKAlgorithm{Algorithm: "DSA"}, http.StatusBadRequest},
		{vtpm.ErrInvalidManifest{Reason: "r"}, http.StatusBadRequest},
		{vtpm.ErrVTPMNotRunning{BundleID: "b"}, http.StatusConflict},
		{vtpm.ErrVTPMAlreadyRunning{BundleID: "b"}, http.StatusConflict},
		{vtpm.ErrInvalidNonce{Reason: "r"}, http.StatusBadRequest},
		{vtpm.ErrInvalidPCRIndex{PCRIndex: 99}, http.StatusBadRequest},
		{vtpm.ErrChecksumMismatch{File: "f", Expected: "a", Actual: "b"}, http.StatusUnprocessableEntity},
		{vtpm.ErrCAUnavailable{Cause: errors.New("down")}, http.StatusServiceUnavailable},
		{errors.New("untyped"), http.StatusInternalServerError},
	}
	h, _ := setupVTPMTestHandler(newMockVTPMService())
	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.writeVTPMError(rec, "op", tc.err)
			require.Equal(t, tc.want, rec.Code)
			assert.Equal(t, ErrVTPMOperationFailed{Operation: "op", Cause: tc.err}.Error(), vtpmErrorMessage(t, rec))
		})
	}
}

// An unencodable payload still commits the status and content type.
func TestVTPMAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	h, _ := setupVTPMTestHandler(newMockVTPMService())
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusOK, map[string]interface{}{"ch": make(chan int)})

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Empty(t, rec.Body.String())
}

func TestVTPMAPIRest_LabelParsing(t *testing.T) {
	assert.Nil(t, splitLabels(""))
	assert.Equal(t, []string{"a=1", "b=2"}, splitLabels("a=1,b=2"))

	key, value, ok := parseLabel("env=prod")
	assert.True(t, ok)
	assert.Equal(t, "env", key)
	assert.Equal(t, "prod", value)

	_, _, ok = parseLabel("novalue")
	assert.False(t, ok)
}
