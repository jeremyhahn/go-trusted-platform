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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// mockVTPMService implements vtpm.VTPMService for testing.
type mockVTPMService struct {
	createBundleFn   func(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error)
	getBundleFn      func(ctx context.Context, id string) (*vtpm.Bundle, error)
	deleteBundleFn   func(ctx context.Context, id string) error
	listBundlesFn    func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error)
	createTemplateFn func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error)
	cloneTemplateFn  func(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error)
	getTemplateFn    func(ctx context.Context, id string) (*vtpm.Template, error)
	deleteTemplateFn func(ctx context.Context, id string) error
	listTemplatesFn  func(ctx context.Context) ([]*vtpm.Template, error)
	exportBundleFn   func(ctx context.Context, id string, w io.Writer) error
	importBundleFn   func(ctx context.Context, r io.Reader) (*vtpm.Bundle, error)
	validateBundleFn func(ctx context.Context, id string) error
	getBundlePathFn  func(id string) string
	getTPMSocketFn   func(id string) string
	getNVRAMPathFn   func(id string) string
}

func (m *mockVTPMService) CreateBundle(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
	if m.createBundleFn != nil {
		return m.createBundleFn(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) GetBundle(ctx context.Context, id string) (*vtpm.Bundle, error) {
	if m.getBundleFn != nil {
		return m.getBundleFn(ctx, id)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) DeleteBundle(ctx context.Context, id string) error {
	if m.deleteBundleFn != nil {
		return m.deleteBundleFn(ctx, id)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) ListBundles(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
	if m.listBundlesFn != nil {
		return m.listBundlesFn(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
	if m.createTemplateFn != nil {
		return m.createTemplateFn(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) CloneTemplate(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
	if m.cloneTemplateFn != nil {
		return m.cloneTemplateFn(ctx, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) GetTemplate(ctx context.Context, id string) (*vtpm.Template, error) {
	if m.getTemplateFn != nil {
		return m.getTemplateFn(ctx, id)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) DeleteTemplate(ctx context.Context, id string) error {
	if m.deleteTemplateFn != nil {
		return m.deleteTemplateFn(ctx, id)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) ListTemplates(ctx context.Context) ([]*vtpm.Template, error) {
	if m.listTemplatesFn != nil {
		return m.listTemplatesFn(ctx)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	if m.exportBundleFn != nil {
		return m.exportBundleFn(ctx, id, w)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) ImportBundle(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
	if m.importBundleFn != nil {
		return m.importBundleFn(ctx, r)
	}
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) ValidateBundle(ctx context.Context, id string) error {
	if m.validateBundleFn != nil {
		return m.validateBundleFn(ctx, id)
	}
	return errors.New("not implemented")
}

func (m *mockVTPMService) GetBundlePath(id string) string {
	if m.getBundlePathFn != nil {
		return m.getBundlePathFn(id)
	}
	return "/bundles/" + id
}

func (m *mockVTPMService) GetTPMSocketPath(id string) string {
	if m.getTPMSocketFn != nil {
		return m.getTPMSocketFn(id)
	}
	return "/bundles/" + id + "/tpm/swtpm.sock"
}

func (m *mockVTPMService) GetNVRAMPath(id string) string {
	if m.getNVRAMPathFn != nil {
		return m.getNVRAMPathFn(id)
	}
	return "/bundles/" + id + "/ovmf/OVMF_VARS.fd"
}

func (m *mockVTPMService) Close() error {
	return nil
}

// Runtime TPM operations (required for VTPMService interface)
func (m *mockVTPMService) Start(ctx context.Context, bundleID string) error {
	return errors.New("not implemented")
}

func (m *mockVTPMService) Stop(ctx context.Context, bundleID string) error {
	return errors.New("not implemented")
}

func (m *mockVTPMService) IsRunning(bundleID string) bool {
	return false
}

func (m *mockVTPMService) Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) Seal(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockVTPMService) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	return errors.New("not implemented")
}

func (m *mockVTPMService) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// mockHttpWriter implements response.HttpWriter for testing.
type mockHttpWriter struct {
	lastStatus  int
	lastPayload interface{}
	lastError   error
}

func (m *mockHttpWriter) Write(w http.ResponseWriter, r *http.Request, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) WriteYaml(w http.ResponseWriter, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
}

func (m *mockHttpWriter) WriteJson(w http.ResponseWriter, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusOK
	m.lastPayload = payload
	w.WriteHeader(http.StatusOK)
	resp := restwire.WebServiceResponse{Code: 200, Success: true, Payload: payload}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusCreated
	m.lastPayload = payload
	w.WriteHeader(http.StatusCreated)
	resp := restwire.WebServiceResponse{Code: 201, Success: true, Payload: payload}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastPayload = payload
	m.lastError = err
	w.WriteHeader(http.StatusNotFound)
}

func (m *mockHttpWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusOK
	m.lastError = err
	w.WriteHeader(http.StatusOK)
}

func (m *mockHttpWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusBadRequest
	m.lastError = err
	w.WriteHeader(http.StatusBadRequest)
	resp := restwire.WebServiceResponse{Code: 400, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusUnauthorized
	m.lastError = err
	w.WriteHeader(http.StatusUnauthorized)
}

func (m *mockHttpWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.lastStatus = http.StatusForbidden
	m.lastError = err
	m.lastPayload = payload
	w.WriteHeader(http.StatusForbidden)
}

func (m *mockHttpWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastError = err
	w.WriteHeader(http.StatusNotFound)
	resp := restwire.WebServiceResponse{Code: 404, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusInternalServerError
	m.lastError = err
	w.WriteHeader(http.StatusInternalServerError)
	resp := restwire.WebServiceResponse{Code: 500, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

// Helper functions for tests

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, os.Stdout)
}

func newTestHandlers(service *mockVTPMService) (*VTPMHandlers, *mockHttpWriter) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewVTPMHandlers(logger, service, writer)
	return handlers, writer
}

func createRequestWithVars(method, path string, body interface{}, vars map[string]string) *http.Request {
	var reqBody bytes.Buffer
	if body != nil {
		json.NewEncoder(&reqBody).Encode(body)
	}

	req := httptest.NewRequest(method, path, &reqBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if vars != nil {
		req = mux.SetURLVars(req, vars)
	}

	return req
}

func createTestBundle(id string) *vtpm.Bundle {
	now := time.Now()
	return &vtpm.Bundle{
		ID:   id,
		Mode: vtpm.BundleModePreAssigned,
		Manifest: &vtpm.Manifest{
			Version:           "1.0",
			ID:                id,
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          "test-host",
			CreatedAt:         now,
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			EKHandle:          0x01C00002,
			SecureBootEnabled: true,
			Checksums:         map[string]string{"tpm/tpm2-00.permall": "sha256:abc123"},
			Labels:            map[string]string{"env": "test"},
		},
		TPMState: &vtpm.TPMState{
			StateDir:    "/bundles/" + id + "/tpm",
			PermallFile: "/bundles/" + id + "/tpm/tpm2-00.permall",
		},
		OVMFState: &vtpm.OVMFState{
			NVRAMFile: "/bundles/" + id + "/ovmf/OVMF_VARS.fd",
		},
		SecureBootKeys: &vtpm.SecureBootKeyPaths{
			Dir:     "/bundles/" + id + "/secure-boot-keys",
			PKKey:   "/bundles/" + id + "/secure-boot-keys/PK.key",
			PKCert:  "/bundles/" + id + "/secure-boot-keys/PK.crt",
			KEKKey:  "/bundles/" + id + "/secure-boot-keys/KEK.key",
			KEKCert: "/bundles/" + id + "/secure-boot-keys/KEK.crt",
			DBKey:   "/bundles/" + id + "/secure-boot-keys/DB.key",
			DBCert:  "/bundles/" + id + "/secure-boot-keys/DB.crt",
		},
		CreatedAt: now,
	}
}

func createTestTemplate(id string) *vtpm.Template {
	now := time.Now()
	return &vtpm.Template{
		ID:                id,
		Description:       "Test template",
		TPMStateDir:       "/templates/" + id + "/tpm",
		NVRAMPath:         "/templates/" + id + "/ovmf/OVMF_VARS.fd",
		SecureBootKeysDir: "/templates/" + id + "/secure-boot-keys",
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: true,
		CreatedAt:         now,
	}
}

// Tests for NewVTPMHandlers

func TestNewVTPMHandlers(t *testing.T) {
	logger := newTestLogger()
	service := &mockVTPMService{}
	writer := &mockHttpWriter{}

	handlers := NewVTPMHandlers(logger, service, writer)

	require.NotNil(t, handlers)
	assert.NotNil(t, handlers.logger)
	assert.NotNil(t, handlers.service)
	assert.NotNil(t, handlers.respWriter)
}

// Tests for CreateBundle

func TestCreateBundle_Success(t *testing.T) {
	bundle := createTestBundle("test-bundle-123")

	service := &mockVTPMService{
		createBundleFn: func(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
			assert.Equal(t, vtpm.BundleModePreAssigned, opts.Mode)
			assert.Equal(t, "test-host", opts.Hostname)
			assert.Equal(t, vtpm.EKAlgorithmRSA, opts.EKAlgorithm)
			assert.True(t, opts.SecureBootEnabled)
			return bundle, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := CreateBundleRequest{
		Mode:              "pre-assigned",
		Hostname:          "test-host",
		EKAlgorithm:       "RSA",
		SecureBootEnabled: true,
		Labels:            map[string]string{"env": "test"},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateBundle(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(BundleResponse)
	require.True(t, ok)
	assert.Equal(t, "test-bundle-123", payload.ID)
	assert.Equal(t, "pre-assigned", payload.Mode)
}

func TestCreateBundle_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.CreateBundle(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestCreateBundle_InvalidBundleMode(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	body := CreateBundleRequest{
		Mode:     "invalid-mode",
		Hostname: "test-host",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateBundle(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidBundleMode)
	assert.True(t, ok)
}

func TestCreateBundle_UnknownEKAlgorithmDefaultsToRSA(t *testing.T) {
	// When an unknown EK algorithm is provided, parseEKAlgorithm defaults to RSA
	// which is always valid. This tests that the service is called with RSA.
	bundle := createTestBundle("test-bundle")

	service := &mockVTPMService{
		createBundleFn: func(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
			// Unknown algorithm defaults to RSA
			assert.Equal(t, vtpm.EKAlgorithmRSA, opts.EKAlgorithm)
			return bundle, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := CreateBundleRequest{
		Mode:        "pre-assigned",
		Hostname:    "test-host",
		EKAlgorithm: "UNKNOWN",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateBundle(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestCreateBundle_MissingHostname(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	body := CreateBundleRequest{
		Mode: "pre-assigned",
		// Hostname omitted
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateBundle(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingHostname)
	assert.True(t, ok)
}

func TestCreateBundle_ServiceError(t *testing.T) {
	service := &mockVTPMService{
		createBundleFn: func(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
			return nil, errors.New("internal service error")
		},
	}

	handlers, writer := newTestHandlers(service)

	body := CreateBundleRequest{
		Mode:     "template",
		Hostname: "",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateBundle(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestCreateBundle_ECCAlgorithm(t *testing.T) {
	bundle := createTestBundle("ecc-bundle")
	bundle.Manifest.EKAlgorithm = vtpm.EKAlgorithmECC

	service := &mockVTPMService{
		createBundleFn: func(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
			assert.Equal(t, vtpm.EKAlgorithmECC, opts.EKAlgorithm)
			return bundle, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := CreateBundleRequest{
		Mode:        "template",
		EKAlgorithm: "ECC",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateBundle(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

// Tests for GetBundle

func TestGetBundle_Success(t *testing.T) {
	bundle := createTestBundle("bundle-123")

	service := &mockVTPMService{
		getBundleFn: func(ctx context.Context, id string) (*vtpm.Bundle, error) {
			assert.Equal(t, "bundle-123", id)
			return bundle, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/bundle-123", nil, map[string]string{"id": "bundle-123"})
	rec := httptest.NewRecorder()

	handlers.GetBundle(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(BundleResponse)
	require.True(t, ok)
	assert.Equal(t, "bundle-123", payload.ID)
}

func TestGetBundle_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/", nil, map[string]string{"id": ""})
	rec := httptest.NewRecorder()

	handlers.GetBundle(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingBundleID)
	assert.True(t, ok)
}

func TestGetBundle_NotFound(t *testing.T) {
	service := &mockVTPMService{
		getBundleFn: func(ctx context.Context, id string) (*vtpm.Bundle, error) {
			return nil, errors.New("bundle not found")
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/nonexistent", nil, map[string]string{"id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetBundle(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Tests for DeleteBundle

func TestDeleteBundle_Success(t *testing.T) {
	service := &mockVTPMService{
		deleteBundleFn: func(ctx context.Context, id string) error {
			assert.Equal(t, "bundle-to-delete", id)
			return nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/vtpm/bundles/bundle-to-delete", nil, map[string]string{"id": "bundle-to-delete"})
	rec := httptest.NewRecorder()

	handlers.DeleteBundle(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(SuccessResponse)
	require.True(t, ok)
	assert.True(t, payload.Success)
	assert.Equal(t, "bundle deleted successfully", payload.Message)
}

func TestDeleteBundle_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/vtpm/bundles/", nil, map[string]string{"id": ""})
	rec := httptest.NewRecorder()

	handlers.DeleteBundle(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingBundleID)
	assert.True(t, ok)
}

func TestDeleteBundle_NotFound(t *testing.T) {
	service := &mockVTPMService{
		deleteBundleFn: func(ctx context.Context, id string) error {
			return errors.New("bundle does not exist")
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/vtpm/bundles/nonexistent", nil, map[string]string{"id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.DeleteBundle(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Tests for ListBundles

func TestListBundles_Success(t *testing.T) {
	bundles := []*vtpm.Bundle{
		createTestBundle("bundle-1"),
		createTestBundle("bundle-2"),
	}

	service := &mockVTPMService{
		listBundlesFn: func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
			return bundles, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListBundles(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListBundlesResponse)
	require.True(t, ok)
	assert.Equal(t, 2, len(payload.Bundles))
	assert.Equal(t, 2, payload.Total)
}

func TestListBundles_WithPagination(t *testing.T) {
	service := &mockVTPMService{
		listBundlesFn: func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
			assert.Equal(t, 10, opts.Limit)
			assert.Equal(t, 5, opts.Offset)
			return []*vtpm.Bundle{}, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?limit=10&offset=5", nil)
	rec := httptest.NewRecorder()

	handlers.ListBundles(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestListBundles_WithModeFilter(t *testing.T) {
	service := &mockVTPMService{
		listBundlesFn: func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
			assert.Equal(t, vtpm.BundleModeTemplate, opts.Mode)
			return []*vtpm.Bundle{}, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?mode=template", nil)
	rec := httptest.NewRecorder()

	handlers.ListBundles(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestListBundles_EmptyList(t *testing.T) {
	service := &mockVTPMService{
		listBundlesFn: func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
			return []*vtpm.Bundle{}, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListBundles(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListBundlesResponse)
	require.True(t, ok)
	assert.Equal(t, 0, len(payload.Bundles))
	assert.Equal(t, 0, payload.Total)
}

func TestListBundles_ServiceError(t *testing.T) {
	service := &mockVTPMService{
		listBundlesFn: func(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
			return nil, errors.New("database error")
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListBundles(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Tests for CreateTemplate

func TestCreateTemplate_Success(t *testing.T) {
	template := createTestTemplate("test-template")

	service := &mockVTPMService{
		createTemplateFn: func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
			assert.Equal(t, "test-template", opts.ID)
			assert.Equal(t, "A test template", opts.Description)
			assert.Equal(t, vtpm.EKAlgorithmRSA, opts.EKAlgorithm)
			assert.True(t, opts.SecureBootEnabled)
			return template, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := CreateTemplateRequest{
		ID:                "test-template",
		Description:       "A test template",
		EKAlgorithm:       "RSA",
		SecureBootEnabled: true,
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/templates", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateTemplate(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(TemplateResponse)
	require.True(t, ok)
	assert.Equal(t, "test-template", payload.ID)
}

func TestCreateTemplate_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.CreateTemplate(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestCreateTemplate_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	body := CreateTemplateRequest{
		Description: "No ID template",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/templates", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateTemplate(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingTemplateID)
	assert.True(t, ok)
}

func TestCreateTemplate_UnknownEKAlgorithmDefaultsToRSA(t *testing.T) {
	// When an unknown EK algorithm is provided, parseEKAlgorithm defaults to RSA
	// which is always valid. This tests that the service is called with RSA.
	template := createTestTemplate("test-template")

	service := &mockVTPMService{
		createTemplateFn: func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
			// Unknown algorithm defaults to RSA
			assert.Equal(t, vtpm.EKAlgorithmRSA, opts.EKAlgorithm)
			return template, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := CreateTemplateRequest{
		ID:          "my-template",
		EKAlgorithm: "UNKNOWN",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/templates", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateTemplate(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestCreateTemplate_ServiceError(t *testing.T) {
	service := &mockVTPMService{
		createTemplateFn: func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
			return nil, errors.New("service failure")
		},
	}

	handlers, writer := newTestHandlers(service)

	body := CreateTemplateRequest{
		ID: "test-template",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/templates", body, nil)
	rec := httptest.NewRecorder()

	handlers.CreateTemplate(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Tests for GetTemplate

func TestGetTemplate_Success(t *testing.T) {
	template := createTestTemplate("template-123")

	service := &mockVTPMService{
		getTemplateFn: func(ctx context.Context, id string) (*vtpm.Template, error) {
			assert.Equal(t, "template-123", id)
			return template, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/templates/template-123", nil, map[string]string{"id": "template-123"})
	rec := httptest.NewRecorder()

	handlers.GetTemplate(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(TemplateResponse)
	require.True(t, ok)
	assert.Equal(t, "template-123", payload.ID)
}

func TestGetTemplate_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/templates/", nil, map[string]string{"id": ""})
	rec := httptest.NewRecorder()

	handlers.GetTemplate(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingTemplateID)
	assert.True(t, ok)
}

func TestGetTemplate_NotFound(t *testing.T) {
	service := &mockVTPMService{
		getTemplateFn: func(ctx context.Context, id string) (*vtpm.Template, error) {
			return nil, errors.New("template not found")
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/templates/nonexistent", nil, map[string]string{"id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.GetTemplate(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Tests for DeleteTemplate

func TestDeleteTemplate_Success(t *testing.T) {
	service := &mockVTPMService{
		deleteTemplateFn: func(ctx context.Context, id string) error {
			assert.Equal(t, "template-to-delete", id)
			return nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/vtpm/templates/template-to-delete", nil, map[string]string{"id": "template-to-delete"})
	rec := httptest.NewRecorder()

	handlers.DeleteTemplate(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(SuccessResponse)
	require.True(t, ok)
	assert.True(t, payload.Success)
	assert.Equal(t, "template deleted successfully", payload.Message)
}

func TestDeleteTemplate_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := createRequestWithVars(http.MethodDelete, "/api/v1/vtpm/templates/", nil, map[string]string{"id": ""})
	rec := httptest.NewRecorder()

	handlers.DeleteTemplate(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingTemplateID)
	assert.True(t, ok)
}

func TestDeleteTemplate_NotFound(t *testing.T) {
	service := &mockVTPMService{
		deleteTemplateFn: func(ctx context.Context, id string) error {
			return errors.New("template does not exist")
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/vtpm/templates/nonexistent", nil, map[string]string{"id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.DeleteTemplate(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Tests for ListTemplates

func TestListTemplates_Success(t *testing.T) {
	templates := []*vtpm.Template{
		createTestTemplate("template-1"),
		createTestTemplate("template-2"),
	}

	service := &mockVTPMService{
		listTemplatesFn: func(ctx context.Context) ([]*vtpm.Template, error) {
			return templates, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/templates", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListTemplates(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListTemplatesResponse)
	require.True(t, ok)
	assert.Equal(t, 2, len(payload.Templates))
}

func TestListTemplates_Empty(t *testing.T) {
	service := &mockVTPMService{
		listTemplatesFn: func(ctx context.Context) ([]*vtpm.Template, error) {
			return []*vtpm.Template{}, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/templates", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListTemplates(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListTemplatesResponse)
	require.True(t, ok)
	assert.Equal(t, 0, len(payload.Templates))
}

func TestListTemplates_ServiceError(t *testing.T) {
	service := &mockVTPMService{
		listTemplatesFn: func(ctx context.Context) ([]*vtpm.Template, error) {
			return nil, errors.New("listing failed")
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/templates", nil, nil)
	rec := httptest.NewRecorder()

	handlers.ListTemplates(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Tests for CloneTemplate

func TestCloneTemplate_Success(t *testing.T) {
	bundle := createTestBundle("cloned-bundle")
	bundle.ClonedFrom = "template-123"

	service := &mockVTPMService{
		cloneTemplateFn: func(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
			assert.Equal(t, "template-123", opts.TemplateID)
			assert.Equal(t, "cloned-host", opts.Hostname)
			return bundle, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := CloneTemplateRequest{
		Hostname: "cloned-host",
		Labels:   map[string]string{"cloned": "true"},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/templates/template-123/clone", body, map[string]string{"id": "template-123"})
	rec := httptest.NewRecorder()

	handlers.CloneTemplate(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(BundleResponse)
	require.True(t, ok)
	assert.Equal(t, "template-123", payload.ClonedFrom)
}

func TestCloneTemplate_MissingTemplateID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	body := CloneTemplateRequest{Hostname: "test-host"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/templates//clone", body, map[string]string{"id": ""})
	rec := httptest.NewRecorder()

	handlers.CloneTemplate(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingTemplateID)
	assert.True(t, ok)
}

func TestCloneTemplate_InvalidRequestBody(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates/template-123/clone", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "template-123"})
	rec := httptest.NewRecorder()

	handlers.CloneTemplate(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestCloneTemplate_MissingHostname(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	body := CloneTemplateRequest{
		// Hostname missing
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/templates/template-123/clone", body, map[string]string{"id": "template-123"})
	rec := httptest.NewRecorder()

	handlers.CloneTemplate(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingHostname)
	assert.True(t, ok)
}

func TestCloneTemplate_ServiceError(t *testing.T) {
	service := &mockVTPMService{
		cloneTemplateFn: func(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
			return nil, errors.New("clone failed")
		},
	}

	handlers, writer := newTestHandlers(service)

	body := CloneTemplateRequest{Hostname: "test-host"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/templates/template-123/clone", body, map[string]string{"id": "template-123"})
	rec := httptest.NewRecorder()

	handlers.CloneTemplate(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Tests for ExportBundle

func TestExportBundle_Success(t *testing.T) {
	service := &mockVTPMService{
		exportBundleFn: func(ctx context.Context, id string, w io.Writer) error {
			assert.Equal(t, "bundle-to-export", id)
			w.Write([]byte("fake tar.gz content"))
			return nil
		},
	}

	handlers, _ := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/bundle-to-export/export", nil, map[string]string{"id": "bundle-to-export"})
	rec := httptest.NewRecorder()

	handlers.ExportBundle(rec, req)

	assert.Equal(t, "application/gzip", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "bundle-to-export.tar.gz")
	assert.Equal(t, "fake tar.gz content", rec.Body.String())
}

func TestExportBundle_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles//export", nil, map[string]string{"id": ""})
	rec := httptest.NewRecorder()

	handlers.ExportBundle(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingBundleID)
	assert.True(t, ok)
}

func TestExportBundle_ServiceError(t *testing.T) {
	service := &mockVTPMService{
		exportBundleFn: func(ctx context.Context, id string, w io.Writer) error {
			return errors.New("bundle not found")
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/nonexistent/export", nil, map[string]string{"id": "nonexistent"})
	rec := httptest.NewRecorder()

	handlers.ExportBundle(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Tests for ImportBundle

func TestImportBundle_Success(t *testing.T) {
	bundle := createTestBundle("imported-bundle")

	service := &mockVTPMService{
		importBundleFn: func(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
			return bundle, nil
		},
	}

	handlers, writer := newTestHandlers(service)

	body := bytes.NewBufferString("fake tar.gz content")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/import", body)
	req.Header.Set("Content-Type", "application/gzip")
	rec := httptest.NewRecorder()

	handlers.ImportBundle(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(BundleResponse)
	require.True(t, ok)
	assert.Equal(t, "imported-bundle", payload.ID)
}

func TestImportBundle_ServiceError(t *testing.T) {
	service := &mockVTPMService{
		importBundleFn: func(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
			return nil, errors.New("invalid archive format")
		},
	}

	handlers, writer := newTestHandlers(service)

	body := bytes.NewBufferString("bad content")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/import", body)
	rec := httptest.NewRecorder()

	handlers.ImportBundle(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

// Tests for ValidateBundle

func TestValidateBundle_Success(t *testing.T) {
	service := &mockVTPMService{
		validateBundleFn: func(ctx context.Context, id string) error {
			assert.Equal(t, "bundle-to-validate", id)
			return nil
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles/bundle-to-validate/validate", nil, map[string]string{"id": "bundle-to-validate"})
	rec := httptest.NewRecorder()

	handlers.ValidateBundle(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ValidateBundleResponse)
	require.True(t, ok)
	assert.True(t, payload.Valid)
	assert.Nil(t, payload.Errors)
}

func TestValidateBundle_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles//validate", nil, map[string]string{"id": ""})
	rec := httptest.NewRecorder()

	handlers.ValidateBundle(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingBundleID)
	assert.True(t, ok)
}

func TestValidateBundle_ValidationFails(t *testing.T) {
	service := &mockVTPMService{
		validateBundleFn: func(ctx context.Context, id string) error {
			return errors.New("checksum mismatch for tpm/tpm2-00.permall")
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodPost, "/api/v1/vtpm/bundles/corrupted-bundle/validate", nil, map[string]string{"id": "corrupted-bundle"})
	rec := httptest.NewRecorder()

	handlers.ValidateBundle(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ValidateBundleResponse)
	require.True(t, ok)
	assert.False(t, payload.Valid)
	assert.Contains(t, payload.Errors, "checksum mismatch for tpm/tpm2-00.permall")
}

// Tests for GetBundlePath

func TestGetBundlePath_Success(t *testing.T) {
	service := &mockVTPMService{
		getBundlePathFn: func(id string) string {
			return "/var/lib/vtpm/bundles/" + id
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/bundle-123/path", nil, map[string]string{"id": "bundle-123"})
	rec := httptest.NewRecorder()

	handlers.GetBundlePath(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(PathResponse)
	require.True(t, ok)
	assert.Equal(t, "/var/lib/vtpm/bundles/bundle-123", payload.Path)
}

func TestGetBundlePath_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles//path", nil, map[string]string{"id": ""})
	rec := httptest.NewRecorder()

	handlers.GetBundlePath(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingBundleID)
	assert.True(t, ok)
}

// Tests for GetTPMSocketPath

func TestGetTPMSocketPath_Success(t *testing.T) {
	service := &mockVTPMService{
		getTPMSocketFn: func(id string) string {
			return "/var/lib/vtpm/bundles/" + id + "/tpm/swtpm.sock"
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/bundle-123/tpm-socket", nil, map[string]string{"id": "bundle-123"})
	rec := httptest.NewRecorder()

	handlers.GetTPMSocketPath(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(PathResponse)
	require.True(t, ok)
	assert.Equal(t, "/var/lib/vtpm/bundles/bundle-123/tpm/swtpm.sock", payload.Path)
}

func TestGetTPMSocketPath_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles//tpm-socket", nil, map[string]string{"id": ""})
	rec := httptest.NewRecorder()

	handlers.GetTPMSocketPath(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingBundleID)
	assert.True(t, ok)
}

// Tests for GetNVRAMPath

func TestGetNVRAMPath_Success(t *testing.T) {
	service := &mockVTPMService{
		getNVRAMPathFn: func(id string) string {
			return "/var/lib/vtpm/bundles/" + id + "/ovmf/OVMF_VARS.fd"
		},
	}

	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles/bundle-123/nvram", nil, map[string]string{"id": "bundle-123"})
	rec := httptest.NewRecorder()

	handlers.GetNVRAMPath(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(PathResponse)
	require.True(t, ok)
	assert.Equal(t, "/var/lib/vtpm/bundles/bundle-123/ovmf/OVMF_VARS.fd", payload.Path)
}

func TestGetNVRAMPath_MissingID(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := createRequestWithVars(http.MethodGet, "/api/v1/vtpm/bundles//nvram", nil, map[string]string{"id": ""})
	rec := httptest.NewRecorder()

	handlers.GetNVRAMPath(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingBundleID)
	assert.True(t, ok)
}

// Tests for helper methods

func TestGetPaginationParams_Defaults(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles", nil)

	limit, offset := handlers.getPaginationParams(req)

	assert.Equal(t, defaultLimit, limit)
	assert.Equal(t, defaultOffset, offset)
}

func TestGetPaginationParams_CustomValues(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?limit=25&offset=10", nil)

	limit, offset := handlers.getPaginationParams(req)

	assert.Equal(t, 25, limit)
	assert.Equal(t, 10, offset)
}

func TestGetPaginationParams_LimitExceedsMax(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?limit=5000", nil)

	limit, _ := handlers.getPaginationParams(req)

	assert.Equal(t, maxLimit, limit)
}

func TestGetPaginationParams_NegativeLimit(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?limit=-5", nil)

	limit, _ := handlers.getPaginationParams(req)

	assert.Equal(t, defaultLimit, limit)
}

func TestGetPaginationParams_NegativeOffset(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?offset=-5", nil)

	_, offset := handlers.getPaginationParams(req)

	assert.Equal(t, defaultOffset, offset)
}

func TestGetPaginationParams_InvalidValues(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?limit=abc&offset=xyz", nil)

	limit, offset := handlers.getPaginationParams(req)

	assert.Equal(t, defaultLimit, limit)
	assert.Equal(t, defaultOffset, offset)
}

func TestParseBundleMode(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	tests := []struct {
		input    string
		expected vtpm.BundleMode
	}{
		{"template", vtpm.BundleModeTemplate},
		{"TEMPLATE", vtpm.BundleModeTemplate},
		{"Template", vtpm.BundleModeTemplate},
		{"pre-assigned", vtpm.BundleModePreAssigned},
		{"preassigned", vtpm.BundleModePreAssigned},
		{"pre_assigned", vtpm.BundleModePreAssigned},
		{"PRE-ASSIGNED", vtpm.BundleModePreAssigned},
		{"invalid", vtpm.BundleMode("")},
		{"", vtpm.BundleMode("")},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := handlers.parseBundleMode(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseEKAlgorithm(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	tests := []struct {
		input    string
		expected vtpm.EKAlgorithm
	}{
		{"RSA", vtpm.EKAlgorithmRSA},
		{"rsa", vtpm.EKAlgorithmRSA},
		{"Rsa", vtpm.EKAlgorithmRSA},
		{"ECC", vtpm.EKAlgorithmECC},
		{"ecc", vtpm.EKAlgorithmECC},
		{"Ecc", vtpm.EKAlgorithmECC},
		{"", vtpm.EKAlgorithmRSA},        // Default to RSA
		{"invalid", vtpm.EKAlgorithmRSA}, // Default to RSA
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := handlers.parseEKAlgorithm(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHandleServiceError_NotFound(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleServiceError(rec, req, errors.New("bundle not found"))

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestHandleServiceError_DoesNotExist(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleServiceError(rec, req, errors.New("resource does not exist"))

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestHandleServiceError_NoSuch(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleServiceError(rec, req, errors.New("no such file or directory"))

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestHandleServiceError_Invalid(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleServiceError(rec, req, errors.New("invalid request parameter"))

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestHandleServiceError_Required(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleServiceError(rec, req, errors.New("field required"))

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestHandleServiceError_MustBe(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleServiceError(rec, req, errors.New("value must be positive"))

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestHandleServiceError_CannotBe(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleServiceError(rec, req, errors.New("value cannot be empty"))

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestHandleServiceError_InternalError(t *testing.T) {
	handlers, writer := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handlers.handleServiceError(rec, req, errors.New("unexpected database error"))

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		s          string
		substrings []string
		expected   bool
	}{
		{"bundle not found", []string{"not found"}, true},
		{"Bundle Not Found", []string{"not found"}, true},
		{"resource does not exist", []string{"does not exist"}, true},
		{"no such file", []string{"no such"}, true},
		{"invalid input", []string{"invalid", "required"}, true},
		{"value is required", []string{"invalid", "required"}, true},
		{"some random error", []string{"not found", "invalid"}, false},
		{"", []string{"not found"}, false},
		{"some error", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			result := containsAny(tt.s, tt.substrings...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Tests for bundleToResponse conversion

func TestBundleToResponse_FullBundle(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	now := time.Now()
	bundle := &vtpm.Bundle{
		ID:   "full-bundle",
		Mode: vtpm.BundleModePreAssigned,
		Manifest: &vtpm.Manifest{
			Version:           "1.0",
			ID:                "full-bundle",
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          "test-host",
			CreatedAt:         now,
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			EKHandle:          0x01C00002,
			SecureBootEnabled: true,
			EKCertificate: &vtpm.EKCertInfo{
				Subject:      "CN=Test EK",
				Issuer:       "CN=Test CA",
				SerialNumber: "12345",
				NotBefore:    now.Add(-24 * time.Hour),
				NotAfter:     now.Add(365 * 24 * time.Hour),
				Fingerprint:  "sha256:abc123",
			},
			SecureBootKeys: &vtpm.SecureBootKeyInfo{
				PKFingerprint:  "sha256:pk123",
				KEKFingerprint: "sha256:kek123",
				DBFingerprint:  "sha256:db123",
				OwnerGUID:      "12345678-1234-1234-1234-123456789012",
			},
			Checksums: map[string]string{"file1": "sha256:hash1"},
			Labels:    map[string]string{"env": "test"},
		},
		TPMState: &vtpm.TPMState{
			StateDir:     "/bundles/full-bundle/tpm",
			PermallFile:  "/bundles/full-bundle/tpm/tpm2-00.permall",
			VolatileFile: "/bundles/full-bundle/tpm/tpm2-00.volatilestate",
		},
		OVMFState: &vtpm.OVMFState{
			NVRAMFile: "/bundles/full-bundle/ovmf/OVMF_VARS.fd",
		},
		SecureBootKeys: &vtpm.SecureBootKeyPaths{
			Dir:     "/bundles/full-bundle/secure-boot-keys",
			PKKey:   "/bundles/full-bundle/secure-boot-keys/PK.key",
			PKCert:  "/bundles/full-bundle/secure-boot-keys/PK.crt",
			KEKKey:  "/bundles/full-bundle/secure-boot-keys/KEK.key",
			KEKCert: "/bundles/full-bundle/secure-boot-keys/KEK.crt",
			DBKey:   "/bundles/full-bundle/secure-boot-keys/DB.key",
			DBCert:  "/bundles/full-bundle/secure-boot-keys/DB.crt",
		},
		CreatedAt:  now,
		ClonedFrom: "template-1",
	}

	resp := handlers.bundleToResponse(bundle)

	assert.Equal(t, "full-bundle", resp.ID)
	assert.Equal(t, "pre-assigned", resp.Mode)
	assert.Equal(t, "template-1", resp.ClonedFrom)
	assert.NotNil(t, resp.CreatedAt)
	assert.NotNil(t, resp.Manifest)
	assert.NotNil(t, resp.TPMState)
	assert.NotNil(t, resp.OVMFState)
	assert.NotNil(t, resp.SecureBootKeys)
}

func TestBundleToResponse_NilBundle(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	resp := handlers.bundleToResponse(nil)

	assert.Equal(t, "", resp.ID)
}

func TestBundleToResponse_MinimalBundle(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	bundle := &vtpm.Bundle{
		ID:   "minimal-bundle",
		Mode: vtpm.BundleModeTemplate,
	}

	resp := handlers.bundleToResponse(bundle)

	assert.Equal(t, "minimal-bundle", resp.ID)
	assert.Equal(t, "template", resp.Mode)
	assert.Nil(t, resp.CreatedAt)
	assert.Nil(t, resp.Manifest)
}

// Tests for templateToResponse conversion

func TestTemplateToResponse_FullTemplate(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	now := time.Now()
	template := &vtpm.Template{
		ID:                "full-template",
		Description:       "A full template",
		TPMStateDir:       "/templates/full-template/tpm",
		NVRAMPath:         "/templates/full-template/ovmf/OVMF_VARS.fd",
		SecureBootKeysDir: "/templates/full-template/secure-boot-keys",
		EKAlgorithm:       vtpm.EKAlgorithmECC,
		SecureBootEnabled: true,
		CreatedAt:         now,
	}

	resp := handlers.templateToResponse(template)

	assert.Equal(t, "full-template", resp.ID)
	assert.Equal(t, "A full template", resp.Description)
	assert.Equal(t, "ECC", resp.EKAlgorithm)
	assert.True(t, resp.SecureBootEnabled)
	assert.NotNil(t, resp.CreatedAt)
}

func TestTemplateToResponse_NilTemplate(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	resp := handlers.templateToResponse(nil)

	assert.Equal(t, "", resp.ID)
}

// Tests for manifestToResponse conversion

func TestManifestToResponse_FullManifest(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	now := time.Now()
	manifest := &vtpm.Manifest{
		Version:           "1.0",
		ID:                "manifest-id",
		Mode:              vtpm.BundleModePreAssigned,
		Hostname:          "test-host",
		CreatedAt:         now,
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		EKHandle:          0x01C00002,
		SecureBootEnabled: true,
		EKCertificate: &vtpm.EKCertInfo{
			Subject:      "CN=Test EK",
			Issuer:       "CN=Test CA",
			SerialNumber: "12345",
			NotBefore:    now.Add(-24 * time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			Fingerprint:  "sha256:abc123",
		},
		SecureBootKeys: &vtpm.SecureBootKeyInfo{
			PKFingerprint:  "sha256:pk123",
			KEKFingerprint: "sha256:kek123",
			DBFingerprint:  "sha256:db123",
			OwnerGUID:      "12345678-1234-1234-1234-123456789012",
		},
		Checksums:  map[string]string{"file1": "sha256:hash1"},
		Labels:     map[string]string{"env": "test"},
		ClonedFrom: "parent-template",
	}

	resp := handlers.manifestToResponse(manifest)

	require.NotNil(t, resp)
	assert.Equal(t, "1.0", resp.Version)
	assert.Equal(t, "manifest-id", resp.ID)
	assert.Equal(t, "pre-assigned", resp.Mode)
	assert.Equal(t, "test-host", resp.Hostname)
	assert.Equal(t, "RSA", resp.EKAlgorithm)
	assert.Equal(t, uint32(0x01C00002), resp.EKHandle)
	assert.True(t, resp.SecureBootEnabled)
	assert.Equal(t, "parent-template", resp.ClonedFrom)
	assert.NotNil(t, resp.CreatedAt)
	assert.NotNil(t, resp.EKCertificate)
	assert.NotNil(t, resp.SecureBootKeys)
}

func TestManifestToResponse_NilManifest(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	resp := handlers.manifestToResponse(nil)

	assert.Nil(t, resp)
}

func TestManifestToResponse_MinimalManifest(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	manifest := &vtpm.Manifest{
		Version:     "1.0",
		ID:          "minimal",
		Mode:        vtpm.BundleModeTemplate,
		EKAlgorithm: vtpm.EKAlgorithmRSA,
	}

	resp := handlers.manifestToResponse(manifest)

	require.NotNil(t, resp)
	assert.Equal(t, "minimal", resp.ID)
	assert.Nil(t, resp.CreatedAt)
	assert.Nil(t, resp.EKCertificate)
	assert.Nil(t, resp.SecureBootKeys)
}

// Tests for exportWriter

func TestExportWriter_Write(t *testing.T) {
	rec := httptest.NewRecorder()
	ew := &exportWriter{w: rec}

	n, err := ew.Write([]byte("test content"))

	assert.NoError(t, err)
	assert.Equal(t, 12, n)
	assert.Equal(t, "test content", rec.Body.String())
}

// Tests for createContext

func TestCreateContext(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	ctx, cancel := handlers.createContext()
	defer cancel()

	deadline, ok := ctx.Deadline()
	assert.True(t, ok)
	assert.True(t, deadline.After(time.Now()))
	assert.True(t, deadline.Before(time.Now().Add(requestTimeout+time.Second)))
}

// Tests for decodeJSON

func TestDecodeJSON_Success(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	body := bytes.NewBufferString(`{"mode": "template", "hostname": "test"}`)
	req := httptest.NewRequest(http.MethodPost, "/test", body)

	var result CreateBundleRequest
	err := handlers.decodeJSON(req, &result)

	assert.NoError(t, err)
	assert.Equal(t, "template", result.Mode)
	assert.Equal(t, "test", result.Hostname)
}

func TestDecodeJSON_InvalidJSON(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	body := bytes.NewBufferString(`invalid json`)
	req := httptest.NewRequest(http.MethodPost, "/test", body)

	var result CreateBundleRequest
	err := handlers.decodeJSON(req, &result)

	assert.Error(t, err)
}

func TestDecodeJSON_UnknownFields(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	body := bytes.NewBufferString(`{"mode": "template", "unknown_field": "value"}`)
	req := httptest.NewRequest(http.MethodPost, "/test", body)

	var result CreateBundleRequest
	err := handlers.decodeJSON(req, &result)

	assert.Error(t, err) // DisallowUnknownFields should cause an error
}

// Tests for getBundleID and getTemplateID

func TestGetBundleID(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/my-bundle", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "my-bundle"})

	id := handlers.getBundleID(req)

	assert.Equal(t, "my-bundle", id)
}

func TestGetTemplateID(t *testing.T) {
	handlers, _ := newTestHandlers(&mockVTPMService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/templates/my-template", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "my-template"})

	id := handlers.getTemplateID(req)

	assert.Equal(t, "my-template", id)
}
