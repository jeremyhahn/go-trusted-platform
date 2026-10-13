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

package rest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock vTPM Service
// =============================================================================

type mockVTPMService struct {
	bundles           map[string]*vtpm.Bundle
	templates         map[string]*vtpm.Template
	running           map[string]bool
	createBundleErr   error
	getBundleErr      error
	deleteBundleErr   error
	listBundlesErr    error
	createTemplateErr error
	getTemplateErr    error
	cloneTemplateErr  error
	startErr          error
	stopErr           error
	quoteErr          error
	readPCRErr        error
	extendPCRErr      error
	sealErr           error
	unsealErr         error
	exportErr         error
	importErr         error
	validateBundleErr error
	quoteResult       *vtpm.QuoteResult
	pcrValue          []byte
	sealedData        []byte
	unsealedData      []byte
	exportData        []byte
	importBundle      *vtpm.Bundle
}

func newMockVTPMService() *mockVTPMService {
	return &mockVTPMService{
		bundles:   make(map[string]*vtpm.Bundle),
		templates: make(map[string]*vtpm.Template),
		running:   make(map[string]bool),
	}
}

func (m *mockVTPMService) CreateBundle(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
	if m.createBundleErr != nil {
		return nil, m.createBundleErr
	}
	bundle := &vtpm.Bundle{
		ID:        opts.Hostname + "-" + time.Now().Format("20060102150405"),
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Hostname:          opts.Hostname,
			EKAlgorithm:       opts.EKAlgorithm,
			SecureBootEnabled: opts.SecureBootEnabled,
			Labels:            opts.Labels,
		},
	}
	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *mockVTPMService) GetBundle(ctx context.Context, id string) (*vtpm.Bundle, error) {
	if m.getBundleErr != nil {
		return nil, m.getBundleErr
	}
	bundle, ok := m.bundles[id]
	if !ok {
		return nil, vtpm.ErrBundleNotFound{ID: id}
	}
	return bundle, nil
}

func (m *mockVTPMService) DeleteBundle(ctx context.Context, id string) error {
	if m.deleteBundleErr != nil {
		return m.deleteBundleErr
	}
	if _, ok := m.bundles[id]; !ok {
		return vtpm.ErrBundleNotFound{ID: id}
	}
	delete(m.bundles, id)
	delete(m.running, id)
	return nil
}

func (m *mockVTPMService) ListBundles(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
	if m.listBundlesErr != nil {
		return nil, m.listBundlesErr
	}
	bundles := make([]*vtpm.Bundle, 0, len(m.bundles))
	for _, bundle := range m.bundles {
		if opts != nil && opts.Mode != "" && bundle.Mode != opts.Mode {
			continue
		}
		bundles = append(bundles, bundle)
	}
	return bundles, nil
}

func (m *mockVTPMService) CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
	if m.createTemplateErr != nil {
		return nil, m.createTemplateErr
	}
	template := &vtpm.Template{
		ID:                opts.ID,
		Description:       opts.Description,
		EKAlgorithm:       opts.EKAlgorithm,
		SecureBootEnabled: opts.SecureBootEnabled,
		CreatedAt:         time.Now(),
	}
	m.templates[template.ID] = template
	return template, nil
}

func (m *mockVTPMService) GetTemplate(ctx context.Context, id string) (*vtpm.Template, error) {
	if m.getTemplateErr != nil {
		return nil, m.getTemplateErr
	}
	template, ok := m.templates[id]
	if !ok {
		return nil, vtpm.ErrTemplateNotFound{ID: id}
	}
	return template, nil
}

func (m *mockVTPMService) DeleteTemplate(ctx context.Context, id string) error {
	if _, ok := m.templates[id]; !ok {
		return vtpm.ErrTemplateNotFound{ID: id}
	}
	delete(m.templates, id)
	return nil
}

func (m *mockVTPMService) ListTemplates(ctx context.Context) ([]*vtpm.Template, error) {
	templates := make([]*vtpm.Template, 0, len(m.templates))
	for _, template := range m.templates {
		templates = append(templates, template)
	}
	return templates, nil
}

func (m *mockVTPMService) CloneTemplate(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
	if m.cloneTemplateErr != nil {
		return nil, m.cloneTemplateErr
	}
	template, ok := m.templates[opts.TemplateID]
	if !ok {
		return nil, vtpm.ErrTemplateNotFound{ID: opts.TemplateID}
	}
	bundle := &vtpm.Bundle{
		ID:         opts.Hostname + "-cloned-" + time.Now().Format("20060102150405"),
		Mode:       vtpm.BundleModePreAssigned,
		CreatedAt:  time.Now(),
		ClonedFrom: opts.TemplateID,
		Manifest: &vtpm.Manifest{
			Hostname:          opts.Hostname,
			EKAlgorithm:       template.EKAlgorithm,
			SecureBootEnabled: template.SecureBootEnabled,
			Labels:            opts.Labels,
		},
	}
	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *mockVTPMService) Start(ctx context.Context, bundleID string) error {
	if m.startErr != nil {
		return m.startErr
	}
	if _, ok := m.bundles[bundleID]; !ok {
		return vtpm.ErrBundleNotFound{ID: bundleID}
	}
	if m.running[bundleID] {
		return vtpm.ErrVTPMAlreadyRunning{BundleID: bundleID}
	}
	m.running[bundleID] = true
	return nil
}

func (m *mockVTPMService) Stop(ctx context.Context, bundleID string) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	if !m.running[bundleID] {
		return vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	m.running[bundleID] = false
	return nil
}

func (m *mockVTPMService) IsRunning(bundleID string) bool {
	return m.running[bundleID]
}

func (m *mockVTPMService) Quote(ctx context.Context, bundleID string, nonce []byte, pcrs []int) (*vtpm.QuoteResult, error) {
	if m.quoteErr != nil {
		return nil, m.quoteErr
	}
	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	if m.quoteResult != nil {
		return m.quoteResult, nil
	}
	pcrValues := make(map[int][]byte)
	for _, pcr := range pcrs {
		pcrValues[pcr] = []byte{0x00, 0x01, 0x02, 0x03}
	}
	return &vtpm.QuoteResult{
		Quote:         []byte("test-quote"),
		Signature:     []byte("test-signature"),
		PCRValues:     pcrValues,
		HashAlgorithm: "SHA256",
	}, nil
}

func (m *mockVTPMService) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	if m.readPCRErr != nil {
		return nil, m.readPCRErr
	}
	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	if m.pcrValue != nil {
		return m.pcrValue, nil
	}
	return []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, nil
}

func (m *mockVTPMService) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	if m.extendPCRErr != nil {
		return m.extendPCRErr
	}
	if !m.running[bundleID] {
		return vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	return nil
}

func (m *mockVTPMService) Seal(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	if m.sealedData != nil {
		return m.sealedData, nil
	}
	return []byte("sealed-data-" + string(data)), nil
}

func (m *mockVTPMService) Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}
	if m.unsealedData != nil {
		return m.unsealedData, nil
	}
	return []byte("unsealed-data"), nil
}

func (m *mockVTPMService) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	if m.exportErr != nil {
		return m.exportErr
	}
	if _, ok := m.bundles[id]; !ok {
		return vtpm.ErrBundleNotFound{ID: id}
	}
	data := m.exportData
	if data == nil {
		data = []byte("test-export-data")
	}
	_, err := w.Write(data)
	return err
}

func (m *mockVTPMService) ImportBundle(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
	if m.importErr != nil {
		return nil, m.importErr
	}
	if m.importBundle != nil {
		m.bundles[m.importBundle.ID] = m.importBundle
		return m.importBundle, nil
	}
	bundle := &vtpm.Bundle{
		ID:        "imported-bundle-" + time.Now().Format("20060102150405"),
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Hostname:    "imported-host",
			EKAlgorithm: vtpm.EKAlgorithmRSA,
		},
	}
	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *mockVTPMService) ValidateBundle(ctx context.Context, id string) error {
	if m.validateBundleErr != nil {
		return m.validateBundleErr
	}
	if _, ok := m.bundles[id]; !ok {
		return vtpm.ErrBundleNotFound{ID: id}
	}
	return nil
}

func (m *mockVTPMService) GetBundlePath(id string) string {
	return "/var/lib/vtpm/bundles/" + id
}

func (m *mockVTPMService) GetTPMSocketPath(id string) string {
	return "/var/lib/vtpm/bundles/" + id + "/tpm/swtpm.sock"
}

func (m *mockVTPMService) GetNVRAMPath(id string) string {
	return "/var/lib/vtpm/bundles/" + id + "/ovmf/OVMF_VARS.fd"
}

// addTestBundle adds a test bundle to the mock service.
func (m *mockVTPMService) addTestBundle(id, hostname string, running bool) {
	m.bundles[id] = &vtpm.Bundle{
		ID:        id,
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Hostname:    hostname,
			EKAlgorithm: vtpm.EKAlgorithmRSA,
		},
	}
	m.running[id] = running
}

// addTestTemplate adds a test template to the mock service.
func (m *mockVTPMService) addTestTemplate(id string) {
	m.templates[id] = &vtpm.Template{
		ID:          id,
		EKAlgorithm: vtpm.EKAlgorithmRSA,
		CreatedAt:   time.Now(),
	}
}

// =============================================================================
// Test Helpers
// =============================================================================

func setupVTPMTestHandler(svc *mockVTPMService) (*VTPMHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewVTPMHandlers(svc, logger)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

func decodeVTPMResponse(t *testing.T, body io.Reader, v interface{}) {
	t.Helper()
	err := json.NewDecoder(body).Decode(v)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestVTPMHandlerErrors(t *testing.T) {
	t.Run("ErrVTPMServiceNotAvailable", func(t *testing.T) {
		err := ErrVTPMServiceNotAvailable{}
		assert.Equal(t, "vTPM service not available", err.Error())
	})

	t.Run("ErrInvalidBundleID with empty ID", func(t *testing.T) {
		err := ErrInvalidBundleID{}
		assert.Equal(t, "bundle ID is required", err.Error())
	})

	t.Run("ErrInvalidBundleID with ID", func(t *testing.T) {
		err := ErrInvalidBundleID{ID: "bad-id"}
		assert.Equal(t, "invalid bundle ID: bad-id", err.Error())
	})

	t.Run("ErrVTPMInvalidPCRIndex", func(t *testing.T) {
		err := ErrVTPMInvalidPCRIndex{Index: 25}
		assert.Equal(t, "invalid PCR index: 25 (must be 0-23)", err.Error())
	})

	t.Run("ErrInvalidTemplateID with empty ID", func(t *testing.T) {
		err := ErrInvalidTemplateID{}
		assert.Equal(t, "template ID is required", err.Error())
	})

	t.Run("ErrInvalidTemplateID with ID", func(t *testing.T) {
		err := ErrInvalidTemplateID{ID: "bad-template"}
		assert.Equal(t, "invalid template ID: bad-template", err.Error())
	})

	t.Run("ErrVTPMOperationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrVTPMOperationFailed{Operation: "start", Cause: cause}
		assert.Equal(t, "vTPM operation start failed: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewVTPMHandlers(t *testing.T) {
	t.Run("creates handlers with service and logger", func(t *testing.T) {
		svc := newMockVTPMService()
		logger := slog.Default()
		handlers := NewVTPMHandlers(svc, logger)
		require.NotNil(t, handlers)
		assert.Equal(t, svc, handlers.service)
		assert.Equal(t, logger, handlers.logger)
	})

	t.Run("creates handlers with nil logger uses default", func(t *testing.T) {
		svc := newMockVTPMService()
		handlers := NewVTPMHandlers(svc, nil)
		require.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger)
	})
}

func TestVTPMRegisterRoutes(t *testing.T) {
	t.Run("registers all vTPM routes", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		routes := []struct {
			method string
			path   string
		}{
			{http.MethodPost, "/api/v1/vtpm/bundles"},
			{http.MethodGet, "/api/v1/vtpm/bundles"},
			{http.MethodGet, "/api/v1/vtpm/bundles/test-id"},
			{http.MethodDelete, "/api/v1/vtpm/bundles/test-id"},
			{http.MethodPost, "/api/v1/vtpm/bundles/test-id/start"},
			{http.MethodPost, "/api/v1/vtpm/bundles/test-id/stop"},
			{http.MethodGet, "/api/v1/vtpm/bundles/test-id/state"},
			{http.MethodPost, "/api/v1/vtpm/bundles/test-id/quote"},
			{http.MethodGet, "/api/v1/vtpm/bundles/test-id/pcr/0"},
			{http.MethodPost, "/api/v1/vtpm/bundles/test-id/pcr/0/extend"},
			{http.MethodPost, "/api/v1/vtpm/bundles/test-id/seal"},
			{http.MethodPost, "/api/v1/vtpm/bundles/test-id/unseal"},
			{http.MethodGet, "/api/v1/vtpm/bundles/test-id/export"},
			{http.MethodPost, "/api/v1/vtpm/bundles/import"},
			{http.MethodPost, "/api/v1/vtpm/templates"},
			{http.MethodPost, "/api/v1/vtpm/templates/test-id/clone"},
		}

		for _, route := range routes {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			matched := router.Match(req, match)
			assert.True(t, matched, "Route %s %s should be registered", route.method, route.path)
		}
	})
}

// =============================================================================
// Create Bundle Tests
// =============================================================================

func TestHandleCreateBundle(t *testing.T) {
	t.Run("creates bundle successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		reqBody := CreateBundleRequest{
			Hostname:          "test-vm",
			EKAlgorithm:       "RSA",
			SecureBootEnabled: true,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var bundleResp BundleResponse
		decodeVTPMResponse(t, resp.Body, &bundleResp)
		assert.Contains(t, bundleResp.ID, "test-vm")
		assert.Equal(t, "RSA", bundleResp.EKAlgorithm)
	})

	t.Run("creates bundle with ECC algorithm", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		reqBody := CreateBundleRequest{
			Hostname:    "ecc-vm",
			EKAlgorithm: "ECC",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var bundleResp BundleResponse
		decodeVTPMResponse(t, resp.Body, &bundleResp)
		assert.Equal(t, "ECC", bundleResp.EKAlgorithm)
	})

	t.Run("accepts the EK algorithm in any case", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		body, _ := json.Marshal(CreateBundleRequest{Hostname: "lower-vm", EKAlgorithm: "ecc"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var bundleResp BundleResponse
		decodeVTPMResponse(t, resp.Body, &bundleResp)
		assert.Equal(t, "ECC", bundleResp.EKAlgorithm)
	})

	t.Run("rejects an undocumented EK algorithm", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		body, _ := json.Marshal(CreateBundleRequest{Hostname: "ecdsa-vm", EKAlgorithm: "ECDSA"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Empty(t, svc.bundles, "an invalid algorithm must not create a bundle")
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := CreateBundleRequest{Hostname: "test"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON body", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles", strings.NewReader("invalid json"))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when hostname is missing", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		reqBody := CreateBundleRequest{EKAlgorithm: "RSA"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp ErrorResponse
		decodeVTPMResponse(t, resp.Body, &errResp)
		assert.Contains(t, errResp.Error, "hostname")
	})

	t.Run("returns error when creation fails", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.createBundleErr = errors.New("creation failed")
		_, router := setupVTPMTestHandler(svc)

		reqBody := CreateBundleRequest{Hostname: "test"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// List Bundles Tests
// =============================================================================

func TestHandleListBundles(t *testing.T) {
	t.Run("returns empty list when no bundles", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp BundleListResponse
		decodeVTPMResponse(t, resp.Body, &listResp)
		assert.Equal(t, 0, listResp.Count)
		assert.Empty(t, listResp.Bundles)
	})

	t.Run("returns list of bundles", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("bundle-1", "host-1", false)
		svc.addTestBundle("bundle-2", "host-2", true)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp BundleListResponse
		decodeVTPMResponse(t, resp.Body, &listResp)
		assert.Equal(t, 2, listResp.Count)
		assert.Len(t, listResp.Bundles, 2)
	})

	t.Run("filters by mode", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("bundle-1", "host-1", false)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?mode=pre-assigned", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Get Bundle Tests
// =============================================================================

func TestHandleGetBundle(t *testing.T) {
	t.Run("returns bundle by ID", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", false)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var bundleResp BundleResponse
		decodeVTPMResponse(t, resp.Body, &bundleResp)
		assert.Equal(t, "test-bundle", bundleResp.ID)
		assert.Equal(t, "test-host", bundleResp.Hostname)
	})

	t.Run("returns 404 when bundle not found", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Delete Bundle Tests
// =============================================================================

func TestHandleDeleteBundle(t *testing.T) {
	t.Run("deletes bundle successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", false)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/vtpm/bundles/test-bundle", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp BundleActionResponse
		decodeVTPMResponse(t, resp.Body, &actionResp)
		assert.Equal(t, "test-bundle", actionResp.BundleID)
		assert.Equal(t, "delete", actionResp.Action)
		assert.True(t, actionResp.Success)
	})

	t.Run("returns 404 when bundle not found", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/vtpm/bundles/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/vtpm/bundles/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Start/Stop Bundle Tests
// =============================================================================

func TestHandleStartBundle(t *testing.T) {
	t.Run("starts bundle successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", false)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp BundleActionResponse
		decodeVTPMResponse(t, resp.Body, &actionResp)
		assert.Equal(t, "test-bundle", actionResp.BundleID)
		assert.Equal(t, "start", actionResp.Action)
		assert.True(t, actionResp.Success)
	})

	t.Run("returns error when already running", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

func TestHandleStopBundle(t *testing.T) {
	t.Run("stops bundle successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp BundleActionResponse
		decodeVTPMResponse(t, resp.Body, &actionResp)
		assert.Equal(t, "test-bundle", actionResp.BundleID)
		assert.Equal(t, "stop", actionResp.Action)
		assert.True(t, actionResp.Success)
	})

	t.Run("returns error when not running", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", false)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Get Bundle State Tests
// =============================================================================

func TestHandleGetBundleState(t *testing.T) {
	t.Run("returns running state with socket path", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/state", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var stateResp BundleStateResponse
		decodeVTPMResponse(t, resp.Body, &stateResp)
		assert.Equal(t, "test-bundle", stateResp.ID)
		assert.True(t, stateResp.Running)
		assert.NotEmpty(t, stateResp.SocketPath)
	})

	t.Run("returns stopped state without socket path", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", false)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/state", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var stateResp BundleStateResponse
		decodeVTPMResponse(t, resp.Body, &stateResp)
		assert.Equal(t, "test-bundle", stateResp.ID)
		assert.False(t, stateResp.Running)
		assert.Empty(t, stateResp.SocketPath)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test/state", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Quote Tests
// =============================================================================

func TestHandleQuote(t *testing.T) {
	t.Run("generates quote successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		nonce := base64.StdEncoding.EncodeToString([]byte("test-nonce"))
		reqBody := QuoteRequest{
			Nonce: nonce,
			PCRs:  []int{0, 1, 7},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var quoteResp QuoteResponse
		decodeVTPMResponse(t, resp.Body, &quoteResp)
		assert.Equal(t, "test-bundle", quoteResp.BundleID)
		assert.NotEmpty(t, quoteResp.Quote)
		assert.NotEmpty(t, quoteResp.Signature)
		assert.Equal(t, "SHA256", quoteResp.HashAlgorithm)
	})

	t.Run("returns error when nonce is missing", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		reqBody := QuoteRequest{PCRs: []int{0}}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when nonce is invalid base64", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		reqBody := QuoteRequest{Nonce: "invalid-base64!!!"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when PCR index is invalid", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		nonce := base64.StdEncoding.EncodeToString([]byte("test-nonce"))
		reqBody := QuoteRequest{
			Nonce: nonce,
			PCRs:  []int{24},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when vTPM not running", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", false)
		_, router := setupVTPMTestHandler(svc)

		nonce := base64.StdEncoding.EncodeToString([]byte("test-nonce"))
		reqBody := QuoteRequest{Nonce: nonce}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		nonce := base64.StdEncoding.EncodeToString([]byte("test-nonce"))
		reqBody := QuoteRequest{Nonce: nonce}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// PCR Read Tests
// =============================================================================

func TestHandleReadPCR(t *testing.T) {
	t.Run("reads PCR successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/pcr/7", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var pcrResp PCRReadResponse
		decodeVTPMResponse(t, resp.Body, &pcrResp)
		assert.Equal(t, "test-bundle", pcrResp.BundleID)
		assert.Equal(t, 7, pcrResp.PCRIndex)
		assert.NotEmpty(t, pcrResp.Value)
	})

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/pcr/25", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for non-numeric PCR index", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/pcr/abc", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when vTPM not running", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", false)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/pcr/0", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test/pcr/0", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// PCR Extend Tests
// =============================================================================

func TestHandleExtendPCR(t *testing.T) {
	t.Run("extends PCR successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		data := base64.StdEncoding.EncodeToString([]byte("test-data"))
		reqBody := PCRExtendRequest{Data: data}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/pcr/7/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp BundleActionResponse
		decodeVTPMResponse(t, resp.Body, &actionResp)
		assert.True(t, actionResp.Success)
	})

	t.Run("returns error when data is missing", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		reqBody := PCRExtendRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/pcr/7/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when data is invalid base64", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		reqBody := PCRExtendRequest{Data: "invalid-base64!!!"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/pcr/7/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		data := base64.StdEncoding.EncodeToString([]byte("test-data"))
		reqBody := PCRExtendRequest{Data: data}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/pcr/25/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		data := base64.StdEncoding.EncodeToString([]byte("test-data"))
		reqBody := PCRExtendRequest{Data: data}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test/pcr/0/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Seal Tests
// =============================================================================

func TestVTPMHandleSeal(t *testing.T) {
	t.Run("seals data successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		data := base64.StdEncoding.EncodeToString([]byte("secret-data"))
		reqBody := SealRequest{
			Data: data,
			PCRs: []int{0, 7},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var sealResp SealResponse
		decodeVTPMResponse(t, resp.Body, &sealResp)
		assert.Equal(t, "test-bundle", sealResp.BundleID)
		assert.NotEmpty(t, sealResp.SealedData)
	})

	t.Run("returns error when data is missing", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		reqBody := SealRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when data is invalid base64", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		reqBody := SealRequest{Data: "invalid-base64!!!"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when PCR index is invalid", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		data := base64.StdEncoding.EncodeToString([]byte("secret-data"))
		reqBody := SealRequest{
			Data: data,
			PCRs: []int{24},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		data := base64.StdEncoding.EncodeToString([]byte("secret-data"))
		reqBody := SealRequest{Data: data}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Unseal Tests
// =============================================================================

func TestVTPMHandleUnseal(t *testing.T) {
	t.Run("unseals data successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		sealedData := base64.StdEncoding.EncodeToString([]byte("sealed-data"))
		reqBody := UnsealRequest{SealedData: sealedData}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/unseal", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var unsealResp UnsealResponse
		decodeVTPMResponse(t, resp.Body, &unsealResp)
		assert.Equal(t, "test-bundle", unsealResp.BundleID)
		assert.NotEmpty(t, unsealResp.Data)
	})

	t.Run("returns error when sealed_data is missing", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		reqBody := UnsealRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/unseal", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when sealed_data is invalid base64", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		reqBody := UnsealRequest{SealedData: "invalid-base64!!!"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/unseal", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		sealedData := base64.StdEncoding.EncodeToString([]byte("sealed-data"))
		reqBody := UnsealRequest{SealedData: sealedData}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test/unseal", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Export/Import Tests
// =============================================================================

func TestHandleExportBundle(t *testing.T) {
	t.Run("exports bundle successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", false)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/export", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/gzip", resp.Header.Get("Content-Type"))
		assert.Contains(t, resp.Header.Get("Content-Disposition"), "test-bundle.tar.gz")
	})

	t.Run("returns error when bundle not found", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/nonexistent/export", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test/export", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

func TestHandleImportBundle(t *testing.T) {
	t.Run("imports bundle successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/import", bytes.NewReader([]byte("archive-data")))
		req.Header.Set("Content-Type", "application/gzip")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var importResp ImportBundleResponse
		decodeVTPMResponse(t, resp.Body, &importResp)
		assert.NotEmpty(t, importResp.Bundle.ID)
	})

	t.Run("returns error when import fails", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.importErr = errors.New("import failed")
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/import", bytes.NewReader([]byte("bad-data")))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/import", bytes.NewReader([]byte("data")))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Template Tests
// =============================================================================

func TestHandleCreateTemplate(t *testing.T) {
	t.Run("creates template successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		reqBody := CreateTemplateRequest{
			ID:                "test-template",
			Description:       "Test template",
			EKAlgorithm:       "RSA",
			SecureBootEnabled: true,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var templateResp TemplateResponse
		decodeVTPMResponse(t, resp.Body, &templateResp)
		assert.Equal(t, "test-template", templateResp.ID)
		assert.Equal(t, "Test template", templateResp.Description)
	})

	t.Run("accepts the EK algorithm in any case", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		body, _ := json.Marshal(CreateTemplateRequest{ID: "lower-template", EKAlgorithm: "ecc"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		require.Contains(t, svc.templates, "lower-template")
		assert.Equal(t, vtpm.EKAlgorithmECC, svc.templates["lower-template"].EKAlgorithm)
	})

	t.Run("rejects an undocumented EK algorithm", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		body, _ := json.Marshal(CreateTemplateRequest{ID: "ecdsa-template", EKAlgorithm: "ECDSA"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Empty(t, svc.templates, "an invalid algorithm must not create a template")
	})

	t.Run("returns error when id is missing", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		reqBody := CreateTemplateRequest{Description: "No ID"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := CreateTemplateRequest{ID: "test"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

func TestHandleCloneTemplate(t *testing.T) {
	t.Run("clones template successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestTemplate("test-template")
		_, router := setupVTPMTestHandler(svc)

		reqBody := CloneTemplateRequest{
			Hostname: "cloned-host",
			Labels:   map[string]string{"env": "test"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates/test-template/clone", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var bundleResp BundleResponse
		decodeVTPMResponse(t, resp.Body, &bundleResp)
		assert.Contains(t, bundleResp.ID, "cloned-host")
		assert.Equal(t, "test-template", bundleResp.ClonedFrom)
	})

	t.Run("returns error when hostname is missing", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestTemplate("test-template")
		_, router := setupVTPMTestHandler(svc)

		reqBody := CloneTemplateRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates/test-template/clone", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when template not found", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		reqBody := CloneTemplateRequest{Hostname: "new-host"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates/nonexistent/clone", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service not available", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := CloneTemplateRequest{Hostname: "test"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/templates/test/clone", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestWriteVTPMError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"BundleNotFound", vtpm.ErrBundleNotFound{ID: "test"}, http.StatusNotFound},
		{"BundleAlreadyExists", vtpm.ErrBundleAlreadyExists{ID: "test"}, http.StatusConflict},
		{"TemplateNotFound", vtpm.ErrTemplateNotFound{ID: "test"}, http.StatusNotFound},
		{"TemplateAlreadyExists", vtpm.ErrTemplateAlreadyExists{ID: "test"}, http.StatusConflict},
		{"InvalidConfig", vtpm.ErrInvalidConfig{Field: "test", Reason: "bad"}, http.StatusBadRequest},
		{"InvalidManifest", vtpm.ErrInvalidManifest{Reason: "bad"}, http.StatusBadRequest},
		{"VTPMNotRunning", vtpm.ErrVTPMNotRunning{BundleID: "test"}, http.StatusConflict},
		{"VTPMAlreadyRunning", vtpm.ErrVTPMAlreadyRunning{BundleID: "test"}, http.StatusConflict},
		{"InvalidNonce", vtpm.ErrInvalidNonce{Reason: "bad"}, http.StatusBadRequest},
		{"InvalidPCRIndex", vtpm.ErrInvalidPCRIndex{PCRIndex: 25}, http.StatusBadRequest},
		{"ChecksumMismatch", vtpm.ErrChecksumMismatch{File: "test"}, http.StatusUnprocessableEntity},
		{"CAUnavailable", vtpm.ErrCAUnavailable{}, http.StatusServiceUnavailable},
		{"UnknownError", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newMockVTPMService()
			handlers := NewVTPMHandlers(svc, slog.Default())
			w := httptest.NewRecorder()

			handlers.writeVTPMError(w, "test", tt.err)

			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
		})
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestParseListOptions(t *testing.T) {
	t.Run("parses all options", func(t *testing.T) {
		svc := newMockVTPMService()
		handlers := NewVTPMHandlers(svc, slog.Default())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?mode=pre-assigned&limit=10&offset=5&labels=env%3Dtest,region%3Dus", nil)

		opts := handlers.parseListOptions(req)

		assert.Equal(t, vtpm.BundleMode("pre-assigned"), opts.Mode)
		assert.Equal(t, 10, opts.Limit)
		assert.Equal(t, 5, opts.Offset)
		assert.Equal(t, "test", opts.Labels["env"])
		assert.Equal(t, "us", opts.Labels["region"])
	})

	t.Run("handles empty options", func(t *testing.T) {
		svc := newMockVTPMService()
		handlers := NewVTPMHandlers(svc, slog.Default())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles", nil)

		opts := handlers.parseListOptions(req)

		assert.Empty(t, opts.Mode)
		assert.Equal(t, 0, opts.Limit)
		assert.Equal(t, 0, opts.Offset)
	})

	t.Run("handles invalid limit", func(t *testing.T) {
		svc := newMockVTPMService()
		handlers := NewVTPMHandlers(svc, slog.Default())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?limit=invalid", nil)

		opts := handlers.parseListOptions(req)

		assert.Equal(t, 0, opts.Limit)
	})

	t.Run("parses device_profile_id", func(t *testing.T) {
		svc := newMockVTPMService()
		handlers := NewVTPMHandlers(svc, slog.Default())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?device_profile_id=4242", nil)

		opts := handlers.parseListOptions(req)

		assert.Equal(t, uint64(4242), opts.DeviceProfileID)
	})

	t.Run("ignores invalid device_profile_id", func(t *testing.T) {
		svc := newMockVTPMService()
		handlers := NewVTPMHandlers(svc, slog.Default())

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles?device_profile_id=not-a-number", nil)

		opts := handlers.parseListOptions(req)

		assert.Equal(t, uint64(0), opts.DeviceProfileID)
	})
}

func TestBundleToResponse(t *testing.T) {
	t.Run("converts full bundle with manifest", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-id", "test-host", true)
		handlers := NewVTPMHandlers(svc, slog.Default())

		bundle := svc.bundles["test-id"]
		bundle.Manifest.EKCertificate = &vtpm.EKCertInfo{
			Subject:      "CN=test",
			Issuer:       "CN=CA",
			SerialNumber: "123",
			Fingerprint:  "abc",
		}
		bundle.Manifest.SecureBootKeys = &vtpm.SecureBootKeyInfo{
			PKFingerprint:  "pk",
			KEKFingerprint: "kek",
			DBFingerprint:  "db",
		}
		bundle.Manifest.Labels = map[string]string{"env": "test"}

		resp := handlers.bundleToResponse(bundle)

		assert.Equal(t, "test-id", resp.ID)
		assert.Equal(t, "test-host", resp.Hostname)
		assert.True(t, resp.Running)
		assert.NotEmpty(t, resp.SocketPath)
		assert.NotNil(t, resp.EKCertificate)
		assert.Equal(t, "CN=test", resp.EKCertificate.Subject)
		assert.NotNil(t, resp.SecureBootKeys)
		assert.Equal(t, "pk", resp.SecureBootKeys.PKFingerprint)
		assert.Equal(t, "test", resp.Labels["env"])
	})

	t.Run("converts bundle without manifest", func(t *testing.T) {
		svc := newMockVTPMService()
		handlers := NewVTPMHandlers(svc, slog.Default())

		bundle := &vtpm.Bundle{
			ID:        "test-id",
			Mode:      vtpm.BundleModePreAssigned,
			CreatedAt: time.Now(),
		}

		resp := handlers.bundleToResponse(bundle)

		assert.Equal(t, "test-id", resp.ID)
		assert.Empty(t, resp.Hostname)
		assert.Nil(t, resp.EKCertificate)
	})
}

func TestTemplateToResponse(t *testing.T) {
	t.Run("converts template", func(t *testing.T) {
		svc := newMockVTPMService()
		handlers := NewVTPMHandlers(svc, slog.Default())

		template := &vtpm.Template{
			ID:                "test-template",
			Description:       "Test description",
			EKAlgorithm:       vtpm.EKAlgorithmECC,
			SecureBootEnabled: true,
			CreatedAt:         time.Now(),
		}

		resp := handlers.templateToResponse(template)

		assert.Equal(t, "test-template", resp.ID)
		assert.Equal(t, "Test description", resp.Description)
		assert.Equal(t, "ECC", resp.EKAlgorithm)
		assert.True(t, resp.SecureBootEnabled)
	})
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

func TestEdgeCases(t *testing.T) {
	t.Run("handles negative PCR index", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/pcr/-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("rejects empty data in seal request", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", true)
		_, router := setupVTPMTestHandler(svc)

		// base64.StdEncoding.EncodeToString([]byte{}) returns "" (empty string)
		// which should be rejected by the handler
		reqBody := SealRequest{Data: base64.StdEncoding.EncodeToString([]byte{})}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		// Empty data should be rejected as a missing required field
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("handles empty bundle ID in URL", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// =============================================================================
// Validate Bundle Tests
// =============================================================================

func TestHandleValidateBundle(t *testing.T) {
	t.Run("validates bundle successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("test-bundle", "test-host", false)
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test-bundle/validate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var validateResp ValidateBundleResponse
		decodeVTPMResponse(t, resp.Body, &validateResp)
		assert.True(t, validateResp.Valid)
		assert.Empty(t, validateResp.Errors)
	})

	t.Run("returns not found for missing bundle", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/nonexistent/validate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns validation errors", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestBundle("bad-bundle", "test-host", false)
		svc.validateBundleErr = errors.New("missing TPM state file")
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/bad-bundle/validate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var validateResp ValidateBundleResponse
		decodeVTPMResponse(t, resp.Body, &validateResp)
		assert.False(t, validateResp.Valid)
		assert.NotEmpty(t, validateResp.Errors)
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/vtpm/bundles/test/validate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Bundle Path Tests
// =============================================================================

func TestHandleGetBundlePath(t *testing.T) {
	t.Run("returns bundle path", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/path", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var pathResp PathResponse
		decodeVTPMResponse(t, resp.Body, &pathResp)
		assert.Contains(t, pathResp.Path, "test-bundle")
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test/path", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

func TestHandleGetTPMSocketPath(t *testing.T) {
	t.Run("returns TPM socket path", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/tpm-socket", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var pathResp PathResponse
		decodeVTPMResponse(t, resp.Body, &pathResp)
		assert.Contains(t, pathResp.Path, "swtpm.sock")
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test/tpm-socket", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

func TestHandleGetNVRAMPath(t *testing.T) {
	t.Run("returns NVRAM path", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test-bundle/nvram", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var pathResp PathResponse
		decodeVTPMResponse(t, resp.Body, &pathResp)
		assert.Contains(t, pathResp.Path, "OVMF_VARS")
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/bundles/test/nvram", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Template List/Get/Delete Tests
// =============================================================================

func TestHandleListTemplates(t *testing.T) {
	t.Run("lists templates successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestTemplate("tmpl-1")
		svc.addTestTemplate("tmpl-2")
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/templates", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp TemplateListResponse
		decodeVTPMResponse(t, resp.Body, &listResp)
		assert.Len(t, listResp.Templates, 2)
	})

	t.Run("returns empty list when no templates", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/templates", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp TemplateListResponse
		decodeVTPMResponse(t, resp.Body, &listResp)
		assert.Empty(t, listResp.Templates)
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/templates", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

func TestHandleGetTemplate(t *testing.T) {
	t.Run("gets template successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestTemplate("tmpl-1")
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/templates/tmpl-1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var tmplResp TemplateResponse
		decodeVTPMResponse(t, resp.Body, &tmplResp)
		assert.Equal(t, "tmpl-1", tmplResp.ID)
	})

	t.Run("returns not found for missing template", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/templates/nonexistent", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/vtpm/templates/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

func TestHandleDeleteTemplate(t *testing.T) {
	t.Run("deletes template successfully", func(t *testing.T) {
		svc := newMockVTPMService()
		svc.addTestTemplate("tmpl-1")
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/vtpm/templates/tmpl-1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns not found for missing template", func(t *testing.T) {
		svc := newMockVTPMService()
		_, router := setupVTPMTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/vtpm/templates/nonexistent", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewVTPMHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/vtpm/templates/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}
