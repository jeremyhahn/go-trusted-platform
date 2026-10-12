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

package quic

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = quicwire.SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Mock vTPM Service
// =============================================================================

// mockVTPMService implements vtpm.VTPMService for testing
type mockVTPMService struct {
	bundles       map[string]*vtpm.Bundle
	templates     map[string]*vtpm.Template
	running       map[string]bool
	createError   error
	getError      error
	deleteError   error
	listError     error
	startError    error
	stopError     error
	quoteError    error
	sealError     error
	unsealError   error
	extendError   error
	readPCRError  error
	exportError   error
	importError   error
	validateError error
	quoteResult   *vtpm.QuoteResult
	sealedData    []byte
	unsealedData  []byte
	pcrValue      []byte
	exportData    []byte
}

func newMockVTPMService() *mockVTPMService {
	return &mockVTPMService{
		bundles:   make(map[string]*vtpm.Bundle),
		templates: make(map[string]*vtpm.Template),
		running:   make(map[string]bool),
	}
}

func (m *mockVTPMService) CreateBundle(ctx context.Context, opts *vtpm.CreateBundleOptions) (*vtpm.Bundle, error) {
	if m.createError != nil {
		return nil, m.createError
	}

	bundle := &vtpm.Bundle{
		ID:        "bundle-" + opts.Hostname,
		Mode:      opts.Mode,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Version:           vtpm.ManifestVersion,
			ID:                "bundle-" + opts.Hostname,
			Mode:              opts.Mode,
			Hostname:          opts.Hostname,
			CreatedAt:         time.Now(),
			EKAlgorithm:       opts.EKAlgorithm,
			SecureBootEnabled: opts.SecureBootEnabled,
			Labels:            opts.Labels,
		},
	}

	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *mockVTPMService) GetBundle(ctx context.Context, id string) (*vtpm.Bundle, error) {
	if m.getError != nil {
		return nil, m.getError
	}

	bundle, ok := m.bundles[id]
	if !ok {
		return nil, vtpm.ErrBundleNotFound{ID: id}
	}

	return bundle, nil
}

func (m *mockVTPMService) DeleteBundle(ctx context.Context, id string) error {
	if m.deleteError != nil {
		return m.deleteError
	}

	if _, ok := m.bundles[id]; !ok {
		return vtpm.ErrBundleNotFound{ID: id}
	}

	delete(m.bundles, id)
	delete(m.running, id)
	return nil
}

func (m *mockVTPMService) ListBundles(ctx context.Context, opts *vtpm.ListOptions) ([]*vtpm.Bundle, error) {
	if m.listError != nil {
		return nil, m.listError
	}

	result := make([]*vtpm.Bundle, 0, len(m.bundles))
	for _, bundle := range m.bundles {
		if opts.Mode != "" && bundle.Mode != opts.Mode {
			continue
		}
		result = append(result, bundle)
	}

	return result, nil
}

func (m *mockVTPMService) CreateTemplate(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
	if m.createError != nil {
		return nil, m.createError
	}

	if _, ok := m.templates[opts.ID]; ok {
		return nil, vtpm.ErrTemplateAlreadyExists{ID: opts.ID}
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
	if m.getError != nil {
		return nil, m.getError
	}

	template, ok := m.templates[id]
	if !ok {
		return nil, vtpm.ErrTemplateNotFound{ID: id}
	}

	return template, nil
}

func (m *mockVTPMService) DeleteTemplate(ctx context.Context, id string) error {
	if m.deleteError != nil {
		return m.deleteError
	}

	if _, ok := m.templates[id]; !ok {
		return vtpm.ErrTemplateNotFound{ID: id}
	}

	delete(m.templates, id)
	return nil
}

func (m *mockVTPMService) ListTemplates(ctx context.Context) ([]*vtpm.Template, error) {
	if m.listError != nil {
		return nil, m.listError
	}

	result := make([]*vtpm.Template, 0, len(m.templates))
	for _, template := range m.templates {
		result = append(result, template)
	}

	return result, nil
}

func (m *mockVTPMService) CloneTemplate(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
	if m.createError != nil {
		return nil, m.createError
	}

	template, ok := m.templates[opts.TemplateID]
	if !ok {
		return nil, vtpm.ErrTemplateNotFound{ID: opts.TemplateID}
	}

	bundle := &vtpm.Bundle{
		ID:         "bundle-" + opts.Hostname,
		Mode:       vtpm.BundleModePreAssigned,
		CreatedAt:  time.Now(),
		ClonedFrom: template.ID,
		Manifest: &vtpm.Manifest{
			Version:           vtpm.ManifestVersion,
			ID:                "bundle-" + opts.Hostname,
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          opts.Hostname,
			CreatedAt:         time.Now(),
			EKAlgorithm:       template.EKAlgorithm,
			SecureBootEnabled: template.SecureBootEnabled,
			Labels:            opts.Labels,
			ClonedFrom:        template.ID,
		},
	}

	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *mockVTPMService) ExportBundle(ctx context.Context, id string, w io.Writer) error {
	if m.exportError != nil {
		return m.exportError
	}

	if _, ok := m.bundles[id]; !ok {
		return vtpm.ErrBundleNotFound{ID: id}
	}

	data := m.exportData
	if data == nil {
		data = []byte("mock-export-data")
	}

	_, err := w.Write(data)
	return err
}

func (m *mockVTPMService) ImportBundle(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
	if m.importError != nil {
		return nil, m.importError
	}

	bundle := &vtpm.Bundle{
		ID:        "imported-bundle",
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Version:     vtpm.ManifestVersion,
			ID:          "imported-bundle",
			Mode:        vtpm.BundleModePreAssigned,
			Hostname:    "imported-host",
			CreatedAt:   time.Now(),
			EKAlgorithm: vtpm.EKAlgorithmRSA,
		},
	}

	m.bundles[bundle.ID] = bundle
	return bundle, nil
}

func (m *mockVTPMService) ValidateBundle(ctx context.Context, id string) error {
	if m.validateError != nil {
		return m.validateError
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
	return "/var/lib/vtpm/bundles/" + id + "/swtpm.sock"
}

func (m *mockVTPMService) GetNVRAMPath(id string) string {
	return "/var/lib/vtpm/bundles/" + id + "/OVMF_VARS.fd"
}

func (m *mockVTPMService) Start(ctx context.Context, bundleID string) error {
	if m.startError != nil {
		return m.startError
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
	if m.stopError != nil {
		return m.stopError
	}

	if _, ok := m.bundles[bundleID]; !ok {
		return vtpm.ErrBundleNotFound{ID: bundleID}
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
	if m.quoteError != nil {
		return nil, m.quoteError
	}

	if _, ok := m.bundles[bundleID]; !ok {
		return nil, vtpm.ErrBundleNotFound{ID: bundleID}
	}

	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}

	if m.quoteResult != nil {
		return m.quoteResult, nil
	}

	pcrValues := make(map[int][]byte)
	for _, pcr := range pcrs {
		pcrValues[pcr] = []byte("mock-pcr-value")
	}

	return &vtpm.QuoteResult{
		Quote:         []byte("mock-quote"),
		Signature:     []byte("mock-signature"),
		PCRValues:     pcrValues,
		HashAlgorithm: "SHA256",
	}, nil
}

func (m *mockVTPMService) Seal(ctx context.Context, bundleID string, data []byte, opts *vtpm.SealOptions) ([]byte, error) {
	if m.sealError != nil {
		return nil, m.sealError
	}

	if _, ok := m.bundles[bundleID]; !ok {
		return nil, vtpm.ErrBundleNotFound{ID: bundleID}
	}

	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}

	if m.sealedData != nil {
		return m.sealedData, nil
	}

	return append([]byte("sealed:"), data...), nil
}

func (m *mockVTPMService) Unseal(ctx context.Context, bundleID string, sealedData []byte, authValue string) ([]byte, error) {
	if m.unsealError != nil {
		return nil, m.unsealError
	}

	if _, ok := m.bundles[bundleID]; !ok {
		return nil, vtpm.ErrBundleNotFound{ID: bundleID}
	}

	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}

	if m.unsealedData != nil {
		return m.unsealedData, nil
	}

	if bytes.HasPrefix(sealedData, []byte("sealed:")) {
		return sealedData[7:], nil
	}

	return sealedData, nil
}

func (m *mockVTPMService) ExtendPCR(ctx context.Context, bundleID string, pcrIndex int, data []byte) error {
	if m.extendError != nil {
		return m.extendError
	}

	if _, ok := m.bundles[bundleID]; !ok {
		return vtpm.ErrBundleNotFound{ID: bundleID}
	}

	if !m.running[bundleID] {
		return vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}

	return nil
}

func (m *mockVTPMService) ReadPCR(ctx context.Context, bundleID string, pcrIndex int) ([]byte, error) {
	if m.readPCRError != nil {
		return nil, m.readPCRError
	}

	if _, ok := m.bundles[bundleID]; !ok {
		return nil, vtpm.ErrBundleNotFound{ID: bundleID}
	}

	if !m.running[bundleID] {
		return nil, vtpm.ErrVTPMNotRunning{BundleID: bundleID}
	}

	if m.pcrValue != nil {
		return m.pcrValue, nil
	}

	return []byte("mock-pcr-value"), nil
}

func (m *mockVTPMService) Close() error {
	return nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newVTPMTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestVTPMHandler() (*VTPMHandler, *mockVTPMService) {
	logger := newVTPMTestLogger()
	service := newMockVTPMService()
	handler := NewVTPMHandler(logger, service)
	return handler, service
}

func createTestBundle(service *mockVTPMService, id, hostname string) *vtpm.Bundle {
	bundle := &vtpm.Bundle{
		ID:        id,
		Mode:      vtpm.BundleModePreAssigned,
		CreatedAt: time.Now(),
		Manifest: &vtpm.Manifest{
			Version:           vtpm.ManifestVersion,
			ID:                id,
			Mode:              vtpm.BundleModePreAssigned,
			Hostname:          hostname,
			CreatedAt:         time.Now(),
			EKAlgorithm:       vtpm.EKAlgorithmRSA,
			SecureBootEnabled: true,
			Labels:            map[string]string{"env": "test"},
			EKCertificate: &vtpm.EKCertInfo{
				Subject:      "CN=Test EK",
				Issuer:       "CN=Test CA",
				SerialNumber: "12345",
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(365 * 24 * time.Hour),
				Fingerprint:  "abc123",
			},
			SecureBootKeys: &vtpm.SecureBootKeyInfo{
				PKFingerprint:  "pk-fingerprint",
				KEKFingerprint: "kek-fingerprint",
				DBFingerprint:  "db-fingerprint",
			},
		},
	}
	service.bundles[id] = bundle
	return bundle
}

func createTestTemplate(service *mockVTPMService, id string) *vtpm.Template {
	template := &vtpm.Template{
		ID:                id,
		Description:       "Test template",
		EKAlgorithm:       vtpm.EKAlgorithmRSA,
		SecureBootEnabled: true,
		CreatedAt:         time.Now(),
	}
	service.templates[id] = template
	return template
}

// =============================================================================
// Test: NewVTPMHandler
// =============================================================================

func TestNewVTPMHandler(t *testing.T) {
	t.Run("creates handler with valid inputs", func(t *testing.T) {
		logger := newVTPMTestLogger()
		service := newMockVTPMService()
		handler := NewVTPMHandler(logger, service)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, service, handler.service)
	})

	t.Run("creates handler with nil service", func(t *testing.T) {
		logger := newVTPMTestLogger()
		handler := NewVTPMHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.service)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestVTPMHandleRequest(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		resp := handler.HandleRequest(context.Background(), nil)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "nil")
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		req := &quicwire.Request{
			Opcode: 0x00, // Unknown opcode for vTPM handler
		}

		resp := handler.HandleRequest(context.Background(), req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown vTPM operation")
	})
}

// =============================================================================
// Test: CreateBundle
// =============================================================================

func TestVTPMHandleCreateBundle(t *testing.T) {
	ctx := context.Background()

	t.Run("creates bundle successfully", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		createReq := &VTPMCreateBundleRequest{
			Hostname:          "test-host",
			EKAlgorithm:       "RSA",
			SecureBootEnabled: true,
			Labels:            map[string]string{"env": "test"},
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var bundleResp VTPMBundleResponse
		err = quicwire.DecodePayload(resp.Payload, &bundleResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-test-host", bundleResp.ID)
		assert.Equal(t, "test-host", bundleResp.Hostname)
		assert.Equal(t, "RSA", bundleResp.EKAlgorithm)
		assert.True(t, bundleResp.SecureBootEnabled)
	})

	t.Run("creates bundle with ECC algorithm", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		createReq := &VTPMCreateBundleRequest{
			Hostname:    "test-host",
			EKAlgorithm: "ECC",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		createReq := &VTPMCreateBundleRequest{
			Hostname: "test-host",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing hostname", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		createReq := &VTPMCreateBundleRequest{}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "hostname")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreate,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when create fails", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		service.createError = errors.New("create failed")

		createReq := &VTPMCreateBundleRequest{
			Hostname: "test-host",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: GetBundle
// =============================================================================

func TestVTPMHandleGetBundle(t *testing.T) {
	ctx := context.Background()

	t.Run("gets bundle successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")

		getReq := &VTPMGetBundleRequest{
			ID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var bundleResp VTPMBundleResponse
		err = quicwire.DecodePayload(resp.Payload, &bundleResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", bundleResp.ID)
		assert.Equal(t, "test-host", bundleResp.Hostname)
		assert.NotNil(t, bundleResp.EKCertificate)
		assert.NotNil(t, bundleResp.SecureBootKeys)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		getReq := &VTPMGetBundleRequest{
			ID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		getReq := &VTPMGetBundleRequest{}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for bundle not found", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		getReq := &VTPMGetBundleRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: DeleteBundle
// =============================================================================

func TestVTPMHandleDeleteBundle(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes bundle successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")

		deleteReq := &VTPMDeleteBundleRequest{
			ID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var deleteResp VTPMDeleteBundleResponse
		err = quicwire.DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", deleteResp.BundleID)
		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		deleteReq := &VTPMDeleteBundleRequest{
			ID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		deleteReq := &VTPMDeleteBundleRequest{}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for bundle not found", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		deleteReq := &VTPMDeleteBundleRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMDelete,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: ListBundles
// =============================================================================

func TestVTPMHandleListBundles(t *testing.T) {
	ctx := context.Background()

	t.Run("lists bundles successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "host-1")
		createTestBundle(service, "bundle-2", "host-2")

		listReq := &VTPMListBundlesRequest{
			Limit: 10,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp VTPMListBundlesResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, 2, listResp.Count)
		assert.Len(t, listResp.Bundles, 2)
	})

	t.Run("uses default limit when not specified", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		listReq := &VTPMListBundlesRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("caps limit at max", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		listReq := &VTPMListBundlesRequest{
			Limit: 5000, // exceeds max
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("filters by mode", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "host-1")

		listReq := &VTPMListBundlesRequest{
			Mode: "pre-assigned",
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		listReq := &VTPMListBundlesRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		service.listError = errors.New("list failed")

		listReq := &VTPMListBundlesRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMList,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: CreateTemplate
// =============================================================================

func TestVTPMHandleCreateTemplate(t *testing.T) {
	ctx := context.Background()

	t.Run("creates template successfully", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		createReq := &VTPMCreateTemplateRequest{
			ID:                "template-1",
			Description:       "Test template",
			EKAlgorithm:       "RSA",
			SecureBootEnabled: true,
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreateTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var templateResp VTPMTemplateResponse
		err = quicwire.DecodePayload(resp.Payload, &templateResp)
		require.NoError(t, err)

		assert.Equal(t, "template-1", templateResp.ID)
		assert.Equal(t, "Test template", templateResp.Description)
		assert.Equal(t, "RSA", templateResp.EKAlgorithm)
		assert.True(t, templateResp.SecureBootEnabled)
	})

	t.Run("creates template with ECC algorithm", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		createReq := &VTPMCreateTemplateRequest{
			ID:          "template-1",
			EKAlgorithm: "ECC",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreateTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		createReq := &VTPMCreateTemplateRequest{
			ID: "template-1",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreateTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		createReq := &VTPMCreateTemplateRequest{}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreateTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when template already exists", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestTemplate(service, "template-1")

		createReq := &VTPMCreateTemplateRequest{
			ID: "template-1",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCreateTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
	})
}

// =============================================================================
// Test: GetTemplate
// =============================================================================

func TestVTPMHandleGetTemplate(t *testing.T) {
	ctx := context.Background()

	t.Run("gets template successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestTemplate(service, "template-1")

		getReq := &VTPMGetTemplateRequest{
			ID: "template-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var templateResp VTPMTemplateResponse
		err = quicwire.DecodePayload(resp.Payload, &templateResp)
		require.NoError(t, err)

		assert.Equal(t, "template-1", templateResp.ID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		getReq := &VTPMGetTemplateRequest{
			ID: "template-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		getReq := &VTPMGetTemplateRequest{}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for template not found", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		getReq := &VTPMGetTemplateRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: DeleteTemplate
// =============================================================================

func TestVTPMHandleDeleteTemplate(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes template successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestTemplate(service, "template-1")

		deleteReq := &VTPMDeleteTemplateRequest{
			ID: "template-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMDeleteTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var deleteResp VTPMDeleteTemplateResponse
		err = quicwire.DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, "template-1", deleteResp.TemplateID)
		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		deleteReq := &VTPMDeleteTemplateRequest{
			ID: "template-1",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMDeleteTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		deleteReq := &VTPMDeleteTemplateRequest{}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMDeleteTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for template not found", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		deleteReq := &VTPMDeleteTemplateRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMDeleteTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: ListTemplates
// =============================================================================

func TestVTPMHandleListTemplates(t *testing.T) {
	ctx := context.Background()

	t.Run("lists templates successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestTemplate(service, "template-1")
		createTestTemplate(service, "template-2")

		req := &quicwire.Request{
			Opcode: quicwire.OpVTPMListTemplates,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp VTPMListTemplatesResponse
		err := quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, 2, listResp.Count)
		assert.Len(t, listResp.Templates, 2)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		req := &quicwire.Request{
			Opcode: quicwire.OpVTPMListTemplates,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		service.listError = errors.New("list failed")

		req := &quicwire.Request{
			Opcode: quicwire.OpVTPMListTemplates,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: CloneTemplate
// =============================================================================

func TestVTPMHandleCloneTemplate(t *testing.T) {
	ctx := context.Background()

	t.Run("clones template successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestTemplate(service, "template-1")

		cloneReq := &VTPMCloneTemplateRequest{
			TemplateID: "template-1",
			Hostname:   "cloned-host",
			Labels:     map[string]string{"cloned": "true"},
		}

		payload, err := quicwire.EncodePayload(cloneReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCloneTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var bundleResp VTPMBundleResponse
		err = quicwire.DecodePayload(resp.Payload, &bundleResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-cloned-host", bundleResp.ID)
		assert.Equal(t, "cloned-host", bundleResp.Hostname)
		assert.Equal(t, "template-1", bundleResp.ClonedFrom)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		cloneReq := &VTPMCloneTemplateRequest{
			TemplateID: "template-1",
			Hostname:   "cloned-host",
		}

		payload, err := quicwire.EncodePayload(cloneReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCloneTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing template ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		cloneReq := &VTPMCloneTemplateRequest{
			Hostname: "cloned-host",
		}

		payload, err := quicwire.EncodePayload(cloneReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCloneTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing hostname", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		cloneReq := &VTPMCloneTemplateRequest{
			TemplateID: "template-1",
		}

		payload, err := quicwire.EncodePayload(cloneReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCloneTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for template not found", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		cloneReq := &VTPMCloneTemplateRequest{
			TemplateID: "nonexistent",
			Hostname:   "cloned-host",
		}

		payload, err := quicwire.EncodePayload(cloneReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMCloneTemplate,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: Start/Stop vTPM
// =============================================================================

func TestVTPMHandleStart(t *testing.T) {
	ctx := context.Background()

	t.Run("starts vTPM successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")

		startReq := &VTPMStartRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(startReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var startResp VTPMStartResponse
		err = quicwire.DecodePayload(resp.Payload, &startResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", startResp.BundleID)
		assert.True(t, startResp.Success)
		assert.NotEmpty(t, startResp.SocketPath)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		startReq := &VTPMStartRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(startReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		startReq := &VTPMStartRequest{}

		payload, err := quicwire.EncodePayload(startReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when already running", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")
		service.running["bundle-1"] = true

		startReq := &VTPMStartRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(startReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMStart,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
	})
}

func TestVTPMHandleStop(t *testing.T) {
	ctx := context.Background()

	t.Run("stops vTPM successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")
		service.running["bundle-1"] = true

		stopReq := &VTPMStopRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var stopResp VTPMStopResponse
		err = quicwire.DecodePayload(resp.Payload, &stopResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", stopResp.BundleID)
		assert.True(t, stopResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		stopReq := &VTPMStopRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		stopReq := &VTPMStopRequest{}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when not running", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")

		stopReq := &VTPMStopRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(stopReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMStop,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: GetState and IsRunning
// =============================================================================

func TestVTPMHandleGetState(t *testing.T) {
	ctx := context.Background()

	t.Run("gets state when running", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")
		service.running["bundle-1"] = true

		stateReq := &VTPMGetStateRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(stateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var stateResp VTPMGetStateResponse
		err = quicwire.DecodePayload(resp.Payload, &stateResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", stateResp.BundleID)
		assert.True(t, stateResp.Running)
		assert.NotEmpty(t, stateResp.SocketPath)
	})

	t.Run("gets state when not running", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")

		stateReq := &VTPMGetStateRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(stateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var stateResp VTPMGetStateResponse
		err = quicwire.DecodePayload(resp.Payload, &stateResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", stateResp.BundleID)
		assert.False(t, stateResp.Running)
		assert.Empty(t, stateResp.SocketPath)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		stateReq := &VTPMGetStateRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(stateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		stateReq := &VTPMGetStateRequest{}

		payload, err := quicwire.EncodePayload(stateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetState,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestVTPMHandleIsRunning(t *testing.T) {
	ctx := context.Background()

	t.Run("checks running status", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")
		service.running["bundle-1"] = true

		runningReq := &VTPMIsRunningRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(runningReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMIsRunning,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var runningResp VTPMIsRunningResponse
		err = quicwire.DecodePayload(resp.Payload, &runningResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", runningResp.BundleID)
		assert.True(t, runningResp.Running)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		runningReq := &VTPMIsRunningRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(runningReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMIsRunning,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		runningReq := &VTPMIsRunningRequest{}

		payload, err := quicwire.EncodePayload(runningReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMIsRunning,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Quote
// =============================================================================

func TestVTPMHandleQuote(t *testing.T) {
	ctx := context.Background()

	t.Run("generates quote successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")
		service.running["bundle-1"] = true

		quoteReq := &VTPMQuoteRequest{
			BundleID: "bundle-1",
			Nonce:    []byte("test-nonce"),
			PCRs:     []int{0, 1, 7},
		}

		payload, err := quicwire.EncodePayload(quoteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMQuote,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var quoteResp VTPMQuoteResponse
		err = quicwire.DecodePayload(resp.Payload, &quoteResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", quoteResp.BundleID)
		assert.NotEmpty(t, quoteResp.Quote)
		assert.NotEmpty(t, quoteResp.Signature)
		assert.NotEmpty(t, quoteResp.PCRValues)
		assert.Equal(t, "SHA256", quoteResp.HashAlgorithm)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		quoteReq := &VTPMQuoteRequest{
			BundleID: "bundle-1",
			Nonce:    []byte("test-nonce"),
			PCRs:     []int{0},
		}

		payload, err := quicwire.EncodePayload(quoteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMQuote,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		quoteReq := &VTPMQuoteRequest{
			Nonce: []byte("test-nonce"),
		}

		payload, err := quicwire.EncodePayload(quoteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMQuote,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing nonce", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		quoteReq := &VTPMQuoteRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(quoteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMQuote,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		quoteReq := &VTPMQuoteRequest{
			BundleID: "bundle-1",
			Nonce:    []byte("test-nonce"),
			PCRs:     []int{24}, // Invalid
		}

		payload, err := quicwire.EncodePayload(quoteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMQuote,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when vTPM not running", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")

		quoteReq := &VTPMQuoteRequest{
			BundleID: "bundle-1",
			Nonce:    []byte("test-nonce"),
			PCRs:     []int{0},
		}

		payload, err := quicwire.EncodePayload(quoteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMQuote,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: ReadPCR and ExtendPCR
// =============================================================================

func TestVTPMHandleReadPCR(t *testing.T) {
	ctx := context.Background()

	t.Run("reads PCR successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")
		service.running["bundle-1"] = true

		readReq := &VTPMReadPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: 7,
		}

		payload, err := quicwire.EncodePayload(readReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMReadPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var readResp VTPMReadPCRResponse
		err = quicwire.DecodePayload(resp.Payload, &readResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", readResp.BundleID)
		assert.Equal(t, 7, readResp.PCRIndex)
		assert.NotEmpty(t, readResp.Value)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		readReq := &VTPMReadPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: 0,
		}

		payload, err := quicwire.EncodePayload(readReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMReadPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		readReq := &VTPMReadPCRRequest{
			PCRIndex: 0,
		}

		payload, err := quicwire.EncodePayload(readReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMReadPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		readReq := &VTPMReadPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: 24, // Invalid
		}

		payload, err := quicwire.EncodePayload(readReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMReadPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestVTPMHandleExtendPCR(t *testing.T) {
	ctx := context.Background()

	t.Run("extends PCR successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")
		service.running["bundle-1"] = true

		extendReq := &VTPMExtendPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: 14,
			Data:     []byte("extend-data"),
		}

		payload, err := quicwire.EncodePayload(extendReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExtendPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var extendResp VTPMExtendPCRResponse
		err = quicwire.DecodePayload(resp.Payload, &extendResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", extendResp.BundleID)
		assert.Equal(t, 14, extendResp.PCRIndex)
		assert.True(t, extendResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		extendReq := &VTPMExtendPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: 14,
			Data:     []byte("extend-data"),
		}

		payload, err := quicwire.EncodePayload(extendReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExtendPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		extendReq := &VTPMExtendPCRRequest{
			PCRIndex: 14,
			Data:     []byte("extend-data"),
		}

		payload, err := quicwire.EncodePayload(extendReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExtendPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		extendReq := &VTPMExtendPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: -1, // Invalid
			Data:     []byte("extend-data"),
		}

		payload, err := quicwire.EncodePayload(extendReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExtendPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing data", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		extendReq := &VTPMExtendPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: 14,
		}

		payload, err := quicwire.EncodePayload(extendReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExtendPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Seal and Unseal
// =============================================================================

func TestVTPMHandleSeal(t *testing.T) {
	ctx := context.Background()

	t.Run("seals data successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")
		service.running["bundle-1"] = true

		sealReq := &VTPMSealRequest{
			BundleID:  "bundle-1",
			Data:      []byte("secret-data"),
			PCRs:      []int{0, 7},
			AuthValue: "password",
		}

		payload, err := quicwire.EncodePayload(sealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMSeal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var sealResp VTPMSealResponse
		err = quicwire.DecodePayload(resp.Payload, &sealResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", sealResp.BundleID)
		assert.NotEmpty(t, sealResp.SealedData)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		sealReq := &VTPMSealRequest{
			BundleID: "bundle-1",
			Data:     []byte("secret-data"),
		}

		payload, err := quicwire.EncodePayload(sealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMSeal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		sealReq := &VTPMSealRequest{
			Data: []byte("secret-data"),
		}

		payload, err := quicwire.EncodePayload(sealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMSeal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing data", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		sealReq := &VTPMSealRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(sealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMSeal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		sealReq := &VTPMSealRequest{
			BundleID: "bundle-1",
			Data:     []byte("secret-data"),
			PCRs:     []int{25}, // Invalid
		}

		payload, err := quicwire.EncodePayload(sealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMSeal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when seal fails", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		service.sealError = errors.New("seal operation failed")

		sealReq := &VTPMSealRequest{
			BundleID: "bundle-1",
			Data:     []byte("secret-data"),
		}

		payload, err := quicwire.EncodePayload(sealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMSeal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestVTPMHandleUnseal(t *testing.T) {
	ctx := context.Background()

	t.Run("unseals data successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")
		service.running["bundle-1"] = true

		unsealReq := &VTPMUnsealRequest{
			BundleID:   "bundle-1",
			SealedData: []byte("sealed:secret-data"),
			AuthValue:  "password",
		}

		payload, err := quicwire.EncodePayload(unsealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMUnseal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var unsealResp VTPMUnsealResponse
		err = quicwire.DecodePayload(resp.Payload, &unsealResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", unsealResp.BundleID)
		assert.Equal(t, []byte("secret-data"), unsealResp.Data)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		unsealReq := &VTPMUnsealRequest{
			BundleID:   "bundle-1",
			SealedData: []byte("sealed-data"),
		}

		payload, err := quicwire.EncodePayload(unsealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMUnseal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		unsealReq := &VTPMUnsealRequest{
			SealedData: []byte("sealed-data"),
		}

		payload, err := quicwire.EncodePayload(unsealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMUnseal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing sealed data", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		unsealReq := &VTPMUnsealRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(unsealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMUnseal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Export/Import/Validate
// =============================================================================

func TestVTPMHandleExportBundle(t *testing.T) {
	ctx := context.Background()

	t.Run("exports bundle successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")

		exportReq := &VTPMExportBundleRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExportBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var exportResp VTPMExportBundleResponse
		err = quicwire.DecodePayload(resp.Payload, &exportResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", exportResp.BundleID)
		assert.NotEmpty(t, exportResp.Data)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		exportReq := &VTPMExportBundleRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExportBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		exportReq := &VTPMExportBundleRequest{}

		payload, err := quicwire.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExportBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for bundle not found", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		exportReq := &VTPMExportBundleRequest{
			BundleID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExportBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

func TestVTPMHandleImportBundle(t *testing.T) {
	ctx := context.Background()

	t.Run("imports bundle successfully", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		importReq := &VTPMImportBundleRequest{
			Data: []byte("mock-bundle-data"),
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMImportBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var bundleResp VTPMBundleResponse
		err = quicwire.DecodePayload(resp.Payload, &bundleResp)
		require.NoError(t, err)

		assert.Equal(t, "imported-bundle", bundleResp.ID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		importReq := &VTPMImportBundleRequest{
			Data: []byte("mock-bundle-data"),
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMImportBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing data", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		importReq := &VTPMImportBundleRequest{}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMImportBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestVTPMHandleValidateBundle(t *testing.T) {
	ctx := context.Background()

	t.Run("validates bundle successfully", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")

		validateReq := &VTPMValidateBundleRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(validateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMValidateBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var validateResp VTPMValidateBundleResponse
		err = quicwire.DecodePayload(resp.Payload, &validateResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", validateResp.BundleID)
		assert.True(t, validateResp.Valid)
	})

	t.Run("returns invalid when validation fails", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		createTestBundle(service, "bundle-1", "test-host")
		service.validateError = vtpm.ErrChecksumMismatch{File: "test.bin", Expected: "abc", Actual: "def"}

		validateReq := &VTPMValidateBundleRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(validateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMValidateBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var validateResp VTPMValidateBundleResponse
		err = quicwire.DecodePayload(resp.Payload, &validateResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", validateResp.BundleID)
		assert.False(t, validateResp.Valid)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		validateReq := &VTPMValidateBundleRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(validateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMValidateBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		validateReq := &VTPMValidateBundleRequest{}

		payload, err := quicwire.EncodePayload(validateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMValidateBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Path Operations
// =============================================================================

func TestVTPMHandleGetBundlePath(t *testing.T) {
	ctx := context.Background()

	t.Run("gets bundle path successfully", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		pathReq := &VTPMGetPathRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(pathReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetBundlePath,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var pathResp VTPMGetPathResponse
		err = quicwire.DecodePayload(resp.Payload, &pathResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", pathResp.BundleID)
		assert.Contains(t, pathResp.Path, "bundle-1")
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		pathReq := &VTPMGetPathRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(pathReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetBundlePath,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		pathReq := &VTPMGetPathRequest{}

		payload, err := quicwire.EncodePayload(pathReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetBundlePath,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestVTPMHandleGetSocketPath(t *testing.T) {
	ctx := context.Background()

	t.Run("gets socket path successfully", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		pathReq := &VTPMGetPathRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(pathReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetSocketPath,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var pathResp VTPMGetPathResponse
		err = quicwire.DecodePayload(resp.Payload, &pathResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", pathResp.BundleID)
		assert.Contains(t, pathResp.Path, "swtpm.sock")
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		pathReq := &VTPMGetPathRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(pathReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetSocketPath,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		pathReq := &VTPMGetPathRequest{}

		payload, err := quicwire.EncodePayload(pathReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetSocketPath,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestVTPMHandleGetNVRAMPath(t *testing.T) {
	ctx := context.Background()

	t.Run("gets NVRAM path successfully", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		pathReq := &VTPMGetPathRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(pathReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetNVRAMPath,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var pathResp VTPMGetPathResponse
		err = quicwire.DecodePayload(resp.Payload, &pathResp)
		require.NoError(t, err)

		assert.Equal(t, "bundle-1", pathResp.BundleID)
		assert.Contains(t, pathResp.Path, "OVMF_VARS.fd")
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		pathReq := &VTPMGetPathRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(pathReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetNVRAMPath,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bundle ID", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		pathReq := &VTPMGetPathRequest{}

		payload, err := quicwire.EncodePayload(pathReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMGetNVRAMPath,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: Error Types
// =============================================================================

func TestVTPMErrorTypes(t *testing.T) {
	t.Run("ErrVTPMEncodingFailed", func(t *testing.T) {
		cause := errors.New("encoding error")
		err := ErrVTPMEncodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "encoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrVTPMDecodingFailed", func(t *testing.T) {
		cause := errors.New("decoding error")
		err := ErrVTPMDecodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "decoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrVTPMOperationFailed", func(t *testing.T) {
		cause := errors.New("operation error")
		err := ErrVTPMOperationFailed{
			Operation: "seal",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "seal")
		assert.Contains(t, err.Error(), "operation error")
		assert.Equal(t, cause, err.Unwrap())
	})
}

// =============================================================================
// Test: vtpmErrorResponse - Comprehensive Error Mapping
// =============================================================================

func TestVTPMErrorResponse(t *testing.T) {
	handler, _ := createTestVTPMHandler()

	testCases := []struct {
		name           string
		err            error
		expectedStatus byte
	}{
		{"bundle not found", vtpm.ErrBundleNotFound{ID: "test"}, quicwire.StatusNotFound},
		{"bundle exists", vtpm.ErrBundleAlreadyExists{ID: "test"}, quicwire.StatusAlreadyExists},
		{"template not found", vtpm.ErrTemplateNotFound{ID: "test"}, quicwire.StatusNotFound},
		{"template exists", vtpm.ErrTemplateAlreadyExists{ID: "test"}, quicwire.StatusAlreadyExists},
		{"invalid config", vtpm.ErrInvalidConfig{Field: "test", Reason: "invalid"}, quicwire.StatusInvalidArgument},
		{"invalid manifest", vtpm.ErrInvalidManifest{Reason: "invalid"}, quicwire.StatusInvalidArgument},
		{"vTPM not running", vtpm.ErrVTPMNotRunning{BundleID: "test"}, quicwire.StatusInvalidRequest},
		{"vTPM already running", vtpm.ErrVTPMAlreadyRunning{BundleID: "test"}, quicwire.StatusAlreadyExists},
		{"invalid nonce", vtpm.ErrInvalidNonce{Reason: "too short"}, quicwire.StatusInvalidArgument},
		{"invalid PCR index", vtpm.ErrInvalidPCRIndex{PCRIndex: 99}, quicwire.StatusInvalidArgument},
		{"checksum mismatch", vtpm.ErrChecksumMismatch{File: "test.bin", Expected: "a", Actual: "b"}, quicwire.StatusInvalidArgument},
		{"CA unavailable", vtpm.ErrCAUnavailable{}, quicwire.StatusUnavailable},
		{"generic error", errors.New("unknown error"), quicwire.StatusInternalError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.vtpmErrorResponse(tc.err)
			assert.Equal(t, tc.expectedStatus, resp.Status)
		})
	}
}

// =============================================================================
// Test: bundleToResponse and templateToResponse
// =============================================================================

func TestBundleToResponse(t *testing.T) {
	handler, service := createTestVTPMHandler()

	t.Run("converts complete bundle", func(t *testing.T) {
		bundle := createTestBundle(service, "bundle-1", "test-host")
		service.running["bundle-1"] = true

		resp := handler.bundleToResponse(bundle)

		assert.Equal(t, "bundle-1", resp.ID)
		assert.Equal(t, "test-host", resp.Hostname)
		assert.Equal(t, "RSA", resp.EKAlgorithm)
		assert.True(t, resp.SecureBootEnabled)
		assert.True(t, resp.Running)
		assert.NotEmpty(t, resp.SocketPath)
		assert.NotNil(t, resp.EKCertificate)
		assert.NotNil(t, resp.SecureBootKeys)
	})

	t.Run("handles nil bundle", func(t *testing.T) {
		resp := handler.bundleToResponse(nil)
		assert.Nil(t, resp)
	})

	t.Run("handles bundle without manifest", func(t *testing.T) {
		bundle := &vtpm.Bundle{
			ID:        "bundle-1",
			Mode:      vtpm.BundleModePreAssigned,
			CreatedAt: time.Now(),
		}

		resp := handler.bundleToResponse(bundle)

		assert.NotNil(t, resp)
		assert.Equal(t, "bundle-1", resp.ID)
		assert.Empty(t, resp.Hostname)
	})
}

func TestTemplateToResponse(t *testing.T) {
	handler, service := createTestVTPMHandler()

	t.Run("converts complete template", func(t *testing.T) {
		template := createTestTemplate(service, "template-1")

		resp := handler.templateToResponse(template)

		assert.Equal(t, "template-1", resp.ID)
		assert.Equal(t, "Test template", resp.Description)
		assert.Equal(t, "RSA", resp.EKAlgorithm)
		assert.True(t, resp.SecureBootEnabled)
		assert.Greater(t, resp.CreatedAt, int64(0))
	})

	t.Run("handles nil template", func(t *testing.T) {
		resp := handler.templateToResponse(nil)
		assert.Nil(t, resp)
	})
}

// =============================================================================
// Test: Pagination Constants
// =============================================================================

func TestVTPMPaginationConstants(t *testing.T) {
	assert.Equal(t, 50, vtpmDefaultLimit)
	assert.Equal(t, 1000, vtpmMaxLimit)
	assert.Less(t, vtpmDefaultLimit, vtpmMaxLimit)
}

// =============================================================================
// Test: PCR Operations - Additional Error Paths
// =============================================================================

func TestVTPMHandleReadPCRErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		readReq := &VTPMReadPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: 24, // Invalid - must be 0-23
		}

		payload, err := quicwire.EncodePayload(readReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMReadPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for negative PCR index", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		readReq := &VTPMReadPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: -1, // Invalid
		}

		payload, err := quicwire.EncodePayload(readReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMReadPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestVTPMHandleExtendPCRErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		extendReq := &VTPMExtendPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: 30, // Invalid - must be 0-23
			Data:     []byte("test-data"),
		}

		payload, err := quicwire.EncodePayload(extendReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExtendPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestVTPMHandleUnsealErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error for missing sealed data", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		unsealReq := &VTPMUnsealRequest{
			BundleID: "bundle-1",
		}

		payload, err := quicwire.EncodePayload(unsealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMUnseal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestVTPMHandleImportBundleErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error for missing bundle data", func(t *testing.T) {
		handler, _ := createTestVTPMHandler()

		importReq := &VTPMImportBundleRequest{
			Data: nil, // Empty data
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMImportBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewVTPMHandler(newVTPMTestLogger(), nil)

		importReq := &VTPMImportBundleRequest{
			Data: []byte("test-bundle-data"),
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMImportBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})
}

// =============================================================================
// Test: Additional Operation Failure Paths
// =============================================================================

func TestVTPMHandleReadPCROperationFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when read fails", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		service.readPCRError = errors.New("TPM communication error")

		readReq := &VTPMReadPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: 0,
		}

		payload, err := quicwire.EncodePayload(readReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMReadPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestVTPMHandleExtendPCROperationFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when extend fails", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		service.extendError = errors.New("PCR extend failed")

		extendReq := &VTPMExtendPCRRequest{
			BundleID: "bundle-1",
			PCRIndex: 0,
			Data:     []byte("test-data"),
		}

		payload, err := quicwire.EncodePayload(extendReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMExtendPCR,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestVTPMHandleUnsealOperationFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when unseal fails", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		service.unsealError = errors.New("unseal operation failed")

		unsealReq := &VTPMUnsealRequest{
			BundleID:   "bundle-1",
			SealedData: []byte("sealed-data"),
		}

		payload, err := quicwire.EncodePayload(unsealReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMUnseal,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestVTPMHandleImportBundleOperationFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when import fails", func(t *testing.T) {
		handler, service := createTestVTPMHandler()
		service.importError = errors.New("import failed")

		importReq := &VTPMImportBundleRequest{
			Data: []byte("test-bundle-data"),
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpVTPMImportBundle,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}
