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
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock TPM Service
// =============================================================================

// mockTPMService implements xkmssdk.TrustedPlatformModule for TPM handler testing.
// It embeds the interface so only methods used by the handlers need to be overridden.
type mockTPMService struct {
	xkmssdk.TrustedPlatformModule

	infoResult          string
	infoErr             error
	fixedProps          *xkmssdk.PropertiesFixed
	fixedPropsErr       error
	config              *xkmssdk.TPMConfig
	provisionOwnerErr   error
	clearErr            error
	ekAttrs             *xkmssdk.KeyAttributes
	ekAttrsErr          error
	createEKErr         error
	flushed             []xkmssdk.TPMHandle
	ekCert              *x509.Certificate
	ekCertErr           error
	provisionEKCertErr  error
	ssrkAttrs           *xkmssdk.KeyAttributes
	ssrkAttrsErr        error
	createSRKErr        error
	iakAttrs            *xkmssdk.KeyAttributes
	iakAttrsErr         error
	iakPubKey           crypto.PublicKey
	iakPubKeyErr        error
	createIAKAttrs      *xkmssdk.KeyAttributes
	createIAKErr        error
	idevidAttrs         *xkmssdk.KeyAttributes
	idevidAttrsErr      error
	idevidPubKey        crypto.PublicKey
	idevidPubKeyErr     error
	quoteResult         xkmssdk.Quote
	quoteErr            error
	certifyResult       *xkmssdk.CertifyResult
	certifyErr          error
	keyAttrs            *xkmssdk.KeyAttributes
	keyAttrsErr         error
	readPCRsResult      []xkmssdk.PCRBank
	readPCRsErr         error
	extendPCRErr        error
	eventLogData        []byte
	eventLogErr         error
	parsedEvents        []xkmssdk.TPMEvent
	parsedEventLogErr   error
	supportedAlgorithms []string
	supportedAlgoErr    error
	supportedCommands   []string
	supportedCmdsErr    error
	supportedCurves     []string
	supportedCurvesErr  error
	randomBytesResult   []byte
	randomBytesErr      error
	sealResult          *xkmssdk.SealedData
	sealErr             error
	unsealResult        []byte
	unsealErr           error
}

func newMockTPMService() *mockTPMService {
	return &mockTPMService{
		config: &xkmssdk.TPMConfig{
			UseSimulator: true,
		},
		ekAttrs: &xkmssdk.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81010001,
				PublicKeyBytes: []byte("test-ek-public-key"),
			},
		},
		ssrkAttrs: &xkmssdk.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81000001,
				PublicKeyBytes: []byte("test-srk-public-key"),
			},
		},
		iakAttrs: &xkmssdk.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81020001,
				PublicKeyBytes: []byte("test-iak-public-key"),
			},
		},
		idevidAttrs: &xkmssdk.KeyAttributes{
			KeyAlgorithm: x509.RSA,
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle:         0x81030001,
				PublicKeyBytes: []byte("test-idevid-public-key"),
			},
		},
	}
}

func (m *mockTPMService) Info() (string, error) {
	return m.infoResult, m.infoErr
}

func (m *mockTPMService) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return m.fixedProps, m.fixedPropsErr
}

func (m *mockTPMService) Config() *xkmssdk.TPMConfig {
	return m.config
}

func (m *mockTPMService) ProvisionOwner(hierarchyAuth xkmssdk.Password) (*xkmssdk.KeyAttributes, error) {
	if m.provisionOwnerErr != nil {
		return nil, m.provisionOwnerErr
	}
	return m.ekAttrs, nil
}

func (m *mockTPMService) Clear(lockoutAuth []byte) error {
	return m.clearErr
}

func (m *mockTPMService) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.ekAttrs, m.ekAttrsErr
}

func (m *mockTPMService) CreateEK(keyAttrs *xkmssdk.KeyAttributes) error {
	return m.createEKErr
}

func (m *mockTPMService) Flush(handle xkmssdk.TPMHandle) {
	m.flushed = append(m.flushed, handle)
}

func (m *mockTPMService) EKCertificate() (*x509.Certificate, error) {
	if m.ekCertErr != nil {
		return nil, m.ekCertErr
	}
	if m.ekCert != nil {
		return m.ekCert, nil
	}
	return &x509.Certificate{
		Raw:          []byte("test-ek-cert"),
		SerialNumber: big.NewInt(1),
	}, nil
}

func (m *mockTPMService) ProvisionEKCert(hierarchyAuth, ekCert []byte) error {
	return m.provisionEKCertErr
}

func (m *mockTPMService) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.ssrkAttrs, m.ssrkAttrsErr
}

func (m *mockTPMService) CreateSRK(keyAttrs *xkmssdk.KeyAttributes) error {
	return m.createSRKErr
}

func (m *mockTPMService) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.iakAttrs, m.iakAttrsErr
}

func (m *mockTPMService) IAK() (crypto.PublicKey, error) {
	if m.iakPubKeyErr != nil {
		return nil, m.iakPubKeyErr
	}
	return m.iakPubKey, nil
}

func (m *mockTPMService) CreateIAK(ekAttrs *xkmssdk.KeyAttributes, qualifyingData []byte) (*xkmssdk.KeyAttributes, error) {
	if m.createIAKErr != nil {
		return nil, m.createIAKErr
	}
	return m.createIAKAttrs, nil
}

func (m *mockTPMService) IDevIDAttributes() (*xkmssdk.KeyAttributes, error) {
	return m.idevidAttrs, m.idevidAttrsErr
}

func (m *mockTPMService) IDevID() (crypto.PublicKey, error) {
	if m.idevidPubKeyErr != nil {
		return nil, m.idevidPubKeyErr
	}
	return m.idevidPubKey, nil
}

func (m *mockTPMService) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	return m.quoteResult, m.quoteErr
}

func (m *mockTPMService) CertifyKey(keyAttrs *xkmssdk.KeyAttributes, nonce []byte, backend xkmssdk.TPMKeyBackend) (*xkmssdk.CertifyResult, error) {
	return m.certifyResult, m.certifyErr
}

func (m *mockTPMService) KeyAttributes(handle xkmssdk.TPMHandle) (*xkmssdk.KeyAttributes, error) {
	return m.keyAttrs, m.keyAttrsErr
}

func (m *mockTPMService) ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error) {
	return m.readPCRsResult, m.readPCRsErr
}

func (m *mockTPMService) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	return m.extendPCRErr
}

func (m *mockTPMService) EventLog() ([]byte, error) {
	return m.eventLogData, m.eventLogErr
}

func (m *mockTPMService) ParsedEventLog() ([]xkmssdk.TPMEvent, error) {
	return m.parsedEvents, m.parsedEventLogErr
}

func (m *mockTPMService) SupportedAlgorithms() ([]string, error) {
	return m.supportedAlgorithms, m.supportedAlgoErr
}

func (m *mockTPMService) SupportedCommands() ([]string, error) {
	return m.supportedCommands, m.supportedCmdsErr
}

func (m *mockTPMService) SupportedECCCurves() ([]string, error) {
	return m.supportedCurves, m.supportedCurvesErr
}

func (m *mockTPMService) RandomBytes(fixedLength int) ([]byte, error) {
	return m.randomBytesResult, m.randomBytesErr
}

func (m *mockTPMService) Seal(ctx context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	if m.sealResult != nil {
		return m.sealResult, nil
	}
	return &xkmssdk.SealedData{
		Ciphertext: []byte("sealed-" + string(data)),
	}, nil
}

func (m *mockTPMService) Unseal(ctx context.Context, sealed *xkmssdk.SealedData, opts *xkmssdk.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	return m.unsealResult, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func setupTPMTestHandler(tpm *mockTPMService) (*TPMHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewTPMHandlers(logger)
	if tpm != nil {
		handlers.SetTPM2Service(tpm)
	}
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

func decodeTPMResponse(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	defer resp.Body.Close()
	err := json.NewDecoder(resp.Body).Decode(v)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestTPMHandlerErrors(t *testing.T) {
	t.Run("ErrTPMServiceNotAvailable", func(t *testing.T) {
		err := ErrTPMServiceNotAvailable{}
		assert.Equal(t, "TPM service not available", err.Error())
	})

	t.Run("ErrTPMInvalidPCRIndex", func(t *testing.T) {
		err := ErrTPMInvalidPCRIndex{Index: 25}
		assert.Equal(t, "invalid PCR index: 25 (must be 0-23)", err.Error())
	})

	t.Run("ErrTPMOperationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrTPMOperationFailed{Operation: "seal", Cause: cause}
		assert.Equal(t, "TPM operation seal failed: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrTPMInvalidNVIndex empty", func(t *testing.T) {
		err := ErrTPMInvalidNVIndex{}
		assert.Equal(t, "NV index is required", err.Error())
	})

	t.Run("ErrTPMInvalidNVIndex with value", func(t *testing.T) {
		err := ErrTPMInvalidNVIndex{Index: "0xBadIndex"}
		assert.Equal(t, "invalid NV index: 0xBadIndex", err.Error())
	})

	t.Run("ErrTPMInvalidRandomSize", func(t *testing.T) {
		err := ErrTPMInvalidRandomSize{Size: 2048}
		assert.Equal(t, "invalid random size: 2048 (must be 1-1024)", err.Error())
	})
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewTPMHandlers(t *testing.T) {
	t.Run("creates handlers with logger", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewTPMHandlers(logger)
		require.NotNil(t, handlers)
		assert.Equal(t, logger, handlers.logger)
	})

	t.Run("creates handlers with nil logger uses default", func(t *testing.T) {
		handlers := NewTPMHandlers(nil)
		require.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger)
	})
}

func TestSetTPM2Service(t *testing.T) {
	t.Run("sets TPM service", func(t *testing.T) {
		handlers := NewTPMHandlers(slog.Default())
		tpm := newMockTPMService()
		handlers.SetTPM2Service(tpm)
		assert.NotNil(t, handlers.getTPM())
	})
}

func TestTPMRegisterRoutes(t *testing.T) {
	t.Run("registers all TPM routes", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		routes := []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/api/v1/tpm/info"},
			{http.MethodPost, "/api/v1/tpm/provision"},
			{http.MethodPost, "/api/v1/tpm/clear"},
			{http.MethodGet, "/api/v1/tpm/ek"},
			{http.MethodPost, "/api/v1/tpm/ek"},
			{http.MethodDelete, "/api/v1/tpm/ek"},
			{http.MethodGet, "/api/v1/tpm/ek/certificate"},
			{http.MethodPost, "/api/v1/tpm/ek/certificate"},
			{http.MethodGet, "/api/v1/tpm/srk"},
			{http.MethodPost, "/api/v1/tpm/srk"},
			{http.MethodDelete, "/api/v1/tpm/srk"},
			{http.MethodGet, "/api/v1/tpm/iak"},
			{http.MethodPost, "/api/v1/tpm/iak"},
			{http.MethodDelete, "/api/v1/tpm/iak"},
			{http.MethodGet, "/api/v1/tpm/idevid"},
			{http.MethodPost, "/api/v1/tpm/quote"},
			{http.MethodPost, "/api/v1/tpm/verify-quote"},
			{http.MethodPost, "/api/v1/tpm/certify"},
			{http.MethodGet, "/api/v1/tpm/pcrs"},
			{http.MethodPost, "/api/v1/tpm/pcrs/extend"},
			{http.MethodGet, "/api/v1/tpm/eventlog"},
			{http.MethodGet, "/api/v1/tpm/capabilities"},
			{http.MethodPost, "/api/v1/tpm/random"},
			{http.MethodPost, "/api/v1/tpm/seal"},
			{http.MethodPost, "/api/v1/tpm/unseal"},
			{http.MethodPost, "/api/v1/tpm/nv/read"},
			{http.MethodPost, "/api/v1/tpm/nv/write"},
			{http.MethodDelete, "/api/v1/tpm/nv"},
			{http.MethodPost, "/api/v1/tpm/nv/define"},
			{http.MethodPost, "/api/v1/tpm/csr/idevid"},
			{http.MethodPost, "/api/v1/tpm/csr/ldevid"},
			{http.MethodGet, "/api/v1/tpm/platform"},
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
// handleGetInfo Tests
// =============================================================================

func TestTPMHandleGetInfo(t *testing.T) {
	t.Run("returns info successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.infoResult = "TPM Simulator v2.0"
		tpm.fixedProps = &xkmssdk.PropertiesFixed{
			Manufacturer:   "TestMfg",
			Model:          "TestModel",
			FwMajor:        1,
			FwMinor:        2,
			NVBufferMax:    2048,
			Fips1402:       true,
			LockoutCounter: 0,
			MaxAuthFail:    32,
			Family:         "2.0",
			Revision:       "164",
			VendorID:       "TST",
		}
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/info", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var infoResp TPMInfoResponse
		decodeTPMResponse(t, resp, &infoResp)
		assert.Equal(t, "TPM Simulator v2.0", infoResp.Info)
		assert.True(t, infoResp.IsSimulator)
		assert.True(t, infoResp.FIPSMode)
		assert.Equal(t, uint32(2048), infoResp.MaxNVRAMSize)
		require.NotNil(t, infoResp.Manufacturer)
		assert.Equal(t, "TestMfg", infoResp.Manufacturer.Name)
		assert.Equal(t, "TestModel", infoResp.Manufacturer.Model)
		assert.Equal(t, "1.2", infoResp.Manufacturer.FirmwareVersion)
		require.Len(t, infoResp.Capabilities, 5)
	})

	t.Run("returns info without fixed properties", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.infoResult = "TPM v2.0"
		tpm.fixedPropsErr = errors.New("not supported")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/info", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var infoResp TPMInfoResponse
		decodeTPMResponse(t, resp, &infoResp)
		assert.Equal(t, "TPM v2.0", infoResp.Info)
		assert.Nil(t, infoResp.Manufacturer)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/info", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when Info fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.infoErr = errors.New("TPM not initialized")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/info", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns info with nil config", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.infoResult = "TPM v2.0"
		tpm.config = nil
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/info", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var infoResp TPMInfoResponse
		decodeTPMResponse(t, resp, &infoResp)
		assert.False(t, infoResp.IsSimulator)
	})
}

// =============================================================================
// handleProvision Tests
// =============================================================================

func TestTPMHandleProvision(t *testing.T) {
	t.Run("provisions successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMProvisionRequest{OwnerPassword: "test-pw"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/provision", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var status TPMStatusResponse
		decodeTPMResponse(t, resp, &status)
		assert.True(t, status.Success)
	})

	t.Run("provisions without password", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMProvisionRequest{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/provision", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMProvisionRequest{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/provision", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/provision", strings.NewReader("bad json"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when provision fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.provisionOwnerErr = errors.New("already provisioned")
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMProvisionRequest{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/provision", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

// =============================================================================
// handleClear Tests
// =============================================================================

func TestTPMHandleClear(t *testing.T) {
	t.Run("clears successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMClearRequest{OwnerPassword: "test-pw"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/clear", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var status TPMStatusResponse
		decodeTPMResponse(t, resp, &status)
		assert.True(t, status.Success)
	})

	t.Run("clears without password", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMClearRequest{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/clear", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMClearRequest{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/clear", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/clear", strings.NewReader("not json"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when clear fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.clearErr = errors.New("permission denied")
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMClearRequest{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/clear", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

// =============================================================================
// EK Handler Tests
// =============================================================================

func TestTPMHandleGetEK(t *testing.T) {
	t.Run("returns EK attributes", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/ek", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var keyResp TPMKeyResponse
		decodeTPMResponse(t, resp, &keyResp)
		assert.Equal(t, uint32(0x81010001), keyResp.Handle)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/ek", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when EKAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.ekAttrs = nil
		tpm.ekAttrsErr = errors.New("EK not found")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/ek", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestTPMHandleCreateEK(t *testing.T) {
	t.Run("creates EK successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/ek", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var status TPMStatusResponse
		decodeTPMResponse(t, resp, &status)
		assert.True(t, status.Success)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/ek", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when EKAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.ekAttrs = nil
		tpm.ekAttrsErr = errors.New("TPM not initialized")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/ek", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("returns error when CreateEK fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.createEKErr = errors.New("already exists")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/ek", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})
}

func TestTPMHandleDeleteEK(t *testing.T) {
	t.Run("deletes EK successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/ek", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, tpm.flushed, xkmssdk.TPMHandle(0x81010001))
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/ek", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when EKAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.ekAttrs = nil
		tpm.ekAttrsErr = errors.New("not provisioned")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/ek", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

// =============================================================================
// EK Certificate Tests
// =============================================================================

func TestTPMHandleGetEKCertificate(t *testing.T) {
	t.Run("returns EK certificate", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/ek/certificate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var certResp TPMCertificateResponse
		decodeTPMResponse(t, resp, &certResp)
		assert.NotEmpty(t, certResp.Certificate)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/ek/certificate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when EKCertificate fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.ekCertErr = errors.New("certificate not found")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/ek/certificate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestTPMHandleImportEKCertificate(t *testing.T) {
	t.Run("imports EK certificate successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		certB64 := base64.StdEncoding.EncodeToString([]byte("fake-cert-der"))
		body, _ := json.Marshal(TPMImportEKCertRequest{Certificate: certB64})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/ek/certificate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMImportEKCertRequest{Certificate: "dGVzdA=="})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/ek/certificate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/ek/certificate", strings.NewReader("bad"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when certificate field empty", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMImportEKCertRequest{Certificate: ""})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/ek/certificate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMImportEKCertRequest{Certificate: "not-valid-base64!!!"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/ek/certificate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when ProvisionEKCert fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.provisionEKCertErr = errors.New("invalid certificate")
		_, router := setupTPMTestHandler(tpm)

		certB64 := base64.StdEncoding.EncodeToString([]byte("fake-cert"))
		body, _ := json.Marshal(TPMImportEKCertRequest{Certificate: certB64})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/ek/certificate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

// =============================================================================
// SRK Handler Tests
// =============================================================================

func TestTPMHandleGetSRK(t *testing.T) {
	t.Run("returns SRK attributes", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/srk", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var keyResp TPMKeyResponse
		decodeTPMResponse(t, resp, &keyResp)
		assert.Equal(t, uint32(0x81000001), keyResp.Handle)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/srk", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when SSRKAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.ssrkAttrs = nil
		tpm.ssrkAttrsErr = errors.New("SRK not found")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/srk", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestTPMHandleCreateSRK(t *testing.T) {
	t.Run("creates SRK successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/srk", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/srk", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when SSRKAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.ssrkAttrs = nil
		tpm.ssrkAttrsErr = errors.New("not provisioned")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/srk", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("returns error when CreateSRK fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.createSRKErr = errors.New("already exists")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/srk", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})
}

func TestTPMHandleDeleteSRK(t *testing.T) {
	t.Run("deletes SRK successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/srk", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, tpm.flushed, xkmssdk.TPMHandle(0x81000001))
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/srk", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when SSRKAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.ssrkAttrs = nil
		tpm.ssrkAttrsErr = errors.New("not provisioned")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/srk", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

// =============================================================================
// IAK Handler Tests
// =============================================================================

func TestTPMHandleGetIAK(t *testing.T) {
	t.Run("returns IAK successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.iakPubKey = []byte("public-key-data")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var keyResp TPMKeyResponse
		decodeTPMResponse(t, resp, &keyResp)
		assert.Equal(t, uint32(0x81020001), keyResp.Handle)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when IAKAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.iakAttrs = nil
		tpm.iakAttrsErr = errors.New("IAK not found")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when IAK returns error", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.iakPubKeyErr = errors.New("IAK not initialized")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns not found when IAK returns nil public key", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.iakPubKey = nil
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestTPMHandleCreateIAK(t *testing.T) {
	t.Run("creates IAK successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.createIAKAttrs = &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle: 0x81020001,
			},
		}
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when EKAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.ekAttrs = nil
		tpm.ekAttrsErr = errors.New("EK not found")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when CreateIAK fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.createIAKErr = errors.New("duplicate key")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusCreated, resp.StatusCode)
	})
}

func TestTPMHandleDeleteIAK(t *testing.T) {
	t.Run("deletes IAK successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, tpm.flushed, xkmssdk.TPMHandle(0x81020001))
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when IAKAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.iakAttrs = nil
		tpm.iakAttrsErr = errors.New("not provisioned")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/iak", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

// =============================================================================
// IDevID Handler Tests
// =============================================================================

func TestTPMHandleGetIDevID(t *testing.T) {
	t.Run("returns IDevID successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.idevidPubKey = []byte("idevid-public-key")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/idevid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var keyResp TPMKeyResponse
		decodeTPMResponse(t, resp, &keyResp)
		assert.Equal(t, uint32(0x81030001), keyResp.Handle)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/idevid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when IDevIDAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.idevidAttrs = nil
		tpm.idevidAttrsErr = errors.New("IDevID not found")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/idevid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when IDevID returns error", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.idevidPubKeyErr = errors.New("IDevID not initialized")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/idevid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns not found when IDevID returns nil public key", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.idevidPubKey = nil
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/idevid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// =============================================================================
// Quote Handler Tests
// =============================================================================

func TestTPMHandleQuote(t *testing.T) {
	t.Run("generates quote successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.quoteResult = xkmssdk.Quote{
			Quoted:    []byte("test-quoted"),
			Signature: []byte("test-sig"),
		}
		_, router := setupTPMTestHandler(tpm)

		nonce := base64.StdEncoding.EncodeToString([]byte("test-nonce"))
		body, _ := json.Marshal(TPMQuoteRequest{
			Nonce:      nonce,
			PCRIndices: []int{0, 1, 7},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var quoteResp TPMQuoteResponse
		decodeTPMResponse(t, resp, &quoteResp)
		assert.NotEmpty(t, quoteResp.Quote)
		assert.NotEmpty(t, quoteResp.Signature)
	})

	t.Run("includes event log when present", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.quoteResult = xkmssdk.Quote{
			Quoted:    []byte("quoted"),
			Signature: []byte("sig"),
			EventLog:  []byte("event-log-data"),
		}
		_, router := setupTPMTestHandler(tpm)

		nonce := base64.StdEncoding.EncodeToString([]byte("nonce"))
		body, _ := json.Marshal(TPMQuoteRequest{Nonce: nonce})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var quoteResp TPMQuoteResponse
		decodeTPMResponse(t, resp, &quoteResp)
		assert.NotEmpty(t, quoteResp.EventLog)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMQuoteRequest{Nonce: "dGVzdA=="})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/quote", strings.NewReader("bad"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when nonce is missing", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMQuoteRequest{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid base64 nonce", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMQuoteRequest{Nonce: "not-valid-base64!!!"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for out of range PCR index", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		nonce := base64.StdEncoding.EncodeToString([]byte("nonce"))
		body, _ := json.Marshal(TPMQuoteRequest{
			Nonce:      nonce,
			PCRIndices: []int{0, 25},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when Quote fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.quoteErr = errors.New("TPM not initialized")
		_, router := setupTPMTestHandler(tpm)

		nonce := base64.StdEncoding.EncodeToString([]byte("nonce"))
		body, _ := json.Marshal(TPMQuoteRequest{Nonce: nonce})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/quote", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

// =============================================================================
// Verify Quote Handler Tests
// =============================================================================

func TestTPMHandleVerifyQuote(t *testing.T) {
	t.Run("returns not implemented", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/verify-quote", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/verify-quote", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Certify Handler Tests
// =============================================================================

func TestTPMHandleCertify(t *testing.T) {
	t.Run("certifies key successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.keyAttrs = &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{
				Handle: 0x81000001,
			},
		}
		tpm.certifyResult = &xkmssdk.CertifyResult{
			CertifyInfo: []byte("certify-info"),
			Signature:   []byte("certify-sig"),
		}
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMCertifyRequest{Handle: 0x81000001})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/certify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var certResp TPMCertifyResponse
		decodeTPMResponse(t, resp, &certResp)
		assert.NotEmpty(t, certResp.CertifyInfo)
		assert.NotEmpty(t, certResp.Signature)
	})

	t.Run("certifies with nonce", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.keyAttrs = &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{Handle: 0x81000001},
		}
		tpm.certifyResult = &xkmssdk.CertifyResult{
			CertifyInfo: []byte("info"),
			Signature:   []byte("sig"),
		}
		_, router := setupTPMTestHandler(tpm)

		nonce := base64.StdEncoding.EncodeToString([]byte("test-nonce"))
		body, _ := json.Marshal(TPMCertifyRequest{Handle: 0x81000001, Nonce: nonce})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/certify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMCertifyRequest{Handle: 1})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/certify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/certify", strings.NewReader("bad"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when handle is zero", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMCertifyRequest{Handle: 0})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/certify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid base64 nonce", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMCertifyRequest{Handle: 1, Nonce: "bad-base64!!!"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/certify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when KeyAttributes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.keyAttrsErr = errors.New("key not found")
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMCertifyRequest{Handle: 0x81000001})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/certify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when CertifyKey fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.keyAttrs = &xkmssdk.KeyAttributes{
			TPMAttributes: &xkmssdk.TPMAttributes{Handle: 0x81000001},
		}
		tpm.certifyErr = errors.New("certify failed")
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMCertifyRequest{Handle: 0x81000001})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/certify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

// =============================================================================
// PCR Handler Tests
// =============================================================================

func TestTPMHandleReadPCRs(t *testing.T) {
	t.Run("reads all PCRs by default", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.readPCRsResult = []xkmssdk.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []xkmssdk.PCR{
					{ID: 0, Value: []byte{0x01, 0x02}},
					{ID: 1, Value: []byte{0x03, 0x04}},
				},
			},
		}
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/pcrs", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var pcrResp TPMPCRResponse
		decodeTPMResponse(t, resp, &pcrResp)
		assert.Len(t, pcrResp.PCRValues, 2)
	})

	t.Run("reads specific PCR indices", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.readPCRsResult = []xkmssdk.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []xkmssdk.PCR{
					{ID: 7, Value: []byte{0x01}},
				},
			},
		}
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/pcrs?indices=7", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("parses comma-separated PCR indices", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.readPCRsResult = []xkmssdk.PCRBank{}
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/pcrs?indices=0,1,7", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/pcrs", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/pcrs?indices=25", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for non-numeric PCR index", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/pcrs?indices=abc", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when ReadPCRs fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.readPCRsErr = errors.New("TPM not initialized")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/pcrs", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

func TestTPMHandleExtendPCR(t *testing.T) {
	t.Run("extends PCR successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		data := base64.StdEncoding.EncodeToString([]byte("extend-data"))
		body, _ := json.Marshal(TPMPCRExtendRequest{
			PCRIndex: 7,
			Data:     data,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/pcrs/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("extends PCR with explicit hash algorithm", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		data := base64.StdEncoding.EncodeToString([]byte("data"))
		body, _ := json.Marshal(TPMPCRExtendRequest{
			PCRIndex: 0,
			HashAlg:  "sha384",
			Data:     data,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/pcrs/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMPCRExtendRequest{PCRIndex: 0, Data: "dGVzdA=="})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/pcrs/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/pcrs/extend", strings.NewReader("bad"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for out of range PCR index", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		data := base64.StdEncoding.EncodeToString([]byte("data"))
		body, _ := json.Marshal(TPMPCRExtendRequest{PCRIndex: 24, Data: data})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/pcrs/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for negative PCR index", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		data := base64.StdEncoding.EncodeToString([]byte("data"))
		body, _ := json.Marshal(TPMPCRExtendRequest{PCRIndex: -1, Data: data})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/pcrs/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when data is missing", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMPCRExtendRequest{PCRIndex: 7})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/pcrs/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid base64 data", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMPCRExtendRequest{PCRIndex: 7, Data: "not-base64!!!"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/pcrs/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when ExtendPCR fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.extendPCRErr = errors.New("extend failed")
		_, router := setupTPMTestHandler(tpm)

		data := base64.StdEncoding.EncodeToString([]byte("data"))
		body, _ := json.Marshal(TPMPCRExtendRequest{PCRIndex: 7, Data: data})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/pcrs/extend", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

// =============================================================================
// Event Log Handler Tests
// =============================================================================

func TestTPMHandleEventLog(t *testing.T) {
	t.Run("returns event log successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.eventLogData = []byte("raw-event-log")
		tpm.parsedEvents = []xkmssdk.TPMEvent{{}, {}, {}}
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/eventlog", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var logResp TPMEventLogResponse
		decodeTPMResponse(t, resp, &logResp)
		assert.NotEmpty(t, logResp.EventLog)
		assert.Equal(t, "tcg2", logResp.Format)
		assert.Equal(t, uint64(3), logResp.EventCount)
	})

	t.Run("returns event log with parse error", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.eventLogData = []byte("raw-log")
		tpm.parsedEventLogErr = errors.New("parse error")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/eventlog", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var logResp TPMEventLogResponse
		decodeTPMResponse(t, resp, &logResp)
		assert.Equal(t, uint64(0), logResp.EventCount)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/eventlog", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when EventLog fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.eventLogErr = errors.New("not available")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/eventlog", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Capabilities Handler Tests
// =============================================================================

func TestTPMHandleCapabilities(t *testing.T) {
	t.Run("returns capabilities successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.supportedAlgorithms = []string{"RSA", "ECC", "AES"}
		tpm.supportedCommands = []string{"TPM2_CreatePrimary", "TPM2_Create"}
		tpm.supportedCurves = []string{"P-256", "P-384"}
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/capabilities", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var capsResp TPMCapabilitiesResponse
		decodeTPMResponse(t, resp, &capsResp)
		assert.Len(t, capsResp.Algorithms, 3)
		assert.Len(t, capsResp.Commands, 2)
		assert.Len(t, capsResp.ECCCurves, 2)
	})

	t.Run("returns capabilities with partial errors", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.supportedAlgorithms = []string{"RSA"}
		tpm.supportedCmdsErr = errors.New("not supported")
		tpm.supportedCurvesErr = errors.New("not supported")
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/capabilities", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var capsResp TPMCapabilitiesResponse
		decodeTPMResponse(t, resp, &capsResp)
		assert.Len(t, capsResp.Algorithms, 1)
		assert.Nil(t, capsResp.Commands)
		assert.Nil(t, capsResp.ECCCurves)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/capabilities", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Random Handler Tests
// =============================================================================

func TestTPMHandleRandom(t *testing.T) {
	t.Run("returns random bytes successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.randomBytesResult = []byte{0x01, 0x02, 0x03, 0x04}
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMRandomRequest{NumBytes: 4})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/random", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var randResp TPMRandomResponse
		decodeTPMResponse(t, resp, &randResp)
		assert.NotEmpty(t, randResp.RandomBytes)
	})

	t.Run("uses default 32 bytes when NumBytes is zero", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.randomBytesResult = make([]byte, 32)
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMRandomRequest{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/random", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMRandomRequest{NumBytes: 16})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/random", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/random", strings.NewReader("bad"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for size too large", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMRandomRequest{NumBytes: 2048})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/random", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when RandomBytes fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.randomBytesErr = errors.New("RNG failure")
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMRandomRequest{NumBytes: 16})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/random", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

// =============================================================================
// Seal/Unseal Handler Tests
// =============================================================================

func TestTPMHandleSeal(t *testing.T) {
	t.Run("seals data successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		data := base64.StdEncoding.EncodeToString([]byte("secret-data"))
		body, _ := json.Marshal(TPMSealRequest{Data: data})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var sealResp TPMSealResponse
		decodeTPMResponse(t, resp, &sealResp)
		assert.NotEmpty(t, sealResp.SealedData)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMSealRequest{Data: "dGVzdA=="})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/seal", strings.NewReader("bad"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when data is missing", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMSealRequest{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid base64 data", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMSealRequest{Data: "not-base64!!!"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when Seal fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.sealErr = errors.New("seal failed")
		_, router := setupTPMTestHandler(tpm)

		data := base64.StdEncoding.EncodeToString([]byte("data"))
		body, _ := json.Marshal(TPMSealRequest{Data: data})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/seal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})
}

func TestTPMHandleUnseal(t *testing.T) {
	t.Run("unseals data successfully", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.unsealResult = []byte("unsealed-secret")
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMUnsealRequest{CN: "my-sealed-key"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/unseal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var unsealResp TPMUnsealResponse
		decodeTPMResponse(t, resp, &unsealResp)
		assert.NotEmpty(t, unsealResp.Data)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMUnsealRequest{CN: "test"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/unseal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/unseal", strings.NewReader("bad"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when CN is missing", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMUnsealRequest{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/unseal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when Unseal fails", func(t *testing.T) {
		tpm := newMockTPMService()
		tpm.unsealErr = errors.New("key not found")
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMUnsealRequest{CN: "missing-key"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/unseal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// =============================================================================
// NVRAM Handler Tests
// =============================================================================

func TestTPMHandleNVRead(t *testing.T) {
	t.Run("returns not implemented", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMNVReadRequest{Index: 0x01500001, DataSize: 32})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/nv/read", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMNVReadRequest{Index: 1})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/nv/read", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/nv/read", strings.NewReader("bad"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when index is zero", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMNVReadRequest{Index: 0})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/nv/read", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestTPMHandleNVWrite(t *testing.T) {
	t.Run("returns not implemented", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMNVWriteRequest{Index: 0x01500001})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/nv/write", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		body, _ := json.Marshal(TPMNVWriteRequest{Index: 1})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/nv/write", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/nv/write", strings.NewReader("bad"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when index is zero", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		body, _ := json.Marshal(TPMNVWriteRequest{Index: 0})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/nv/write", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestTPMHandleNVDelete(t *testing.T) {
	t.Run("returns not implemented", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/nv", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/tpm/nv", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

func TestTPMHandleNVDefine(t *testing.T) {
	t.Run("returns not implemented", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/nv/define", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/nv/define", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// CSR Handler Tests
// =============================================================================

func TestTPMHandleCreateLDevIDCSR(t *testing.T) {
	t.Run("returns not implemented", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/csr/ldevid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/tpm/csr/ldevid", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Platform Attributes Handler Tests
// =============================================================================

func TestTPMHandlePlatformAttributes(t *testing.T) {
	t.Run("returns platform attributes", func(t *testing.T) {
		tpm := newMockTPMService()
		_, router := setupTPMTestHandler(tpm)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/platform", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var attrs TPMPlatformAttributesResponse
		decodeTPMResponse(t, resp, &attrs)
		assert.NotZero(t, attrs.Timestamp)
	})

	t.Run("returns service unavailable when TPM not set", func(t *testing.T) {
		_, router := setupTPMTestHandler(nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/platform", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// mapErrorToStatus Tests
// =============================================================================

func TestTPMMapErrorToStatus(t *testing.T) {
	handlers := NewTPMHandlers(slog.Default())

	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{
			name:     "nil error returns OK",
			err:      nil,
			expected: http.StatusOK,
		},
		{
			name:     "not found error",
			err:      errors.New("key not found"),
			expected: http.StatusNotFound,
		},
		{
			name:     "does not exist error",
			err:      errors.New("handle does not exist"),
			expected: http.StatusNotFound,
		},
		{
			name:     "not initialized error",
			err:      errors.New("TPM not initialized"),
			expected: http.StatusNotFound,
		},
		{
			name:     "not provisioned error",
			err:      errors.New("TPM not provisioned"),
			expected: http.StatusNotFound,
		},
		{
			name:     "already exists error",
			err:      errors.New("key already exists"),
			expected: http.StatusConflict,
		},
		{
			name:     "duplicate error",
			err:      errors.New("duplicate handle"),
			expected: http.StatusConflict,
		},
		{
			name:     "already open error",
			err:      errors.New("device already open"),
			expected: http.StatusConflict,
		},
		{
			name:     "invalid error",
			err:      errors.New("invalid parameter"),
			expected: http.StatusBadRequest,
		},
		{
			name:     "required error",
			err:      errors.New("field required"),
			expected: http.StatusBadRequest,
		},
		{
			name:     "must be error",
			err:      errors.New("value must be positive"),
			expected: http.StatusBadRequest,
		},
		{
			name:     "cannot be error",
			err:      errors.New("value cannot be zero"),
			expected: http.StatusBadRequest,
		},
		{
			name:     "too large error",
			err:      errors.New("data too large"),
			expected: http.StatusBadRequest,
		},
		{
			name:     "permission denied error",
			err:      errors.New("permission denied"),
			expected: http.StatusForbidden,
		},
		{
			name:     "unauthorized error",
			err:      errors.New("unauthorized access"),
			expected: http.StatusForbidden,
		},
		{
			name:     "forbidden error",
			err:      errors.New("forbidden operation"),
			expected: http.StatusForbidden,
		},
		{
			name:     "authorization error",
			err:      errors.New("authorization failed"),
			expected: http.StatusForbidden,
		},
		{
			name:     "not configured error",
			err:      errors.New("TPM not configured"),
			expected: http.StatusServiceUnavailable,
		},
		{
			name:     "not available error",
			err:      errors.New("service not available"),
			expected: http.StatusServiceUnavailable,
		},
		{
			name:     "unavailable error",
			err:      errors.New("TPM unavailable"),
			expected: http.StatusServiceUnavailable,
		},
		{
			name:     "unknown error returns 500",
			err:      errors.New("something completely unexpected"),
			expected: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := handlers.mapErrorToStatus(tt.err)
			assert.Equal(t, tt.expected, status)
		})
	}
}

// =============================================================================
// writeJSON, writeError, writeTPMError Tests
// =============================================================================

func TestTPMWriteJSON(t *testing.T) {
	t.Run("writes JSON response", func(t *testing.T) {
		handlers := NewTPMHandlers(slog.Default())
		w := httptest.NewRecorder()

		handlers.writeJSON(w, http.StatusOK, map[string]string{"key": "value"})

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

		var body map[string]string
		err := json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.Equal(t, "value", body["key"])
	})
}

func TestTPMWriteError(t *testing.T) {
	t.Run("writes error response", func(t *testing.T) {
		handlers := NewTPMHandlers(slog.Default())
		w := httptest.NewRecorder()

		handlers.writeError(w, http.StatusBadRequest, ErrTPMInvalidPCRIndex{Index: 30})

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Contains(t, errResp.Error, "invalid PCR index")
		assert.Equal(t, http.StatusBadRequest, errResp.Code)
	})
}

func TestTPMWriteTPMError(t *testing.T) {
	t.Run("maps TPM error to appropriate status", func(t *testing.T) {
		handlers := NewTPMHandlers(slog.Default())
		w := httptest.NewRecorder()

		handlers.writeTPMError(w, "test_op", errors.New("key not found"))

		resp := w.Result()
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		var errResp ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Contains(t, errResp.Error, "test_op")
	})
}
