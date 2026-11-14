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
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-codec"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = quicwire.SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Mock Attestation Service
// =============================================================================

// mockAttestationService implements AttestationServiceInterface for testing
type mockAttestationService struct {
	manifests            map[string]*manifest.HostManifest
	reports              map[string]*AttestationReport
	policies             map[string]*AttestationPolicy
	getManifestErr       error
	buildManifestErr     error
	verifyManifestErr    error
	collectHostErr       error
	attestVMErr          error
	attestContainerErr   error
	attestDeviceErr      error
	listReportsErr       error
	getReportErr         error
	createPolicyErr      error
	listPoliciesErr      error
	verificationResult   *manifest.VerificationResult
	hostAttestation      *manifest.HostAttestation
	vmAttestation        *manifest.VMAttestation
	containerAttestation *manifest.ContainerAttestation
	deviceResult         *AttestationDeviceResult
}

func newMockAttestationService() *mockAttestationService {
	return &mockAttestationService{
		manifests: make(map[string]*manifest.HostManifest),
		reports:   make(map[string]*AttestationReport),
		policies:  make(map[string]*AttestationPolicy),
	}
}

func (m *mockAttestationService) GetManifest(ctx context.Context, id string) (*manifest.HostManifest, error) {
	if m.getManifestErr != nil {
		return nil, m.getManifestErr
	}

	if id == "" {
		// Return the first manifest (current manifest)
		for _, mf := range m.manifests {
			return mf, nil
		}
		return nil, nil
	}

	mf, ok := m.manifests[id]
	if !ok {
		return nil, nil
	}
	return mf, nil
}

func (m *mockAttestationService) BuildManifest(ctx context.Context, config *AttestationBuildManifestConfig) (*manifest.HostManifest, error) {
	if m.buildManifestErr != nil {
		return nil, m.buildManifestErr
	}

	mf := &manifest.HostManifest{
		ID:        "test-manifest-id",
		HostID:    config.HostID,
		Timestamp: time.Now(),
		Nonce:     config.Nonce,
		Host: &manifest.HostAttestation{
			QuoteData:     []byte("test-quote"),
			Signature:     []byte("test-signature"),
			Nonce:         config.Nonce,
			Timestamp:     time.Now(),
			HashAlgorithm: config.HashAlgorithm,
			PCRs: []manifest.PCRValue{
				{Index: 0, Value: []byte("pcr0-value"), Algorithm: config.HashAlgorithm},
			},
		},
		MerkleRoot: []byte("test-merkle-root"),
		Version:    "1.0",
	}

	if config.Sign {
		mf.Signature = []byte("test-manifest-signature")
		mf.SignatureAlgorithm = "RSASSA-PSS-SHA256"
	}

	m.manifests[mf.ID] = mf
	return mf, nil
}

func (m *mockAttestationService) VerifyManifest(ctx context.Context, mf *manifest.HostManifest, opts *AttestationVerifyManifestOptions) (*manifest.VerificationResult, error) {
	if m.verifyManifestErr != nil {
		return nil, m.verifyManifestErr
	}

	if m.verificationResult != nil {
		return m.verificationResult, nil
	}

	return &manifest.VerificationResult{
		Status:                     manifest.VerificationStatusVerified,
		SignatureValid:             true,
		MerkleRootValid:            true,
		NonceValid:                 true,
		TimestampValid:             true,
		HostAttestationValid:       true,
		VMAttestationsValid:        true,
		ContainerAttestationsValid: true,
		VerifiedAt:                 time.Now(),
	}, nil
}

func (m *mockAttestationService) CollectHostAttestation(ctx context.Context, opts *AttestationCollectOptions) (*manifest.HostAttestation, error) {
	if m.collectHostErr != nil {
		return nil, m.collectHostErr
	}

	if m.hostAttestation != nil {
		return m.hostAttestation, nil
	}

	return &manifest.HostAttestation{
		QuoteData:          []byte("test-quote-data"),
		Signature:          []byte("test-signature"),
		SignatureAlgorithm: "RSASSA-PSS-SHA256",
		PCRs: []manifest.PCRValue{
			{Index: 0, Value: []byte("pcr0"), Algorithm: opts.HashAlgorithm},
			{Index: 7, Value: []byte("pcr7"), Algorithm: opts.HashAlgorithm},
		},
		PCRDigest:     []byte("test-pcr-digest"),
		Nonce:         opts.Nonce,
		Timestamp:     time.Now(),
		AKPublicKey:   []byte("test-ak-public-key"),
		HashAlgorithm: opts.HashAlgorithm,
	}, nil
}

func (m *mockAttestationService) AttestVM(ctx context.Context, vmID string, opts *AttestationCollectOptions) (*manifest.VMAttestation, error) {
	if m.attestVMErr != nil {
		return nil, m.attestVMErr
	}

	if m.vmAttestation != nil {
		return m.vmAttestation, nil
	}

	return &manifest.VMAttestation{
		VMID:               vmID,
		HostID:             "test-host-id",
		QuoteData:          []byte("test-vm-quote"),
		Signature:          []byte("test-vm-signature"),
		SignatureAlgorithm: "RSASSA-PSS-SHA256",
		PCRs: []manifest.PCRValue{
			{Index: 0, Value: []byte("vm-pcr0"), Algorithm: opts.HashAlgorithm},
		},
		PCRDigest:     []byte("test-vm-pcr-digest"),
		Nonce:         opts.Nonce,
		Timestamp:     time.Now(),
		HashAlgorithm: opts.HashAlgorithm,
	}, nil
}

func (m *mockAttestationService) AttestContainer(ctx context.Context, containerID string, opts *AttestationCollectOptions) (*manifest.ContainerAttestation, error) {
	if m.attestContainerErr != nil {
		return nil, m.attestContainerErr
	}

	if m.containerAttestation != nil {
		return m.containerAttestation, nil
	}

	return &manifest.ContainerAttestation{
		ContainerID: containerID,
		ImageID:     "sha256:abc123",
		ImageDigest: "sha256:def456",
		Digest:      []byte("test-container-digest"),
		PCRValue:    []byte("test-pcr14-value"),
		Timestamp:   time.Now(),
		Metadata:    map[string]string{"name": "test-container"},
	}, nil
}

func (m *mockAttestationService) AttestDevice(ctx context.Context, deviceID string, opts *AttestationCollectOptions) (*AttestationDeviceResult, error) {
	if m.attestDeviceErr != nil {
		return nil, m.attestDeviceErr
	}

	if m.deviceResult != nil {
		return m.deviceResult, nil
	}

	return &AttestationDeviceResult{
		DeviceID:    deviceID,
		DeviceType:  "tpm",
		Verified:    true,
		QuoteData:   []byte("test-device-quote"),
		Signature:   []byte("test-device-signature"),
		PCRValues:   map[int][]byte{0: []byte("device-pcr0")},
		Certificate: []byte("test-device-cert"),
		Timestamp:   time.Now(),
		Metadata:    map[string]string{"vendor": "test"},
	}, nil
}

func (m *mockAttestationService) ListReports(ctx context.Context, filter *AttestationReportFilter) ([]*AttestationReport, int, error) {
	if m.listReportsErr != nil {
		return nil, 0, m.listReportsErr
	}

	result := make([]*AttestationReport, 0, len(m.reports))
	for _, r := range m.reports {
		result = append(result, r)
	}

	return result, len(result), nil
}

func (m *mockAttestationService) GetReport(ctx context.Context, id string) (*AttestationReport, error) {
	if m.getReportErr != nil {
		return nil, m.getReportErr
	}

	r, ok := m.reports[id]
	if !ok {
		return nil, nil
	}
	return r, nil
}

func (m *mockAttestationService) CreatePolicy(ctx context.Context, policy *AttestationPolicyCreateRequest) (*AttestationPolicy, error) {
	if m.createPolicyErr != nil {
		return nil, m.createPolicyErr
	}

	p := &AttestationPolicy{
		ID:          "test-policy-id",
		Name:        policy.Name,
		Description: policy.Description,
		MaxAge:      policy.MaxAge,
		Active:      policy.Active,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Metadata:    policy.Metadata,
	}

	if policy.PCRPolicy != nil {
		p.PCRPolicy = policy.PCRPolicy
	}

	m.policies[p.ID] = p
	return p, nil
}

func (m *mockAttestationService) ListPolicies(ctx context.Context, filter *AttestationPolicyListFilter) ([]*AttestationPolicy, int, error) {
	if m.listPoliciesErr != nil {
		return nil, 0, m.listPoliciesErr
	}

	result := make([]*AttestationPolicy, 0, len(m.policies))
	for _, p := range m.policies {
		result = append(result, p)
	}

	return result, len(result), nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newAttestTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestAttestationHandler() (*AttestationHandler, *mockAttestationService) {
	logger := newAttestTestLogger()
	service := newMockAttestationService()
	handler := NewAttestationHandler(logger, service)
	return handler, service
}

func createTestManifest(service *mockAttestationService, id string) *manifest.HostManifest {
	m := &manifest.HostManifest{
		ID:        id,
		HostID:    "test-host-id",
		Timestamp: time.Now(),
		Nonce:     []byte("test-nonce-12345678"),
		Host: &manifest.HostAttestation{
			QuoteData:          []byte("test-quote"),
			Signature:          []byte("test-sig"),
			SignatureAlgorithm: "RSASSA-PSS-SHA256",
			PCRs: []manifest.PCRValue{
				{Index: 0, Value: []byte("pcr0"), Algorithm: manifest.HashAlgorithmSHA256},
			},
			PCRDigest:     []byte("test-digest"),
			Nonce:         []byte("test-nonce-12345678"),
			Timestamp:     time.Now(),
			HashAlgorithm: manifest.HashAlgorithmSHA256,
		},
		MerkleRoot: []byte("test-merkle-root"),
		Signature:  []byte("test-manifest-sig"),
		Version:    "1.0",
	}
	service.manifests[id] = m
	return m
}

func createTestReport(service *mockAttestationService, id string) *AttestationReport {
	r := &AttestationReport{
		ID:         id,
		HostID:     "test-host-id",
		Type:       "host",
		Status:     "verified",
		ManifestID: "test-manifest-id",
		CreatedAt:  time.Now(),
		Metadata:   map[string]string{"test": "value"},
	}
	service.reports[id] = r
	return r
}

func createTestPolicy(service *mockAttestationService, id, name string) *AttestationPolicy {
	p := &AttestationPolicy{
		ID:          id,
		Name:        name,
		Description: "Test policy",
		Active:      true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		PCRPolicy: &AttestationPCRPolicyConfig{
			RequiredPCRs: []int{0, 7},
		},
	}
	service.policies[id] = p
	return p
}

// =============================================================================
// Test: NewAttestationHandler
// =============================================================================

func TestNewAttestationHandler(t *testing.T) {
	t.Run("creates handler with valid inputs", func(t *testing.T) {
		logger := newAttestTestLogger()
		service := newMockAttestationService()
		handler := NewAttestationHandler(logger, service)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, service, handler.service)
	})

	t.Run("creates handler with nil service", func(t *testing.T) {
		logger := newAttestTestLogger()
		handler := NewAttestationHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.service)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestAttestationHandleRequest(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		resp := handler.HandleRequest(context.Background(), nil)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "nil")
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode: 0x00, // Unknown opcode for attestation handler
		}

		resp := handler.HandleRequest(context.Background(), req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown attestation operation")
	})
}

// =============================================================================
// Test: GetManifest
// =============================================================================

func TestHandleGetManifest(t *testing.T) {
	ctx := context.Background()

	t.Run("gets manifest successfully", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		createTestManifest(service, "manifest-1")

		getReq := &GetManifestRequest{
			ID: "manifest-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var getResp GetManifestResponse
		err = quicwire.DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Manifest)
		assert.Equal(t, "manifest-1", getResp.Manifest.ID)
		assert.Equal(t, "test-host-id", getResp.Manifest.HostID)
		assert.Greater(t, getResp.Timestamp, int64(0))
	})

	t.Run("returns not found for missing manifest", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		getReq := &GetManifestRequest{
			ID: "nonexistent",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		getReq := &GetManifestRequest{ID: "manifest-1"}
		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetManifest,
			Payload: []byte("invalid"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when service fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.getManifestErr = errors.New("service error")

		getReq := &GetManifestRequest{ID: "manifest-1"}
		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: BuildManifest
// =============================================================================

func TestHandleBuildManifest(t *testing.T) {
	ctx := context.Background()

	t.Run("builds manifest successfully", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		buildReq := &BuildManifestRequest{
			HostID:            "test-host",
			Nonce:             []byte("test-nonce-12345678"),
			PCRIndices:        []int{0, 7, 14},
			HashAlgorithm:     "sha256",
			IncludeVMs:        true,
			IncludeContainers: true,
			Sign:              true,
		}

		payload, err := quicwire.EncodePayload(buildReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestBuildManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var buildResp BuildManifestResponse
		err = quicwire.DecodePayload(resp.Payload, &buildResp)
		require.NoError(t, err)

		assert.NotNil(t, buildResp.Manifest)
		assert.NotEmpty(t, buildResp.Manifest.ID)
		assert.NotNil(t, buildResp.Manifest.Host)
	})

	t.Run("builds manifest with defaults", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		buildReq := &BuildManifestRequest{
			HostID: "test-host",
		}

		payload, err := quicwire.EncodePayload(buildReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestBuildManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error for invalid nonce", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		buildReq := &BuildManifestRequest{
			HostID: "test-host",
			Nonce:  []byte("short"), // Less than 16 bytes
		}

		payload, err := quicwire.EncodePayload(buildReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestBuildManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid hash algorithm", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		buildReq := &BuildManifestRequest{
			HostID:        "test-host",
			HashAlgorithm: "md5", // Invalid algorithm
		}

		payload, err := quicwire.EncodePayload(buildReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestBuildManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		buildReq := &BuildManifestRequest{
			HostID:     "test-host",
			PCRIndices: []int{0, 7, 25}, // 25 is invalid
		}

		payload, err := quicwire.EncodePayload(buildReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestBuildManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		buildReq := &BuildManifestRequest{HostID: "test-host"}
		payload, err := quicwire.EncodePayload(buildReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestBuildManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when build fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.buildManifestErr = errors.New("build failed")

		buildReq := &BuildManifestRequest{HostID: "test-host"}
		payload, err := quicwire.EncodePayload(buildReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestBuildManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestBuildManifest,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: VerifyManifest
// =============================================================================

func TestHandleVerifyManifest(t *testing.T) {
	ctx := context.Background()

	t.Run("verifies manifest successfully", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		verifyReq := &VerifyManifestRequest{
			Manifest: &ManifestData{
				ID:         "test-manifest",
				HostID:     "test-host",
				Timestamp:  time.Now().Unix(),
				Nonce:      []byte("test-nonce-12345678"),
				MerkleRoot: []byte("test-merkle-root"),
				Version:    "1.0",
				Host: &HostAttestationData{
					QuoteData:     []byte("test-quote"),
					Signature:     []byte("test-sig"),
					Nonce:         []byte("test-nonce-12345678"),
					Timestamp:     time.Now().Unix(),
					HashAlgorithm: "sha256",
					PCRs: []PCRValueData{
						{Index: 0, Value: []byte("pcr0"), Algorithm: "sha256"},
					},
				},
			},
			ExpectedNonce: []byte("test-nonce-12345678"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVerifyManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var verifyResp VerifyManifestResponse
		err = quicwire.DecodePayload(resp.Payload, &verifyResp)
		require.NoError(t, err)

		assert.True(t, verifyResp.Valid)
		assert.Equal(t, "verified", verifyResp.Status)
		assert.True(t, verifyResp.SignatureValid)
		assert.True(t, verifyResp.MerkleRootValid)
	})

	t.Run("returns error for missing manifest", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		verifyReq := &VerifyManifestRequest{}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVerifyManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		verifyReq := &VerifyManifestRequest{
			Manifest: &ManifestData{ID: "test"},
		}
		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVerifyManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when verification fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.verifyManifestErr = errors.New("verification failed")

		verifyReq := &VerifyManifestRequest{
			Manifest: &ManifestData{
				ID:         "test",
				MerkleRoot: []byte("root"),
				Nonce:      []byte("nonce"),
			},
		}
		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVerifyManifest,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVerifyManifest,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// recordingManifestService holds one stored manifest and records the
// manifest the handler hands to VerifyManifest. An unknown id answers
// (nil, nil), the shape the daemon's service gives for a missing manifest.
type recordingManifestService struct {
	AttestationServiceInterface
	stored   *manifest.HostManifest
	verified *manifest.HostManifest
}

func (r *recordingManifestService) GetManifest(_ context.Context, id string) (*manifest.HostManifest, error) {
	if id != r.stored.ID {
		return nil, nil
	}
	return r.stored, nil
}

func (r *recordingManifestService) VerifyManifest(_ context.Context, m *manifest.HostManifest, _ *AttestationVerifyManifestOptions) (*manifest.VerificationResult, error) {
	r.verified = m
	return &manifest.VerificationResult{
		Status:          manifest.VerificationStatusVerified,
		SignatureValid:  true,
		MerkleRootValid: true,
		VerifiedAt:      time.Now(),
	}, nil
}

// TestHandleManifest_GetThenVerifyRoundTrip pins the QUIC manifest wire
// shape a client speaks (#964 step b, from the attestation QUIC adapter
// tests): GetManifest decodes a GetManifestRequest and answers the stored
// manifest, VerifyManifest receives exactly the manifest GetManifest
// returned, and an unknown id is StatusNotFound that never reaches the
// verifier.
func TestHandleManifest_GetThenVerifyRoundTrip(t *testing.T) {
	ctx := context.Background()
	newService := func() *recordingManifestService {
		return &recordingManifestService{stored: &manifest.HostManifest{
			ID:         "manifest-1",
			HostID:     "host-1",
			Timestamp:  time.Unix(1700000000, 0),
			MerkleRoot: []byte("merkle-root"),
		}}
	}
	call := func(t *testing.T, h *AttestationHandler, opcode uint8, msg any) *quicwire.Response {
		t.Helper()
		payload, err := quicwire.EncodePayload(msg)
		require.NoError(t, err)
		return h.HandleRequest(ctx, &quicwire.Request{Opcode: opcode, Payload: payload})
	}
	getManifest := func(t *testing.T, h *AttestationHandler, id string) *ManifestData {
		t.Helper()
		resp := call(t, h, quicwire.OpAttestGetManifest, &GetManifestRequest{ID: id})
		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
		var got GetManifestResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
		require.NotNil(t, got.Manifest)
		return got.Manifest
	}

	t.Run("get answers the stored manifest", func(t *testing.T) {
		got := getManifest(t, NewAttestationHandler(newAttestTestLogger(), newService()), "manifest-1")
		assert.Equal(t, "manifest-1", got.ID)
		assert.Equal(t, "host-1", got.HostID)
		assert.Equal(t, []byte("merkle-root"), got.MerkleRoot)
		assert.Equal(t, int64(1700000000), got.Timestamp)
	})

	t.Run("verify receives the stored manifest", func(t *testing.T) {
		service := newService()
		h := NewAttestationHandler(newAttestTestLogger(), service)

		resp := call(t, h, quicwire.OpAttestVerifyManifest, &VerifyManifestRequest{Manifest: getManifest(t, h, "manifest-1")})
		require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
		require.NotNil(t, service.verified, "the service never received a manifest to verify")
		assert.Equal(t, "manifest-1", service.verified.ID)
		assert.Equal(t, []byte("merkle-root"), service.verified.MerkleRoot)

		var got VerifyManifestResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
		assert.True(t, got.Valid)
		assert.True(t, got.SignatureValid)
		assert.True(t, got.MerkleRootValid)
	})

	t.Run("unknown id is not found and never reaches the verifier", func(t *testing.T) {
		service := newService()
		h := NewAttestationHandler(newAttestTestLogger(), service)

		resp := call(t, h, quicwire.OpAttestGetManifest, &GetManifestRequest{ID: "absent"})
		assert.Equal(t, quicwire.StatusNotFound, resp.Status, string(resp.Payload))
		assert.Nil(t, service.verified, "an unknown manifest reached the verifier")
	})
}

// =============================================================================
// Test: CollectHostAttestation
// =============================================================================

func TestHandleCollectHostAttestation(t *testing.T) {
	state := testutil.ServerConnectionState(t)
	ctx := WithConnectionTLS(context.Background(), state)

	t.Run("quotes the nonce bound to its own connection", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()
		nonce := []byte("test-nonce-12345678")

		payload, err := quicwire.EncodePayload(&CollectHostAttestationRequest{Nonce: nonce})
		require.NoError(t, err)

		resp := handler.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpAttestHost, Payload: payload})
		require.Equal(t, quicwire.StatusOK, resp.Status)

		var collectResp CollectHostAttestationResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &collectResp))
		binding, err := state.ExportKeyingMaterial(xkmssdk.PeerChannelBindingExporterLabel, nil, xkmssdk.PeerChannelBindingLength)
		require.NoError(t, err)
		assert.Equal(t, xkmssdk.PeerQualifyingData(nonce, binding), collectResp.Attestation.Nonce,
			"the service quotes the connection-bound value, never the nonce as sent (#482)")
	})

	t.Run("refuses a connection with no channel binding", func(t *testing.T) {
		contexts := map[string]context.Context{
			"no TLS state":     context.Background(),
			"exporter refused": WithConnectionTLS(context.Background(), &tls.ConnectionState{Version: tls.VersionTLS12}),
		}
		for name, unbound := range contexts {
			t.Run(name, func(t *testing.T) {
				handler, service := createTestAttestationHandler()
				service.collectHostErr = errors.New("the TPM must not be reached")

				payload, err := quicwire.EncodePayload(&CollectHostAttestationRequest{Nonce: []byte("test-nonce-12345678")})
				require.NoError(t, err)

				resp := handler.HandleRequest(unbound, &quicwire.Request{Opcode: quicwire.OpAttestHost, Payload: payload})

				assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
				assert.Contains(t, string(resp.Payload), "bound to the TLS connection")
			})
		}
	})

	t.Run("collects host attestation successfully", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		collectReq := &CollectHostAttestationRequest{
			Nonce:           []byte("test-nonce-12345678"),
			PCRIndices:      []int{0, 7, 14},
			HashAlgorithm:   "sha256",
			IncludeEventLog: true,
		}

		payload, err := quicwire.EncodePayload(collectReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestHost,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var collectResp CollectHostAttestationResponse
		err = quicwire.DecodePayload(resp.Payload, &collectResp)
		require.NoError(t, err)

		assert.NotNil(t, collectResp.Attestation)
		assert.NotEmpty(t, collectResp.Attestation.QuoteData)
		assert.NotEmpty(t, collectResp.Attestation.Signature)
		assert.NotEmpty(t, collectResp.Attestation.PCRs)
	})

	t.Run("uses default parameters", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		collectReq := &CollectHostAttestationRequest{}

		payload, err := quicwire.EncodePayload(collectReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestHost,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error for invalid nonce", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		collectReq := &CollectHostAttestationRequest{
			Nonce: []byte("short"),
		}

		payload, err := quicwire.EncodePayload(collectReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestHost,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid hash algorithm", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		collectReq := &CollectHostAttestationRequest{
			HashAlgorithm: "md5", // Invalid algorithm
		}

		payload, err := quicwire.EncodePayload(collectReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestHost,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "hash")
	})

	t.Run("returns error for invalid PCR indices", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		collectReq := &CollectHostAttestationRequest{
			PCRIndices: []int{-1}, // Invalid negative index
		}

		payload, err := quicwire.EncodePayload(collectReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestHost,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		collectReq := &CollectHostAttestationRequest{}
		payload, err := quicwire.EncodePayload(collectReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestHost,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when collection fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.collectHostErr = errors.New("TPM not available")

		collectReq := &CollectHostAttestationRequest{}
		payload, err := quicwire.EncodePayload(collectReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestHost,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestHost,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: AttestVM
// =============================================================================

func TestHandleAttestVM(t *testing.T) {
	ctx := context.Background()

	t.Run("attests VM successfully", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestVMRequest{
			VMID:          "vm-123",
			Nonce:         []byte("test-nonce-12345678"),
			PCRIndices:    []int{0, 7},
			HashAlgorithm: "sha256",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVMWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var attestResp AttestVMResponse
		err = quicwire.DecodePayload(resp.Payload, &attestResp)
		require.NoError(t, err)

		assert.NotNil(t, attestResp.Attestation)
		assert.Equal(t, "vm-123", attestResp.Attestation.VMID)

		// #483: this asserted True while the handler set Verified from a
		// literal, so it held for the placeholder quote below and for any
		// other bytes. The service returns the evidence; it does not verify
		// it, and "test-vm-quote" is not a TPMS_ATTEST.
		assert.False(t, attestResp.Verified,
			"placeholder quote bytes must not report as verified")
		assert.NotEqual(t, string(verdict.StatusVerified), attestResp.VerificationStatus)
		assert.NotEmpty(t, attestResp.VerificationError)
	})

	t.Run("returns error for missing VM ID", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestVMRequest{}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVMWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "VM ID")
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		attestReq := &AttestVMRequest{VMID: "vm-123"}
		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVMWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when attestation fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.attestVMErr = errors.New("VM not found")

		attestReq := &AttestVMRequest{VMID: "vm-123"}
		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVMWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error for short nonce", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestVMRequest{
			VMID:  "vm-123",
			Nonce: []byte("short"), // Less than 16 bytes
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVMWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "nonce")
	})

	t.Run("returns error for invalid hash algorithm", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestVMRequest{
			VMID:          "vm-123",
			Nonce:         []byte("valid-nonce-16byte"),
			HashAlgorithm: "invalid-hash",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVMWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "hash")
	})

	t.Run("attests with PCR indices", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestVMRequest{
			VMID:       "vm-123",
			Nonce:      []byte("valid-nonce-16byte"),
			PCRIndices: []int{0, 1, 7},
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVMWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error for invalid PCR index", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestVMRequest{
			VMID:       "vm-123",
			Nonce:      []byte("valid-nonce-16byte"),
			PCRIndices: []int{-1}, // Invalid negative index
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVMWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestVMWorkload,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: AttestContainer
// =============================================================================

func TestHandleAttestContainer(t *testing.T) {
	ctx := context.Background()

	t.Run("attests container successfully", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestContainerRequest{
			ContainerID:   "container-123",
			Nonce:         []byte("test-nonce-12345678"),
			PCRIndices:    []int{14},
			HashAlgorithm: "sha256",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestContainerWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var attestResp AttestContainerResponse
		err = quicwire.DecodePayload(resp.Payload, &attestResp)
		require.NoError(t, err)

		assert.NotNil(t, attestResp.Attestation)
		assert.Equal(t, "container-123", attestResp.Attestation.ContainerID)

		// #483: container evidence carries a digest and a PCR value and no
		// signature, so there is nothing to verify cryptographically. The
		// honest report is not_evaluated, not a pass.
		assert.False(t, attestResp.Verified)
		assert.Equal(t, string(verdict.StatusNotEvaluated), attestResp.VerificationStatus)
		assert.NotEmpty(t, attestResp.VerificationError)
	})

	t.Run("returns error for missing container ID", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestContainerRequest{}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestContainerWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "container ID")
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		attestReq := &AttestContainerRequest{ContainerID: "container-123"}
		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestContainerWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when attestation fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.attestContainerErr = errors.New("container not found")

		attestReq := &AttestContainerRequest{ContainerID: "container-123"}
		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestContainerWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error for short nonce", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestContainerRequest{
			ContainerID: "container-123",
			Nonce:       []byte("short"), // Less than 16 bytes
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestContainerWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "nonce")
	})

	t.Run("returns error for invalid hash algorithm", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestContainerRequest{
			ContainerID:   "container-123",
			Nonce:         []byte("valid-nonce-16byte"),
			HashAlgorithm: "invalid-hash",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestContainerWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "hash")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestContainerWorkload,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: AttestDevice
// =============================================================================

func TestHandleAttestDevice(t *testing.T) {
	ctx := context.Background()

	t.Run("attests device successfully", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestDeviceRequest{
			DeviceID:      "device-123",
			Nonce:         []byte("test-nonce-12345678"),
			PCRIndices:    []int{0, 7},
			HashAlgorithm: "sha256",
			PolicyID:      "policy-1",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestDeviceWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var attestResp AttestDeviceResponse
		err = quicwire.DecodePayload(resp.Payload, &attestResp)
		require.NoError(t, err)

		assert.Equal(t, "device-123", attestResp.DeviceID)
		assert.True(t, attestResp.Verified)
		assert.NotEmpty(t, attestResp.QuoteData)
	})

	t.Run("returns error for missing device ID", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestDeviceRequest{}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestDeviceWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "device ID")
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		attestReq := &AttestDeviceRequest{DeviceID: "device-123"}
		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestDeviceWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns device with policy result", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.deviceResult = &AttestationDeviceResult{
			DeviceID:   "device-123",
			DeviceType: "tpm",
			Verified:   true,
			Timestamp:  time.Now(),
			PolicyResult: &AttestationPolicyEvalResult{
				PolicyID:    "policy-1",
				PolicyName:  "default-policy",
				Passed:      true,
				Details:     []string{"All PCRs verified"},
				EvaluatedAt: time.Now(),
			},
		}

		attestReq := &AttestDeviceRequest{DeviceID: "device-123", PolicyID: "policy-1"}
		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestDeviceWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var attestResp AttestDeviceResponse
		err = quicwire.DecodePayload(resp.Payload, &attestResp)
		require.NoError(t, err)

		assert.NotNil(t, attestResp.PolicyResult)
		assert.Equal(t, "policy-1", attestResp.PolicyResult.PolicyID)
		assert.True(t, attestResp.PolicyResult.Passed)
	})

	t.Run("returns error for short nonce", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestDeviceRequest{
			DeviceID: "device-123",
			Nonce:    []byte("short"), // Less than 16 bytes
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestDeviceWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "nonce")
	})

	t.Run("returns error for invalid hash algorithm", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		attestReq := &AttestDeviceRequest{
			DeviceID:      "device-123",
			Nonce:         []byte("valid-nonce-16byte"),
			HashAlgorithm: "invalid-hash",
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestDeviceWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "hash")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestDeviceWorkload,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: ListReports
// =============================================================================

func TestHandleListReports(t *testing.T) {
	ctx := context.Background()

	t.Run("lists reports successfully", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		createTestReport(service, "report-1")
		createTestReport(service, "report-2")

		listReq := &ListReportsRequest{
			HostID: "test-host-id",
			Limit:  10,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListReports,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp ListReportsResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(2), listResp.Count)
		assert.Equal(t, int32(2), listResp.Total)
		assert.Len(t, listResp.Reports, 2)
	})

	t.Run("uses default limit", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		listReq := &ListReportsRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListReports,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("caps limit at max", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		listReq := &ListReportsRequest{
			Limit: 5000, // exceeds max
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListReports,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		listReq := &ListReportsRequest{}
		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListReports,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.listReportsErr = errors.New("database error")

		listReq := &ListReportsRequest{}
		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListReports,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("filters by time range", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		createTestReport(service, "report-time-1")

		listReq := &ListReportsRequest{
			StartTime: 1000,
			EndTime:   2000,
			Limit:     10,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListReports,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})
	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListReports,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: GetReport
// =============================================================================

func TestHandleGetReport(t *testing.T) {
	ctx := context.Background()

	t.Run("gets report successfully", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		createTestReport(service, "report-1")

		getReq := &GetReportRequest{
			ID: "report-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetReportByID,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var getResp GetReportResponse
		err = quicwire.DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Report)
		assert.Equal(t, "report-1", getResp.Report.ID)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		getReq := &GetReportRequest{}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetReportByID,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns not found for missing report", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		getReq := &GetReportRequest{ID: "nonexistent"}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetReportByID,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		getReq := &GetReportRequest{ID: "report-1"}
		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetReportByID,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetReportByID,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: CreatePolicy
// =============================================================================

func TestHandleCreatePolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("creates policy successfully", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		createReq := &CreatePolicyRequest{
			Name:        "test-policy",
			Description: "A test policy",
			PCRPolicy: &PCRPolicyData{
				RequiredPCRs:    []int{0, 7, 14},
				AllowedHashAlgs: []string{"sha256", "sha384"},
				AllowZeroValues: false,
			},
			MaxAge: 300,
			Active: true,
			Metadata: map[string]string{
				"created_by": "test",
			},
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestCreatePolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var createResp CreatePolicyResponse
		err = quicwire.DecodePayload(resp.Payload, &createResp)
		require.NoError(t, err)

		assert.NotNil(t, createResp.Policy)
		assert.NotEmpty(t, createResp.Policy.ID)
		assert.Equal(t, "test-policy", createResp.Policy.Name)
		assert.True(t, createResp.Policy.Active)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		createReq := &CreatePolicyRequest{
			Description: "A test policy",
		}

		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestCreatePolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "policy name")
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		createReq := &CreatePolicyRequest{Name: "test-policy"}
		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestCreatePolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when creation fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.createPolicyErr = errors.New("policy already exists")

		createReq := &CreatePolicyRequest{Name: "test-policy"}
		payload, err := quicwire.EncodePayload(createReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestCreatePolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestCreatePolicy,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: ListPolicies
// =============================================================================

func TestHandleListPolicies(t *testing.T) {
	ctx := context.Background()

	t.Run("lists policies successfully", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		createTestPolicy(service, "policy-1", "default-policy")
		createTestPolicy(service, "policy-2", "strict-policy")

		listReq := &ListPoliciesRequest{
			Limit:  10,
			Active: true,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp ListPoliciesResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(2), listResp.Count)
		assert.Len(t, listResp.Policies, 2)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewAttestationHandler(newAttestTestLogger(), nil)

		listReq := &ListPoliciesRequest{}
		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.listPoliciesErr = errors.New("database error")

		listReq := &ListPoliciesRequest{}
		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("uses default limit", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		listReq := &ListPoliciesRequest{
			Limit: 0, // zero limit should use default
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("caps limit at max", func(t *testing.T) {
		handler, _ := createTestAttestationHandler()

		listReq := &ListPoliciesRequest{
			Limit: 5000, // exceeds max
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})

	t.Run("filters by name", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		createTestPolicy(service, "policy-named", "named-policy")

		listReq := &ListPoliciesRequest{
			Name:  "named-policy",
			Limit: 10,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})
}

// =============================================================================
// Test: Error Types
// =============================================================================

func TestAttestationErrorTypes(t *testing.T) {
	t.Run("ErrAttestationEncodingFailed", func(t *testing.T) {
		cause := errors.New("encoding error")
		err := ErrAttestationEncodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "encoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrAttestationDecodingFailed", func(t *testing.T) {
		cause := errors.New("decoding error")
		err := ErrAttestationDecodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "decoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrAttestationOperationFailed", func(t *testing.T) {
		cause := errors.New("operation error")
		err := ErrAttestationOperationFailed{
			Operation: "build_manifest",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "build_manifest")
		assert.Contains(t, err.Error(), "operation error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrAttestationManifestNotFound with ID", func(t *testing.T) {
		err := ErrAttestationManifestNotFound{ID: "manifest-123"}
		assert.Contains(t, err.Error(), "manifest-123")
	})

	t.Run("ErrAttestationManifestNotFound without ID", func(t *testing.T) {
		err := ErrAttestationManifestNotFound{}
		assert.Contains(t, err.Error(), "manifest not found")
	})

	t.Run("ErrAttestationReportNotFound with ID", func(t *testing.T) {
		err := ErrAttestationReportNotFound{ID: "report-123"}
		assert.Contains(t, err.Error(), "report-123")
	})

	t.Run("ErrAttestationReportNotFound without ID", func(t *testing.T) {
		err := ErrAttestationReportNotFound{}
		assert.Contains(t, err.Error(), "report not found")
	})

	t.Run("ErrAttestationPolicyNotFound with ID", func(t *testing.T) {
		err := ErrAttestationPolicyNotFound{ID: "policy-123"}
		assert.Contains(t, err.Error(), "policy-123")
	})

	t.Run("ErrAttestationPolicyNotFound without ID", func(t *testing.T) {
		err := ErrAttestationPolicyNotFound{}
		assert.Contains(t, err.Error(), "policy not found")
	})
}

// =============================================================================
// Test: attestationErrorResponse - Comprehensive Error Mapping
// =============================================================================

func TestAttestationErrorResponse(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	testCases := []struct {
		name           string
		err            error
		expectedStatus byte
	}{
		{"builder not initialized", manifest.ErrBuilderNotInitialized{}, quicwire.StatusUnavailable},
		{"verifier not initialized", manifest.ErrVerifierNotInitialized{}, quicwire.StatusUnavailable},
		{"signer not initialized", manifest.ErrSignerNotInitialized{}, quicwire.StatusUnavailable},
		{"host not attested", manifest.ErrHostNotAttested{}, quicwire.StatusNotFound},
		{"empty manifest", manifest.ErrEmptyManifest{}, quicwire.StatusInvalidArgument},
		{"not found error", errors.New("manifest not found"), quicwire.StatusNotFound},
		{"invalid error", errors.New("invalid request"), quicwire.StatusInvalidArgument},
		{"expired error", errors.New("manifest expired"), quicwire.StatusTimeout},
		{"unavailable error", errors.New("TPM not available"), quicwire.StatusUnavailable},
		{"permission denied", errors.New("permission denied"), quicwire.StatusPermissionDenied},
		{"already exists", errors.New("policy already exists"), quicwire.StatusAlreadyExists},
		{"generic error", errors.New("unknown error"), quicwire.StatusInternalError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.attestationErrorResponse(tc.err)
			assert.Equal(t, tc.expectedStatus, resp.Status)
		})
	}
}

// =============================================================================
// Test: Helper Methods
// =============================================================================

func TestIsValidHashAlgorithm(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	testCases := []struct {
		algorithm string
		valid     bool
	}{
		{"sha256", true},
		{"SHA256", true},
		{"sha384", true},
		{"sha512", true},
		{"sha1", true},
		{"md5", false},
		{"", false},
		{"invalid", false},
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			result := handler.isValidHashAlgorithm(tc.algorithm)
			assert.Equal(t, tc.valid, result)
		})
	}
}

func TestParseHashAlgorithm(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	testCases := []struct {
		algorithm string
		expected  manifest.HashAlgorithm
	}{
		{"sha256", manifest.HashAlgorithmSHA256},
		{"SHA256", manifest.HashAlgorithmSHA256},
		{"sha384", manifest.HashAlgorithmSHA384},
		{"sha512", manifest.HashAlgorithmSHA512},
		{"sha1", manifest.HashAlgorithmSHA1},
		{"", manifest.HashAlgorithmSHA256},        // default
		{"invalid", manifest.HashAlgorithmSHA256}, // default
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			result := handler.parseHashAlgorithm(tc.algorithm)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidatePCRIndices(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("valid indices", func(t *testing.T) {
		err := handler.validatePCRIndices([]int{0, 7, 14, 23})
		assert.NoError(t, err)
	})

	t.Run("negative index", func(t *testing.T) {
		err := handler.validatePCRIndices([]int{0, -1, 7})
		assert.Error(t, err)
	})

	t.Run("index too high", func(t *testing.T) {
		err := handler.validatePCRIndices([]int{0, 7, 24})
		assert.Error(t, err)
	})

	t.Run("empty indices", func(t *testing.T) {
		err := handler.validatePCRIndices([]int{})
		assert.NoError(t, err)
	})
}

func TestGetDefaultPCRIndices(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	indices := handler.getDefaultPCRIndices()

	assert.NotEmpty(t, indices)
	assert.Contains(t, indices, 0)
	assert.Contains(t, indices, 14) // workload PCR
}

// =============================================================================
// Test: Data Conversion Methods
// =============================================================================

func TestManifestToData(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("converts complete manifest", func(t *testing.T) {
		m := &manifest.HostManifest{
			ID:        "test-manifest",
			HostID:    "test-host",
			Timestamp: time.Now(),
			Nonce:     []byte("test-nonce"),
			Host: &manifest.HostAttestation{
				QuoteData:     []byte("quote"),
				Signature:     []byte("sig"),
				Nonce:         []byte("nonce"),
				Timestamp:     time.Now(),
				HashAlgorithm: manifest.HashAlgorithmSHA256,
			},
			VMs: []manifest.VMAttestation{
				{
					VMID:          "vm-1",
					HostID:        "test-host",
					QuoteData:     []byte("vm-quote"),
					Signature:     []byte("vm-sig"),
					Nonce:         []byte("vm-nonce"),
					Timestamp:     time.Now(),
					HashAlgorithm: manifest.HashAlgorithmSHA256,
				},
			},
			Containers: []manifest.ContainerAttestation{
				{
					ContainerID: "container-1",
					Digest:      []byte("digest"),
					PCRValue:    []byte("pcr"),
					Timestamp:   time.Now(),
				},
			},
			MerkleRoot: []byte("merkle-root"),
			Signature:  []byte("manifest-sig"),
			Version:    "1.0",
		}

		data := handler.manifestToData(m)

		assert.NotNil(t, data)
		assert.Equal(t, "test-manifest", data.ID)
		assert.Equal(t, "test-host", data.HostID)
		assert.NotNil(t, data.Host)
		assert.Len(t, data.VMs, 1)
		assert.Len(t, data.Containers, 1)
	})

	t.Run("keeps sub-second manifest time", func(t *testing.T) {
		m := &manifest.HostManifest{
			ID:        "frac",
			HostID:    "test-host",
			Timestamp: time.Unix(1700000000, 123456789).UTC(),
		}
		data := handler.manifestToData(m)
		assert.Equal(t, int64(1700000000), data.Timestamp)
		assert.Equal(t, int64(123456789), data.TimestampNanos)
		back, err := handler.dataToManifest(data)
		assert.NoError(t, err)
		assert.True(t, back.Timestamp.Equal(m.Timestamp), "round trip %v != %v", back.Timestamp, m.Timestamp)
	})

	t.Run("handles nil manifest", func(t *testing.T) {
		data := handler.manifestToData(nil)
		assert.Nil(t, data)
	})
}

func TestDataToManifest(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("converts complete data", func(t *testing.T) {
		data := &ManifestData{
			ID:         "test-manifest",
			HostID:     "test-host",
			Timestamp:  time.Now().Unix(),
			Nonce:      []byte("test-nonce"),
			MerkleRoot: []byte("merkle-root"),
			Version:    "1.0",
			Host: &HostAttestationData{
				QuoteData:     []byte("quote"),
				Signature:     []byte("sig"),
				Nonce:         []byte("nonce"),
				Timestamp:     time.Now().Unix(),
				HashAlgorithm: "sha256",
			},
		}

		m, err := handler.dataToManifest(data)

		assert.NoError(t, err)
		assert.NotNil(t, m)
		assert.Equal(t, "test-manifest", m.ID)
		assert.NotNil(t, m.Host)
	})

	t.Run("keeps sub-second manifest time", func(t *testing.T) {
		want := time.Unix(1700000000, 123456789).UTC()
		m, err := handler.dataToManifest(&ManifestData{
			ID:             "frac",
			HostID:         "test-host",
			Timestamp:      1700000000,
			TimestampNanos: 123456789,
		})
		assert.NoError(t, err)
		assert.True(t, m.Timestamp.Equal(want), "timestamp %v != %v", m.Timestamp, want)
	})

	t.Run("handles nil data", func(t *testing.T) {
		m, err := handler.dataToManifest(nil)
		assert.Error(t, err)
		assert.Nil(t, m)
	})
}

// A stored manifest whose host, VM and container evidence carry
// sub-second times crosses the QUIC wire unchanged (#1686, Codex round 5).
func TestManifestNestedEvidenceKeepsNanoseconds(t *testing.T) {
	handler, _ := createTestAttestationHandler()
	hostTS := time.Unix(1700000100, 111111111).UTC()
	vmTS := time.Unix(1700000200, 222222222).UTC()
	ctrTS := time.Unix(1700000300, 333333333).UTC()
	m := &manifest.HostManifest{
		ID:         "frac-nested",
		HostID:     "test-host",
		Timestamp:  time.Unix(1700000000, 123456789).UTC(),
		Host:       &manifest.HostAttestation{QuoteData: []byte("q"), Timestamp: hostTS, HashAlgorithm: manifest.HashAlgorithmSHA256},
		VMs:        []manifest.VMAttestation{{VMID: "vm-1", Timestamp: vmTS, HashAlgorithm: manifest.HashAlgorithmSHA256}},
		Containers: []manifest.ContainerAttestation{{ContainerID: "c-1", Timestamp: ctrTS}},
	}

	data := handler.manifestToData(m)
	require.NotNil(t, data.Host)
	require.Len(t, data.VMs, 1)
	require.Len(t, data.Containers, 1)
	assert.Equal(t, int64(111111111), data.Host.TimestampNanos)
	assert.Equal(t, int64(222222222), data.VMs[0].TimestampNanos)
	assert.Equal(t, int64(333333333), data.Containers[0].TimestampNanos)

	back, err := handler.dataToManifest(data)
	require.NoError(t, err)
	assert.True(t, back.Host.Timestamp.Equal(hostTS), "host %v != %v", back.Host.Timestamp, hostTS)
	assert.True(t, back.VMs[0].Timestamp.Equal(vmTS), "vm %v != %v", back.VMs[0].Timestamp, vmTS)
	assert.True(t, back.Containers[0].Timestamp.Equal(ctrTS), "container %v != %v", back.Containers[0].Timestamp, ctrTS)
}

func TestHostAttestationDataConversion(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("round trip conversion", func(t *testing.T) {
		original := &manifest.HostAttestation{
			QuoteData:          []byte("quote-data"),
			Signature:          []byte("signature"),
			SignatureAlgorithm: "RSASSA-PSS-SHA256",
			PCRs: []manifest.PCRValue{
				{Index: 0, Value: []byte("pcr0"), Algorithm: manifest.HashAlgorithmSHA256},
				{Index: 7, Value: []byte("pcr7"), Algorithm: manifest.HashAlgorithmSHA256},
			},
			PCRDigest:         []byte("pcr-digest"),
			Nonce:             []byte("nonce"),
			Timestamp:         time.Now(),
			AKPublicKey:       []byte("ak-key"),
			IDevIDCertificate: []byte("idevid"),
			HashAlgorithm:     manifest.HashAlgorithmSHA256,
			FirmwareVersion:   "1.0.0",
		}

		data := handler.hostAttestationToData(original)
		assert.NotNil(t, data)
		assert.Equal(t, original.QuoteData, data.QuoteData)
		assert.Len(t, data.PCRs, 2)

		restored := handler.dataToHostAttestation(data)
		assert.NotNil(t, restored)
		assert.Equal(t, original.QuoteData, restored.QuoteData)
		assert.Equal(t, original.HashAlgorithm, restored.HashAlgorithm)
	})

	t.Run("handles nil", func(t *testing.T) {
		assert.Nil(t, handler.hostAttestationToData(nil))
		assert.Nil(t, handler.dataToHostAttestation(nil))
	})
}

func TestVMAttestationDataConversion(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("round trip conversion", func(t *testing.T) {
		original := &manifest.VMAttestation{
			VMID:               "vm-123",
			HostID:             "host-123",
			QuoteData:          []byte("vm-quote"),
			Signature:          []byte("vm-sig"),
			SignatureAlgorithm: "RSASSA-PSS-SHA256",
			PCRs: []manifest.PCRValue{
				{Index: 0, Value: []byte("pcr0"), Algorithm: manifest.HashAlgorithmSHA256},
			},
			Nonce:         []byte("vm-nonce"),
			Timestamp:     time.Now(),
			AIKPublicKey:  []byte("aik"),
			HashAlgorithm: manifest.HashAlgorithmSHA256,
			Metadata:      map[string]string{"key": "value"},
		}

		data := handler.vmAttestationToData(original)
		assert.NotNil(t, data)
		assert.Equal(t, "vm-123", data.VMID)

		restored := handler.dataToVMAttestation(data)
		assert.NotNil(t, restored)
		assert.Equal(t, original.VMID, restored.VMID)
	})

	t.Run("handles nil", func(t *testing.T) {
		assert.Nil(t, handler.vmAttestationToData(nil))
		assert.Nil(t, handler.dataToVMAttestation(nil))
	})
}

func TestContainerAttestationDataConversion(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("round trip conversion", func(t *testing.T) {
		original := &manifest.ContainerAttestation{
			ContainerID: "container-123",
			ImageID:     "sha256:abc",
			ImageDigest: "sha256:def",
			Digest:      []byte("digest"),
			PCRValue:    []byte("pcr"),
			Timestamp:   time.Now(),
			Metadata:    map[string]string{"key": "value"},
		}

		data := handler.containerAttestationToData(original)
		assert.NotNil(t, data)
		assert.Equal(t, "container-123", data.ContainerID)

		restored := handler.dataToContainerAttestation(data)
		assert.NotNil(t, restored)
		assert.Equal(t, original.ContainerID, restored.ContainerID)
	})

	t.Run("handles nil", func(t *testing.T) {
		assert.Nil(t, handler.containerAttestationToData(nil))
		assert.Nil(t, handler.dataToContainerAttestation(nil))
	})
}

// =============================================================================
// Test: Opcode Constants
// =============================================================================

func TestAttestationOpcodeConstants(t *testing.T) {
	// Verify opcodes are unique
	opcodes := []struct {
		name   string
		opcode byte
	}{
		{"OpAttestGetManifest", quicwire.OpAttestGetManifest},
		{"OpAttestBuildManifest", quicwire.OpAttestBuildManifest},
		{"OpAttestVerifyManifest", quicwire.OpAttestVerifyManifest},
		{"OpAttestHost", quicwire.OpAttestHost},
		{"OpAttestVMWorkload", quicwire.OpAttestVMWorkload},
		{"OpAttestContainerWorkload", quicwire.OpAttestContainerWorkload},
		{"OpAttestDeviceWorkload", quicwire.OpAttestDeviceWorkload},
		{"OpAttestListReports", quicwire.OpAttestListReports},
		{"OpAttestGetReportByID", quicwire.OpAttestGetReportByID},
		{"OpAttestCreatePolicy", quicwire.OpAttestCreatePolicy},
		{"OpAttestListPolicies", quicwire.OpAttestListPolicies},
	}

	seen := make(map[byte]string)
	for _, op := range opcodes {
		if existing, ok := seen[op.opcode]; ok {
			t.Errorf("duplicate opcode 0x%02X: %s and %s", op.opcode, existing, op.name)
		}
		seen[op.opcode] = op.name
	}
}

// =============================================================================
// Test: Pagination Constants
// =============================================================================

func TestAttestationPaginationConstants(t *testing.T) {
	assert.Equal(t, int32(50), attestationDefaultLimit)
	assert.Equal(t, int32(1000), attestationMaxLimit)
	assert.Less(t, attestationDefaultLimit, attestationMaxLimit)
}

// =============================================================================
// Test: Verification Result Conversion
// =============================================================================

func TestVerificationResultToResponse(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("converts verified result", func(t *testing.T) {
		result := &manifest.VerificationResult{
			Status:                     manifest.VerificationStatusVerified,
			SignatureValid:             true,
			MerkleRootValid:            true,
			NonceValid:                 true,
			TimestampValid:             true,
			HostAttestationValid:       true,
			VMAttestationsValid:        true,
			ContainerAttestationsValid: true,
			VerifiedAt:                 time.Now(),
		}

		resp := handler.verificationResultToResponse(result)

		assert.NotNil(t, resp)
		assert.True(t, resp.Valid)
		assert.Equal(t, "verified", resp.Status)
		assert.True(t, resp.SignatureValid)
	})

	t.Run("converts failed result with errors", func(t *testing.T) {
		result := &manifest.VerificationResult{
			Status:          manifest.VerificationStatusFailed,
			SignatureValid:  false,
			VerifiedAt:      time.Now(),
			Errors:          []string{"signature invalid", "nonce mismatch"},
			VMErrors:        map[string]string{"vm-1": "not attested"},
			ContainerErrors: map[string]string{"c-1": "not found"},
		}

		resp := handler.verificationResultToResponse(result)

		assert.NotNil(t, resp)
		assert.False(t, resp.Valid)
		assert.Equal(t, "failed", resp.Status)
		assert.Len(t, resp.Errors, 2)
		assert.NotEmpty(t, resp.VMErrors)
		assert.NotEmpty(t, resp.ContainerErrors)
	})

	t.Run("handles nil result", func(t *testing.T) {
		resp := handler.verificationResultToResponse(nil)
		assert.Nil(t, resp)
	})
}

// =============================================================================
// Test: Device Result Conversion
// =============================================================================

func TestDeviceResultToResponse(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("converts complete result", func(t *testing.T) {
		result := &AttestationDeviceResult{
			DeviceID:    "device-123",
			DeviceType:  "tpm",
			Verified:    true,
			QuoteData:   []byte("quote"),
			Signature:   []byte("sig"),
			PCRValues:   map[int][]byte{0: []byte("pcr0")},
			Certificate: []byte("cert"),
			Timestamp:   time.Now(),
			Metadata:    map[string]string{"key": "value"},
			PolicyResult: &AttestationPolicyEvalResult{
				PolicyID:    "policy-1",
				PolicyName:  "default",
				Passed:      true,
				Details:     []string{"all checks passed"},
				EvaluatedAt: time.Now(),
			},
		}

		resp := handler.deviceResultToResponse(result)

		assert.NotNil(t, resp)
		assert.Equal(t, "device-123", resp.DeviceID)
		assert.True(t, resp.Verified)
		assert.NotNil(t, resp.PolicyResult)
		assert.Equal(t, "policy-1", resp.PolicyResult.PolicyID)
	})

	t.Run("converts result without policy", func(t *testing.T) {
		result := &AttestationDeviceResult{
			DeviceID:   "device-123",
			DeviceType: "tpm",
			Verified:   true,
			Timestamp:  time.Now(),
		}

		resp := handler.deviceResultToResponse(result)

		assert.NotNil(t, resp)
		assert.Nil(t, resp.PolicyResult)
	})

	t.Run("handles nil result", func(t *testing.T) {
		resp := handler.deviceResultToResponse(nil)
		assert.Nil(t, resp)
	})
}

// =============================================================================
// Test: Policy Conversion
// =============================================================================

func TestPolicyToData(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("converts complete policy", func(t *testing.T) {
		policy := &AttestationPolicy{
			ID:          "policy-1",
			Name:        "test-policy",
			Description: "A test policy",
			PCRPolicy: &AttestationPCRPolicyConfig{
				RequiredPCRs:    []int{0, 7},
				AllowedHashAlgs: []string{"sha256"},
				ExpectedValues:  map[int][]byte{0: []byte("expected")},
				AllowZeroValues: false,
			},
			GoldenValues: map[int][]byte{0: []byte("golden")},
			MaxAge:       300,
			Active:       true,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			Metadata:     map[string]string{"key": "value"},
		}

		data := handler.policyToData(policy)

		assert.NotNil(t, data)
		assert.Equal(t, "policy-1", data.ID)
		assert.Equal(t, "test-policy", data.Name)
		assert.NotNil(t, data.PCRPolicy)
		assert.Equal(t, []int{0, 7}, data.PCRPolicy.RequiredPCRs)
	})

	t.Run("handles nil policy", func(t *testing.T) {
		data := handler.policyToData(nil)
		assert.Nil(t, data)
	})
}

func TestDataToPolicyCreateRequest(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("converts complete request", func(t *testing.T) {
		req := &CreatePolicyRequest{
			Name:        "test-policy",
			Description: "A test policy",
			PCRPolicy: &PCRPolicyData{
				RequiredPCRs:    []int{0, 7},
				AllowedHashAlgs: []string{"sha256"},
				AllowZeroValues: false,
			},
			GoldenValues: map[int][]byte{0: []byte("golden")},
			MaxAge:       300,
			Active:       true,
			Metadata:     map[string]string{"key": "value"},
		}

		policyReq := handler.dataToPolicyCreateRequest(req)

		assert.NotNil(t, policyReq)
		assert.Equal(t, "test-policy", policyReq.Name)
		assert.NotNil(t, policyReq.PCRPolicy)
		assert.Equal(t, []int{0, 7}, policyReq.PCRPolicy.RequiredPCRs)
	})

	t.Run("handles request without PCR policy", func(t *testing.T) {
		req := &CreatePolicyRequest{
			Name: "simple-policy",
		}

		policyReq := handler.dataToPolicyCreateRequest(req)

		assert.NotNil(t, policyReq)
		assert.Nil(t, policyReq.PCRPolicy)
	})
}

// =============================================================================
// Test: Report Conversion
// =============================================================================

func TestReportToData(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("converts complete report", func(t *testing.T) {
		report := &AttestationReport{
			ID:         "report-1",
			HostID:     "host-1",
			Type:       "host",
			WorkloadID: "workload-1",
			Status:     "verified",
			ManifestID: "manifest-1",
			PolicyID:   "policy-1",
			CreatedAt:  time.Now(),
			ExpiresAt:  time.Now().Add(24 * time.Hour),
			Metadata:   map[string]string{"key": "value"},
		}

		data := handler.reportToData(report)

		assert.Equal(t, "report-1", data.ID)
		assert.Equal(t, "host-1", data.HostID)
		assert.Greater(t, data.ExpiresAt, int64(0))
	})

	t.Run("handles report without expiry", func(t *testing.T) {
		report := &AttestationReport{
			ID:        "report-1",
			HostID:    "host-1",
			CreatedAt: time.Now(),
		}

		data := handler.reportToData(report)

		assert.Equal(t, int64(0), data.ExpiresAt)
	})
}

// =============================================================================
// Test: dataToManifest Additional Coverage
// =============================================================================

func TestDataToManifestAdditional(t *testing.T) {
	handler, _ := createTestAttestationHandler()

	t.Run("returns error for nil data", func(t *testing.T) {
		result, err := handler.dataToManifest(nil)

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAttestationMissingManifest)
	})

	t.Run("converts manifest with VMs", func(t *testing.T) {
		data := &ManifestData{
			ID:        "manifest-1",
			HostID:    "host-1",
			Timestamp: time.Now().Unix(),
			VMs: []VMAttestationData{
				{
					VMID:   "vm-1",
					HostID: "host-1",
				},
			},
		}

		result, err := handler.dataToManifest(data)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.VMs, 1)
		assert.Equal(t, "vm-1", result.VMs[0].VMID)
	})

	t.Run("converts manifest with containers", func(t *testing.T) {
		data := &ManifestData{
			ID:        "manifest-1",
			HostID:    "host-1",
			Timestamp: time.Now().Unix(),
			Containers: []ContainerAttestData{
				{
					ContainerID: "container-1",
					ImageID:     "image-1",
				},
			},
		}

		result, err := handler.dataToManifest(data)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Containers, 1)
		assert.Equal(t, "container-1", result.Containers[0].ContainerID)
	})
}

// =============================================================================
// Test: Attest Device Additional Error Paths
// =============================================================================

func TestHandleAttestDeviceAdditionalErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when service unavailable", func(t *testing.T) {
		logger := newAttestTestLogger()
		handler := NewAttestationHandler(logger, nil)

		attestReq := &AttestDeviceRequest{
			DeviceID: "device-1",
			Nonce:    []byte("test-nonce"),
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestDeviceWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when attestation fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.attestDeviceErr = errors.New("attestation failed")

		attestReq := &AttestDeviceRequest{
			DeviceID: "device-1",
			Nonce:    []byte("test-nonce-123456"), // Must be at least 16 bytes
		}

		payload, err := quicwire.EncodePayload(attestReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestDeviceWorkload,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: Get Report Additional Error Paths
// =============================================================================

func TestHandleGetReportAdditionalErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when get fails", func(t *testing.T) {
		handler, service := createTestAttestationHandler()
		service.getReportErr = errors.New("get failed")

		getReq := &GetReportRequest{
			ID: "report-1",
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpAttestGetReportByID,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}
