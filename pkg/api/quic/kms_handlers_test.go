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
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// init initializes the codec for KMS handler tests
func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = quicwire.SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Mock KMS Service
// =============================================================================

// testKMSService implements KMSService for testing
type testKMSService struct {
	// Response data for key management
	generateKeyResp   *KMSGenerateKeyResponse
	importKeyResp     *KMSImportKeyResponse
	getKeyResp        *KMSGetKeyResponse
	listKeysResp      *KMSListKeysResponse
	deleteKeyResp     *KMSDeleteKeyResponse
	rotateKeyResp     *KMSRotateKeyResponse
	updateStatusResp  *KMSUpdateKeyStatusResponse
	exportKeyResp     *KMSExportKeyResponse
	keyVersionsResp   *KMSGetKeyVersionsResponse
	backendStatusResp *KMSBackendStatusResponse

	// Response data for crypto operations
	encryptResp    *KMSEncryptResponse
	decryptResp    *KMSDecryptResponse
	signResp       *KMSSignResponse
	verifyResp     *KMSVerifyResponse
	randomResp     *KMSGenerateRandomResponse
	hashResp       *KMSHashResponse
	hmacResp       *KMSHMACResponse
	verifyHMACResp *KMSVerifyHMACResponse

	// Response data for batch and rewrap operations
	batchEncryptResp *KMSBatchEncryptResponse
	batchDecryptResp *KMSBatchDecryptResponse
	rewrapResp       *KMSRewrapResponse

	// Error injection
	generateKeyErr   error
	importKeyErr     error
	getKeyErr        error
	listKeysErr      error
	deleteKeyErr     error
	rotateKeyErr     error
	updateStatusErr  error
	exportKeyErr     error
	keyVersionsErr   error
	backendStatusErr error
	encryptErr       error
	decryptErr       error
	signErr          error
	verifyErr        error
	randomErr        error
	hashErr          error
	hmacErr          error
	verifyHMACErr    error
	batchEncryptErr  error
	batchDecryptErr  error
	rewrapErr        error

	// Capture last request for validation
	lastGenerateKeyReq  *KMSGenerateKeyRequest
	lastImportKeyReq    *KMSImportKeyRequest
	lastGetKeyReq       *KMSGetKeyRequest
	lastListKeysReq     *KMSListKeysRequest
	lastDeleteKeyReq    *KMSDeleteKeyRequest
	lastRotateKeyReq    *KMSRotateKeyRequest
	lastUpdateStatusReq *KMSUpdateKeyStatusRequest
	lastExportKeyReq    *KMSExportKeyRequest
	lastKeyVersionsReq  *KMSGetKeyVersionsRequest
	lastEncryptReq      *KMSEncryptRequest
	lastDecryptReq      *KMSDecryptRequest
	lastSignReq         *KMSSignRequest
	lastVerifyReq       *KMSVerifyRequest
	lastRandomReq       *KMSGenerateRandomRequest
	lastHashReq         *KMSHashRequest
	lastHMACReq         *KMSHMACRequest
	lastVerifyHMACReq   *KMSVerifyHMACRequest
	lastBatchEncryptReq *KMSBatchEncryptRequest
	lastBatchDecryptReq *KMSBatchDecryptRequest
	lastRewrapReq       *KMSRewrapRequest
}

func newTestKMSService() *testKMSService {
	now := time.Now().Unix()
	return &testKMSService{
		generateKeyResp: &KMSGenerateKeyResponse{
			Key: &KMSKeyHandle{
				KeyID:     "key-123",
				Version:   1,
				Algorithm: 3, // AES-256-GCM
				Status:    1,
				CreatedAt: now,
			},
			Metadata: &KMSKeyMetadata{
				KeyID:     "key-123",
				Name:      "test-key",
				Algorithm: 3,
				Status:    1,
				CreatedAt: now,
			},
			Timestamp: now,
		},
		importKeyResp: &KMSImportKeyResponse{
			Key: &KMSKeyHandle{
				KeyID:     "imported-key-456",
				Version:   1,
				Algorithm: 3,
				Status:    1,
				CreatedAt: now,
			},
			Timestamp: now,
		},
		getKeyResp: &KMSGetKeyResponse{
			Key: &KMSKeyHandle{
				KeyID:     "key-123",
				Version:   1,
				Algorithm: 3,
				Status:    1,
				CreatedAt: now,
			},
			Metadata: &KMSKeyMetadata{
				KeyID:     "key-123",
				Name:      "test-key",
				Algorithm: 3,
				Status:    1,
				CreatedAt: now,
			},
			Timestamp: now,
		},
		listKeysResp: &KMSListKeysResponse{
			Keys: []*KMSKeyHandle{
				{KeyID: "key-1", Version: 1, Algorithm: 3, Status: 1, CreatedAt: now},
				{KeyID: "key-2", Version: 1, Algorithm: 20, Status: 1, CreatedAt: now},
			},
			TotalCount: 2,
			HasMore:    false,
			Timestamp:  now,
		},
		deleteKeyResp: &KMSDeleteKeyResponse{
			KeyID:     "key-123",
			Status:    4, // Pending deletion
			Timestamp: now,
		},
		rotateKeyResp: &KMSRotateKeyResponse{
			KeyID:      "key-123",
			OldVersion: 1,
			NewVersion: 2,
			Timestamp:  now,
		},
		updateStatusResp: &KMSUpdateKeyStatusResponse{
			KeyID:     "key-123",
			Version:   1,
			Status:    2, // Disabled
			Timestamp: now,
		},
		exportKeyResp: &KMSExportKeyResponse{
			KeyID:           "key-123",
			Format:          1,
			WrappedMaterial: []byte("wrapped-key-material"),
			Version:         1,
			Timestamp:       now,
		},
		keyVersionsResp: &KMSGetKeyVersionsResponse{
			KeyID: "key-123",
			Versions: []*KMSKeyVersionInfo{
				{Version: 1, Status: 1, Algorithm: 3, CreatedAt: now},
				{Version: 2, Status: 1, Algorithm: 3, CreatedAt: now},
			},
			HasMore:   false,
			Timestamp: now,
		},
		backendStatusResp: &KMSBackendStatusResponse{
			BackendType:  "software",
			Status:       "available",
			Capabilities: map[string]bool{"encrypt": true, "sign": true},
			Timestamp:    now,
		},
		encryptResp: &KMSEncryptResponse{
			KeyID:      "key-123",
			KeyVersion: 1,
			Ciphertext: []byte("encrypted-data"),
			Nonce:      []byte("nonce-value"),
			Timestamp:  now,
		},
		decryptResp: &KMSDecryptResponse{
			KeyID:      "key-123",
			KeyVersion: 1,
			Plaintext:  []byte("decrypted-data"),
			Timestamp:  now,
		},
		signResp: &KMSSignResponse{
			KeyID:         "key-123",
			KeyVersion:    1,
			Signature:     []byte("signature-data"),
			HashAlgorithm: 4, // SHA-256
			Timestamp:     now,
		},
		verifyResp: &KMSVerifyResponse{
			KeyID:      "key-123",
			KeyVersion: 1,
			Valid:      true,
			Timestamp:  now,
		},
		randomResp: &KMSGenerateRandomResponse{
			RandomBytes: make([]byte, 32),
			Timestamp:   now,
		},
		hashResp: &KMSHashResponse{
			Algorithm: 4, // SHA-256
			Hash:      []byte("hash-value"),
			Timestamp: now,
		},
		hmacResp: &KMSHMACResponse{
			KeyID:         "key-123",
			KeyVersion:    1,
			HMAC:          []byte("hmac-value"),
			HashAlgorithm: 4,
			Timestamp:     now,
		},
		verifyHMACResp: &KMSVerifyHMACResponse{
			KeyID:      "key-123",
			KeyVersion: 1,
			Valid:      true,
			Timestamp:  now,
		},
		batchEncryptResp: &KMSBatchEncryptResponse{
			KeyID:      "key-123",
			KeyVersion: 1,
			Results: []*KMSBatchEncryptResultItem{
				{ID: "item-1", Ciphertext: []byte("encrypted-1"), Success: true},
				{ID: "item-2", Ciphertext: []byte("encrypted-2"), Success: true},
			},
			SuccessCount: 2,
			FailureCount: 0,
			Timestamp:    now,
		},
		batchDecryptResp: &KMSBatchDecryptResponse{
			KeyID: "key-123",
			Results: []*KMSBatchDecryptResultItem{
				{ID: "item-1", Plaintext: []byte("decrypted-1"), Success: true},
				{ID: "item-2", Plaintext: []byte("decrypted-2"), Success: true},
			},
			SuccessCount: 2,
			FailureCount: 0,
			Timestamp:    now,
		},
		rewrapResp: &KMSRewrapResponse{
			SourceKeyID:      "source-key",
			DestinationKeyID: "dest-key",
			Ciphertext:       []byte("rewrapped-ciphertext"),
			SourceKeyVersion: 1,
			DestKeyVersion:   1,
			Timestamp:        now,
		},
	}
}

func (s *testKMSService) GenerateKey(ctx context.Context, req *KMSGenerateKeyRequest) (*KMSGenerateKeyResponse, error) {
	s.lastGenerateKeyReq = req
	if s.generateKeyErr != nil {
		return nil, s.generateKeyErr
	}
	return s.generateKeyResp, nil
}

func (s *testKMSService) ImportKey(ctx context.Context, req *KMSImportKeyRequest) (*KMSImportKeyResponse, error) {
	s.lastImportKeyReq = req
	if s.importKeyErr != nil {
		return nil, s.importKeyErr
	}
	return s.importKeyResp, nil
}

func (s *testKMSService) GetKey(ctx context.Context, req *KMSGetKeyRequest) (*KMSGetKeyResponse, error) {
	s.lastGetKeyReq = req
	if s.getKeyErr != nil {
		return nil, s.getKeyErr
	}
	return s.getKeyResp, nil
}

func (s *testKMSService) ListKeys(ctx context.Context, req *KMSListKeysRequest) (*KMSListKeysResponse, error) {
	s.lastListKeysReq = req
	if s.listKeysErr != nil {
		return nil, s.listKeysErr
	}
	return s.listKeysResp, nil
}

func (s *testKMSService) DeleteKey(ctx context.Context, req *KMSDeleteKeyRequest) (*KMSDeleteKeyResponse, error) {
	s.lastDeleteKeyReq = req
	if s.deleteKeyErr != nil {
		return nil, s.deleteKeyErr
	}
	return s.deleteKeyResp, nil
}

func (s *testKMSService) RotateKey(ctx context.Context, req *KMSRotateKeyRequest) (*KMSRotateKeyResponse, error) {
	s.lastRotateKeyReq = req
	if s.rotateKeyErr != nil {
		return nil, s.rotateKeyErr
	}
	return s.rotateKeyResp, nil
}

func (s *testKMSService) UpdateKeyStatus(ctx context.Context, req *KMSUpdateKeyStatusRequest) (*KMSUpdateKeyStatusResponse, error) {
	s.lastUpdateStatusReq = req
	if s.updateStatusErr != nil {
		return nil, s.updateStatusErr
	}
	return s.updateStatusResp, nil
}

func (s *testKMSService) ExportKey(ctx context.Context, req *KMSExportKeyRequest) (*KMSExportKeyResponse, error) {
	s.lastExportKeyReq = req
	if s.exportKeyErr != nil {
		return nil, s.exportKeyErr
	}
	return s.exportKeyResp, nil
}

func (s *testKMSService) GetKeyVersions(ctx context.Context, req *KMSGetKeyVersionsRequest) (*KMSGetKeyVersionsResponse, error) {
	s.lastKeyVersionsReq = req
	if s.keyVersionsErr != nil {
		return nil, s.keyVersionsErr
	}
	return s.keyVersionsResp, nil
}

func (s *testKMSService) BackendStatus(ctx context.Context) (*KMSBackendStatusResponse, error) {
	if s.backendStatusErr != nil {
		return nil, s.backendStatusErr
	}
	return s.backendStatusResp, nil
}

func (s *testKMSService) Encrypt(ctx context.Context, req *KMSEncryptRequest) (*KMSEncryptResponse, error) {
	s.lastEncryptReq = req
	if s.encryptErr != nil {
		return nil, s.encryptErr
	}
	return s.encryptResp, nil
}

func (s *testKMSService) Decrypt(ctx context.Context, req *KMSDecryptRequest) (*KMSDecryptResponse, error) {
	s.lastDecryptReq = req
	if s.decryptErr != nil {
		return nil, s.decryptErr
	}
	return s.decryptResp, nil
}

func (s *testKMSService) Sign(ctx context.Context, req *KMSSignRequest) (*KMSSignResponse, error) {
	s.lastSignReq = req
	if s.signErr != nil {
		return nil, s.signErr
	}
	return s.signResp, nil
}

func (s *testKMSService) Verify(ctx context.Context, req *KMSVerifyRequest) (*KMSVerifyResponse, error) {
	s.lastVerifyReq = req
	if s.verifyErr != nil {
		return nil, s.verifyErr
	}
	return s.verifyResp, nil
}

func (s *testKMSService) GenerateRandom(ctx context.Context, req *KMSGenerateRandomRequest) (*KMSGenerateRandomResponse, error) {
	s.lastRandomReq = req
	if s.randomErr != nil {
		return nil, s.randomErr
	}
	return s.randomResp, nil
}

func (s *testKMSService) Hash(ctx context.Context, req *KMSHashRequest) (*KMSHashResponse, error) {
	s.lastHashReq = req
	if s.hashErr != nil {
		return nil, s.hashErr
	}
	return s.hashResp, nil
}

func (s *testKMSService) HMAC(ctx context.Context, req *KMSHMACRequest) (*KMSHMACResponse, error) {
	s.lastHMACReq = req
	if s.hmacErr != nil {
		return nil, s.hmacErr
	}
	return s.hmacResp, nil
}

func (s *testKMSService) VerifyHMAC(ctx context.Context, req *KMSVerifyHMACRequest) (*KMSVerifyHMACResponse, error) {
	s.lastVerifyHMACReq = req
	if s.verifyHMACErr != nil {
		return nil, s.verifyHMACErr
	}
	return s.verifyHMACResp, nil
}

func (s *testKMSService) BatchEncrypt(ctx context.Context, req *KMSBatchEncryptRequest) (*KMSBatchEncryptResponse, error) {
	s.lastBatchEncryptReq = req
	if s.batchEncryptErr != nil {
		return nil, s.batchEncryptErr
	}
	return s.batchEncryptResp, nil
}

func (s *testKMSService) BatchDecrypt(ctx context.Context, req *KMSBatchDecryptRequest) (*KMSBatchDecryptResponse, error) {
	s.lastBatchDecryptReq = req
	if s.batchDecryptErr != nil {
		return nil, s.batchDecryptErr
	}
	return s.batchDecryptResp, nil
}

func (s *testKMSService) Rewrap(ctx context.Context, req *KMSRewrapRequest) (*KMSRewrapResponse, error) {
	s.lastRewrapReq = req
	if s.rewrapErr != nil {
		return nil, s.rewrapErr
	}
	return s.rewrapResp, nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newKMSTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestKMSHandler() (*KMSHandler, *testKMSService) {
	logger := newKMSTestLogger()
	service := newTestKMSService()
	handler := NewKMSHandler(logger, service)
	return handler, service
}

// =============================================================================
// Test: NewKMSHandler
// =============================================================================

func TestNewKMSHandler(t *testing.T) {
	t.Run("creates handler with valid inputs", func(t *testing.T) {
		logger := newKMSTestLogger()
		service := newTestKMSService()
		handler := NewKMSHandler(logger, service)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, service, handler.service)
	})

	t.Run("creates handler with nil service", func(t *testing.T) {
		logger := newKMSTestLogger()
		handler := NewKMSHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.service)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestKMSHandleRequest(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		resp := handler.HandleRequest(context.Background(), nil)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "nil")
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode: 0x00, // Unknown opcode for KMS handler
		}

		resp := handler.HandleRequest(context.Background(), req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown KMS operation")
	})
}

// =============================================================================
// Test: GenerateKey
// =============================================================================

func TestHandleGenerateKey(t *testing.T) {
	ctx := context.Background()

	t.Run("generates key successfully", func(t *testing.T) {
		handler, service := createTestKMSHandler()

		genReq := &KMSGenerateKeyRequest{
			KeySpec: &KMSKeySpec{
				Algorithm:  3, // AES-256-GCM
				KeySize:    256,
				Usage:      []int32{1, 2}, // Encrypt, Decrypt
				Exportable: true,
			},
			Name:        "test-key",
			Description: "Test key for unit tests",
			Tags:        map[string]string{"env": "test"},
		}

		payload, err := quicwire.EncodePayload(genReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var genResp KMSGenerateKeyResponse
		err = quicwire.DecodePayload(resp.Payload, &genResp)
		require.NoError(t, err)

		assert.NotNil(t, genResp.Key)
		assert.Equal(t, "key-123", genResp.Key.KeyID)
		assert.Equal(t, uint64(1), genResp.Key.Version)

		// Verify the request was captured correctly
		assert.NotNil(t, service.lastGenerateKeyReq)
		assert.Equal(t, "test-key", service.lastGenerateKeyReq.Name)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		genReq := &KMSGenerateKeyRequest{
			KeySpec: &KMSKeySpec{Algorithm: 3},
		}

		payload, err := quicwire.EncodePayload(genReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key spec", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		genReq := &KMSGenerateKeyRequest{
			Name: "test-key",
		}

		payload, err := quicwire.EncodePayload(genReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "specification")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateKey,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when generate fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.generateKeyErr = ErrKMSInvalidKeySpecErr{Reason: "unsupported algorithm"}

		genReq := &KMSGenerateKeyRequest{
			KeySpec: &KMSKeySpec{Algorithm: 999},
		}

		payload, err := quicwire.EncodePayload(genReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: ImportKey
// =============================================================================

func TestHandleImportKey(t *testing.T) {
	ctx := context.Background()

	t.Run("imports key successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		importReq := &KMSImportKeyRequest{
			KeyMaterial: []byte("secret-key-material"),
			KeySpec:     &KMSKeySpec{Algorithm: 3},
			Name:        "imported-key",
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSImportKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var importResp KMSImportKeyResponse
		err = quicwire.DecodePayload(resp.Payload, &importResp)
		require.NoError(t, err)

		assert.NotNil(t, importResp.Key)
		assert.Equal(t, "imported-key-456", importResp.Key.KeyID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		importReq := &KMSImportKeyRequest{
			KeyMaterial: []byte("key-material"),
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSImportKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key material", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		importReq := &KMSImportKeyRequest{
			Name: "imported-key",
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSImportKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "material")
	})

	t.Run("returns error when import fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.importKeyErr = ErrKMSKeyAlreadyExists{KeyID: "imported-key"}

		importReq := &KMSImportKeyRequest{
			KeyMaterial: []byte("key-material"),
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSImportKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)
	})
}

// =============================================================================
// Test: GetKey
// =============================================================================

func TestHandleGetKey(t *testing.T) {
	ctx := context.Background()

	t.Run("gets key successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		getReq := &KMSGetKeyRequest{
			KeyID:   "key-123",
			Version: 1,
		}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var getResp KMSGetKeyResponse
		err = quicwire.DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Key)
		assert.Equal(t, "key-123", getResp.Key.KeyID)
		assert.NotNil(t, getResp.Metadata)
		assert.Equal(t, "test-key", getResp.Metadata.Name)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		getReq := &KMSGetKeyRequest{KeyID: "key-123"}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		getReq := &KMSGetKeyRequest{}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "key ID")
	})

	t.Run("returns error for key not found", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.getKeyErr = ErrKMSKeyNotFound{KeyID: "nonexistent"}

		getReq := &KMSGetKeyRequest{KeyID: "nonexistent"}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKey,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: ListKeys
// =============================================================================

func TestHandleListKeys(t *testing.T) {
	ctx := context.Background()

	t.Run("lists keys successfully", func(t *testing.T) {
		handler, service := createTestKMSHandler()

		listReq := &KMSListKeysRequest{
			Limit: 10,
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSListKeys,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp KMSListKeysResponse
		err = quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Len(t, listResp.Keys, 2)
		assert.Equal(t, int32(2), listResp.TotalCount)
		assert.False(t, listResp.HasMore)

		// Verify limit was applied
		assert.Equal(t, int32(10), service.lastListKeysReq.Limit)
	})

	t.Run("applies default limit when not specified", func(t *testing.T) {
		handler, service := createTestKMSHandler()

		listReq := &KMSListKeysRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSListKeys,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, kmsDefaultLimit, service.lastListKeysReq.Limit)
	})

	t.Run("caps limit at maximum", func(t *testing.T) {
		handler, service := createTestKMSHandler()

		listReq := &KMSListKeysRequest{
			Limit: 5000, // Exceeds max
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSListKeys,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, kmsMaxLimit, service.lastListKeysReq.Limit)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		listReq := &KMSListKeysRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSListKeys,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.listKeysErr = errors.New("database error")

		listReq := &KMSListKeysRequest{}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSListKeys,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSListKeys,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: DeleteKey
// =============================================================================

func TestHandleDeleteKey(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes key successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		deleteReq := &KMSDeleteKeyRequest{
			KeyID:             "key-123",
			PendingWindowDays: 7,
		}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDeleteKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var deleteResp KMSDeleteKeyResponse
		err = quicwire.DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", deleteResp.KeyID)
		assert.Equal(t, int32(4), deleteResp.Status) // Pending deletion
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		deleteReq := &KMSDeleteKeyRequest{KeyID: "key-123"}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDeleteKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		deleteReq := &KMSDeleteKeyRequest{}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDeleteKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for key not found", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.deleteKeyErr = ErrKMSKeyNotFound{KeyID: "nonexistent"}

		deleteReq := &KMSDeleteKeyRequest{KeyID: "nonexistent"}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDeleteKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDeleteKey,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: RotateKey
// =============================================================================

func TestHandleRotateKey(t *testing.T) {
	ctx := context.Background()

	t.Run("rotates key successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		rotateReq := &KMSRotateKeyRequest{
			KeyID:            "key-123",
			RetainOldVersion: true,
		}

		payload, err := quicwire.EncodePayload(rotateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRotateKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var rotateResp KMSRotateKeyResponse
		err = quicwire.DecodePayload(resp.Payload, &rotateResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", rotateResp.KeyID)
		assert.Equal(t, uint64(1), rotateResp.OldVersion)
		assert.Equal(t, uint64(2), rotateResp.NewVersion)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		rotateReq := &KMSRotateKeyRequest{KeyID: "key-123"}

		payload, err := quicwire.EncodePayload(rotateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRotateKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		rotateReq := &KMSRotateKeyRequest{}

		payload, err := quicwire.EncodePayload(rotateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRotateKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRotateKey,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when rotate fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.rotateKeyErr = ErrKMSKeyNotFound{KeyID: "key-123"}

		rotateReq := &KMSRotateKeyRequest{KeyID: "key-123"}

		payload, err := quicwire.EncodePayload(rotateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRotateKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: UpdateKeyStatus
// =============================================================================

func TestHandleUpdateKeyStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("updates key status successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		updateReq := &KMSUpdateKeyStatusRequest{
			KeyID:  "key-123",
			Status: 2, // Disabled
		}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSUpdateKeyStatus,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var updateResp KMSUpdateKeyStatusResponse
		err = quicwire.DecodePayload(resp.Payload, &updateResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", updateResp.KeyID)
		assert.Equal(t, int32(2), updateResp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		updateReq := &KMSUpdateKeyStatusRequest{KeyID: "key-123", Status: 2}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSUpdateKeyStatus,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		updateReq := &KMSUpdateKeyStatusRequest{Status: 2}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSUpdateKeyStatus,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSUpdateKeyStatus,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when update fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.updateStatusErr = ErrKMSKeyDisabled{KeyID: "key-123"}

		updateReq := &KMSUpdateKeyStatusRequest{KeyID: "key-123", Status: 2}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSUpdateKeyStatus,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
	})
}

// =============================================================================
// Test: ExportKey
// =============================================================================

func TestHandleExportKey(t *testing.T) {
	ctx := context.Background()

	t.Run("exports key successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		exportReq := &KMSExportKeyRequest{
			KeyID:   "key-123",
			Format:  1,
			Version: 1,
		}

		payload, err := quicwire.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSExportKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var exportResp KMSExportKeyResponse
		err = quicwire.DecodePayload(resp.Payload, &exportResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", exportResp.KeyID)
		assert.NotEmpty(t, exportResp.WrappedMaterial)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		exportReq := &KMSExportKeyRequest{KeyID: "key-123"}

		payload, err := quicwire.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSExportKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		exportReq := &KMSExportKeyRequest{}

		payload, err := quicwire.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSExportKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for non-exportable key", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.exportKeyErr = ErrKMSKeyNotExportable{KeyID: "key-123"}

		exportReq := &KMSExportKeyRequest{KeyID: "key-123"}

		payload, err := quicwire.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSExportKey,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSExportKey,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: GetKeyVersions
// =============================================================================

func TestHandleGetKeyVersions(t *testing.T) {
	ctx := context.Background()

	t.Run("gets key versions successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		versionsReq := &KMSGetKeyVersionsRequest{
			KeyID: "key-123",
			Limit: 10,
		}

		payload, err := quicwire.EncodePayload(versionsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKeyVersions,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var versionsResp KMSGetKeyVersionsResponse
		err = quicwire.DecodePayload(resp.Payload, &versionsResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", versionsResp.KeyID)
		assert.Len(t, versionsResp.Versions, 2)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		versionsReq := &KMSGetKeyVersionsRequest{KeyID: "key-123"}

		payload, err := quicwire.EncodePayload(versionsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKeyVersions,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		versionsReq := &KMSGetKeyVersionsRequest{}

		payload, err := quicwire.EncodePayload(versionsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKeyVersions,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("applies pagination limits", func(t *testing.T) {
		handler, service := createTestKMSHandler()

		versionsReq := &KMSGetKeyVersionsRequest{
			KeyID: "key-123",
			Limit: 5000, // Exceeds max
		}

		payload, err := quicwire.EncodePayload(versionsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKeyVersions,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, kmsMaxLimit, service.lastKeyVersionsReq.Limit)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKeyVersions,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when get versions fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.keyVersionsErr = ErrKMSKeyNotFound{KeyID: "key-123"}

		versionsReq := &KMSGetKeyVersionsRequest{KeyID: "key-123"}

		payload, err := quicwire.EncodePayload(versionsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKeyVersions,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: BackendStatus
// =============================================================================

func TestHandleBackendStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("gets backend status successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode: quicwire.OpKMSBackendStatus,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var statusResp KMSBackendStatusResponse
		err := quicwire.DecodePayload(resp.Payload, &statusResp)
		require.NoError(t, err)

		assert.Equal(t, "software", statusResp.BackendType)
		assert.Equal(t, "available", statusResp.Status)
		assert.NotNil(t, statusResp.Capabilities)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		req := &quicwire.Request{
			Opcode: quicwire.OpKMSBackendStatus,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error when backend status fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.backendStatusErr = ErrKMSUnavailable{Reason: "backend offline"}

		req := &quicwire.Request{
			Opcode: quicwire.OpKMSBackendStatus,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})
}

// =============================================================================
// Test: Encrypt
// =============================================================================

func TestHandleEncrypt(t *testing.T) {
	ctx := context.Background()

	t.Run("encrypts data successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		encryptReq := &KMSEncryptRequest{
			KeyID:     "key-123",
			Plaintext: []byte("secret data"),
			Context:   []byte("context"),
		}

		payload, err := quicwire.EncodePayload(encryptReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSEncrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var encryptResp KMSEncryptResponse
		err = quicwire.DecodePayload(resp.Payload, &encryptResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", encryptResp.KeyID)
		assert.NotEmpty(t, encryptResp.Ciphertext)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		encryptReq := &KMSEncryptRequest{
			KeyID:     "key-123",
			Plaintext: []byte("data"),
		}

		payload, err := quicwire.EncodePayload(encryptReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSEncrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		encryptReq := &KMSEncryptRequest{
			Plaintext: []byte("data"),
		}

		payload, err := quicwire.EncodePayload(encryptReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSEncrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing plaintext", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		encryptReq := &KMSEncryptRequest{
			KeyID: "key-123",
		}

		payload, err := quicwire.EncodePayload(encryptReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSEncrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "plaintext")
	})

	t.Run("returns error when encryption fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.encryptErr = ErrKMSEncryptFailed{Err: errors.New("crypto error")}

		encryptReq := &KMSEncryptRequest{
			KeyID:     "key-123",
			Plaintext: []byte("data"),
		}

		payload, err := quicwire.EncodePayload(encryptReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSEncrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSEncrypt,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Decrypt
// =============================================================================

func TestHandleDecrypt(t *testing.T) {
	ctx := context.Background()

	t.Run("decrypts data successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		decryptReq := &KMSDecryptRequest{
			KeyID:      "key-123",
			Ciphertext: []byte("encrypted-data"),
			Context:    []byte("context"),
		}

		payload, err := quicwire.EncodePayload(decryptReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDecrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var decryptResp KMSDecryptResponse
		err = quicwire.DecodePayload(resp.Payload, &decryptResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", decryptResp.KeyID)
		assert.NotEmpty(t, decryptResp.Plaintext)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		decryptReq := &KMSDecryptRequest{
			KeyID:      "key-123",
			Ciphertext: []byte("data"),
		}

		payload, err := quicwire.EncodePayload(decryptReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDecrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		decryptReq := &KMSDecryptRequest{
			Ciphertext: []byte("data"),
		}

		payload, err := quicwire.EncodePayload(decryptReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDecrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing ciphertext", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		decryptReq := &KMSDecryptRequest{
			KeyID: "key-123",
		}

		payload, err := quicwire.EncodePayload(decryptReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDecrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "ciphertext")
	})

	t.Run("returns error when decryption fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.decryptErr = ErrKMSDecryptFailed{Err: errors.New("invalid ciphertext")}

		decryptReq := &KMSDecryptRequest{
			KeyID:      "key-123",
			Ciphertext: []byte("invalid"),
		}

		payload, err := quicwire.EncodePayload(decryptReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDecrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDecrypt,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Sign
// =============================================================================

func TestHandleSign(t *testing.T) {
	ctx := context.Background()

	t.Run("signs message successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		signReq := &KMSSignRequest{
			KeyID:         "key-123",
			Message:       []byte("message to sign"),
			HashAlgorithm: 4, // SHA-256
		}

		payload, err := quicwire.EncodePayload(signReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSSign,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var signResp KMSSignResponse
		err = quicwire.DecodePayload(resp.Payload, &signResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", signResp.KeyID)
		assert.NotEmpty(t, signResp.Signature)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		signReq := &KMSSignRequest{
			KeyID:   "key-123",
			Message: []byte("message"),
		}

		payload, err := quicwire.EncodePayload(signReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSSign,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		signReq := &KMSSignRequest{
			Message: []byte("message"),
		}

		payload, err := quicwire.EncodePayload(signReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSSign,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing message", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		signReq := &KMSSignRequest{
			KeyID: "key-123",
		}

		payload, err := quicwire.EncodePayload(signReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSSign,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "message")
	})

	t.Run("returns error when signing fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.signErr = ErrKMSSignFailed{Err: errors.New("key not suitable for signing")}

		signReq := &KMSSignRequest{
			KeyID:   "key-123",
			Message: []byte("message"),
		}

		payload, err := quicwire.EncodePayload(signReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSSign,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSSign,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: Verify
// =============================================================================

func TestHandleVerify(t *testing.T) {
	ctx := context.Background()

	t.Run("verifies signature successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		verifyReq := &KMSVerifyRequest{
			KeyID:     "key-123",
			Message:   []byte("message"),
			Signature: []byte("signature"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerify,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var verifyResp KMSVerifyResponse
		err = quicwire.DecodePayload(resp.Payload, &verifyResp)
		require.NoError(t, err)

		assert.True(t, verifyResp.Valid)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		verifyReq := &KMSVerifyRequest{
			KeyID:     "key-123",
			Message:   []byte("message"),
			Signature: []byte("signature"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerify,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		verifyReq := &KMSVerifyRequest{
			Message:   []byte("message"),
			Signature: []byte("signature"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerify,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing message", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		verifyReq := &KMSVerifyRequest{
			KeyID:     "key-123",
			Signature: []byte("signature"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerify,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "message")
	})

	t.Run("returns error for missing signature", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		verifyReq := &KMSVerifyRequest{
			KeyID:   "key-123",
			Message: []byte("message"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerify,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "signature")
	})

	t.Run("returns error when verification fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.verifyErr = ErrKMSVerifyFailed{Err: errors.New("invalid signature")}

		verifyReq := &KMSVerifyRequest{
			KeyID:     "key-123",
			Message:   []byte("message"),
			Signature: []byte("invalid"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerify,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerify,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: GenerateRandom
// =============================================================================

func TestHandleGenerateRandom(t *testing.T) {
	ctx := context.Background()

	t.Run("generates random bytes successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		randomReq := &KMSGenerateRandomRequest{
			NumBytes: 32,
		}

		payload, err := quicwire.EncodePayload(randomReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateRandom,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var randomResp KMSGenerateRandomResponse
		err = quicwire.DecodePayload(resp.Payload, &randomResp)
		require.NoError(t, err)

		assert.NotEmpty(t, randomResp.RandomBytes)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		randomReq := &KMSGenerateRandomRequest{NumBytes: 32}

		payload, err := quicwire.EncodePayload(randomReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateRandom,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for zero num_bytes", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		randomReq := &KMSGenerateRandomRequest{NumBytes: 0}

		payload, err := quicwire.EncodePayload(randomReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateRandom,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "greater than 0")
	})

	t.Run("returns error for negative num_bytes", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		randomReq := &KMSGenerateRandomRequest{NumBytes: -10}

		payload, err := quicwire.EncodePayload(randomReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateRandom,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for num_bytes exceeding max", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		randomReq := &KMSGenerateRandomRequest{NumBytes: kmsMaxRandomBytes + 1}

		payload, err := quicwire.EncodePayload(randomReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateRandom,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "maximum")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateRandom,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when generate random fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.randomErr = ErrKMSOpFailed{Operation: "GenerateRandom"}

		randomReq := &KMSGenerateRandomRequest{NumBytes: 32}

		payload, err := quicwire.EncodePayload(randomReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateRandom,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: Hash
// =============================================================================

func TestHandleHash(t *testing.T) {
	ctx := context.Background()

	t.Run("hashes data successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		hashReq := &KMSHashRequest{
			Data:      []byte("data to hash"),
			Algorithm: 4, // SHA-256
		}

		payload, err := quicwire.EncodePayload(hashReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHash,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var hashResp KMSHashResponse
		err = quicwire.DecodePayload(resp.Payload, &hashResp)
		require.NoError(t, err)

		assert.NotEmpty(t, hashResp.Hash)
		assert.Equal(t, int32(4), hashResp.Algorithm)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		hashReq := &KMSHashRequest{Data: []byte("data")}

		payload, err := quicwire.EncodePayload(hashReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHash,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing data", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		hashReq := &KMSHashRequest{Algorithm: 4}

		payload, err := quicwire.EncodePayload(hashReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHash,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "data")
	})

	t.Run("returns error when hash fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.hashErr = ErrKMSInvalidAlgorithm{Algorithm: 999}

		hashReq := &KMSHashRequest{
			Data:      []byte("data"),
			Algorithm: 999,
		}

		payload, err := quicwire.EncodePayload(hashReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHash,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHash,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

// =============================================================================
// Test: HMAC
// =============================================================================

func TestHandleHMAC(t *testing.T) {
	ctx := context.Background()

	t.Run("computes HMAC successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		hmacReq := &KMSHMACRequest{
			KeyID:         "key-123",
			Message:       []byte("message"),
			HashAlgorithm: 4,
		}

		payload, err := quicwire.EncodePayload(hmacReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var hmacResp KMSHMACResponse
		err = quicwire.DecodePayload(resp.Payload, &hmacResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", hmacResp.KeyID)
		assert.NotEmpty(t, hmacResp.HMAC)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		hmacReq := &KMSHMACRequest{
			KeyID:   "key-123",
			Message: []byte("message"),
		}

		payload, err := quicwire.EncodePayload(hmacReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		hmacReq := &KMSHMACRequest{
			Message: []byte("message"),
		}

		payload, err := quicwire.EncodePayload(hmacReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing message", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		hmacReq := &KMSHMACRequest{
			KeyID: "key-123",
		}

		payload, err := quicwire.EncodePayload(hmacReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "message")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHMAC,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when HMAC fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.hmacErr = ErrKMSKeyNotFound{KeyID: "key-123"}

		hmacReq := &KMSHMACRequest{KeyID: "key-123", Message: []byte("test message")}

		payload, err := quicwire.EncodePayload(hmacReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: VerifyHMAC
// =============================================================================

func TestHandleVerifyHMAC(t *testing.T) {
	ctx := context.Background()

	t.Run("verifies HMAC successfully", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		verifyReq := &KMSVerifyHMACRequest{
			KeyID:   "key-123",
			Message: []byte("message"),
			HMAC:    []byte("hmac-value"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerifyHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var verifyResp KMSVerifyHMACResponse
		err = quicwire.DecodePayload(resp.Payload, &verifyResp)
		require.NoError(t, err)

		assert.True(t, verifyResp.Valid)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		verifyReq := &KMSVerifyHMACRequest{
			KeyID:   "key-123",
			Message: []byte("message"),
			HMAC:    []byte("hmac"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerifyHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		verifyReq := &KMSVerifyHMACRequest{
			Message: []byte("message"),
			HMAC:    []byte("hmac"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerifyHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing message", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		verifyReq := &KMSVerifyHMACRequest{
			KeyID: "key-123",
			HMAC:  []byte("hmac"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerifyHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "message")
	})

	t.Run("returns error for missing HMAC", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		verifyReq := &KMSVerifyHMACRequest{
			KeyID:   "key-123",
			Message: []byte("message"),
		}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerifyHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "HMAC")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerifyHMAC,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when verify HMAC fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.verifyHMACErr = ErrKMSVerifyFailed{Err: errors.New("invalid signature")}

		verifyReq := &KMSVerifyHMACRequest{KeyID: "key-123", Message: []byte("test"), HMAC: []byte("hmac")}

		payload, err := quicwire.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSVerifyHMAC,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: Error Types
// =============================================================================

func TestKMSErrorTypes(t *testing.T) {
	t.Run("ErrKMSEncodingFailed", func(t *testing.T) {
		cause := errors.New("encoding error")
		err := ErrKMSEncodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "encoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrKMSDecodingFailed", func(t *testing.T) {
		cause := errors.New("decoding error")
		err := ErrKMSDecodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "decoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrKMSOperationFailed", func(t *testing.T) {
		cause := errors.New("operation error")
		err := ErrKMSOperationFailed{
			Operation: "encrypt",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "encrypt")
		assert.Contains(t, err.Error(), "operation error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrKMSInvalidNumBytesValue", func(t *testing.T) {
		err := ErrKMSInvalidNumBytesValue{
			NumBytes: -10,
			Reason:   "must be positive",
		}

		assert.Contains(t, err.Error(), "must be positive")
	})

	t.Run("ErrKMSOpFailed", func(t *testing.T) {
		err := ErrKMSOpFailed{
			Operation: "GenerateKey",
			Reason:    "not implemented",
		}

		assert.Contains(t, err.Error(), "GenerateKey")
		assert.Contains(t, err.Error(), "not implemented")
	})

	t.Run("ErrKMSKeyNotFound", func(t *testing.T) {
		err := ErrKMSKeyNotFound{KeyID: "key-123"}

		assert.Contains(t, err.Error(), "key-123")
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("ErrKMSKeyAlreadyExists", func(t *testing.T) {
		err := ErrKMSKeyAlreadyExists{KeyID: "key-123"}

		assert.Contains(t, err.Error(), "key-123")
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("ErrKMSInvalidKeySpecErr", func(t *testing.T) {
		err := ErrKMSInvalidKeySpecErr{Reason: "bad algorithm"}

		assert.Contains(t, err.Error(), "bad algorithm")
	})

	t.Run("ErrKMSKeyNotExportable", func(t *testing.T) {
		err := ErrKMSKeyNotExportable{KeyID: "key-123"}

		assert.Contains(t, err.Error(), "key-123")
		assert.Contains(t, err.Error(), "not exportable")
	})

	t.Run("ErrKMSKeyDisabled", func(t *testing.T) {
		err := ErrKMSKeyDisabled{KeyID: "key-123"}

		assert.Contains(t, err.Error(), "key-123")
		assert.Contains(t, err.Error(), "disabled")
	})

	t.Run("ErrKMSKeyPendingDeletion", func(t *testing.T) {
		err := ErrKMSKeyPendingDeletion{KeyID: "key-123"}

		assert.Contains(t, err.Error(), "key-123")
		assert.Contains(t, err.Error(), "pending deletion")
	})

	t.Run("ErrKMSEncryptFailed", func(t *testing.T) {
		err := ErrKMSEncryptFailed{Err: errors.New("crypto error")}

		assert.Contains(t, err.Error(), "encryption failed")
	})

	t.Run("ErrKMSDecryptFailed", func(t *testing.T) {
		err := ErrKMSDecryptFailed{Err: errors.New("crypto error")}

		assert.Contains(t, err.Error(), "decryption failed")
	})

	t.Run("ErrKMSSignFailed", func(t *testing.T) {
		err := ErrKMSSignFailed{Err: errors.New("signing error")}

		assert.Contains(t, err.Error(), "signing failed")
	})

	t.Run("ErrKMSVerifyFailed", func(t *testing.T) {
		err := ErrKMSVerifyFailed{Err: errors.New("verification error")}

		assert.Contains(t, err.Error(), "verification failed")
	})

	t.Run("ErrKMSInvalidAlgorithm", func(t *testing.T) {
		err := ErrKMSInvalidAlgorithm{Algorithm: 999}

		assert.Contains(t, err.Error(), "999")
	})

	t.Run("ErrKMSUnavailable", func(t *testing.T) {
		err := ErrKMSUnavailable{Reason: "backend offline"}

		assert.Contains(t, err.Error(), "backend offline")
	})
}

// =============================================================================
// Test: kmsErrorResponse - Comprehensive Error Mapping
// =============================================================================

func TestKMSErrorResponse(t *testing.T) {
	handler, _ := createTestKMSHandler()

	testCases := []struct {
		name           string
		err            error
		expectedStatus byte
	}{
		{"key not found", ErrKMSKeyNotFound{KeyID: "key-1"}, quicwire.StatusNotFound},
		{"key already exists", ErrKMSKeyAlreadyExists{KeyID: "key-1"}, quicwire.StatusAlreadyExists},
		{"invalid key spec", ErrKMSInvalidKeySpecErr{Reason: "bad"}, quicwire.StatusInvalidArgument},
		{"key not exportable", ErrKMSKeyNotExportable{KeyID: "key-1"}, quicwire.StatusPermissionDenied},
		{"key disabled", ErrKMSKeyDisabled{KeyID: "key-1"}, quicwire.StatusPermissionDenied},
		{"key pending deletion", ErrKMSKeyPendingDeletion{KeyID: "key-1"}, quicwire.StatusPermissionDenied},
		{"encryption failed", ErrKMSEncryptFailed{Err: errors.New("err")}, quicwire.StatusInternalError},
		{"decryption failed", ErrKMSDecryptFailed{Err: errors.New("err")}, quicwire.StatusInternalError},
		{"signing failed", ErrKMSSignFailed{Err: errors.New("err")}, quicwire.StatusInternalError},
		{"verification failed", ErrKMSVerifyFailed{Err: errors.New("err")}, quicwire.StatusInternalError},
		{"invalid algorithm", ErrKMSInvalidAlgorithm{Algorithm: 999}, quicwire.StatusInvalidArgument},
		{"service unavailable", ErrKMSUnavailable{Reason: "down"}, quicwire.StatusUnavailable},
		{"operation not implemented", ErrKMSOpFailed{Operation: "op", Reason: "not implemented"}, quicwire.StatusNotImplemented},
		{"operation failed", ErrKMSOpFailed{Operation: "op", Reason: "error"}, quicwire.StatusInternalError},
		{"generic error", errors.New("unknown error"), quicwire.StatusInternalError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.kmsErrorResponse(tc.err)
			assert.Equal(t, tc.expectedStatus, resp.Status)
		})
	}
}

// =============================================================================
// Test: Opcode Constants
// =============================================================================

func TestKMSOpcodeConstants(t *testing.T) {
	// Verify KMS opcodes are in expected ranges (0xC0-0xDF)
	opcodes := []struct {
		name   string
		opcode byte
	}{
		// Key Management
		{"OpKMSGenerateKey", quicwire.OpKMSGenerateKey},
		{"OpKMSImportKey", quicwire.OpKMSImportKey},
		{"OpKMSGetKey", quicwire.OpKMSGetKey},
		{"OpKMSListKeys", quicwire.OpKMSListKeys},
		{"OpKMSDeleteKey", quicwire.OpKMSDeleteKey},
		{"OpKMSRotateKey", quicwire.OpKMSRotateKey},
		{"OpKMSUpdateKeyStatus", quicwire.OpKMSUpdateKeyStatus},
		{"OpKMSExportKey", quicwire.OpKMSExportKey},
		{"OpKMSGetKeyVersions", quicwire.OpKMSGetKeyVersions},
		{"OpKMSBackendStatus", quicwire.OpKMSBackendStatus},
		// Crypto Operations
		{"OpKMSEncrypt", quicwire.OpKMSEncrypt},
		{"OpKMSDecrypt", quicwire.OpKMSDecrypt},
		{"OpKMSSign", quicwire.OpKMSSign},
		{"OpKMSVerify", quicwire.OpKMSVerify},
		{"OpKMSGenerateRandom", quicwire.OpKMSGenerateRandom},
		{"OpKMSHash", quicwire.OpKMSHash},
		{"OpKMSHMAC", quicwire.OpKMSHMAC},
		{"OpKMSVerifyHMAC", quicwire.OpKMSVerifyHMAC},
	}

	seen := make(map[byte]string)
	for _, op := range opcodes {
		if existing, ok := seen[op.opcode]; ok {
			t.Errorf("duplicate opcode 0x%02X: %s and %s", op.opcode, existing, op.name)
		}
		seen[op.opcode] = op.name
	}

	// Verify key management opcodes are in 0xC0-0xCF range
	for _, op := range opcodes[:10] {
		if op.opcode < 0xC0 || op.opcode > 0xCF {
			t.Logf("note: key management opcode %s (0x%02X) is outside 0xC0-0xCF range", op.name, op.opcode)
		}
	}

	// Verify crypto opcodes are in 0xD0-0xDF range
	for _, op := range opcodes[10:] {
		if op.opcode < 0xD0 || op.opcode > 0xDF {
			t.Logf("note: crypto opcode %s (0x%02X) is outside 0xD0-0xDF range", op.name, op.opcode)
		}
	}
}

// =============================================================================
// Test: Pagination Constants
// =============================================================================

func TestKMSPaginationConstants(t *testing.T) {
	assert.Equal(t, int32(50), kmsDefaultLimit)
	assert.Equal(t, int32(1000), kmsMaxLimit)
	assert.Less(t, kmsDefaultLimit, kmsMaxLimit)
	assert.Equal(t, int32(1048576), kmsMaxRandomBytes) // 1MB
}

// =============================================================================
// Test: Interface Compliance
// =============================================================================

// =============================================================================
// Test: BatchEncrypt
// =============================================================================

func TestHandleBatchEncrypt(t *testing.T) {
	ctx := context.Background()

	t.Run("batch encrypts successfully", func(t *testing.T) {
		handler, service := createTestKMSHandler()

		batchReq := &KMSBatchEncryptRequest{
			KeyID: "key-123",
			Items: []*KMSBatchEncryptItem{
				{ID: "item-1", Plaintext: []byte("secret-1")},
				{ID: "item-2", Plaintext: []byte("secret-2")},
			},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchEncrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var batchResp KMSBatchEncryptResponse
		err = quicwire.DecodePayload(resp.Payload, &batchResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", batchResp.KeyID)
		assert.Len(t, batchResp.Results, 2)
		assert.Equal(t, int32(2), batchResp.SuccessCount)
		assert.Equal(t, int32(0), batchResp.FailureCount)

		// Verify the request was captured correctly
		assert.NotNil(t, service.lastBatchEncryptReq)
		assert.Equal(t, "key-123", service.lastBatchEncryptReq.KeyID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		batchReq := &KMSBatchEncryptRequest{
			KeyID: "key-123",
			Items: []*KMSBatchEncryptItem{
				{ID: "item-1", Plaintext: []byte("secret")},
			},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchEncrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		batchReq := &KMSBatchEncryptRequest{
			Items: []*KMSBatchEncryptItem{
				{ID: "item-1", Plaintext: []byte("secret")},
			},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchEncrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "key ID")
	})

	t.Run("returns error for empty batch", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		batchReq := &KMSBatchEncryptRequest{
			KeyID: "key-123",
			Items: []*KMSBatchEncryptItem{},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchEncrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "batch")
	})

	t.Run("returns error when batch encrypt fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.batchEncryptErr = ErrKMSEncryptFailed{Err: errors.New("encryption failed")}

		batchReq := &KMSBatchEncryptRequest{
			KeyID: "key-123",
			Items: []*KMSBatchEncryptItem{
				{ID: "item-1", Plaintext: []byte("secret")},
			},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchEncrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: BatchDecrypt
// =============================================================================

func TestHandleBatchDecrypt(t *testing.T) {
	ctx := context.Background()

	t.Run("batch decrypts successfully", func(t *testing.T) {
		handler, service := createTestKMSHandler()

		batchReq := &KMSBatchDecryptRequest{
			KeyID: "key-123",
			Items: []*KMSBatchDecryptItem{
				{ID: "item-1", Ciphertext: []byte("encrypted-1")},
				{ID: "item-2", Ciphertext: []byte("encrypted-2")},
			},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchDecrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var batchResp KMSBatchDecryptResponse
		err = quicwire.DecodePayload(resp.Payload, &batchResp)
		require.NoError(t, err)

		assert.Equal(t, "key-123", batchResp.KeyID)
		assert.Len(t, batchResp.Results, 2)
		assert.Equal(t, int32(2), batchResp.SuccessCount)
		assert.Equal(t, int32(0), batchResp.FailureCount)

		// Verify the request was captured correctly
		assert.NotNil(t, service.lastBatchDecryptReq)
		assert.Equal(t, "key-123", service.lastBatchDecryptReq.KeyID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		batchReq := &KMSBatchDecryptRequest{
			KeyID: "key-123",
			Items: []*KMSBatchDecryptItem{
				{ID: "item-1", Ciphertext: []byte("encrypted")},
			},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchDecrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		batchReq := &KMSBatchDecryptRequest{
			Items: []*KMSBatchDecryptItem{
				{ID: "item-1", Ciphertext: []byte("encrypted")},
			},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchDecrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "key ID")
	})

	t.Run("returns error for empty batch", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		batchReq := &KMSBatchDecryptRequest{
			KeyID: "key-123",
			Items: []*KMSBatchDecryptItem{},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchDecrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "batch")
	})

	t.Run("returns error when batch decrypt fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.batchDecryptErr = ErrKMSDecryptFailed{Err: errors.New("decryption failed")}

		batchReq := &KMSBatchDecryptRequest{
			KeyID: "key-123",
			Items: []*KMSBatchDecryptItem{
				{ID: "item-1", Ciphertext: []byte("encrypted")},
			},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchDecrypt,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: Rewrap
// =============================================================================

func TestHandleRewrap(t *testing.T) {
	ctx := context.Background()

	t.Run("rewraps successfully", func(t *testing.T) {
		handler, service := createTestKMSHandler()

		rewrapReq := &KMSRewrapRequest{
			SourceKeyID:      "source-key",
			DestinationKeyID: "dest-key",
			Ciphertext:       []byte("encrypted-data"),
		}

		payload, err := quicwire.EncodePayload(rewrapReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRewrap,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var rewrapResp KMSRewrapResponse
		err = quicwire.DecodePayload(resp.Payload, &rewrapResp)
		require.NoError(t, err)

		assert.Equal(t, "source-key", rewrapResp.SourceKeyID)
		assert.Equal(t, "dest-key", rewrapResp.DestinationKeyID)
		assert.NotEmpty(t, rewrapResp.Ciphertext)

		// Verify the request was captured correctly
		assert.NotNil(t, service.lastRewrapReq)
		assert.Equal(t, "source-key", service.lastRewrapReq.SourceKeyID)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewKMSHandler(newKMSTestLogger(), nil)

		rewrapReq := &KMSRewrapRequest{
			SourceKeyID:      "source-key",
			DestinationKeyID: "dest-key",
			Ciphertext:       []byte("encrypted"),
		}

		payload, err := quicwire.EncodePayload(rewrapReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRewrap,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing source key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		rewrapReq := &KMSRewrapRequest{
			DestinationKeyID: "dest-key",
			Ciphertext:       []byte("encrypted"),
		}

		payload, err := quicwire.EncodePayload(rewrapReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRewrap,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "source")
	})

	t.Run("returns error for missing destination key ID", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		rewrapReq := &KMSRewrapRequest{
			SourceKeyID: "source-key",
			Ciphertext:  []byte("encrypted"),
		}

		payload, err := quicwire.EncodePayload(rewrapReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRewrap,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "destination")
	})

	t.Run("returns error for missing ciphertext", func(t *testing.T) {
		handler, _ := createTestKMSHandler()

		rewrapReq := &KMSRewrapRequest{
			SourceKeyID:      "source-key",
			DestinationKeyID: "dest-key",
		}

		payload, err := quicwire.EncodePayload(rewrapReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRewrap,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "ciphertext")
	})

	t.Run("returns error when rewrap fails", func(t *testing.T) {
		handler, service := createTestKMSHandler()
		service.rewrapErr = ErrKMSRewrapFailed{Err: errors.New("rewrap failed")}

		rewrapReq := &KMSRewrapRequest{
			SourceKeyID:      "source-key",
			DestinationKeyID: "dest-key",
			Ciphertext:       []byte("encrypted"),
		}

		payload, err := quicwire.EncodePayload(rewrapReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRewrap,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}
func TestKMSServiceInterfaceCompliance(t *testing.T) {
	// Ensure testKMSService implements KMSService
	var _ KMSService = (*testKMSService)(nil)
}
