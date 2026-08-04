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

package daemon

import (
	"context"
	"errors"
	"testing"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// KMS Handler Coverage Tests - Error Paths and Edge Cases
// =============================================================================

// TestHandleKMSImportKey_DecodingError tests decoding failure path
func TestHandleKMSImportKey_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSImportKey,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSImportKey_ServiceError tests service failure path
func TestHandleKMSImportKey_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("import failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	importReq := KMSImportKeyRequest{
		KeyMaterial: []byte("raw-key-material-32-bytes-long!!"),
		Name:        "imported-key",
	}

	payload, err := quic.EncodePayload(importReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSImportKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSImportKey_WithKeySpec tests import with key spec
func TestHandleKMSImportKey_WithKeySpec(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	importReq := KMSImportKeyRequest{
		KeyMaterial:   []byte("raw-key-material-32-bytes-long!!"),
		Name:          "imported-key-with-spec",
		Description:   "Imported with full key spec",
		WrappingKeyId: "wrapping-key-123",
		KeySpec: &KMSKeySpecRequest{
			Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
			KeySize:   256,
			Usage: []int32{
				int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT),
				int32(platformv1.KeyUsage_KEY_USAGE_DECRYPT),
			},
			Exportable:         true,
			DeletionProtection: true,
		},
		Tags: map[string]string{"env": "test"},
	}

	payload, err := quic.EncodePayload(importReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSImportKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusOK, resp.Status)
}

// TestHandleKMSExportKey_DecodingError tests decoding failure path
func TestHandleKMSExportKey_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSExportKey,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSExportKey_ServiceError tests service failure path
func TestHandleKMSExportKey_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("export failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	exportReq := KMSExportKeyRequest{
		KeyId:             "export-key",
		WrappingKeyId:     "wrapping-key",
		WrappingAlgorithm: int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_KWP),
		Format:            int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_RAW),
		Version:           1,
	}

	payload, err := quic.EncodePayload(exportReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSExportKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSDeleteKey_DecodingError tests decoding failure path
func TestHandleKMSDeleteKey_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSDeleteKey,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSDeleteKey_ServiceError tests service failure path
func TestHandleKMSDeleteKey_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("delete failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	deleteReq := KMSDeleteKeyRequest{
		KeyId:             "delete-me",
		PendingWindowDays: 7,
		Force:             true,
	}

	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSDeleteKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSRotateKey_DecodingError tests decoding failure path
func TestHandleKMSRotateKey_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSRotateKey,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSRotateKey_ServiceError tests service failure path
func TestHandleKMSRotateKey_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("rotate failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	rotateReq := KMSRotateKeyRequest{
		KeyId:            "rotate-me",
		RetainOldVersion: true,
	}

	payload, err := quic.EncodePayload(rotateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSRotateKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSUpdateKeyStatus_DecodingError tests decoding failure path
func TestHandleKMSUpdateKeyStatus_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSUpdateKeyStatus,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSUpdateKeyStatus_ServiceError tests service failure path
func TestHandleKMSUpdateKeyStatus_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("update status failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	updateReq := KMSUpdateKeyStatusRequest{
		KeyId:   "status-key",
		Version: 1,
		Status:  int32(platformv1.KeyStatus_KEY_STATUS_DISABLED),
	}

	payload, err := quic.EncodePayload(updateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSUpdateKeyStatus,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSGenerateRandom_DecodingError tests decoding failure path
func TestHandleKMSGenerateRandom_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateRandom,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSGenerateRandom_ServiceError tests service failure path
func TestHandleKMSGenerateRandom_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("random generation failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	randomReq := KMSGenerateRandomRequest{
		NumBytes: 32,
	}

	payload, err := quic.EncodePayload(randomReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateRandom,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSGenerateRandom_NegativeNumBytes tests negative num_bytes validation
func TestHandleKMSGenerateRandom_NegativeNumBytes(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	randomReq := KMSGenerateRandomRequest{
		NumBytes: -5,
	}

	payload, err := quic.EncodePayload(randomReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateRandom,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

// TestHandleKMSHash_DecodingError tests decoding failure path
func TestHandleKMSHash_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSHash,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSHash_ServiceError tests service failure path
func TestHandleKMSHash_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("hash failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	hashReq := KMSHashRequest{
		Data:      []byte("data to hash"),
		Algorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256),
	}

	payload, err := quic.EncodePayload(hashReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSHash,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSHash_DifferentAlgorithms tests various hash algorithms
func TestHandleKMSHash_DifferentAlgorithms(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	supported := []platformv1.HashAlgorithm{
		platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
		platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
		platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
	}

	for _, alg := range supported {
		t.Run("supported_"+alg.String(), func(t *testing.T) {
			hashReq := KMSHashRequest{
				Data:      []byte("data to hash"),
				Algorithm: int32(alg),
			}

			payload, err := quic.EncodePayload(hashReq)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpKMSHash,
				Payload: payload,
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quic.StatusOK, resp.Status)
		})
	}

	unsupported := []platformv1.HashAlgorithm{
		platformv1.HashAlgorithm_HASH_ALGORITHM_SHA1,
		platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_256,
	}

	for _, alg := range unsupported {
		t.Run("unsupported_"+alg.String(), func(t *testing.T) {
			hashReq := KMSHashRequest{
				Data:      []byte("data to hash"),
				Algorithm: int32(alg),
			}

			payload, err := quic.EncodePayload(hashReq)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpKMSHash,
				Payload: payload,
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
		})
	}
}

// TestHandleKMSGenerateDataKey_DecodingError tests decoding failure path
func TestHandleKMSGenerateDataKey_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockCrypto := newMockCryptoService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateDataKey,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSGenerateDataKey_ServiceError tests service failure path
func TestHandleKMSGenerateDataKey_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockCrypto := newMockCryptoService()
	mockCrypto.shouldErr = true
	mockCrypto.errToReturn = errors.New("data key generation failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))
	ctx := context.Background()

	dataKeyReq := KMSGenerateDataKeyQUICRequest{
		KeyId:     "kek-key",
		Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
	}

	payload, err := quic.EncodePayload(dataKeyReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateDataKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSGenerateDataKey_InvalidAlgorithm tests invalid algorithm error path
func TestHandleKMSGenerateDataKey_InvalidAlgorithm(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockCrypto := newMockCryptoService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))
	ctx := context.Background()

	dataKeyReq := KMSGenerateDataKeyQUICRequest{
		KeyId:     "kek-key",
		Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048),
	}

	payload, err := quic.EncodePayload(dataKeyReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateDataKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

// TestHandleKMSGenerateDataKey_DefaultAlgorithm tests default algorithm when not specified
func TestHandleKMSGenerateDataKey_DefaultAlgorithm(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockCrypto := newMockCryptoService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))
	ctx := context.Background()

	dataKeyReq := KMSGenerateDataKeyQUICRequest{
		KeyId:     "kek-key",
		Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED), // Defaults to AES-256-GCM
		Context:   []byte("encryption-context"),
	}

	payload, err := quic.EncodePayload(dataKeyReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateDataKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusOK, resp.Status)
}

// TestHandleKMSGenerateDataKey_AllAlgorithms tests all supported algorithms
func TestHandleKMSGenerateDataKey_AllAlgorithms(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockCrypto := newMockCryptoService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))
	ctx := context.Background()

	algorithms := []platformv1.KMSKeyAlgorithm{
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305,
	}

	for _, alg := range algorithms {
		t.Run("algorithm_"+alg.String(), func(t *testing.T) {
			dataKeyReq := KMSGenerateDataKeyQUICRequest{
				KeyId:     "kek-key",
				Algorithm: int32(alg),
			}

			payload, err := quic.EncodePayload(dataKeyReq)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpKMSGenerateDataKey,
				Payload: payload,
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quic.StatusOK, resp.Status)
		})
	}
}

// TestHandleKMSGenerateWrappedDataKey_DecodingError tests decoding failure path
func TestHandleKMSGenerateWrappedDataKey_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockCrypto := newMockCryptoService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateWrappedDataKey,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSGenerateWrappedDataKey_ServiceError tests service failure path
func TestHandleKMSGenerateWrappedDataKey_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockCrypto := newMockCryptoService()
	mockCrypto.shouldErr = true
	mockCrypto.errToReturn = errors.New("wrapped data key generation failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))
	ctx := context.Background()

	wrappedReq := KMSGenerateWrappedDataKeyQUICRequest{
		WrappingKeyId: "kek-key",
		KeyAlgorithm:  int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
	}

	payload, err := quic.EncodePayload(wrappedReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateWrappedDataKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSGenerateWrappedDataKey_InvalidAlgorithm tests invalid algorithm error path
func TestHandleKMSGenerateWrappedDataKey_InvalidAlgorithm(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockCrypto := newMockCryptoService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))
	ctx := context.Background()

	wrappedReq := KMSGenerateWrappedDataKeyQUICRequest{
		WrappingKeyId: "kek-key",
		KeyAlgorithm:  int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048),
	}

	payload, err := quic.EncodePayload(wrappedReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateWrappedDataKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

// TestHandleKMSGenerateWrappedDataKey_DefaultAlgorithm tests default algorithm when not specified
func TestHandleKMSGenerateWrappedDataKey_DefaultAlgorithm(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockCrypto := newMockCryptoService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))
	ctx := context.Background()

	wrappedReq := KMSGenerateWrappedDataKeyQUICRequest{
		WrappingKeyId: "kek-key",
		KeyAlgorithm:  int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED), // Defaults to AES-256-GCM
		Context:       []byte("encryption-context"),
	}

	payload, err := quic.EncodePayload(wrappedReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateWrappedDataKey,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusOK, resp.Status)
}

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

// TestHandleKMSGenerateKey_DecodingError tests decoding failure path
func TestHandleKMSGenerateKey_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSGenerateKey,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSGetKey_DecodingError tests decoding failure path
func TestHandleKMSGetKey_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSGetKey,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSListKeys_DecodingError tests decoding failure path when payload is present
func TestHandleKMSListKeys_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSListKeys,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSListKeys_ServiceError tests service failure path
func TestHandleKMSListKeys_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("list failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSListKeys,
		Payload: nil,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSListKeys_LimitClamping tests limit clamping behavior
func TestHandleKMSListKeys_LimitClamping(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	t.Run("limit_exceeds_max", func(t *testing.T) {
		listReq := KMSListKeysRequest{
			Limit: 5000, // Exceeds kmsMaxLimit of 1000
		}

		payload, err := quic.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSListKeys,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)
	})

	t.Run("negative_limit_uses_default", func(t *testing.T) {
		listReq := KMSListKeysRequest{
			Limit: -10,
		}

		payload, err := quic.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSListKeys,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)
	})
}

// TestHandleKMSGetKeyVersions_DecodingError tests decoding failure path
func TestHandleKMSGetKeyVersions_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSGetKeyVersions,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSGetKeyVersions_ServiceError tests service failure path
func TestHandleKMSGetKeyVersions_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("list versions failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	versionsReq := KMSGetKeyVersionsRequest{
		KeyId: "versioned-key",
		Limit: 10,
	}

	payload, err := quic.EncodePayload(versionsReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSGetKeyVersions,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSGetKeyVersions_LimitClamping tests limit clamping behavior
func TestHandleKMSGetKeyVersions_LimitClamping(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	t.Run("limit_exceeds_max", func(t *testing.T) {
		versionsReq := KMSGetKeyVersionsRequest{
			KeyId: "versioned-key",
			Limit: 5000, // Exceeds kmsMaxLimit of 1000
		}

		payload, err := quic.EncodePayload(versionsReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGetKeyVersions,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)
	})

	t.Run("zero_limit_uses_default", func(t *testing.T) {
		versionsReq := KMSGetKeyVersionsRequest{
			KeyId: "versioned-key",
			Limit: 0,
		}

		payload, err := quic.EncodePayload(versionsReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGetKeyVersions,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)
	})
}

// TestHandleKMSEncrypt_DecodingError tests decoding failure path
func TestHandleKMSEncrypt_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSEncrypt,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSEncrypt_ServiceError tests service failure path
func TestHandleKMSEncrypt_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("encrypt failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	encryptReq := KMSEncryptRequest{
		KeyId:     "encrypt-key",
		Plaintext: []byte("secret data"),
	}

	payload, err := quic.EncodePayload(encryptReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSEncrypt,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSDecrypt_DecodingError tests decoding failure path
func TestHandleKMSDecrypt_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSDecrypt,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSDecrypt_ServiceError tests service failure path
func TestHandleKMSDecrypt_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("decrypt failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	decryptReq := KMSDecryptRequest{
		KeyId:      "decrypt-key",
		Ciphertext: []byte("encrypted-data"),
	}

	payload, err := quic.EncodePayload(decryptReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSDecrypt,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSSign_DecodingError tests decoding failure path
func TestHandleKMSSign_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSSign,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSSign_ServiceError tests service failure path
func TestHandleKMSSign_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("sign failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	signReq := KMSSignRequest{
		KeyId:   "sign-key",
		Message: []byte("message to sign"),
	}

	payload, err := quic.EncodePayload(signReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSSign,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSVerify_DecodingError tests decoding failure path
func TestHandleKMSVerify_DecodingError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSVerify,
		Payload: []byte{0xFF, 0xFE, 0xFD}, // Invalid msgpack data
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

// TestHandleKMSVerify_ServiceError tests service failure path
func TestHandleKMSVerify_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	mockKMS.shouldErr = true
	mockKMS.errToReturn = errors.New("verify failed")
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	verifyReq := KMSVerifyRequest{
		KeyId:     "verify-key",
		Message:   []byte("message"),
		Signature: []byte("signature"),
	}

	payload, err := quic.EncodePayload(verifyReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpKMSVerify,
		Payload: payload,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// TestHandleKMSOperation_UnknownOpcode tests unknown opcode handling
func TestHandleKMSOperation_UnknownOpcode(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))
	ctx := context.Background()

	// Use an opcode in the KMS range but not defined
	req := &quic.Request{
		Opcode:  0xCF, // Unused KMS opcode
		Payload: nil,
	}
	resp := handler.handleKMSOperation(ctx, req)

	assert.Equal(t, quic.StatusNotImplemented, resp.Status)
}

// =============================================================================
// Conversion Helper Edge Cases
// =============================================================================

// TestConvertKeyMetadataToQUIC_MinimalFields tests conversion of a metadata
// message with only the identifying fields populated.
func TestConvertKeyMetadataToQUIC_MinimalFields(t *testing.T) {
	meta := &pb.KeyMetadata{
		KeyId:       "key-123",
		Name:        "test-key",
		Description: "Test key",
	}
	result := convertKeyMetadataToQUIC(meta)
	require.NotNil(t, result)
	assert.Equal(t, "key-123", result.KeyId)
	assert.Equal(t, "test-key", result.Name)
	assert.Equal(t, int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED), result.Algorithm)
	assert.Equal(t, int32(platformv1.KeyStatus_KEY_STATUS_UNSPECIFIED), result.Status)
}

// TestStringToKeyUsage_AlternateFormats tests alternate input formats
func TestStringToKeyUsage_AlternateFormats(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.KeyUsage
	}{
		{"key_usage_encrypt", pb.KeyUsage_KEY_USAGE_ENCRYPT},
		{"key_usage_decrypt", pb.KeyUsage_KEY_USAGE_DECRYPT},
		{"key_usage_sign", pb.KeyUsage_KEY_USAGE_SIGN},
		{"key_usage_verify", pb.KeyUsage_KEY_USAGE_VERIFY},
		{"wrap_key", pb.KeyUsage_KEY_USAGE_WRAP_KEY},
		{"key_usage_wrap_key", pb.KeyUsage_KEY_USAGE_WRAP_KEY},
		{"derive_key", pb.KeyUsage_KEY_USAGE_DERIVE_KEY},
		{"key_usage_derive_key", pb.KeyUsage_KEY_USAGE_DERIVE_KEY},
		{"generate_mac", pb.KeyUsage_KEY_USAGE_GENERATE_MAC},
		{"key_usage_generate_mac", pb.KeyUsage_KEY_USAGE_GENERATE_MAC},
		{"key_usage_verify_mac", pb.KeyUsage_KEY_USAGE_VERIFY_MAC},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToKeyUsage(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestBuildDataKeySpecForQUIC_KeySize verifies the requested key size is
// propagated into the pb key spec.
func TestBuildDataKeySpecForQUIC_KeySize(t *testing.T) {
	spec, err := buildDataKeySpecForQUIC(int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128), 128)
	require.NoError(t, err)
	assert.Equal(t, pb.KeyAlgorithm_KEY_ALG_AES_128_GCM, spec.Algorithm)
	assert.Equal(t, int32(128), spec.KeySize)
}
