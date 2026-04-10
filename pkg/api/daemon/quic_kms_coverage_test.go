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
		WrappingKeyID: "wrapping-key-123",
		KeySpec: &KMSKeySpecRequest{
			Algorithm:          "AES_256_GCM",
			KeySize:            256,
			Usage:              []string{"ENCRYPT", "DECRYPT"},
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
		KeyID:             "export-key",
		WrappingKeyID:     "wrapping-key",
		WrappingAlgorithm: "AES_KW",
		Format:            "RAW",
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
		KeyID:             "delete-me",
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
		KeyID:            "rotate-me",
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
		KeyID:   "status-key",
		Version: 1,
		Status:  "DISABLED",
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
		Algorithm: "SHA256",
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

	algorithms := []string{"SHA256", "SHA384", "SHA512", "SHA3_256", "BLAKE2B_256", ""}

	for _, alg := range algorithms {
		t.Run("algorithm_"+alg, func(t *testing.T) {
			hashReq := KMSHashRequest{
				Data:      []byte("data to hash"),
				Algorithm: alg,
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
		KeyID:     "kek-key",
		Algorithm: "aes-256-gcm",
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
		KeyID:     "kek-key",
		Algorithm: "invalid-algorithm",
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
		KeyID:     "kek-key",
		Algorithm: "", // Empty - should default to aes-256-gcm
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

	algorithms := []string{
		"aes-128-gcm", "aes128gcm", "aes128",
		"aes-192-gcm", "aes192gcm", "aes192",
		"aes-256-gcm", "aes256gcm", "aes256",
		"chacha20-poly1305", "chacha20poly1305", "chacha20",
		"xchacha20-poly1305", "xchacha20poly1305", "xchacha20",
	}

	for _, alg := range algorithms {
		t.Run("algorithm_"+alg, func(t *testing.T) {
			dataKeyReq := KMSGenerateDataKeyQUICRequest{
				KeyID:     "kek-key",
				Algorithm: alg,
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
		KeyID:     "kek-key",
		Algorithm: "aes-256-gcm",
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
		KeyID:     "kek-key",
		Algorithm: "invalid-algorithm",
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
		KeyID:     "kek-key",
		Algorithm: "", // Empty - should default to aes-256-gcm
		Context:   []byte("encryption-context"),
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
		KeyID: "versioned-key",
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
			KeyID: "versioned-key",
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
			KeyID: "versioned-key",
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
		KeyID:     "encrypt-key",
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
		KeyID:      "decrypt-key",
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
		KeyID:   "sign-key",
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
		KeyID:     "verify-key",
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

// TestConvertKeyMetadataToQUIC_WithoutRotationPolicy tests conversion without rotation policy
func TestConvertKeyMetadataToQUIC_WithoutRotationPolicy(t *testing.T) {
	meta := &pb.KeyMetadata{
		KeyId:          "key-123",
		Name:           "test-key",
		Description:    "Test key without rotation",
		RotationPolicy: nil,
	}
	result := convertKeyMetadataToQUIC(meta)
	require.NotNil(t, result)
	assert.Nil(t, result.RotationPolicy)
}

// TestStringToKeyAlgorithm_AlternateFormats tests alternate input formats
func TestStringToKeyAlgorithm_AlternateFormats(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.KeyAlgorithm
	}{
		{"aes-128-gcm", pb.KeyAlgorithm_KEY_ALG_AES_128_GCM},
		{"AES-128-GCM", pb.KeyAlgorithm_KEY_ALG_AES_128_GCM},
		{"aes_128_gcm", pb.KeyAlgorithm_KEY_ALG_AES_128_GCM},
		{"ec_p256", pb.KeyAlgorithm_KEY_ALG_ECDSA_P256},
		{"ec_p384", pb.KeyAlgorithm_KEY_ALG_ECDSA_P384},
		{"ec_p521", pb.KeyAlgorithm_KEY_ALG_ECDSA_P521},
		{"eddsa", pb.KeyAlgorithm_KEY_ALG_ED25519},
		{"rsa2048", pb.KeyAlgorithm_KEY_ALG_RSA_2048},
		{"rsa3072", pb.KeyAlgorithm_KEY_ALG_RSA_3072},
		{"rsa4096", pb.KeyAlgorithm_KEY_ALG_RSA_4096},
		{"aes192gcm", pb.KeyAlgorithm_KEY_ALG_AES_192_GCM},
		{"aes256gcm", pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
		{"chacha20poly1305", pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305},
		{"xchacha20poly1305", pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToKeyAlgorithm(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
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

// TestStringToKeyStatus_AlternateFormats tests alternate input formats
func TestStringToKeyStatus_AlternateFormats(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.KeyStatus
	}{
		{"key_status_enabled", pb.KeyStatus_KEY_STATUS_ENABLED},
		{"key_status_disabled", pb.KeyStatus_KEY_STATUS_DISABLED},
		{"key_status_pending_deletion", pb.KeyStatus_KEY_STATUS_PENDING_DELETION},
		{"key_status_deleted", pb.KeyStatus_KEY_STATUS_DELETED},
		{"key_status_rotating", pb.KeyStatus_KEY_STATUS_ROTATING},
		{"key_status_compromised", pb.KeyStatus_KEY_STATUS_COMPROMISED},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToKeyStatus(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestStringToWrappingAlgorithm_AlternateFormats tests alternate input formats
func TestStringToWrappingAlgorithm_AlternateFormats(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.WrappingAlgorithm
	}{
		{"aeskw", pb.WrappingAlgorithm_WRAP_ALG_AES_KW},
		{"wrap_alg_aes_kw", pb.WrappingAlgorithm_WRAP_ALG_AES_KW},
		{"aeskwp", pb.WrappingAlgorithm_WRAP_ALG_AES_KWP},
		{"wrap_alg_aes_kwp", pb.WrappingAlgorithm_WRAP_ALG_AES_KWP},
		{"aesgcm", pb.WrappingAlgorithm_WRAP_ALG_AES_GCM},
		{"wrap_alg_aes_gcm", pb.WrappingAlgorithm_WRAP_ALG_AES_GCM},
		{"rsaoaepsha256", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256},
		{"wrap_alg_rsa_oaep_sha256", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256},
		{"rsaoaepsha384", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384},
		{"wrap_alg_rsa_oaep_sha384", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384},
		{"rsaoaepsha512", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512},
		{"wrap_alg_rsa_oaep_sha512", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512},
		{"ecdhesa256kw", pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW},
		{"wrap_alg_ecdh_es_a256kw", pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToWrappingAlgorithm(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestStringToExportFormat_AlternateFormats tests alternate input formats
func TestStringToExportFormat_AlternateFormats(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.ExportFormat
	}{
		{"export_format_raw", pb.ExportFormat_EXPORT_FORMAT_RAW},
		{"export_format_jwk", pb.ExportFormat_EXPORT_FORMAT_JWK},
		{"export_format_pem", pb.ExportFormat_EXPORT_FORMAT_PEM},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToExportFormat(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestStringToHashAlgorithm_AlternateFormats tests alternate input formats
func TestStringToHashAlgorithm_AlternateFormats(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.HashAlgorithm
	}{
		{"sha_256", pb.HashAlgorithm_HASH_ALG_SHA256},
		{"hash_alg_sha256", pb.HashAlgorithm_HASH_ALG_SHA256},
		{"sha_384", pb.HashAlgorithm_HASH_ALG_SHA384},
		{"hash_alg_sha384", pb.HashAlgorithm_HASH_ALG_SHA384},
		{"sha_512", pb.HashAlgorithm_HASH_ALG_SHA512},
		{"hash_alg_sha512", pb.HashAlgorithm_HASH_ALG_SHA512},
		{"sha3256", pb.HashAlgorithm_HASH_ALG_SHA3_256},
		{"hash_alg_sha3_256", pb.HashAlgorithm_HASH_ALG_SHA3_256},
		{"sha3384", pb.HashAlgorithm_HASH_ALG_SHA3_384},
		{"hash_alg_sha3_384", pb.HashAlgorithm_HASH_ALG_SHA3_384},
		{"sha3512", pb.HashAlgorithm_HASH_ALG_SHA3_512},
		{"hash_alg_sha3_512", pb.HashAlgorithm_HASH_ALG_SHA3_512},
		{"blake2b256", pb.HashAlgorithm_HASH_ALG_BLAKE2B_256},
		{"hash_alg_blake2b_256", pb.HashAlgorithm_HASH_ALG_BLAKE2B_256},
		{"blake2b512", pb.HashAlgorithm_HASH_ALG_BLAKE2B_512},
		{"hash_alg_blake2b_512", pb.HashAlgorithm_HASH_ALG_BLAKE2B_512},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToHashAlgorithm(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestBuildDataKeySpecForQUIC_WhitespaceTrimming tests whitespace handling
func TestBuildDataKeySpecForQUIC_WhitespaceTrimming(t *testing.T) {
	testCases := []struct {
		algorithm string
		expected  pb.KeyAlgorithm
	}{
		{"  aes-256-gcm  ", pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
		{" AES-128-GCM ", pb.KeyAlgorithm_KEY_ALG_AES_128_GCM},
		{"	chacha20-poly1305	", pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305},
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			result, err := buildDataKeySpecForQUIC(tc.algorithm)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Algorithm)
		})
	}
}
