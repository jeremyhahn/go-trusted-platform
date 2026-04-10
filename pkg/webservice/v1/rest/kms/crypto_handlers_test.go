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

package kms

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-quicbaas/api/proto"
)

// Extended mock crypto client with all required methods for crypto operations
type extendedMockCryptoClient struct {
	proto.CryptoClient

	encryptFn        func(ctx context.Context, req *proto.CryptoEncryptRequest, opts ...grpc.CallOption) (*proto.CryptoEncryptResponse, error)
	decryptFn        func(ctx context.Context, req *proto.CryptoDecryptRequest, opts ...grpc.CallOption) (*proto.CryptoDecryptResponse, error)
	signFn           func(ctx context.Context, req *proto.SignRequest, opts ...grpc.CallOption) (*proto.SignResponse, error)
	verifyFn         func(ctx context.Context, req *proto.VerifyRequest, opts ...grpc.CallOption) (*proto.VerifyResponse, error)
	hashFn           func(ctx context.Context, req *proto.HashRequest, opts ...grpc.CallOption) (*proto.HashResponse, error)
	generateHMACFn   func(ctx context.Context, req *proto.HMACRequest, opts ...grpc.CallOption) (*proto.HMACResponse, error)
	verifyHMACFn     func(ctx context.Context, req *proto.VerifyHMACRequest, opts ...grpc.CallOption) (*proto.VerifyHMACResponse, error)
	generateRandomFn func(ctx context.Context, req *proto.GenerateRandomRequest, opts ...grpc.CallOption) (*proto.GenerateRandomResponse, error)
	rewrapFn         func(ctx context.Context, req *proto.RewrapRequest, opts ...grpc.CallOption) (*proto.RewrapResponse, error)
	encryptBatchFn   func(ctx context.Context, req *proto.EncryptBatchRequest, opts ...grpc.CallOption) (*proto.EncryptBatchResponse, error)
	decryptBatchFn   func(ctx context.Context, req *proto.DecryptBatchRequest, opts ...grpc.CallOption) (*proto.DecryptBatchResponse, error)
}

func (m *extendedMockCryptoClient) Encrypt(ctx context.Context, req *proto.CryptoEncryptRequest, opts ...grpc.CallOption) (*proto.CryptoEncryptResponse, error) {
	if m.encryptFn != nil {
		return m.encryptFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *extendedMockCryptoClient) Decrypt(ctx context.Context, req *proto.CryptoDecryptRequest, opts ...grpc.CallOption) (*proto.CryptoDecryptResponse, error) {
	if m.decryptFn != nil {
		return m.decryptFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *extendedMockCryptoClient) Sign(ctx context.Context, req *proto.SignRequest, opts ...grpc.CallOption) (*proto.SignResponse, error) {
	if m.signFn != nil {
		return m.signFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *extendedMockCryptoClient) Verify(ctx context.Context, req *proto.VerifyRequest, opts ...grpc.CallOption) (*proto.VerifyResponse, error) {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *extendedMockCryptoClient) Hash(ctx context.Context, req *proto.HashRequest, opts ...grpc.CallOption) (*proto.HashResponse, error) {
	if m.hashFn != nil {
		return m.hashFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *extendedMockCryptoClient) GenerateHMAC(ctx context.Context, req *proto.HMACRequest, opts ...grpc.CallOption) (*proto.HMACResponse, error) {
	if m.generateHMACFn != nil {
		return m.generateHMACFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *extendedMockCryptoClient) VerifyHMAC(ctx context.Context, req *proto.VerifyHMACRequest, opts ...grpc.CallOption) (*proto.VerifyHMACResponse, error) {
	if m.verifyHMACFn != nil {
		return m.verifyHMACFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *extendedMockCryptoClient) GenerateRandom(ctx context.Context, req *proto.GenerateRandomRequest, opts ...grpc.CallOption) (*proto.GenerateRandomResponse, error) {
	if m.generateRandomFn != nil {
		return m.generateRandomFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *extendedMockCryptoClient) Rewrap(ctx context.Context, req *proto.RewrapRequest, opts ...grpc.CallOption) (*proto.RewrapResponse, error) {
	if m.rewrapFn != nil {
		return m.rewrapFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *extendedMockCryptoClient) EncryptBatch(ctx context.Context, req *proto.EncryptBatchRequest, opts ...grpc.CallOption) (*proto.EncryptBatchResponse, error) {
	if m.encryptBatchFn != nil {
		return m.encryptBatchFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *extendedMockCryptoClient) DecryptBatch(ctx context.Context, req *proto.DecryptBatchRequest, opts ...grpc.CallOption) (*proto.DecryptBatchResponse, error) {
	if m.decryptBatchFn != nil {
		return m.decryptBatchFn(ctx, req, opts...)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func newExtendedTestHandlers(keyMgmt *mockKeyManagementClient, crypto *extendedMockCryptoClient, dekMgmt *mockDEKManagementClient) (*KMSHandlers, *mockHttpWriter) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, keyMgmt, crypto, dekMgmt, nil, writer)
	return handlers, writer
}

// =============================================================================
// Sign Handler Tests
// =============================================================================

func TestSign_Success(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		signFn: func(ctx context.Context, req *proto.SignRequest, opts ...grpc.CallOption) (*proto.SignResponse, error) {
			return &proto.SignResponse{
				KeyId:         req.KeyId,
				KeyVersion:    1,
				Signature:     []byte("test-signature"),
				HashAlgorithm: req.HashAlgorithm,
				Timestamp:     1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := SignRequest{
		Message:       []byte("message to sign"),
		HashAlgorithm: "SHA256",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/sign/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Sign(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(SignResponse)
	require.True(t, ok)
	assert.Equal(t, "my-key", payload.KeyID)
	assert.Equal(t, uint64(1), payload.KeyVersion)
	assert.Equal(t, []byte("test-signature"), payload.Signature)
	assert.Equal(t, int64(1234567890), payload.Timestamp)
}

func TestSign_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, &mockKeyManagementClient{}, nil, nil, nil, writer)

	body := SignRequest{Message: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/sign/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Sign(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	_, ok := writer.lastError.(ErrCryptoClientNotInitialized)
	assert.True(t, ok)
}

func TestSign_MissingKeyName(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := SignRequest{Message: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/sign/", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.Sign(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingKeyName)
	assert.True(t, ok)
}

func TestSign_InvalidRequestBody(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/sign/my-key", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req = setVars(req, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Sign(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestSign_MissingMessage(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := SignRequest{}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/sign/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Sign(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingMessage)
	assert.True(t, ok)
}

func TestSign_GRPCError(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		signFn: func(ctx context.Context, req *proto.SignRequest, opts ...grpc.CallOption) (*proto.SignResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := SignRequest{Message: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/sign/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Sign(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// =============================================================================
// Verify Handler Tests
// =============================================================================

func TestVerify_Success(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		verifyFn: func(ctx context.Context, req *proto.VerifyRequest, opts ...grpc.CallOption) (*proto.VerifyResponse, error) {
			return &proto.VerifyResponse{
				KeyId:      req.KeyId,
				KeyVersion: 1,
				Valid:      true,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := VerifyRequest{
		Message:       []byte("message"),
		Signature:     []byte("signature"),
		HashAlgorithm: "SHA256",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/verify/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Verify(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(VerifyResponse)
	require.True(t, ok)
	assert.Equal(t, "my-key", payload.KeyID)
	assert.True(t, payload.Valid)
}

func TestVerify_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, &mockKeyManagementClient{}, nil, nil, nil, writer)

	body := VerifyRequest{Message: []byte("data"), Signature: []byte("sig")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/verify/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Verify(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	_, ok := writer.lastError.(ErrCryptoClientNotInitialized)
	assert.True(t, ok)
}

func TestVerify_MissingKeyName(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := VerifyRequest{Message: []byte("data"), Signature: []byte("sig")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/verify/", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.Verify(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingKeyName)
	assert.True(t, ok)
}

func TestVerify_InvalidRequestBody(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/verify/my-key", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req = setVars(req, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Verify(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestVerify_MissingMessage(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := VerifyRequest{Signature: []byte("sig")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/verify/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Verify(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingMessage)
	assert.True(t, ok)
}

func TestVerify_MissingSignature(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := VerifyRequest{Message: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/verify/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Verify(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingSignature)
	assert.True(t, ok)
}

func TestVerify_GRPCError(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		verifyFn: func(ctx context.Context, req *proto.VerifyRequest, opts ...grpc.CallOption) (*proto.VerifyResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "invalid signature format")
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := VerifyRequest{Message: []byte("data"), Signature: []byte("sig")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/verify/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Verify(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestVerify_InvalidSignature(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		verifyFn: func(ctx context.Context, req *proto.VerifyRequest, opts ...grpc.CallOption) (*proto.VerifyResponse, error) {
			return &proto.VerifyResponse{
				KeyId:      req.KeyId,
				KeyVersion: 1,
				Valid:      false,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := VerifyRequest{Message: []byte("data"), Signature: []byte("bad-sig")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/verify/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Verify(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(VerifyResponse)
	require.True(t, ok)
	assert.False(t, payload.Valid)
}

// =============================================================================
// Hash Handler Tests
// =============================================================================

func TestHash_Success(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		hashFn: func(ctx context.Context, req *proto.HashRequest, opts ...grpc.CallOption) (*proto.HashResponse, error) {
			return &proto.HashResponse{
				Algorithm: req.Algorithm,
				Hash:      []byte("hash-result"),
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := HashRequest{
		Data:      []byte("data to hash"),
		Algorithm: "SHA256",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hash", body, nil)
	rec := httptest.NewRecorder()

	handlers.Hash(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(HashResponse)
	require.True(t, ok)
	assert.Equal(t, []byte("hash-result"), payload.Hash)
	assert.Equal(t, int64(1234567890), payload.Timestamp)
}

func TestHash_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, &mockKeyManagementClient{}, nil, nil, nil, writer)

	body := HashRequest{Data: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hash", body, nil)
	rec := httptest.NewRecorder()

	handlers.Hash(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	_, ok := writer.lastError.(ErrCryptoClientNotInitialized)
	assert.True(t, ok)
}

func TestHash_InvalidRequestBody(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hash", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.Hash(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestHash_MissingData(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := HashRequest{}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hash", body, nil)
	rec := httptest.NewRecorder()

	handlers.Hash(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingData)
	assert.True(t, ok)
}

func TestHash_GRPCError(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		hashFn: func(ctx context.Context, req *proto.HashRequest, opts ...grpc.CallOption) (*proto.HashResponse, error) {
			return nil, status.Error(codes.Internal, "hashing failed")
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := HashRequest{Data: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hash", body, nil)
	rec := httptest.NewRecorder()

	handlers.Hash(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// =============================================================================
// HMAC Handler Tests
// =============================================================================

func TestHMAC_Success(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		generateHMACFn: func(ctx context.Context, req *proto.HMACRequest, opts ...grpc.CallOption) (*proto.HMACResponse, error) {
			return &proto.HMACResponse{
				KeyId:         req.KeyId,
				KeyVersion:    1,
				Hmac:          []byte("hmac-result"),
				HashAlgorithm: req.HashAlgorithm,
				Timestamp:     1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := HMACRequest{
		Message:       []byte("message to mac"),
		HashAlgorithm: "SHA256",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.HMAC(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(HMACResponse)
	require.True(t, ok)
	assert.Equal(t, "my-key", payload.KeyID)
	assert.Equal(t, uint64(1), payload.KeyVersion)
	assert.Equal(t, []byte("hmac-result"), payload.HMAC)
}

func TestHMAC_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, &mockKeyManagementClient{}, nil, nil, nil, writer)

	body := HMACRequest{Message: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.HMAC(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	_, ok := writer.lastError.(ErrCryptoClientNotInitialized)
	assert.True(t, ok)
}

func TestHMAC_MissingKeyName(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := HMACRequest{Message: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.HMAC(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingKeyName)
	assert.True(t, ok)
}

func TestHMAC_InvalidRequestBody(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hmac/my-key", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req = setVars(req, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.HMAC(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestHMAC_MissingMessage(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := HMACRequest{}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.HMAC(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingMessage)
	assert.True(t, ok)
}

func TestHMAC_GRPCError(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		generateHMACFn: func(ctx context.Context, req *proto.HMACRequest, opts ...grpc.CallOption) (*proto.HMACResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := HMACRequest{Message: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.HMAC(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// =============================================================================
// VerifyHMAC Handler Tests
// =============================================================================

func TestVerifyHMAC_Success(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		verifyHMACFn: func(ctx context.Context, req *proto.VerifyHMACRequest, opts ...grpc.CallOption) (*proto.VerifyHMACResponse, error) {
			return &proto.VerifyHMACResponse{
				KeyId:      req.KeyId,
				KeyVersion: 1,
				Valid:      true,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := VerifyHMACRequest{
		Message:       []byte("message"),
		HMAC:          []byte("hmac-value"),
		HashAlgorithm: "SHA256",
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/my-key/verify", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.VerifyHMAC(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(VerifyHMACResponse)
	require.True(t, ok)
	assert.Equal(t, "my-key", payload.KeyID)
	assert.True(t, payload.Valid)
}

func TestVerifyHMAC_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, &mockKeyManagementClient{}, nil, nil, nil, writer)

	body := VerifyHMACRequest{Message: []byte("data"), HMAC: []byte("hmac")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/my-key/verify", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.VerifyHMAC(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	_, ok := writer.lastError.(ErrCryptoClientNotInitialized)
	assert.True(t, ok)
}

func TestVerifyHMAC_MissingKeyName(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := VerifyHMACRequest{Message: []byte("data"), HMAC: []byte("hmac")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac//verify", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.VerifyHMAC(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingKeyName)
	assert.True(t, ok)
}

func TestVerifyHMAC_InvalidRequestBody(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/hmac/my-key/verify", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req = setVars(req, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.VerifyHMAC(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestVerifyHMAC_MissingMessage(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := VerifyHMACRequest{HMAC: []byte("hmac")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/my-key/verify", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.VerifyHMAC(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingMessage)
	assert.True(t, ok)
}

func TestVerifyHMAC_MissingHMAC(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := VerifyHMACRequest{Message: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/my-key/verify", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.VerifyHMAC(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingHMAC)
	assert.True(t, ok)
}

func TestVerifyHMAC_GRPCError(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		verifyHMACFn: func(ctx context.Context, req *proto.VerifyHMACRequest, opts ...grpc.CallOption) (*proto.VerifyHMACResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := VerifyHMACRequest{Message: []byte("data"), HMAC: []byte("hmac")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/my-key/verify", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.VerifyHMAC(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestVerifyHMAC_InvalidHMAC(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		verifyHMACFn: func(ctx context.Context, req *proto.VerifyHMACRequest, opts ...grpc.CallOption) (*proto.VerifyHMACResponse, error) {
			return &proto.VerifyHMACResponse{
				KeyId:      req.KeyId,
				KeyVersion: 1,
				Valid:      false,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := VerifyHMACRequest{Message: []byte("data"), HMAC: []byte("bad-hmac")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/hmac/my-key/verify", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.VerifyHMAC(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(VerifyHMACResponse)
	require.True(t, ok)
	assert.False(t, payload.Valid)
}

// =============================================================================
// GenerateRandom Handler Tests
// =============================================================================

func TestGenerateRandom_Success(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		generateRandomFn: func(ctx context.Context, req *proto.GenerateRandomRequest, opts ...grpc.CallOption) (*proto.GenerateRandomResponse, error) {
			randomBytes := make([]byte, req.NumBytes)
			for i := range randomBytes {
				randomBytes[i] = byte(i % 256)
			}
			return &proto.GenerateRandomResponse{
				RandomBytes: randomBytes,
				Timestamp:   1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := GenerateRandomRequest{NumBytes: 32}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/random", body, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateRandom(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(GenerateRandomResponse)
	require.True(t, ok)
	assert.Len(t, payload.RandomBytes, 32)
	assert.Equal(t, int64(1234567890), payload.Timestamp)
}

func TestGenerateRandom_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, &mockKeyManagementClient{}, nil, nil, nil, writer)

	body := GenerateRandomRequest{NumBytes: 32}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/random", body, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateRandom(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	_, ok := writer.lastError.(ErrCryptoClientNotInitialized)
	assert.True(t, ok)
}

func TestGenerateRandom_InvalidRequestBody(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/random", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.GenerateRandom(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestGenerateRandom_InvalidNumBytes_Zero(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := GenerateRandomRequest{NumBytes: 0}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/random", body, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateRandom(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidNumBytes)
	assert.True(t, ok)
}

func TestGenerateRandom_InvalidNumBytes_Negative(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := GenerateRandomRequest{NumBytes: -1}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/random", body, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateRandom(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidNumBytes)
	assert.True(t, ok)
}

func TestGenerateRandom_InvalidNumBytes_ExceedsMax(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := GenerateRandomRequest{NumBytes: maxRandomBytes + 1}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/random", body, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateRandom(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidNumBytes)
	assert.True(t, ok)
}

func TestGenerateRandom_GRPCError(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		generateRandomFn: func(ctx context.Context, req *proto.GenerateRandomRequest, opts ...grpc.CallOption) (*proto.GenerateRandomResponse, error) {
			return nil, status.Error(codes.Internal, "random generation failed")
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := GenerateRandomRequest{NumBytes: 32}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/random", body, nil)
	rec := httptest.NewRecorder()

	handlers.GenerateRandom(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// =============================================================================
// Rewrap Handler Tests
// =============================================================================

func TestRewrap_Success(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		rewrapFn: func(ctx context.Context, req *proto.RewrapRequest, opts ...grpc.CallOption) (*proto.RewrapResponse, error) {
			return &proto.RewrapResponse{
				KeyId:         req.KeyId,
				OldKeyVersion: 1,
				NewKeyVersion: 2,
				Ciphertext:    []byte("rewrapped-ciphertext"),
				Nonce:         []byte("new-nonce"),
				Timestamp:     1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := RewrapRequest{
		Ciphertext: []byte("old-ciphertext"),
		Context:    []byte("context"),
		Nonce:      []byte("old-nonce"),
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/rewrap/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Rewrap(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(RewrapResponse)
	require.True(t, ok)
	assert.Equal(t, "my-key", payload.KeyID)
	assert.Equal(t, uint64(1), payload.OldKeyVersion)
	assert.Equal(t, uint64(2), payload.NewKeyVersion)
	assert.Equal(t, []byte("rewrapped-ciphertext"), payload.Ciphertext)
}

func TestRewrap_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, &mockKeyManagementClient{}, nil, nil, nil, writer)

	body := RewrapRequest{Ciphertext: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/rewrap/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Rewrap(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	_, ok := writer.lastError.(ErrCryptoClientNotInitialized)
	assert.True(t, ok)
}

func TestRewrap_MissingKeyName(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := RewrapRequest{Ciphertext: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/rewrap/", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.Rewrap(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingKeyName)
	assert.True(t, ok)
}

func TestRewrap_InvalidRequestBody(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/rewrap/my-key", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req = setVars(req, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Rewrap(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestRewrap_MissingCiphertext(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := RewrapRequest{}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/rewrap/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Rewrap(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingCiphertext)
	assert.True(t, ok)
}

func TestRewrap_GRPCError(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		rewrapFn: func(ctx context.Context, req *proto.RewrapRequest, opts ...grpc.CallOption) (*proto.RewrapResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := RewrapRequest{Ciphertext: []byte("data")}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/rewrap/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Rewrap(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// =============================================================================
// Batch Handler Tests
// =============================================================================

func TestBatch_Encrypt_Success(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		encryptBatchFn: func(ctx context.Context, req *proto.EncryptBatchRequest, opts ...grpc.CallOption) (*proto.EncryptBatchResponse, error) {
			results := make([]*proto.BatchEncryptResult, len(req.Items))
			for i := range req.Items {
				results[i] = &proto.BatchEncryptResult{
					Ciphertext: []byte("encrypted-" + string(rune(i))),
					Nonce:      []byte("nonce-" + string(rune(i))),
				}
			}
			return &proto.EncryptBatchResponse{
				KeyId:      req.KeyId,
				KeyVersion: 1,
				Results:    results,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := BatchRequest{
		Operation: "encrypt",
		EncryptItems: []BatchEncryptItem{
			{Plaintext: []byte("data1")},
			{Plaintext: []byte("data2")},
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(BatchResponse)
	require.True(t, ok)
	assert.Equal(t, "my-key", payload.KeyID)
	assert.Len(t, payload.EncryptResults, 2)
}

func TestBatch_Decrypt_Success(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		decryptBatchFn: func(ctx context.Context, req *proto.DecryptBatchRequest, opts ...grpc.CallOption) (*proto.DecryptBatchResponse, error) {
			results := make([]*proto.BatchDecryptResult, len(req.Items))
			for i := range req.Items {
				results[i] = &proto.BatchDecryptResult{
					Plaintext: []byte("decrypted-" + string(rune(i))),
				}
			}
			return &proto.DecryptBatchResponse{
				KeyId:     req.KeyId,
				Results:   results,
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := BatchRequest{
		Operation: "decrypt",
		DecryptItems: []BatchDecryptItem{
			{Ciphertext: []byte("encrypted1"), Nonce: []byte("nonce1")},
			{Ciphertext: []byte("encrypted2"), Nonce: []byte("nonce2")},
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(BatchResponse)
	require.True(t, ok)
	assert.Equal(t, "my-key", payload.KeyID)
	assert.Len(t, payload.DecryptResults, 2)
}

func TestBatch_NilClient(t *testing.T) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewKMSHandlers(logger, &mockKeyManagementClient{}, nil, nil, nil, writer)

	body := BatchRequest{Operation: "encrypt", EncryptItems: []BatchEncryptItem{{Plaintext: []byte("data")}}}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
	_, ok := writer.lastError.(ErrCryptoClientNotInitialized)
	assert.True(t, ok)
}

func TestBatch_MissingKeyName(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := BatchRequest{Operation: "encrypt", EncryptItems: []BatchEncryptItem{{Plaintext: []byte("data")}}}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/", body, map[string]string{"name": ""})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingKeyName)
	assert.True(t, ok)
}

func TestBatch_InvalidRequestBody(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/batch/my-key", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req = setVars(req, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestBatch_InvalidOperation(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := BatchRequest{Operation: "invalid"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidBatchOperation)
	assert.True(t, ok)
}

func TestBatch_Encrypt_MissingItems(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := BatchRequest{Operation: "encrypt", EncryptItems: []BatchEncryptItem{}}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingBatchItems)
	assert.True(t, ok)
}

func TestBatch_Decrypt_MissingItems(t *testing.T) {
	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, &extendedMockCryptoClient{}, &mockDEKManagementClient{})

	body := BatchRequest{Operation: "decrypt", DecryptItems: []BatchDecryptItem{}}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingBatchItems)
	assert.True(t, ok)
}

func TestBatch_Encrypt_GRPCError(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		encryptBatchFn: func(ctx context.Context, req *proto.EncryptBatchRequest, opts ...grpc.CallOption) (*proto.EncryptBatchResponse, error) {
			return nil, status.Error(codes.NotFound, "key not found")
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := BatchRequest{Operation: "encrypt", EncryptItems: []BatchEncryptItem{{Plaintext: []byte("data")}}}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestBatch_Decrypt_GRPCError(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		decryptBatchFn: func(ctx context.Context, req *proto.DecryptBatchRequest, opts ...grpc.CallOption) (*proto.DecryptBatchResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "invalid ciphertext")
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := BatchRequest{Operation: "decrypt", DecryptItems: []BatchDecryptItem{{Ciphertext: []byte("bad")}}}
	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestBatch_Encrypt_WithContext(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		encryptBatchFn: func(ctx context.Context, req *proto.EncryptBatchRequest, opts ...grpc.CallOption) (*proto.EncryptBatchResponse, error) {
			results := make([]*proto.BatchEncryptResult, len(req.Items))
			for i, item := range req.Items {
				results[i] = &proto.BatchEncryptResult{
					Ciphertext: append(item.Plaintext, item.Context...),
					Nonce:      []byte("nonce"),
				}
			}
			return &proto.EncryptBatchResponse{
				KeyId:      req.KeyId,
				KeyVersion: 1,
				Results:    results,
				Timestamp:  1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := BatchRequest{
		Operation: "encrypt",
		EncryptItems: []BatchEncryptItem{
			{Plaintext: []byte("data1"), Context: []byte("ctx1")},
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestBatch_Decrypt_WithContext(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		decryptBatchFn: func(ctx context.Context, req *proto.DecryptBatchRequest, opts ...grpc.CallOption) (*proto.DecryptBatchResponse, error) {
			results := make([]*proto.BatchDecryptResult, len(req.Items))
			for i := range req.Items {
				results[i] = &proto.BatchDecryptResult{
					Plaintext: []byte("decrypted"),
				}
			}
			return &proto.DecryptBatchResponse{
				KeyId:     req.KeyId,
				Results:   results,
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := BatchRequest{
		Operation: "decrypt",
		DecryptItems: []BatchDecryptItem{
			{Ciphertext: []byte("encrypted"), Context: []byte("ctx"), Nonce: []byte("nonce")},
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestBatch_Encrypt_PartialFailure(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		encryptBatchFn: func(ctx context.Context, req *proto.EncryptBatchRequest, opts ...grpc.CallOption) (*proto.EncryptBatchResponse, error) {
			return &proto.EncryptBatchResponse{
				KeyId:      req.KeyId,
				KeyVersion: 1,
				Results: []*proto.BatchEncryptResult{
					{Ciphertext: []byte("encrypted"), Nonce: []byte("nonce")},
					{Error: "encryption failed for item 2"},
				},
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := BatchRequest{
		Operation: "encrypt",
		EncryptItems: []BatchEncryptItem{
			{Plaintext: []byte("data1")},
			{Plaintext: []byte("data2")},
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(BatchResponse)
	require.True(t, ok)
	assert.Len(t, payload.EncryptResults, 2)
	assert.Empty(t, payload.EncryptResults[0].Error)
	assert.Equal(t, "encryption failed for item 2", payload.EncryptResults[1].Error)
}

func TestBatch_Decrypt_PartialFailure(t *testing.T) {
	crypto := &extendedMockCryptoClient{
		decryptBatchFn: func(ctx context.Context, req *proto.DecryptBatchRequest, opts ...grpc.CallOption) (*proto.DecryptBatchResponse, error) {
			return &proto.DecryptBatchResponse{
				KeyId: req.KeyId,
				Results: []*proto.BatchDecryptResult{
					{Plaintext: []byte("decrypted")},
					{Error: "decryption failed for item 2"},
				},
				Timestamp: 1234567890,
			}, nil
		},
	}

	handlers, writer := newExtendedTestHandlers(&mockKeyManagementClient{}, crypto, &mockDEKManagementClient{})

	body := BatchRequest{
		Operation: "decrypt",
		DecryptItems: []BatchDecryptItem{
			{Ciphertext: []byte("encrypted1")},
			{Ciphertext: []byte("encrypted2")},
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/kms/batch/my-key", body, map[string]string{"name": "my-key"})
	rec := httptest.NewRecorder()

	handlers.Batch(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(BatchResponse)
	require.True(t, ok)
	assert.Len(t, payload.DecryptResults, 2)
	assert.Empty(t, payload.DecryptResults[0].Error)
	assert.Equal(t, "decryption failed for item 2", payload.DecryptResults[1].Error)
}

// =============================================================================
// Helper function
// =============================================================================

func setVars(r *http.Request, vars map[string]string) *http.Request {
	return createRequestWithVars(r.Method, r.URL.Path, nil, vars)
}
