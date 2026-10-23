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
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock KMS Service
// =============================================================================

type mockKMSService struct {
	keys                map[string]*pb.KeyHandle
	metadata            map[string]*pb.KeyMetadata
	policies            map[string]*pb.KeyPolicy
	shouldErr           bool
	errToReturn         error
	lastOperation       string
	lastSignReq         *pb.SignRequest
	lastHMACReq         *pb.HMACRequest
	lastVerifyHMACReq   *pb.VerifyHMACRequest
	lastRewrapReq       *pb.RewrapRequest
	lastBatchEncryptReq *pb.EncryptBatchRequest
	lastBatchDecryptReq *pb.DecryptBatchRequest
	batchEncryptErrors  []string
	batchDecryptErrors  []string
}

var _ KMSServiceInterface = (*mockKMSService)(nil)

func newMockKMSService() *mockKMSService {
	return &mockKMSService{
		keys:     make(map[string]*pb.KeyHandle),
		metadata: make(map[string]*pb.KeyMetadata),
		policies: make(map[string]*pb.KeyPolicy),
	}
}

func (m *mockKMSService) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	m.lastOperation = "GenerateKey"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	keyID := "generated-key-" + req.Name
	key := &pb.KeyHandle{
		KeyId:     keyID,
		Version:   1,
		Algorithm: req.KeySpec.Algorithm,
		Status:    pb.KeyStatus_KEY_STATUS_ENABLED,
		CreatedAt: time.Now().Unix(),
	}
	meta := &pb.KeyMetadata{
		KeyId:       keyID,
		Name:        req.Name,
		Description: req.Description,
		Algorithm:   req.KeySpec.Algorithm,
		Status:      pb.KeyStatus_KEY_STATUS_ENABLED,
		Usage:       req.KeySpec.Usage,
		Version:     1,
		Exportable:  req.KeySpec.Exportable,
		CreatedAt:   time.Now().Unix(),
		Tags:        req.Tags,
		Owner:       req.Owner,
	}
	m.keys[keyID] = key
	m.metadata[keyID] = meta
	return &pb.GenerateKeyResponse{Key: key, Metadata: meta}, nil
}

func (m *mockKMSService) ImportKey(ctx context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	m.lastOperation = "ImportKey"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	keyID := "imported-key-" + req.Name
	key := &pb.KeyHandle{
		KeyId:     keyID,
		Version:   1,
		Status:    pb.KeyStatus_KEY_STATUS_ENABLED,
		CreatedAt: time.Now().Unix(),
	}
	meta := &pb.KeyMetadata{
		KeyId:       keyID,
		Name:        req.Name,
		Description: req.Description,
		Status:      pb.KeyStatus_KEY_STATUS_ENABLED,
		Version:     1,
		CreatedAt:   time.Now().Unix(),
	}
	m.keys[keyID] = key
	m.metadata[keyID] = meta
	return &pb.ImportKeyResponse{Key: key, Metadata: meta}, nil
}

func (m *mockKMSService) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	m.lastOperation = "GetKey"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	key, ok := m.keys[req.KeyId]
	if !ok {
		return nil, status.Error(codes.NotFound, "key not found")
	}
	return &pb.GetKeyResponse{Key: key, Metadata: m.metadata[req.KeyId]}, nil
}

func (m *mockKMSService) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	m.lastOperation = "ListKeys"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	keys := make([]*pb.KeyHandle, 0, len(m.keys))
	for _, k := range m.keys {
		keys = append(keys, k)
	}
	return &pb.ListKeysResponse{
		Keys:       keys,
		NextCursor: "",
		HasMore:    false,
		TotalCount: int32(len(keys)),
	}, nil
}

func (m *mockKMSService) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	m.lastOperation = "DeleteKey"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	if _, ok := m.keys[req.KeyId]; !ok {
		return nil, status.Error(codes.NotFound, "key not found")
	}
	delete(m.keys, req.KeyId)
	delete(m.metadata, req.KeyId)
	return &pb.DeleteKeyResponse{
		KeyId:        req.KeyId,
		Status:       pb.KeyStatus_KEY_STATUS_PENDING_DELETION,
		DeletionDate: time.Now().Add(24 * time.Hour).Unix(),
	}, nil
}

func (m *mockKMSService) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	m.lastOperation = "RotateKey"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	key, ok := m.keys[req.KeyId]
	if !ok {
		return nil, status.Error(codes.NotFound, "key not found")
	}
	oldVersion := key.Version
	key.Version++
	return &pb.RotateKeyResponse{
		KeyId:      req.KeyId,
		OldVersion: oldVersion,
		NewVersion: key.Version,
	}, nil
}

func (m *mockKMSService) UpdateKeyStatus(ctx context.Context, req *pb.UpdateKeyStatusRequest) (*pb.UpdateKeyStatusResponse, error) {
	m.lastOperation = "UpdateKeyStatus"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	key, ok := m.keys[req.KeyId]
	if !ok {
		return nil, status.Error(codes.NotFound, "key not found")
	}
	key.Status = req.Status
	return &pb.UpdateKeyStatusResponse{
		KeyId:   req.KeyId,
		Version: key.Version,
		Status:  req.Status,
	}, nil
}

func (m *mockKMSService) ExportKey(ctx context.Context, req *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	m.lastOperation = "ExportKey"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	if _, ok := m.keys[req.KeyId]; !ok {
		return nil, status.Error(codes.NotFound, "key not found")
	}
	return &pb.ExportKeyResponse{
		KeyId:             req.KeyId,
		Format:            req.Format,
		WrappingKeyId:     req.WrappingKeyId,
		WrappingAlgorithm: req.WrappingAlgorithm,
		WrappedMaterial:   []byte("mock-wrapped-key-material"),
		Version:           1,
	}, nil
}

func (m *mockKMSService) ListKeyVersions(ctx context.Context, req *pb.ListKeyVersionsRequest) (*pb.ListKeyVersionsResponse, error) {
	m.lastOperation = "ListKeyVersions"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	versions := []*pb.KeyVersionInfo{
		{Version: 1, Status: pb.KeyStatus_KEY_STATUS_ENABLED, Algorithm: pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, CreatedAt: time.Now().Unix()},
	}
	return &pb.ListKeyVersionsResponse{
		KeyId:      req.KeyId,
		Versions:   versions,
		NextCursor: "",
		HasMore:    false,
	}, nil
}

func (m *mockKMSService) Encrypt(ctx context.Context, req *pb.CryptoEncryptRequest) (*pb.CryptoEncryptResponse, error) {
	m.lastOperation = "Encrypt"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.CryptoEncryptResponse{
		KeyId:      req.KeyId,
		KeyVersion: 1,
		Ciphertext: []byte("encrypted-" + string(req.Plaintext)),
		Nonce:      []byte("mock-nonce"),
	}, nil
}

func (m *mockKMSService) Decrypt(ctx context.Context, req *pb.CryptoDecryptRequest) (*pb.CryptoDecryptResponse, error) {
	m.lastOperation = "Decrypt"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.CryptoDecryptResponse{
		KeyId:      req.KeyId,
		KeyVersion: 1,
		Plaintext:  []byte("decrypted-data"),
	}, nil
}

func (m *mockKMSService) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	m.lastOperation = "Sign"
	m.lastSignReq = req
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.SignResponse{
		KeyId:         req.KeyId,
		KeyVersion:    1,
		Signature:     []byte("mock-signature"),
		HashAlgorithm: req.HashAlgorithm,
	}, nil
}

func (m *mockKMSService) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	m.lastOperation = "Verify"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.VerifyResponse{
		KeyId:      req.KeyId,
		KeyVersion: 1,
		Valid:      true,
	}, nil
}

func (m *mockKMSService) GenerateRandom(ctx context.Context, req *pb.GenerateRandomRequest) (*pb.GenerateRandomResponse, error) {
	m.lastOperation = "GenerateRandom"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	randomBytes := make([]byte, req.NumBytes)
	for i := range randomBytes {
		randomBytes[i] = byte(i % 256)
	}
	return &pb.GenerateRandomResponse{RandomBytes: randomBytes}, nil
}

func (m *mockKMSService) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	m.lastOperation = "Hash"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.HashResponse{
		Algorithm: req.Algorithm,
		Hash:      []byte("mock-hash-value"),
	}, nil
}

func (m *mockKMSService) GenerateHMAC(ctx context.Context, req *pb.HMACRequest) (*pb.HMACResponse, error) {
	m.lastOperation = "GenerateHMAC"
	m.lastHMACReq = req
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.HMACResponse{
		KeyId:         req.KeyId,
		KeyVersion:    1,
		Hmac:          []byte("mock-hmac"),
		HashAlgorithm: req.HashAlgorithm,
		Timestamp:     time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) VerifyHMAC(ctx context.Context, req *pb.VerifyHMACRequest) (*pb.VerifyHMACResponse, error) {
	m.lastOperation = "VerifyHMAC"
	m.lastVerifyHMACReq = req
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.VerifyHMACResponse{
		KeyId:      req.KeyId,
		KeyVersion: req.KeyVersion,
		Valid:      true,
		Timestamp:  time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) Rewrap(ctx context.Context, req *pb.RewrapRequest) (*pb.RewrapResponse, error) {
	m.lastOperation = "Rewrap"
	m.lastRewrapReq = req
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.RewrapResponse{
		KeyId:         req.KeyId,
		OldKeyVersion: 1,
		NewKeyVersion: 2,
		Ciphertext:    []byte("rewrapped-" + string(req.Ciphertext)),
		Nonce:         []byte("new-nonce"),
		Timestamp:     time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) BatchEncrypt(ctx context.Context, req *pb.EncryptBatchRequest) (*pb.EncryptBatchResponse, error) {
	m.lastOperation = "BatchEncrypt"
	m.lastBatchEncryptReq = req
	if m.shouldErr {
		return nil, m.errToReturn
	}
	results := make([]*pb.BatchEncryptResult, 0, len(req.Items))
	for i, item := range req.Items {
		if i < len(m.batchEncryptErrors) && m.batchEncryptErrors[i] != "" {
			results = append(results, &pb.BatchEncryptResult{Error: m.batchEncryptErrors[i]})
			continue
		}
		results = append(results, &pb.BatchEncryptResult{
			Ciphertext: []byte("encrypted-" + string(item.Plaintext)),
			Nonce:      []byte("nonce"),
		})
	}
	return &pb.EncryptBatchResponse{
		KeyId:      req.KeyId,
		KeyVersion: 3,
		Results:    results,
		Timestamp:  time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) BatchDecrypt(ctx context.Context, req *pb.DecryptBatchRequest) (*pb.DecryptBatchResponse, error) {
	m.lastOperation = "BatchDecrypt"
	m.lastBatchDecryptReq = req
	if m.shouldErr {
		return nil, m.errToReturn
	}
	results := make([]*pb.BatchDecryptResult, 0, len(req.Items))
	for i, item := range req.Items {
		if i < len(m.batchDecryptErrors) && m.batchDecryptErrors[i] != "" {
			results = append(results, &pb.BatchDecryptResult{Error: m.batchDecryptErrors[i]})
			continue
		}
		results = append(results, &pb.BatchDecryptResult{
			Plaintext: []byte("decrypted-" + string(item.Ciphertext)),
		})
	}
	return &pb.DecryptBatchResponse{
		KeyId:     req.KeyId,
		Results:   results,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) RevokeKey(ctx context.Context, req *pb.RevokeKeyRequest) (*pb.RevokeKeyResponse, error) {
	m.lastOperation = "RevokeKey"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	key, ok := m.keys[req.KeyId]
	if !ok {
		return nil, status.Error(codes.NotFound, "key not found")
	}
	key.Status = pb.KeyStatus_KEY_STATUS_DISABLED
	return &pb.RevokeKeyResponse{
		KeyId:     req.KeyId,
		Status:    pb.KeyStatus_KEY_STATUS_DISABLED,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) GetKeyMetadata(ctx context.Context, req *pb.GetKeyMetadataRequest) (*pb.GetKeyMetadataResponse, error) {
	m.lastOperation = "GetKeyMetadata"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	meta, ok := m.metadata[req.KeyId]
	if !ok {
		return nil, status.Error(codes.NotFound, "key not found")
	}
	return &pb.GetKeyMetadataResponse{
		Metadata:  meta,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) UpdateKeyMetadata(ctx context.Context, req *pb.UpdateKeyMetadataRequest) (*pb.UpdateKeyMetadataResponse, error) {
	m.lastOperation = "UpdateKeyMetadata"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	meta, ok := m.metadata[req.KeyId]
	if !ok {
		return nil, status.Error(codes.NotFound, "key not found")
	}
	if req.Name != "" {
		meta.Name = req.Name
	}
	if req.Description != "" {
		meta.Description = req.Description
	}
	return &pb.UpdateKeyMetadataResponse{
		Metadata:  meta,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) SetKeyPolicy(ctx context.Context, req *pb.SetKeyPolicyRequest) (*pb.SetKeyPolicyResponse, error) {
	m.lastOperation = "SetKeyPolicy"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	m.policies[req.KeyId] = req.Policy
	return &pb.SetKeyPolicyResponse{
		KeyId:         req.KeyId,
		PolicyVersion: req.GetPolicy().GetVersion(),
		Timestamp:     time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) GetKeyPolicy(ctx context.Context, req *pb.GetKeyPolicyRequest) (*pb.GetKeyPolicyResponse, error) {
	m.lastOperation = "GetKeyPolicy"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	policy, ok := m.policies[req.KeyId]
	if !ok {
		return nil, status.Error(codes.NotFound, "policy not found")
	}
	return &pb.GetKeyPolicyResponse{
		Policy:    policy,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockKMSService) GetSupportedAlgorithms(ctx context.Context, req *pb.GetSupportedAlgorithmsRequest) (*pb.GetSupportedAlgorithmsResponse, error) {
	m.lastOperation = "GetSupportedAlgorithms"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.GetSupportedAlgorithmsResponse{
		Algorithms: []string{"AES-256-GCM", "RSA-2048", "ECDSA-P256", "ED25519"},
	}, nil
}

func (m *mockKMSService) BackendStatus(ctx context.Context, req *pb.BackendStatusRequest) (*pb.BackendStatusResponse, error) {
	m.lastOperation = "BackendStatus"
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.BackendStatusResponse{
		BackendType:  "quicbaas",
		Status:       "healthy",
		Capabilities: map[string]bool{"encrypt": true, "sign": true},
		Timestamp:    time.Now().Unix(),
	}, nil
}

// =============================================================================
// Mock Crypto Service
// =============================================================================

type mockCryptoService struct {
	shouldErr   bool
	errToReturn error
}

func newMockCryptoService() *mockCryptoService {
	return &mockCryptoService{}
}

func (m *mockCryptoService) GenerateDataKey(ctx context.Context, req *pb.GenerateDataKeyRequest) (*pb.GenerateDataKeyResponse, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.GenerateDataKeyResponse{
		KeyId:          req.KeyId,
		Plaintext:      []byte("plaintext-data-key"),
		CiphertextBlob: []byte("encrypted-data-key"),
	}, nil
}

func (m *mockCryptoService) GenerateWrappedDataKey(ctx context.Context, req *pb.GenerateWrappedDataKeyRequest) (*pb.GenerateWrappedDataKeyResponse, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	return &pb.GenerateWrappedDataKeyResponse{
		KeyId:          req.KeyId,
		CiphertextBlob: []byte("wrapped-data-key"),
	}, nil
}

// =============================================================================
// Tests
// =============================================================================

func TestHandleKMSOperation_ServiceNotAvailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)

	ctx := context.Background()

	testCases := []struct {
		name   string
		opcode byte
	}{
		{"GenerateKey", quicwire.OpKMSGenerateKey},
		{"ImportKey", quicwire.OpKMSImportKey},
		{"GetKey", quicwire.OpKMSGetKey},
		{"ListKeys", quicwire.OpKMSListKeys},
		{"DeleteKey", quicwire.OpKMSDeleteKey},
		{"RotateKey", quicwire.OpKMSRotateKey},
		{"UpdateKeyStatus", quicwire.OpKMSUpdateKeyStatus},
		{"ExportKey", quicwire.OpKMSExportKey},
		{"GetKeyVersions", quicwire.OpKMSGetKeyVersions},
		{"BackendStatus", quicwire.OpKMSBackendStatus},
		{"BatchEncrypt", quicwire.OpKMSBatchEncrypt},
		{"BatchDecrypt", quicwire.OpKMSBatchDecrypt},
		{"Encrypt", quicwire.OpKMSEncrypt},
		{"Decrypt", quicwire.OpKMSDecrypt},
		{"Sign", quicwire.OpKMSSign},
		{"Verify", quicwire.OpKMSVerify},
		{"GenerateRandom", quicwire.OpKMSGenerateRandom},
		{"Hash", quicwire.OpKMSHash},
		{"HMAC", quicwire.OpKMSHMAC},
		{"VerifyHMAC", quicwire.OpKMSVerifyHMAC},
		{"Rewrap", quicwire.OpKMSRewrap},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &quicwire.Request{
				Opcode:  tc.opcode,
				Payload: []byte{},
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
			assert.Contains(t, string(resp.Payload), "kms")
		})
	}
}

func TestHandleKMSGenerateKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		genReq := KMSGenerateKeyRequest{
			Name:        "test-key",
			Description: "Test encryption key",
			KeySpec: &KMSKeySpecRequest{
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
				Usage: []int32{
					int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT),
					int32(platformv1.KeyUsage_KEY_USAGE_DECRYPT),
				},
			},
			Tags:  map[string]string{"env": "test"},
			Owner: "test-user",
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
		assert.NotEmpty(t, genResp.Key.KeyId)
		assert.Equal(t, int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256), genResp.Key.Algorithm)
		assert.Equal(t, int32(platformv1.KeyStatus_KEY_STATUS_ENABLED), genResp.Key.Status)
	})

	t.Run("missing name", func(t *testing.T) {
		genReq := KMSGenerateKeyRequest{
			KeySpec: &KMSKeySpecRequest{
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
			},
		}

		payload, err := quicwire.EncodePayload(genReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "name")
	})

	t.Run("missing key_spec", func(t *testing.T) {
		genReq := KMSGenerateKeyRequest{
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
		assert.Contains(t, string(resp.Payload), "key_spec")
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		genReq := KMSGenerateKeyRequest{
			Name: "test-key",
			KeySpec: &KMSKeySpecRequest{
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM2),
			},
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

	t.Run("unsupported usage", func(t *testing.T) {
		genReq := KMSGenerateKeyRequest{
			Name: "test-key",
			KeySpec: &KMSKeySpecRequest{
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
				Usage:     []int32{int32(platformv1.KeyUsage_KEY_USAGE_UNWRAP)},
			},
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

	t.Run("service error", func(t *testing.T) {
		mockKMS.shouldErr = true
		mockKMS.errToReturn = errors.New("key generation failed")
		defer func() { mockKMS.shouldErr = false }()

		genReq := KMSGenerateKeyRequest{
			Name: "test-key",
			KeySpec: &KMSKeySpecRequest{
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
			},
		}

		payload, err := quicwire.EncodePayload(genReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestHandleKMSImportKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		importReq := KMSImportKeyRequest{
			KeyMaterial: []byte("raw-key-material-32-bytes-long!!"),
			Name:        "imported-key",
			Description: "Imported test key",
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
	})

	t.Run("missing key_material", func(t *testing.T) {
		importReq := KMSImportKeyRequest{
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
		assert.Contains(t, string(resp.Payload), "key_material")
	})

	t.Run("missing name", func(t *testing.T) {
		importReq := KMSImportKeyRequest{
			KeyMaterial: []byte("raw-key-material"),
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSImportKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "name")
	})

	t.Run("unsupported key_spec algorithm", func(t *testing.T) {
		importReq := KMSImportKeyRequest{
			KeyMaterial: []byte("raw-key-material"),
			Name:        "imported-key",
			KeySpec: &KMSKeySpecRequest{
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256),
			},
		}

		payload, err := quicwire.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSImportKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSGetKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	// Pre-create a key
	mockKMS.keys["test-key-123"] = &pb.KeyHandle{KeyId: "test-key-123", Version: 1}
	mockKMS.metadata["test-key-123"] = &pb.KeyMetadata{KeyId: "test-key-123", Name: "test-key"}

	t.Run("success", func(t *testing.T) {
		getReq := KMSGetKeyRequest{KeyId: "test-key-123"}

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
		assert.Equal(t, "test-key-123", getResp.Key.KeyId)
	})

	t.Run("missing key_id", func(t *testing.T) {
		getReq := KMSGetKeyRequest{}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "key_id")
	})

	t.Run("key not found", func(t *testing.T) {
		getReq := KMSGetKeyRequest{KeyId: "nonexistent"}

		payload, err := quicwire.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	})
}

// TestHandleKMSErrorClasses: each QUIC KMS handler answers a failed call with
// the QUIC status for the error's class (#304), the class gRPC answers, and an
// error that names no class with InternalError.
func TestHandleKMSErrorClasses(t *testing.T) {
	classes := []struct {
		name string
		err  error
		want byte
	}{
		{"not found", status.Error(codes.NotFound, "no key"), quicwire.StatusNotFound},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad key id"), quicwire.StatusInvalidArgument},
		{"already exists", status.Error(codes.AlreadyExists, "dup"), quicwire.StatusAlreadyExists},
		{"failed precondition", status.Error(codes.FailedPrecondition, "disabled"), quicwire.StatusFailedPrecondition},
		{"permission denied", status.Error(codes.PermissionDenied, "no"), quicwire.StatusPermissionDenied},
		{"unimplemented", status.Error(codes.Unimplemented, "later"), quicwire.StatusNotImplemented},
		{"unavailable", status.Error(codes.Unavailable, "down"), quicwire.StatusUnavailable},
		{"no class", errors.New("key not found"), quicwire.StatusInternalError},
	}
	calls := []struct {
		name    string
		request func(t *testing.T) *quicwire.Request
	}{
		{"GetKey", func(t *testing.T) *quicwire.Request {
			payload, err := quicwire.EncodePayload(KMSGetKeyRequest{KeyId: "k"})
			require.NoError(t, err)
			return &quicwire.Request{Opcode: quicwire.OpKMSGetKey, Payload: payload}
		}},
		{"ListKeys", func(t *testing.T) *quicwire.Request {
			return &quicwire.Request{Opcode: quicwire.OpKMSListKeys}
		}},
		{"GetKeyMetadata", func(t *testing.T) *quicwire.Request {
			return kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetKeyMetadata,
				&KMSGetKeyMetadataRequest{KeyID: "k"})
		}},
	}
	for _, call := range calls {
		for _, class := range classes {
			t.Run(call.name+"/"+class.name, func(t *testing.T) {
				svc := newMockKMSService()
				svc.shouldErr = true
				svc.errToReturn = class.err
				handler := newTestQUICServiceHandler(logging.DefaultLogger(), WithQUICKMSService(svc))

				resp := handler.HandleRequest(context.Background(), call.request(t))
				assert.Equal(t, class.want, resp.Status)
			})
		}
	}
}

func TestHandleKMSListKeys(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	// Pre-create some keys
	mockKMS.keys["key-1"] = &pb.KeyHandle{KeyId: "key-1"}
	mockKMS.keys["key-2"] = &pb.KeyHandle{KeyId: "key-2"}

	t.Run("success with empty payload", func(t *testing.T) {
		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSListKeys,
			Payload: nil,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var listResp KMSListKeysResponse
		err := quicwire.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)
		assert.Equal(t, int32(2), listResp.TotalCount)
	})

	t.Run("success with pagination", func(t *testing.T) {
		listReq := KMSListKeysRequest{
			Limit:  10,
			Cursor: "",
		}

		payload, err := quicwire.EncodePayload(listReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSListKeys,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
	})
}

func TestHandleKMSDeleteKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	mockKMS.keys["delete-me"] = &pb.KeyHandle{KeyId: "delete-me"}

	t.Run("success", func(t *testing.T) {
		deleteReq := KMSDeleteKeyRequest{
			KeyId:             "delete-me",
			PendingWindowDays: 7,
			Force:             false,
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
		assert.Equal(t, int32(platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION), deleteResp.KeyStatus)
	})

	t.Run("missing key_id", func(t *testing.T) {
		deleteReq := KMSDeleteKeyRequest{}

		payload, err := quicwire.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSDeleteKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSRotateKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	mockKMS.keys["rotate-me"] = &pb.KeyHandle{KeyId: "rotate-me", Version: 1}

	t.Run("success", func(t *testing.T) {
		rotateReq := KMSRotateKeyRequest{
			KeyId:            "rotate-me",
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
		assert.Equal(t, uint64(1), rotateResp.OldVersion)
		assert.Equal(t, uint64(2), rotateResp.NewVersion)
	})

	t.Run("missing key_id", func(t *testing.T) {
		rotateReq := KMSRotateKeyRequest{}

		payload, err := quicwire.EncodePayload(rotateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRotateKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSUpdateKeyStatus(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	mockKMS.keys["status-key"] = &pb.KeyHandle{KeyId: "status-key", Version: 1}

	t.Run("success", func(t *testing.T) {
		updateReq := KMSUpdateKeyStatusRequest{
			KeyId:   "status-key",
			Version: 1,
			Status:  int32(platformv1.KeyStatus_KEY_STATUS_DISABLED),
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
		assert.Equal(t, int32(platformv1.KeyStatus_KEY_STATUS_DISABLED), updateResp.KeyStatus)
	})

	t.Run("missing key_id", func(t *testing.T) {
		updateReq := KMSUpdateKeyStatusRequest{
			Status: int32(platformv1.KeyStatus_KEY_STATUS_DISABLED),
		}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSUpdateKeyStatus,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing status", func(t *testing.T) {
		updateReq := KMSUpdateKeyStatusRequest{KeyId: "status-key"}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSUpdateKeyStatus,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("unsupported status", func(t *testing.T) {
		updateReq := KMSUpdateKeyStatusRequest{
			KeyId:  "status-key",
			Status: int32(platformv1.KeyStatus_KEY_STATUS_PENDING_IMPORT),
		}

		payload, err := quicwire.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSUpdateKeyStatus,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSExportKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	mockKMS.keys["export-key"] = &pb.KeyHandle{KeyId: "export-key"}

	t.Run("success", func(t *testing.T) {
		exportReq := KMSExportKeyRequest{
			KeyId:             "export-key",
			WrappingKeyId:     "wrapping-key",
			WrappingAlgorithm: int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_KWP),
			Format:            int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_RAW),
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
		assert.NotEmpty(t, exportResp.WrappedMaterial)
		assert.Equal(t, int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_KWP), exportResp.WrappingAlgorithm)
		assert.Equal(t, int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_RAW), exportResp.Format)
	})

	t.Run("missing key_id", func(t *testing.T) {
		exportReq := KMSExportKeyRequest{}

		payload, err := quicwire.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSExportKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("unsupported export format", func(t *testing.T) {
		exportReq := KMSExportKeyRequest{
			KeyId:  "export-key",
			Format: int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PKCS8),
		}

		payload, err := quicwire.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSExportKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSGetKeyVersions(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		versionsReq := KMSGetKeyVersionsRequest{
			KeyId: "versioned-key",
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
		assert.NotEmpty(t, versionsResp.Versions)
		assert.Equal(t, int32(platformv1.KeyStatus_KEY_STATUS_ENABLED), versionsResp.Versions[0].Status)
		assert.Equal(t, int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256), versionsResp.Versions[0].Algorithm)
	})

	t.Run("missing key_id", func(t *testing.T) {
		versionsReq := KMSGetKeyVersionsRequest{}

		payload, err := quicwire.EncodePayload(versionsReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGetKeyVersions,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSBackendStatus(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBackendStatus,
			Payload: nil,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var statusResp KMSBackendStatusResponse
		err := quicwire.DecodePayload(resp.Payload, &statusResp)
		require.NoError(t, err)
		assert.Equal(t, "quicbaas", statusResp.BackendType)
		assert.Equal(t, "healthy", statusResp.BackendStatus)
		assert.NotNil(t, statusResp.Capabilities)
	})
}

func TestHandleKMSEncrypt(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		encryptReq := KMSEncryptRequest{
			KeyId:     "encrypt-key",
			Plaintext: []byte("secret data"),
			Context:   []byte("aad"),
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
		assert.NotEmpty(t, encryptResp.Ciphertext)
	})

	t.Run("missing key_id", func(t *testing.T) {
		encryptReq := KMSEncryptRequest{
			Plaintext: []byte("secret data"),
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

	t.Run("missing plaintext", func(t *testing.T) {
		encryptReq := KMSEncryptRequest{
			KeyId: "encrypt-key",
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
}

func TestHandleKMSDecrypt(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		decryptReq := KMSDecryptRequest{
			KeyId:      "decrypt-key",
			Ciphertext: []byte("encrypted-data"),
			Context:    []byte("aad"),
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
		assert.NotEmpty(t, decryptResp.Plaintext)
	})

	t.Run("missing key_id", func(t *testing.T) {
		decryptReq := KMSDecryptRequest{
			Ciphertext: []byte("encrypted-data"),
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

	t.Run("missing ciphertext", func(t *testing.T) {
		decryptReq := KMSDecryptRequest{
			KeyId: "decrypt-key",
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
}

func TestHandleKMSSign(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		signReq := KMSSignRequest{
			KeyId:         "sign-key",
			Message:       []byte("message to sign"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256),
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
		assert.NotEmpty(t, signResp.Signature)
		assert.Equal(t, int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256), signResp.HashAlgorithm)

		require.NotNil(t, mockKMS.lastSignReq)
		assert.Equal(t, pb.HashAlgorithm_HASH_ALG_SHA256, mockKMS.lastSignReq.GetHashAlgorithm(),
			"platform.v1 SHA256 must convert to the quicbaas pb SHA256 value")
	})

	t.Run("pre_hashed round-trips to the backend", func(t *testing.T) {
		signReq := KMSSignRequest{
			KeyId:         "sign-key",
			Message:       []byte{0xde, 0xad, 0xbe, 0xef},
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256),
			PreHashed:     true,
		}

		payload, err := quicwire.EncodePayload(signReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSSign,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)
		require.NotNil(t, mockKMS.lastSignReq)
		assert.True(t, mockKMS.lastSignReq.GetPreHashed(),
			"pre_hashed must survive the QUIC wire decode and pb conversion")
	})

	t.Run("missing key_id", func(t *testing.T) {
		signReq := KMSSignRequest{
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

	t.Run("missing message", func(t *testing.T) {
		signReq := KMSSignRequest{
			KeyId: "sign-key",
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

	t.Run("unsupported hash algorithm", func(t *testing.T) {
		signReq := KMSSignRequest{
			KeyId:         "sign-key",
			Message:       []byte("message"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA1),
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
}

func TestHandleKMSVerify(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		verifyReq := KMSVerifyRequest{
			KeyId:         "verify-key",
			Message:       []byte("signed message"),
			Signature:     []byte("signature"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256),
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

	t.Run("missing key_id", func(t *testing.T) {
		verifyReq := KMSVerifyRequest{
			Message:   []byte("message"),
			Signature: []byte("sig"),
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

	t.Run("missing message", func(t *testing.T) {
		verifyReq := KMSVerifyRequest{
			KeyId:     "verify-key",
			Signature: []byte("sig"),
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

	t.Run("missing signature", func(t *testing.T) {
		verifyReq := KMSVerifyRequest{
			KeyId:   "verify-key",
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
	})
}

func TestHandleKMSGenerateRandom(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		randomReq := KMSGenerateRandomRequest{
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
		assert.Len(t, randomResp.RandomBytes, 32)
	})

	t.Run("invalid num_bytes", func(t *testing.T) {
		randomReq := KMSGenerateRandomRequest{
			NumBytes: 0,
		}

		payload, err := quicwire.EncodePayload(randomReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateRandom,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSHash(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		hashReq := KMSHashRequest{
			Data:      []byte("data to hash"),
			Algorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256),
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
		assert.Equal(t, int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256), hashResp.Algorithm)
	})

	t.Run("missing data", func(t *testing.T) {
		hashReq := KMSHashRequest{
			Algorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256),
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
}

func TestHandleKMSHMAC(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		hmacReq := KMSHMACRequest{
			KeyId:         "hmac-key",
			Message:       []byte("message"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384),
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
		assert.Equal(t, "hmac-key", hmacResp.KeyId)
		assert.NotEmpty(t, hmacResp.Hmac)
		assert.Equal(t, int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384), hmacResp.HashAlgorithm)

		require.NotNil(t, mockKMS.lastHMACReq)
		assert.Equal(t, pb.HashAlgorithm_HASH_ALG_SHA384, mockKMS.lastHMACReq.GetHashAlgorithm(),
			"platform.v1 SHA384 must convert to the quicbaas pb SHA384 value")
	})

	t.Run("missing key_id", func(t *testing.T) {
		hmacReq := KMSHMACRequest{
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

	t.Run("missing message", func(t *testing.T) {
		hmacReq := KMSHMACRequest{
			KeyId: "hmac-key",
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

	t.Run("unsupported hash algorithm", func(t *testing.T) {
		hmacReq := KMSHMACRequest{
			KeyId:         "hmac-key",
			Message:       []byte("message"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_512),
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

	t.Run("decoding error", func(t *testing.T) {
		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHMAC,
			Payload: []byte{0xFF, 0xFE, 0xFD},
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("service error", func(t *testing.T) {
		mockKMS.shouldErr = true
		mockKMS.errToReturn = errors.New("hmac failed")
		defer func() { mockKMS.shouldErr = false }()

		hmacReq := KMSHMACRequest{
			KeyId:   "hmac-key",
			Message: []byte("message"),
		}

		payload, err := quicwire.EncodePayload(hmacReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSHMAC,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	})
}

func TestHandleKMSVerifyHMAC(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		verifyReq := KMSVerifyHMACRequest{
			KeyId:         "hmac-key",
			Message:       []byte("message"),
			Hmac:          []byte("mac"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512),
			KeyVersion:    3,
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
		assert.Equal(t, uint64(3), verifyResp.KeyVersion)

		require.NotNil(t, mockKMS.lastVerifyHMACReq)
		assert.Equal(t, pb.HashAlgorithm_HASH_ALG_SHA512, mockKMS.lastVerifyHMACReq.GetHashAlgorithm(),
			"platform.v1 SHA512 must convert to the quicbaas pb SHA512 value")
		assert.Equal(t, []byte("mac"), mockKMS.lastVerifyHMACReq.GetHmac())
		assert.Equal(t, uint64(3), mockKMS.lastVerifyHMACReq.GetKeyVersion())
	})

	t.Run("missing key_id", func(t *testing.T) {
		verifyReq := KMSVerifyHMACRequest{
			Message: []byte("message"),
			Hmac:    []byte("mac"),
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

	t.Run("missing hmac", func(t *testing.T) {
		verifyReq := KMSVerifyHMACRequest{
			KeyId:   "hmac-key",
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
	})

	t.Run("service error", func(t *testing.T) {
		mockKMS.shouldErr = true
		mockKMS.errToReturn = errors.New("verify hmac failed")
		defer func() { mockKMS.shouldErr = false }()

		verifyReq := KMSVerifyHMACRequest{
			KeyId:   "hmac-key",
			Message: []byte("message"),
			Hmac:    []byte("mac"),
		}

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

func TestHandleKMSRewrap(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		rewrapReq := KMSRewrapRequest{
			KeyId:      "rewrap-key",
			Ciphertext: []byte("old-ct"),
			Context:    []byte("aad"),
			Nonce:      []byte("nonce"),
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
		assert.Equal(t, "rewrap-key", rewrapResp.KeyId)
		assert.Equal(t, uint64(1), rewrapResp.SourceVersion)
		assert.Equal(t, uint64(2), rewrapResp.TargetVersion)
		assert.NotEmpty(t, rewrapResp.Ciphertext)

		require.NotNil(t, mockKMS.lastRewrapReq)
		assert.Equal(t, []byte("old-ct"), mockKMS.lastRewrapReq.GetCiphertext())
		assert.Equal(t, []byte("aad"), mockKMS.lastRewrapReq.GetContext())
	})

	t.Run("missing key_id", func(t *testing.T) {
		rewrapReq := KMSRewrapRequest{
			Ciphertext: []byte("old-ct"),
		}

		payload, err := quicwire.EncodePayload(rewrapReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRewrap,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing ciphertext", func(t *testing.T) {
		rewrapReq := KMSRewrapRequest{
			KeyId: "rewrap-key",
		}

		payload, err := quicwire.EncodePayload(rewrapReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRewrap,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("explicit source_version rejected", func(t *testing.T) {
		rewrapReq := KMSRewrapRequest{
			KeyId:         "rewrap-key",
			Ciphertext:    []byte("old-ct"),
			SourceVersion: 5,
		}

		payload, err := quicwire.EncodePayload(rewrapReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSRewrap,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "source_version")
	})

	t.Run("service error", func(t *testing.T) {
		mockKMS.shouldErr = true
		mockKMS.errToReturn = errors.New("rewrap failed")
		defer func() { mockKMS.shouldErr = false }()

		rewrapReq := KMSRewrapRequest{
			KeyId:      "rewrap-key",
			Ciphertext: []byte("old-ct"),
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

func TestHandleKMSBatchEncrypt(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success with item correlation", func(t *testing.T) {
		mockKMS.batchEncryptErrors = []string{"", "encryption blew up"}
		defer func() { mockKMS.batchEncryptErrors = nil }()

		batchReq := KMSBatchEncryptRequest{
			KeyId: "batch-key",
			Items: []*KMSBatchEncryptItem{
				{ItemId: "item-1", Plaintext: []byte("p1"), Context: []byte("c1")},
				{ItemId: "item-2", Plaintext: []byte("p2")},
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
		assert.Equal(t, "batch-key", batchResp.KeyId)
		assert.Equal(t, int32(1), batchResp.SuccessCount)
		assert.Equal(t, int32(1), batchResp.FailureCount)
		require.Len(t, batchResp.Results, 2)

		assert.Equal(t, "item-1", batchResp.Results[0].ItemId)
		require.NotNil(t, batchResp.Results[0].Status)
		assert.True(t, batchResp.Results[0].Status.Success)
		assert.NotEmpty(t, batchResp.Results[0].Ciphertext)
		assert.Equal(t, uint64(3), batchResp.Results[0].KeyVersion)

		assert.Equal(t, "item-2", batchResp.Results[1].ItemId)
		require.NotNil(t, batchResp.Results[1].Status)
		assert.False(t, batchResp.Results[1].Status.Success)
		assert.Equal(t, "encryption blew up", batchResp.Results[1].Status.Message)

		require.NotNil(t, mockKMS.lastBatchEncryptReq)
		require.Len(t, mockKMS.lastBatchEncryptReq.GetItems(), 2)
		assert.Equal(t, []byte("p1"), mockKMS.lastBatchEncryptReq.GetItems()[0].GetPlaintext())
		assert.Equal(t, []byte("c1"), mockKMS.lastBatchEncryptReq.GetItems()[0].GetContext())
	})

	t.Run("missing key_id", func(t *testing.T) {
		batchReq := KMSBatchEncryptRequest{
			Items: []*KMSBatchEncryptItem{{ItemId: "item-1", Plaintext: []byte("p1")}},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchEncrypt,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing items", func(t *testing.T) {
		batchReq := KMSBatchEncryptRequest{KeyId: "batch-key"}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchEncrypt,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("client-supplied nonce rejected", func(t *testing.T) {
		batchReq := KMSBatchEncryptRequest{
			KeyId: "batch-key",
			Items: []*KMSBatchEncryptItem{
				{ItemId: "item-1", Plaintext: []byte("p1"), Nonce: []byte("client-nonce")},
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
		assert.Contains(t, string(resp.Payload), "nonce")
	})

	t.Run("decoding error", func(t *testing.T) {
		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchEncrypt,
			Payload: []byte{0xFF, 0xFE, 0xFD},
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("service error", func(t *testing.T) {
		mockKMS.shouldErr = true
		mockKMS.errToReturn = errors.New("batch encrypt failed")
		defer func() { mockKMS.shouldErr = false }()

		batchReq := KMSBatchEncryptRequest{
			KeyId: "batch-key",
			Items: []*KMSBatchEncryptItem{{ItemId: "item-1", Plaintext: []byte("p1")}},
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

func TestHandleKMSBatchDecrypt(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success with item correlation", func(t *testing.T) {
		mockKMS.batchDecryptErrors = []string{"", "decryption blew up"}
		defer func() { mockKMS.batchDecryptErrors = nil }()

		batchReq := KMSBatchDecryptRequest{
			KeyId: "batch-key",
			Items: []*KMSBatchDecryptItem{
				{ItemId: "item-1", Ciphertext: []byte("e1"), Context: []byte("c1"), Nonce: []byte("n1")},
				{ItemId: "item-2", Ciphertext: []byte("e2")},
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
		assert.Equal(t, "batch-key", batchResp.KeyId)
		assert.Equal(t, int32(1), batchResp.SuccessCount)
		assert.Equal(t, int32(1), batchResp.FailureCount)
		require.Len(t, batchResp.Results, 2)

		assert.Equal(t, "item-1", batchResp.Results[0].ItemId)
		require.NotNil(t, batchResp.Results[0].Status)
		assert.True(t, batchResp.Results[0].Status.Success)
		assert.NotEmpty(t, batchResp.Results[0].Plaintext)

		assert.Equal(t, "item-2", batchResp.Results[1].ItemId)
		require.NotNil(t, batchResp.Results[1].Status)
		assert.False(t, batchResp.Results[1].Status.Success)
		assert.Equal(t, "decryption blew up", batchResp.Results[1].Status.Message)

		require.NotNil(t, mockKMS.lastBatchDecryptReq)
		require.Len(t, mockKMS.lastBatchDecryptReq.GetItems(), 2)
		assert.Equal(t, []byte("e1"), mockKMS.lastBatchDecryptReq.GetItems()[0].GetCiphertext())
		assert.Equal(t, []byte("n1"), mockKMS.lastBatchDecryptReq.GetItems()[0].GetNonce())
	})

	t.Run("missing key_id", func(t *testing.T) {
		batchReq := KMSBatchDecryptRequest{
			Items: []*KMSBatchDecryptItem{{ItemId: "item-1", Ciphertext: []byte("e1")}},
		}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchDecrypt,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing items", func(t *testing.T) {
		batchReq := KMSBatchDecryptRequest{KeyId: "batch-key"}

		payload, err := quicwire.EncodePayload(batchReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchDecrypt,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("per-item key_version rejected", func(t *testing.T) {
		batchReq := KMSBatchDecryptRequest{
			KeyId: "batch-key",
			Items: []*KMSBatchDecryptItem{
				{ItemId: "item-1", Ciphertext: []byte("e1"), KeyVersion: 2},
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
		assert.Contains(t, string(resp.Payload), "key_version")
	})

	t.Run("decoding error", func(t *testing.T) {
		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSBatchDecrypt,
			Payload: []byte{0xFF, 0xFE, 0xFD},
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})

	t.Run("service error", func(t *testing.T) {
		mockKMS.shouldErr = true
		mockKMS.errToReturn = errors.New("batch decrypt failed")
		defer func() { mockKMS.shouldErr = false }()

		batchReq := KMSBatchDecryptRequest{
			KeyId: "batch-key",
			Items: []*KMSBatchDecryptItem{{ItemId: "item-1", Ciphertext: []byte("e1")}},
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

func TestHandleKMSGenerateDataKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockCrypto := newMockCryptoService()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))

	ctx := context.Background()

	t.Run("crypto service not available", func(t *testing.T) {
		handlerNoService := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

		dataKeyReq := KMSGenerateDataKeyQUICRequest{
			KeyId: "kek-key",
		}

		payload, err := quicwire.EncodePayload(dataKeyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateDataKey,
			Payload: payload,
		}
		resp := handlerNoService.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("success", func(t *testing.T) {
		dataKeyReq := KMSGenerateDataKeyQUICRequest{
			KeyId:     "kek-key",
			Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
		}

		payload, err := quicwire.EncodePayload(dataKeyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateDataKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var dataKeyResp KMSGenerateDataKeyQUICResponse
		err = quicwire.DecodePayload(resp.Payload, &dataKeyResp)
		require.NoError(t, err)
		assert.NotEmpty(t, dataKeyResp.PlaintextKey)
		assert.NotEmpty(t, dataKeyResp.EncryptedKey)
	})

	t.Run("missing key_id", func(t *testing.T) {
		dataKeyReq := KMSGenerateDataKeyQUICRequest{}

		payload, err := quicwire.EncodePayload(dataKeyReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateDataKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSGenerateWrappedDataKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockCrypto := newMockCryptoService()
	mockKMS := newMockKMSService()
	handler := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))

	ctx := context.Background()

	t.Run("crypto service not available", func(t *testing.T) {
		handlerNoService := newTestQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

		wrappedReq := KMSGenerateWrappedDataKeyQUICRequest{
			WrappingKeyId: "kek-key",
		}

		payload, err := quicwire.EncodePayload(wrappedReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateWrappedDataKey,
			Payload: payload,
		}
		resp := handlerNoService.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("success", func(t *testing.T) {
		wrappedReq := KMSGenerateWrappedDataKeyQUICRequest{
			WrappingKeyId: "kek-key",
			KeyAlgorithm:  int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
		}

		payload, err := quicwire.EncodePayload(wrappedReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateWrappedDataKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusOK, resp.Status)

		var wrappedResp KMSGenerateWrappedDataKeyQUICResponse
		err = quicwire.DecodePayload(resp.Payload, &wrappedResp)
		require.NoError(t, err)
		assert.NotEmpty(t, wrappedResp.WrappedKey)
	})

	t.Run("missing wrapping_key_id", func(t *testing.T) {
		wrappedReq := KMSGenerateWrappedDataKeyQUICRequest{}

		payload, err := quicwire.EncodePayload(wrappedReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateWrappedDataKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	})

	t.Run("explicit wrapping_algorithm rejected", func(t *testing.T) {
		wrappedReq := KMSGenerateWrappedDataKeyQUICRequest{
			WrappingKeyId:     "kek-key",
			WrappingAlgorithm: int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM),
		}

		payload, err := quicwire.EncodePayload(wrappedReq)
		require.NoError(t, err)

		req := &quicwire.Request{
			Opcode:  quicwire.OpKMSGenerateWrappedDataKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "wrapping_algorithm")
	})
}

// =============================================================================
// Enum Conversion Tests (platform.v1 <-> QuicBaaS pb)
// =============================================================================

func TestPlatformKMSAlgorithmToPb(t *testing.T) {
	testCases := []struct {
		input    platformv1.KMSKeyAlgorithm
		expected pb.KeyAlgorithm
	}{
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305, pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048, pb.KeyAlgorithm_KEY_ALG_RSA_2048},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096, pb.KeyAlgorithm_KEY_ALG_RSA_4096},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256, pb.KeyAlgorithm_KEY_ALG_ECDSA_P256},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384, pb.KeyAlgorithm_KEY_ALG_ECDSA_P384},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519, pb.KeyAlgorithm_KEY_ALG_ED25519},
	}

	for _, tc := range testCases {
		t.Run(tc.input.String(), func(t *testing.T) {
			result, err := platformKMSAlgorithmToPb(int32(tc.input))
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}

	unsupported := []platformv1.KMSKeyAlgorithm{
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM2,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM3,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM5,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_3072,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P521,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256,
	}
	for _, alg := range unsupported {
		t.Run("unsupported_"+alg.String(), func(t *testing.T) {
			_, err := platformKMSAlgorithmToPb(int32(alg))
			require.Error(t, err)
			var unsupportedErr ErrKMSUnsupportedValue
			assert.ErrorAs(t, err, &unsupportedErr)
		})
	}
}

func TestPbKeyAlgorithmToPlatformKMS(t *testing.T) {
	testCases := []struct {
		input    pb.KeyAlgorithm
		expected platformv1.KMSKeyAlgorithm
	}{
		{pb.KeyAlgorithm_KEY_ALG_AES_128_GCM, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128},
		{pb.KeyAlgorithm_KEY_ALG_AES_192_GCM, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192},
		{pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256},
		{pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305},
		{pb.KeyAlgorithm_KEY_ALG_RSA_2048, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048},
		{pb.KeyAlgorithm_KEY_ALG_RSA_3072, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_3072},
		{pb.KeyAlgorithm_KEY_ALG_RSA_4096, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096},
		{pb.KeyAlgorithm_KEY_ALG_ECDSA_P256, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256},
		{pb.KeyAlgorithm_KEY_ALG_ECDSA_P384, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384},
		{pb.KeyAlgorithm_KEY_ALG_ECDSA_P521, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P521},
		{pb.KeyAlgorithm_KEY_ALG_ED25519, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519},
		{pb.KeyAlgorithm_KEY_ALG_HMAC_SHA256, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256},
		{pb.KeyAlgorithm_KEY_ALG_HMAC_SHA384, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA384},
		{pb.KeyAlgorithm_KEY_ALG_HMAC_SHA512, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA512},
		{pb.KeyAlgorithm_KEY_ALG_ED448, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED},
		{pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED},
		{pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED, platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED},
	}

	for _, tc := range testCases {
		t.Run(tc.input.String(), func(t *testing.T) {
			assert.Equal(t, int32(tc.expected), pbKeyAlgorithmToPlatformKMS(tc.input))
		})
	}
}

func TestPlatformKMSUsagesToPb(t *testing.T) {
	t.Run("supported usages", func(t *testing.T) {
		result, err := platformKMSUsagesToPb([]int32{
			int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT),
			int32(platformv1.KeyUsage_KEY_USAGE_DECRYPT),
			int32(platformv1.KeyUsage_KEY_USAGE_SIGN),
			int32(platformv1.KeyUsage_KEY_USAGE_VERIFY),
			int32(platformv1.KeyUsage_KEY_USAGE_WRAP),
		})
		require.NoError(t, err)
		assert.Equal(t, []pb.KeyUsage{
			pb.KeyUsage_KEY_USAGE_ENCRYPT,
			pb.KeyUsage_KEY_USAGE_DECRYPT,
			pb.KeyUsage_KEY_USAGE_SIGN,
			pb.KeyUsage_KEY_USAGE_VERIFY,
			pb.KeyUsage_KEY_USAGE_WRAP_KEY,
		}, result)
	})

	// QUIC carries the platform HMAC usage to the go-quicbaas MAC usages,
	// which the gRPC adapter generates as sign and verify.
	t.Run("hmac maps to generate and verify mac", func(t *testing.T) {
		result, err := platformKMSUsagesToPb([]int32{int32(platformv1.KeyUsage_KEY_USAGE_HMAC)})
		require.NoError(t, err)
		assert.Equal(t, []pb.KeyUsage{
			pb.KeyUsage_KEY_USAGE_GENERATE_MAC,
			pb.KeyUsage_KEY_USAGE_VERIFY_MAC,
		}, result)
	})

	t.Run("unsupported usages rejected", func(t *testing.T) {
		for _, usage := range []platformv1.KeyUsage{
			platformv1.KeyUsage_KEY_USAGE_UNSPECIFIED,
			platformv1.KeyUsage_KEY_USAGE_UNWRAP,
			platformv1.KeyUsage_KEY_USAGE_DERIVE,
		} {
			_, err := platformKMSUsagesToPb([]int32{int32(usage)})
			require.Error(t, err, "usage %v should be rejected", usage)
			var unsupportedErr ErrKMSUnsupportedValue
			assert.ErrorAs(t, err, &unsupportedErr)
		}
	})
}

func TestPbKeyUsagesToPlatformKMS(t *testing.T) {
	result := pbKeyUsagesToPlatformKMS([]pb.KeyUsage{
		pb.KeyUsage_KEY_USAGE_ENCRYPT,
		pb.KeyUsage_KEY_USAGE_DECRYPT,
		pb.KeyUsage_KEY_USAGE_SIGN,
		pb.KeyUsage_KEY_USAGE_VERIFY,
		pb.KeyUsage_KEY_USAGE_WRAP_KEY,
		pb.KeyUsage_KEY_USAGE_DERIVE_KEY,
		pb.KeyUsage_KEY_USAGE_GENERATE_MAC,
		pb.KeyUsage_KEY_USAGE_VERIFY_MAC,
		pb.KeyUsage_KEY_USAGE_UNSPECIFIED,
	})
	assert.Equal(t, []int32{
		int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT),
		int32(platformv1.KeyUsage_KEY_USAGE_DECRYPT),
		int32(platformv1.KeyUsage_KEY_USAGE_SIGN),
		int32(platformv1.KeyUsage_KEY_USAGE_VERIFY),
		int32(platformv1.KeyUsage_KEY_USAGE_WRAP),
		int32(platformv1.KeyUsage_KEY_USAGE_DERIVE),
		int32(platformv1.KeyUsage_KEY_USAGE_HMAC),
		int32(platformv1.KeyUsage_KEY_USAGE_HMAC),
		int32(platformv1.KeyUsage_KEY_USAGE_UNSPECIFIED),
	}, result)
}

func TestPlatformKMSStatusToPb(t *testing.T) {
	testCases := []struct {
		input    platformv1.KeyStatus
		expected pb.KeyStatus
	}{
		{platformv1.KeyStatus_KEY_STATUS_ENABLED, pb.KeyStatus_KEY_STATUS_ENABLED},
		{platformv1.KeyStatus_KEY_STATUS_DISABLED, pb.KeyStatus_KEY_STATUS_DISABLED},
		{platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION, pb.KeyStatus_KEY_STATUS_PENDING_DELETION},
		{platformv1.KeyStatus_KEY_STATUS_DESTROYED, pb.KeyStatus_KEY_STATUS_DELETED},
	}

	for _, tc := range testCases {
		t.Run(tc.input.String(), func(t *testing.T) {
			result, err := platformKMSStatusToPb(int32(tc.input))
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}

	t.Run("unsupported statuses rejected", func(t *testing.T) {
		for _, status := range []platformv1.KeyStatus{
			platformv1.KeyStatus_KEY_STATUS_UNSPECIFIED,
			platformv1.KeyStatus_KEY_STATUS_PENDING_IMPORT,
		} {
			_, err := platformKMSStatusToPb(int32(status))
			require.Error(t, err, "status %v should be rejected", status)
		}
	})
}

func TestPbKeyStatusToPlatformKMS(t *testing.T) {
	testCases := []struct {
		input    pb.KeyStatus
		expected platformv1.KeyStatus
	}{
		{pb.KeyStatus_KEY_STATUS_ENABLED, platformv1.KeyStatus_KEY_STATUS_ENABLED},
		{pb.KeyStatus_KEY_STATUS_ROTATING, platformv1.KeyStatus_KEY_STATUS_ENABLED},
		{pb.KeyStatus_KEY_STATUS_DISABLED, platformv1.KeyStatus_KEY_STATUS_DISABLED},
		{pb.KeyStatus_KEY_STATUS_COMPROMISED, platformv1.KeyStatus_KEY_STATUS_DISABLED},
		{pb.KeyStatus_KEY_STATUS_PENDING_DELETION, platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION},
		{pb.KeyStatus_KEY_STATUS_DELETED, platformv1.KeyStatus_KEY_STATUS_DESTROYED},
		{pb.KeyStatus_KEY_STATUS_UNSPECIFIED, platformv1.KeyStatus_KEY_STATUS_UNSPECIFIED},
	}

	for _, tc := range testCases {
		t.Run(tc.input.String(), func(t *testing.T) {
			assert.Equal(t, int32(tc.expected), pbKeyStatusToPlatformKMS(tc.input))
		})
	}
}

func TestPlatformKMSHashToPb(t *testing.T) {
	testCases := []struct {
		input    platformv1.HashAlgorithm
		expected pb.HashAlgorithm
	}{
		{platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, pb.HashAlgorithm_HASH_ALG_SHA256},
		{platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256, pb.HashAlgorithm_HASH_ALG_SHA256},
		{platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384, pb.HashAlgorithm_HASH_ALG_SHA384},
		{platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512, pb.HashAlgorithm_HASH_ALG_SHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.input.String(), func(t *testing.T) {
			result, err := platformKMSHashToPb(int32(tc.input))
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}

	t.Run("unsupported hashes rejected", func(t *testing.T) {
		for _, alg := range []platformv1.HashAlgorithm{
			platformv1.HashAlgorithm_HASH_ALGORITHM_SHA1,
			platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_256,
			platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_384,
			platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_512,
		} {
			_, err := platformKMSHashToPb(int32(alg))
			require.Error(t, err, "hash %v should be rejected", alg)
		}
	})
}

func TestPbHashAlgorithmToPlatformKMS(t *testing.T) {
	testCases := []struct {
		input    pb.HashAlgorithm
		expected platformv1.HashAlgorithm
	}{
		{pb.HashAlgorithm_HASH_ALG_SHA256, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256},
		{pb.HashAlgorithm_HASH_ALG_SHA384, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384},
		{pb.HashAlgorithm_HASH_ALG_SHA512, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512},
		{pb.HashAlgorithm_HASH_ALG_SHA3_256, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_256},
		{pb.HashAlgorithm_HASH_ALG_SHA3_384, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_384},
		{pb.HashAlgorithm_HASH_ALG_SHA3_512, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_512},
		{pb.HashAlgorithm_HASH_ALG_BLAKE2B_256, platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED},
		{pb.HashAlgorithm_HASH_ALG_UNSPECIFIED, platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED},
	}

	for _, tc := range testCases {
		t.Run(tc.input.String(), func(t *testing.T) {
			assert.Equal(t, int32(tc.expected), pbHashAlgorithmToPlatformKMS(tc.input))
		})
	}
}

func TestPlatformKMSExportFormatToPb(t *testing.T) {
	testCases := []struct {
		input    platformv1.KeyExportFormat
		expected pb.ExportFormat
	}{
		{platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_UNSPECIFIED, pb.ExportFormat_EXPORT_FORMAT_RAW},
		{platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_RAW, pb.ExportFormat_EXPORT_FORMAT_RAW},
		{platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_JWK, pb.ExportFormat_EXPORT_FORMAT_JWK},
		{platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM, pb.ExportFormat_EXPORT_FORMAT_PEM},
	}

	for _, tc := range testCases {
		t.Run(tc.input.String(), func(t *testing.T) {
			result, err := platformKMSExportFormatToPb(int32(tc.input))
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}

	t.Run("pkcs8 rejected", func(t *testing.T) {
		_, err := platformKMSExportFormatToPb(int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PKCS8))
		require.Error(t, err)
	})
}

func TestPbExportFormatToPlatformKMS(t *testing.T) {
	assert.Equal(t, int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_RAW),
		pbExportFormatToPlatformKMS(pb.ExportFormat_EXPORT_FORMAT_RAW))
	assert.Equal(t, int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_JWK),
		pbExportFormatToPlatformKMS(pb.ExportFormat_EXPORT_FORMAT_JWK))
	assert.Equal(t, int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM),
		pbExportFormatToPlatformKMS(pb.ExportFormat_EXPORT_FORMAT_PEM))
	assert.Equal(t, int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_UNSPECIFIED),
		pbExportFormatToPlatformKMS(pb.ExportFormat_EXPORT_FORMAT_UNSPECIFIED))
}

func TestPlatformKMSWrappingToPb(t *testing.T) {
	testCases := []struct {
		input    platformv1.WrappingAlgorithm
		expected pb.WrappingAlgorithm
	}{
		{platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_UNSPECIFIED, pb.WrappingAlgorithm_WRAP_ALG_UNSPECIFIED},
		{platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA256, pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256},
		{platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA384, pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384},
		{platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA512, pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512},
		{platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM, pb.WrappingAlgorithm_WRAP_ALG_AES_GCM},
		{platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_KWP, pb.WrappingAlgorithm_WRAP_ALG_AES_KWP},
	}

	for _, tc := range testCases {
		t.Run(tc.input.String(), func(t *testing.T) {
			result, err := platformKMSWrappingToPb(int32(tc.input))
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}

	t.Run("unknown value rejected", func(t *testing.T) {
		_, err := platformKMSWrappingToPb(999)
		require.Error(t, err)
	})
}

func TestPbWrappingToPlatformKMS(t *testing.T) {
	assert.Equal(t, int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA256),
		pbWrappingToPlatformKMS(pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256))
	assert.Equal(t, int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM),
		pbWrappingToPlatformKMS(pb.WrappingAlgorithm_WRAP_ALG_AES_GCM))
	assert.Equal(t, int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_KWP),
		pbWrappingToPlatformKMS(pb.WrappingAlgorithm_WRAP_ALG_AES_KWP))
	// AES-KW and ECDH-ES have no platform.v1 equivalent.
	assert.Equal(t, int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_UNSPECIFIED),
		pbWrappingToPlatformKMS(pb.WrappingAlgorithm_WRAP_ALG_AES_KW))
	assert.Equal(t, int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_UNSPECIFIED),
		pbWrappingToPlatformKMS(pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW))
}

func TestStringToKeyUsage(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.KeyUsage
	}{
		{"ENCRYPT", pb.KeyUsage_KEY_USAGE_ENCRYPT},
		{"DECRYPT", pb.KeyUsage_KEY_USAGE_DECRYPT},
		{"SIGN", pb.KeyUsage_KEY_USAGE_SIGN},
		{"VERIFY", pb.KeyUsage_KEY_USAGE_VERIFY},
		{"WRAP", pb.KeyUsage_KEY_USAGE_WRAP_KEY},
		{"DERIVE", pb.KeyUsage_KEY_USAGE_DERIVE_KEY},
		{"MAC", pb.KeyUsage_KEY_USAGE_GENERATE_MAC},
		{"VERIFY_MAC", pb.KeyUsage_KEY_USAGE_VERIFY_MAC},
		{"unknown", pb.KeyUsage_KEY_USAGE_UNSPECIFIED},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToKeyUsage(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestStringsToKeyUsages(t *testing.T) {
	input := []string{"ENCRYPT", "DECRYPT", "unknown"}
	result := stringsToKeyUsages(input)
	assert.Len(t, result, 2)
	assert.Contains(t, result, pb.KeyUsage_KEY_USAGE_ENCRYPT)
	assert.Contains(t, result, pb.KeyUsage_KEY_USAGE_DECRYPT)
}

func TestKeyUsagesToStrings(t *testing.T) {
	input := []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT, pb.KeyUsage_KEY_USAGE_DECRYPT}
	result := keyUsagesToStrings(input)
	assert.Len(t, result, 2)
}

func TestKeyStatusToString(t *testing.T) {
	result := keyStatusToString(pb.KeyStatus_KEY_STATUS_ENABLED)
	assert.NotEmpty(t, result)
}

func TestConvertKeyHandleToQUIC(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		result := convertKeyHandleToQUIC(nil)
		assert.Nil(t, result)
	})

	t.Run("converts correctly", func(t *testing.T) {
		handle := &pb.KeyHandle{
			KeyId:     "key-123",
			Version:   2,
			Algorithm: pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
			Status:    pb.KeyStatus_KEY_STATUS_ENABLED,
			CreatedAt: time.Now().Unix(),
		}
		result := convertKeyHandleToQUIC(handle)
		require.NotNil(t, result)
		assert.Equal(t, "key-123", result.KeyId)
		assert.Equal(t, uint64(2), result.Version)
		assert.Equal(t, int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256), result.Algorithm)
		assert.Equal(t, int32(platformv1.KeyStatus_KEY_STATUS_ENABLED), result.Status)
	})
}

func TestConvertKeyMetadataToQUIC(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		result := convertKeyMetadataToQUIC(nil)
		assert.Nil(t, result)
	})

	t.Run("converts correctly", func(t *testing.T) {
		meta := &pb.KeyMetadata{
			KeyId:       "key-123",
			Name:        "test-key",
			Description: "Test key",
			Algorithm:   pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
			Status:      pb.KeyStatus_KEY_STATUS_ENABLED,
			Usage:       []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT},
			Version:     1,
		}
		result := convertKeyMetadataToQUIC(meta)
		require.NotNil(t, result)
		assert.Equal(t, "key-123", result.KeyId)
		assert.Equal(t, int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256), result.Algorithm)
		assert.Equal(t, int32(platformv1.KeyStatus_KEY_STATUS_ENABLED), result.Status)
		assert.Equal(t, []int32{int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT)}, result.Usage)
	})
}
