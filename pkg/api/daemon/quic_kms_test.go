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
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock KMS Service
// =============================================================================

type mockKMSService struct {
	keys          map[string]*pb.KeyHandle
	metadata      map[string]*pb.KeyMetadata
	versions      map[string][]*pb.KeyVersionInfo
	shouldErr     bool
	errToReturn   error
	lastOperation string
}

func newMockKMSService() *mockKMSService {
	return &mockKMSService{
		keys:     make(map[string]*pb.KeyHandle),
		metadata: make(map[string]*pb.KeyMetadata),
		versions: make(map[string][]*pb.KeyVersionInfo),
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
		return nil, errors.New("key not found")
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
		return nil, errors.New("key not found")
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
		return nil, errors.New("key not found")
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
		return nil, errors.New("key not found")
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
		return nil, errors.New("key not found")
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
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()

	testCases := []struct {
		name   string
		opcode byte
	}{
		{"GenerateKey", quic.OpKMSGenerateKey},
		{"ImportKey", quic.OpKMSImportKey},
		{"GetKey", quic.OpKMSGetKey},
		{"ListKeys", quic.OpKMSListKeys},
		{"DeleteKey", quic.OpKMSDeleteKey},
		{"RotateKey", quic.OpKMSRotateKey},
		{"UpdateKeyStatus", quic.OpKMSUpdateKeyStatus},
		{"ExportKey", quic.OpKMSExportKey},
		{"GetKeyVersions", quic.OpKMSGetKeyVersions},
		{"BackendStatus", quic.OpKMSBackendStatus},
		{"Encrypt", quic.OpKMSEncrypt},
		{"Decrypt", quic.OpKMSDecrypt},
		{"Sign", quic.OpKMSSign},
		{"Verify", quic.OpKMSVerify},
		{"GenerateRandom", quic.OpKMSGenerateRandom},
		{"Hash", quic.OpKMSHash},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &quic.Request{
				Opcode:  tc.opcode,
				Payload: []byte{},
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quic.StatusUnavailable, resp.Status)
			assert.Contains(t, string(resp.Payload), "kms")
		})
	}
}

func TestHandleKMSGenerateKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		genReq := KMSGenerateKeyRequest{
			Name:        "test-key",
			Description: "Test encryption key",
			KeySpec: &KMSKeySpecRequest{
				Algorithm: "AES_256_GCM",
				Usage:     []string{"ENCRYPT", "DECRYPT"},
			},
			Tags:  map[string]string{"env": "test"},
			Owner: "test-user",
		}

		payload, err := quic.EncodePayload(genReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGenerateKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var genResp KMSGenerateKeyResponse
		err = quic.DecodePayload(resp.Payload, &genResp)
		require.NoError(t, err)
		assert.NotNil(t, genResp.Key)
		assert.NotEmpty(t, genResp.Key.KeyID)
	})

	t.Run("missing name", func(t *testing.T) {
		genReq := KMSGenerateKeyRequest{
			KeySpec: &KMSKeySpecRequest{
				Algorithm: "AES_256_GCM",
			},
		}

		payload, err := quic.EncodePayload(genReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGenerateKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "name")
	})

	t.Run("missing key_spec", func(t *testing.T) {
		genReq := KMSGenerateKeyRequest{
			Name: "test-key",
		}

		payload, err := quic.EncodePayload(genReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGenerateKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "key_spec")
	})

	t.Run("service error", func(t *testing.T) {
		mockKMS.shouldErr = true
		mockKMS.errToReturn = errors.New("key generation failed")
		defer func() { mockKMS.shouldErr = false }()

		genReq := KMSGenerateKeyRequest{
			Name: "test-key",
			KeySpec: &KMSKeySpecRequest{
				Algorithm: "AES_256_GCM",
			},
		}

		payload, err := quic.EncodePayload(genReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGenerateKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInternalError, resp.Status)
	})
}

func TestHandleKMSImportKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		importReq := KMSImportKeyRequest{
			KeyMaterial: []byte("raw-key-material-32-bytes-long!!"),
			Name:        "imported-key",
			Description: "Imported test key",
		}

		payload, err := quic.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSImportKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var importResp KMSImportKeyResponse
		err = quic.DecodePayload(resp.Payload, &importResp)
		require.NoError(t, err)
		assert.NotNil(t, importResp.Key)
	})

	t.Run("missing key_material", func(t *testing.T) {
		importReq := KMSImportKeyRequest{
			Name: "imported-key",
		}

		payload, err := quic.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSImportKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "key_material")
	})

	t.Run("missing name", func(t *testing.T) {
		importReq := KMSImportKeyRequest{
			KeyMaterial: []byte("raw-key-material"),
		}

		payload, err := quic.EncodePayload(importReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSImportKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "name")
	})
}

func TestHandleKMSGetKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	// Pre-create a key
	mockKMS.keys["test-key-123"] = &pb.KeyHandle{KeyId: "test-key-123", Version: 1}
	mockKMS.metadata["test-key-123"] = &pb.KeyMetadata{KeyId: "test-key-123", Name: "test-key"}

	t.Run("success", func(t *testing.T) {
		getReq := KMSGetKeyRequest{KeyID: "test-key-123"}

		payload, err := quic.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGetKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var getResp KMSGetKeyResponse
		err = quic.DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)
		assert.Equal(t, "test-key-123", getResp.Key.KeyID)
	})

	t.Run("missing key_id", func(t *testing.T) {
		getReq := KMSGetKeyRequest{}

		payload, err := quic.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGetKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "key_id")
	})

	t.Run("key not found", func(t *testing.T) {
		getReq := KMSGetKeyRequest{KeyID: "nonexistent"}

		payload, err := quic.EncodePayload(getReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGetKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusNotFound, resp.Status)
	})
}

func TestHandleKMSListKeys(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	// Pre-create some keys
	mockKMS.keys["key-1"] = &pb.KeyHandle{KeyId: "key-1"}
	mockKMS.keys["key-2"] = &pb.KeyHandle{KeyId: "key-2"}

	t.Run("success with empty payload", func(t *testing.T) {
		req := &quic.Request{
			Opcode:  quic.OpKMSListKeys,
			Payload: nil,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var listResp KMSListKeysResponse
		err := quic.DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)
		assert.Equal(t, int32(2), listResp.TotalCount)
	})

	t.Run("success with pagination", func(t *testing.T) {
		listReq := KMSListKeysRequest{
			Limit:  10,
			Cursor: "",
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

func TestHandleKMSDeleteKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	mockKMS.keys["delete-me"] = &pb.KeyHandle{KeyId: "delete-me"}

	t.Run("success", func(t *testing.T) {
		deleteReq := KMSDeleteKeyRequest{
			KeyID:             "delete-me",
			PendingWindowDays: 7,
			Force:             false,
		}

		payload, err := quic.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSDeleteKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)
	})

	t.Run("missing key_id", func(t *testing.T) {
		deleteReq := KMSDeleteKeyRequest{}

		payload, err := quic.EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSDeleteKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSRotateKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	mockKMS.keys["rotate-me"] = &pb.KeyHandle{KeyId: "rotate-me", Version: 1}

	t.Run("success", func(t *testing.T) {
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

		assert.Equal(t, quic.StatusOK, resp.Status)

		var rotateResp KMSRotateKeyResponse
		err = quic.DecodePayload(resp.Payload, &rotateResp)
		require.NoError(t, err)
		assert.Equal(t, uint64(1), rotateResp.OldVersion)
		assert.Equal(t, uint64(2), rotateResp.NewVersion)
	})

	t.Run("missing key_id", func(t *testing.T) {
		rotateReq := KMSRotateKeyRequest{}

		payload, err := quic.EncodePayload(rotateReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSRotateKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSUpdateKeyStatus(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	mockKMS.keys["status-key"] = &pb.KeyHandle{KeyId: "status-key", Version: 1}

	t.Run("success", func(t *testing.T) {
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

		assert.Equal(t, quic.StatusOK, resp.Status)
	})

	t.Run("missing key_id", func(t *testing.T) {
		updateReq := KMSUpdateKeyStatusRequest{Status: "DISABLED"}

		payload, err := quic.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSUpdateKeyStatus,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing status", func(t *testing.T) {
		updateReq := KMSUpdateKeyStatusRequest{KeyID: "status-key"}

		payload, err := quic.EncodePayload(updateReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSUpdateKeyStatus,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSExportKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	mockKMS.keys["export-key"] = &pb.KeyHandle{KeyId: "export-key"}

	t.Run("success", func(t *testing.T) {
		exportReq := KMSExportKeyRequest{
			KeyID:             "export-key",
			WrappingKeyID:     "wrapping-key",
			WrappingAlgorithm: "AES_KW",
			Format:            "RAW",
		}

		payload, err := quic.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSExportKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var exportResp KMSExportKeyResponse
		err = quic.DecodePayload(resp.Payload, &exportResp)
		require.NoError(t, err)
		assert.NotEmpty(t, exportResp.WrappedMaterial)
	})

	t.Run("missing key_id", func(t *testing.T) {
		exportReq := KMSExportKeyRequest{}

		payload, err := quic.EncodePayload(exportReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSExportKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSGetKeyVersions(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
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

		assert.Equal(t, quic.StatusOK, resp.Status)

		var versionsResp KMSGetKeyVersionsResponse
		err = quic.DecodePayload(resp.Payload, &versionsResp)
		require.NoError(t, err)
		assert.NotEmpty(t, versionsResp.Versions)
	})

	t.Run("missing key_id", func(t *testing.T) {
		versionsReq := KMSGetKeyVersionsRequest{}

		payload, err := quic.EncodePayload(versionsReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGetKeyVersions,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSBackendStatus(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		req := &quic.Request{
			Opcode:  quic.OpKMSBackendStatus,
			Payload: nil,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var statusResp KMSBackendStatusResponse
		err := quic.DecodePayload(resp.Payload, &statusResp)
		require.NoError(t, err)
		assert.Equal(t, "quicbaas", statusResp.BackendType)
		assert.Equal(t, "healthy", statusResp.Status)
		assert.NotNil(t, statusResp.Capabilities)
	})
}

func TestHandleKMSEncrypt(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		encryptReq := KMSEncryptRequest{
			KeyID:     "encrypt-key",
			Plaintext: []byte("secret data"),
			Context:   []byte("aad"),
		}

		payload, err := quic.EncodePayload(encryptReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSEncrypt,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var encryptResp KMSEncryptResponse
		err = quic.DecodePayload(resp.Payload, &encryptResp)
		require.NoError(t, err)
		assert.NotEmpty(t, encryptResp.Ciphertext)
	})

	t.Run("missing key_id", func(t *testing.T) {
		encryptReq := KMSEncryptRequest{
			Plaintext: []byte("secret data"),
		}

		payload, err := quic.EncodePayload(encryptReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSEncrypt,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing plaintext", func(t *testing.T) {
		encryptReq := KMSEncryptRequest{
			KeyID: "encrypt-key",
		}

		payload, err := quic.EncodePayload(encryptReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSEncrypt,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSDecrypt(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		decryptReq := KMSDecryptRequest{
			KeyID:      "decrypt-key",
			Ciphertext: []byte("encrypted-data"),
			Context:    []byte("aad"),
		}

		payload, err := quic.EncodePayload(decryptReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSDecrypt,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var decryptResp KMSDecryptResponse
		err = quic.DecodePayload(resp.Payload, &decryptResp)
		require.NoError(t, err)
		assert.NotEmpty(t, decryptResp.Plaintext)
	})

	t.Run("missing key_id", func(t *testing.T) {
		decryptReq := KMSDecryptRequest{
			Ciphertext: []byte("encrypted-data"),
		}

		payload, err := quic.EncodePayload(decryptReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSDecrypt,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing ciphertext", func(t *testing.T) {
		decryptReq := KMSDecryptRequest{
			KeyID: "decrypt-key",
		}

		payload, err := quic.EncodePayload(decryptReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSDecrypt,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSSign(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		signReq := KMSSignRequest{
			KeyID:         "sign-key",
			Message:       []byte("message to sign"),
			HashAlgorithm: "SHA256",
		}

		payload, err := quic.EncodePayload(signReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSSign,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var signResp KMSSignResponse
		err = quic.DecodePayload(resp.Payload, &signResp)
		require.NoError(t, err)
		assert.NotEmpty(t, signResp.Signature)
	})

	t.Run("missing key_id", func(t *testing.T) {
		signReq := KMSSignRequest{
			Message: []byte("message"),
		}

		payload, err := quic.EncodePayload(signReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSSign,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing message", func(t *testing.T) {
		signReq := KMSSignRequest{
			KeyID: "sign-key",
		}

		payload, err := quic.EncodePayload(signReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSSign,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSVerify(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		verifyReq := KMSVerifyRequest{
			KeyID:         "verify-key",
			Message:       []byte("signed message"),
			Signature:     []byte("signature"),
			HashAlgorithm: "SHA256",
		}

		payload, err := quic.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSVerify,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusOK, resp.Status)

		var verifyResp KMSVerifyResponse
		err = quic.DecodePayload(resp.Payload, &verifyResp)
		require.NoError(t, err)
		assert.True(t, verifyResp.Valid)
	})

	t.Run("missing key_id", func(t *testing.T) {
		verifyReq := KMSVerifyRequest{
			Message:   []byte("message"),
			Signature: []byte("sig"),
		}

		payload, err := quic.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSVerify,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing message", func(t *testing.T) {
		verifyReq := KMSVerifyRequest{
			KeyID:     "verify-key",
			Signature: []byte("sig"),
		}

		payload, err := quic.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSVerify,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing signature", func(t *testing.T) {
		verifyReq := KMSVerifyRequest{
			KeyID:   "verify-key",
			Message: []byte("message"),
		}

		payload, err := quic.EncodePayload(verifyReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSVerify,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSGenerateRandom(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
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

		assert.Equal(t, quic.StatusOK, resp.Status)

		var randomResp KMSGenerateRandomResponse
		err = quic.DecodePayload(resp.Payload, &randomResp)
		require.NoError(t, err)
		assert.Len(t, randomResp.RandomBytes, 32)
	})

	t.Run("invalid num_bytes", func(t *testing.T) {
		randomReq := KMSGenerateRandomRequest{
			NumBytes: 0,
		}

		payload, err := quic.EncodePayload(randomReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGenerateRandom,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSHash(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
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

		assert.Equal(t, quic.StatusOK, resp.Status)

		var hashResp KMSHashResponse
		err = quic.DecodePayload(resp.Payload, &hashResp)
		require.NoError(t, err)
		assert.NotEmpty(t, hashResp.Hash)
	})

	t.Run("missing data", func(t *testing.T) {
		hashReq := KMSHashRequest{
			Algorithm: "SHA256",
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

func TestHandleKMSHMAC_NotImplemented(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSHMAC,
		Payload: nil,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusNotImplemented, resp.Status)
}

func TestHandleKMSVerifyHMAC_NotImplemented(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSVerifyHMAC,
		Payload: nil,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusNotImplemented, resp.Status)
}

func TestHandleKMSRewrap_NotImplemented(t *testing.T) {
	logger := logging.DefaultLogger()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpKMSRewrap,
		Payload: nil,
	}
	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quic.StatusNotImplemented, resp.Status)
}

func TestHandleKMSGenerateDataKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockCrypto := newMockCryptoService()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))

	ctx := context.Background()

	t.Run("crypto service not available", func(t *testing.T) {
		handlerNoService := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

		dataKeyReq := KMSGenerateDataKeyQUICRequest{
			KeyID: "kek-key",
		}

		payload, err := quic.EncodePayload(dataKeyReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGenerateDataKey,
			Payload: payload,
		}
		resp := handlerNoService.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("success", func(t *testing.T) {
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

		assert.Equal(t, quic.StatusOK, resp.Status)

		var dataKeyResp KMSGenerateDataKeyQUICResponse
		err = quic.DecodePayload(resp.Payload, &dataKeyResp)
		require.NoError(t, err)
		assert.NotEmpty(t, dataKeyResp.Plaintext)
		assert.NotEmpty(t, dataKeyResp.CiphertextBlob)
	})

	t.Run("missing key_id", func(t *testing.T) {
		dataKeyReq := KMSGenerateDataKeyQUICRequest{}

		payload, err := quic.EncodePayload(dataKeyReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGenerateDataKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestHandleKMSGenerateWrappedDataKey(t *testing.T) {
	logger := logging.DefaultLogger()
	mockCrypto := newMockCryptoService()
	mockKMS := newMockKMSService()
	handler := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS), WithQUICCryptoService(mockCrypto))

	ctx := context.Background()

	t.Run("crypto service not available", func(t *testing.T) {
		handlerNoService := NewQUICServiceHandler(logger, WithQUICKMSService(mockKMS))

		wrappedReq := KMSGenerateWrappedDataKeyQUICRequest{
			KeyID: "kek-key",
		}

		payload, err := quic.EncodePayload(wrappedReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGenerateWrappedDataKey,
			Payload: payload,
		}
		resp := handlerNoService.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})

	t.Run("success", func(t *testing.T) {
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

		assert.Equal(t, quic.StatusOK, resp.Status)

		var wrappedResp KMSGenerateWrappedDataKeyQUICResponse
		err = quic.DecodePayload(resp.Payload, &wrappedResp)
		require.NoError(t, err)
		assert.NotEmpty(t, wrappedResp.CiphertextBlob)
	})

	t.Run("missing key_id", func(t *testing.T) {
		wrappedReq := KMSGenerateWrappedDataKeyQUICRequest{}

		payload, err := quic.EncodePayload(wrappedReq)
		require.NoError(t, err)

		req := &quic.Request{
			Opcode:  quic.OpKMSGenerateWrappedDataKey,
			Payload: payload,
		}
		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Algorithm Conversion Tests
// =============================================================================

func TestStringToKeyAlgorithm(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.KeyAlgorithm
	}{
		{"AES_128_GCM", pb.KeyAlgorithm_KEY_ALG_AES_128_GCM},
		{"AES128GCM", pb.KeyAlgorithm_KEY_ALG_AES_128_GCM},
		{"AES_192_GCM", pb.KeyAlgorithm_KEY_ALG_AES_192_GCM},
		{"AES_256_GCM", pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
		{"CHACHA20_POLY1305", pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305},
		{"XCHACHA20_POLY1305", pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305},
		{"RSA_2048", pb.KeyAlgorithm_KEY_ALG_RSA_2048},
		{"RSA_3072", pb.KeyAlgorithm_KEY_ALG_RSA_3072},
		{"RSA_4096", pb.KeyAlgorithm_KEY_ALG_RSA_4096},
		{"ECDSA_P256", pb.KeyAlgorithm_KEY_ALG_ECDSA_P256},
		{"P256", pb.KeyAlgorithm_KEY_ALG_ECDSA_P256},
		{"ECDSA_P384", pb.KeyAlgorithm_KEY_ALG_ECDSA_P384},
		{"ECDSA_P521", pb.KeyAlgorithm_KEY_ALG_ECDSA_P521},
		{"ED25519", pb.KeyAlgorithm_KEY_ALG_ED25519},
		{"ED448", pb.KeyAlgorithm_KEY_ALG_ED448},
		{"unknown", pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToKeyAlgorithm(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
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

func TestStringToKeyStatus(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.KeyStatus
	}{
		{"ENABLED", pb.KeyStatus_KEY_STATUS_ENABLED},
		{"DISABLED", pb.KeyStatus_KEY_STATUS_DISABLED},
		{"PENDING_DELETION", pb.KeyStatus_KEY_STATUS_PENDING_DELETION},
		{"DELETED", pb.KeyStatus_KEY_STATUS_DELETED},
		{"ROTATING", pb.KeyStatus_KEY_STATUS_ROTATING},
		{"COMPROMISED", pb.KeyStatus_KEY_STATUS_COMPROMISED},
		{"unknown", pb.KeyStatus_KEY_STATUS_UNSPECIFIED},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToKeyStatus(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestStringToWrappingAlgorithm(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.WrappingAlgorithm
	}{
		{"AES_KW", pb.WrappingAlgorithm_WRAP_ALG_AES_KW},
		{"AES_KWP", pb.WrappingAlgorithm_WRAP_ALG_AES_KWP},
		{"AES_GCM", pb.WrappingAlgorithm_WRAP_ALG_AES_GCM},
		{"RSA_OAEP_SHA256", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256},
		{"RSA_OAEP_SHA384", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384},
		{"RSA_OAEP_SHA512", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512},
		{"ECDH_ES_A256KW", pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW},
		{"unknown", pb.WrappingAlgorithm_WRAP_ALG_UNSPECIFIED},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToWrappingAlgorithm(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestStringToExportFormat(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.ExportFormat
	}{
		{"RAW", pb.ExportFormat_EXPORT_FORMAT_RAW},
		{"JWK", pb.ExportFormat_EXPORT_FORMAT_JWK},
		{"PEM", pb.ExportFormat_EXPORT_FORMAT_PEM},
		{"unknown", pb.ExportFormat_EXPORT_FORMAT_UNSPECIFIED},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToExportFormat(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestStringToHashAlgorithm(t *testing.T) {
	testCases := []struct {
		input    string
		expected pb.HashAlgorithm
	}{
		{"SHA256", pb.HashAlgorithm_HASH_ALG_SHA256},
		{"SHA384", pb.HashAlgorithm_HASH_ALG_SHA384},
		{"SHA512", pb.HashAlgorithm_HASH_ALG_SHA512},
		{"SHA3_256", pb.HashAlgorithm_HASH_ALG_SHA3_256},
		{"SHA3_384", pb.HashAlgorithm_HASH_ALG_SHA3_384},
		{"SHA3_512", pb.HashAlgorithm_HASH_ALG_SHA3_512},
		{"BLAKE2B_256", pb.HashAlgorithm_HASH_ALG_BLAKE2B_256},
		{"BLAKE2B_512", pb.HashAlgorithm_HASH_ALG_BLAKE2B_512},
		{"unknown", pb.HashAlgorithm_HASH_ALG_UNSPECIFIED},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := stringToHashAlgorithm(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestKeyAlgorithmToString(t *testing.T) {
	result := keyAlgorithmToString(pb.KeyAlgorithm_KEY_ALG_AES_256_GCM)
	assert.NotEmpty(t, result)
}

func TestKeyStatusToString(t *testing.T) {
	result := keyStatusToString(pb.KeyStatus_KEY_STATUS_ENABLED)
	assert.NotEmpty(t, result)
}

func TestWrappingAlgorithmToString(t *testing.T) {
	result := wrappingAlgorithmToString(pb.WrappingAlgorithm_WRAP_ALG_AES_KW)
	assert.NotEmpty(t, result)
}

func TestExportFormatToString(t *testing.T) {
	result := exportFormatToString(pb.ExportFormat_EXPORT_FORMAT_RAW)
	assert.NotEmpty(t, result)
}

func TestHashAlgorithmToString(t *testing.T) {
	result := hashAlgorithmToString(pb.HashAlgorithm_HASH_ALG_SHA256)
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
		assert.Equal(t, "key-123", result.KeyID)
		assert.Equal(t, uint64(2), result.Version)
	})
}

func TestConvertKeyMetadataToQUIC(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		result := convertKeyMetadataToQUIC(nil)
		assert.Nil(t, result)
	})

	t.Run("converts correctly with rotation policy", func(t *testing.T) {
		meta := &pb.KeyMetadata{
			KeyId:       "key-123",
			Name:        "test-key",
			Description: "Test key",
			Algorithm:   pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
			Status:      pb.KeyStatus_KEY_STATUS_ENABLED,
			Usage:       []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_ENCRYPT},
			Version:     1,
			RotationPolicy: &pb.RotationPolicy{
				Enabled:         true,
				IntervalSeconds: 86400,
				AutoRotate:      true,
			},
		}
		result := convertKeyMetadataToQUIC(meta)
		require.NotNil(t, result)
		assert.Equal(t, "key-123", result.KeyID)
		assert.NotNil(t, result.RotationPolicy)
		assert.True(t, result.RotationPolicy.Enabled)
	})
}

func TestBuildDataKeySpecForQUIC(t *testing.T) {
	testCases := []struct {
		algorithm string
		expected  pb.KeyAlgorithm
		shouldErr bool
	}{
		{"aes-128-gcm", pb.KeyAlgorithm_KEY_ALG_AES_128_GCM, false},
		{"aes128gcm", pb.KeyAlgorithm_KEY_ALG_AES_128_GCM, false},
		{"aes128", pb.KeyAlgorithm_KEY_ALG_AES_128_GCM, false},
		{"aes-192-gcm", pb.KeyAlgorithm_KEY_ALG_AES_192_GCM, false},
		{"aes-256-gcm", pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, false},
		{"chacha20-poly1305", pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305, false},
		{"xchacha20-poly1305", pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305, false},
		{"invalid", pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED, true},
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			result, err := buildDataKeySpecForQUIC(tc.algorithm)
			if tc.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result.Algorithm)
			}
		})
	}
}
