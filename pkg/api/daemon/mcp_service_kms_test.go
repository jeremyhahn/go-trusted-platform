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

package daemon

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"log/slog"
	"testing"
	"time"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// =============================================================================
// Mock KMS Service for MCP Service Provider Tests
// =============================================================================

// mockKMSServiceForMCPTests implements baasservice.KMSService for testing
type mockKMSServiceForMCPTests struct {
	generateKeyFunc     func(ctx context.Context, req *service.GenerateKeyRequest) (*service.GenerateKeyResponse, error)
	getPublicKeyFunc    func(ctx context.Context, req *service.GetPublicKeyRequest) (*service.GetPublicKeyResponse, error)
	getKeyFunc          func(ctx context.Context, req *service.GetKeyRequest) (*service.GetKeyResponse, error)
	listKeysFunc        func(ctx context.Context, req *service.ListKeysRequest) (*service.ListKeysResponse, error)
	deleteKeyFunc       func(ctx context.Context, req *service.DeleteKeyRequest) (*service.DeleteKeyResponse, error)
	rotateKeyFunc       func(ctx context.Context, req *service.RotateKeyRequest) (*service.RotateKeyResponse, error)
	updateKeyStatusFunc func(ctx context.Context, req *service.UpdateKeyStatusRequest) (*service.UpdateKeyStatusResponse, error)
}

func (m *mockKMSServiceForMCPTests) GetSupportedAlgorithms(ctx context.Context) ([]string, error) {
	return []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM"}, nil
}

func (m *mockKMSServiceForMCPTests) GenerateKey(ctx context.Context, req *service.GenerateKeyRequest) (*service.GenerateKeyResponse, error) {
	if m.generateKeyFunc != nil {
		return m.generateKeyFunc(ctx, req)
	}
	key := &service.KeyHandle{
		KeyID:     "test-key-id",
		Algorithm: service.KeyAlgAES256GCM,
		Status:    service.KeyStatusEnabled,
		CreatedAt: time.Now(),
		Version:   1,
	}
	return &service.GenerateKeyResponse{Key: key}, nil
}

func (m *mockKMSServiceForMCPTests) GetKey(ctx context.Context, req *service.GetKeyRequest) (*service.GetKeyResponse, error) {
	if m.getKeyFunc != nil {
		return m.getKeyFunc(ctx, req)
	}
	return nil, errors.New("key not found")
}

func (m *mockKMSServiceForMCPTests) ListKeys(ctx context.Context, req *service.ListKeysRequest) (*service.ListKeysResponse, error) {
	if m.listKeysFunc != nil {
		return m.listKeysFunc(ctx, req)
	}
	return &service.ListKeysResponse{
		Keys:       []*service.KeyHandle{},
		HasMore:    false,
		TotalCount: 0,
	}, nil
}

func (m *mockKMSServiceForMCPTests) DeleteKey(ctx context.Context, req *service.DeleteKeyRequest) (*service.DeleteKeyResponse, error) {
	if m.deleteKeyFunc != nil {
		return m.deleteKeyFunc(ctx, req)
	}
	return &service.DeleteKeyResponse{
		KeyID:  req.KeyID,
		Status: service.KeyStatusDeleted,
	}, nil
}

func (m *mockKMSServiceForMCPTests) RotateKey(ctx context.Context, req *service.RotateKeyRequest) (*service.RotateKeyResponse, error) {
	if m.rotateKeyFunc != nil {
		return m.rotateKeyFunc(ctx, req)
	}
	return &service.RotateKeyResponse{
		KeyID:      req.KeyID,
		OldVersion: 1,
		NewVersion: 2,
	}, nil
}

func (m *mockKMSServiceForMCPTests) UpdateKeyStatus(ctx context.Context, req *service.UpdateKeyStatusRequest) (*service.UpdateKeyStatusResponse, error) {
	if m.updateKeyStatusFunc != nil {
		return m.updateKeyStatusFunc(ctx, req)
	}
	return &service.UpdateKeyStatusResponse{
		KeyID:   req.KeyID,
		Status:  req.Status,
		Version: 1,
	}, nil
}

// Stub implementations for unused interface methods
func (m *mockKMSServiceForMCPTests) ImportKey(ctx context.Context, req *service.ImportKeyRequest) (*service.ImportKeyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) GetPublicKey(ctx context.Context, req *service.GetPublicKeyRequest) (*service.GetPublicKeyResponse, error) {
	if m.getPublicKeyFunc != nil {
		return m.getPublicKeyFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) RevokeKey(ctx context.Context, req *service.RevokeKeyRequest) (*service.RevokeKeyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) GetKeyMetadata(ctx context.Context, req *service.GetKeyMetadataRequest) (*service.GetKeyMetadataResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) UpdateKeyMetadata(ctx context.Context, req *service.UpdateKeyMetadataRequest) (*service.UpdateKeyMetadataResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) ListKeyVersions(ctx context.Context, req *service.ListKeyVersionsRequest) (*service.ListKeyVersionsResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) SetKeyPolicy(ctx context.Context, req *service.SetKeyPolicyRequest) (*service.SetKeyPolicyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) GetKeyPolicy(ctx context.Context, req *service.GetKeyPolicyRequest) (*service.GetKeyPolicyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) DeleteKeyPolicy(ctx context.Context, req *service.DeleteKeyPolicyRequest) (*service.DeleteKeyPolicyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) SetKeyRotationPolicy(ctx context.Context, req *service.SetKeyRotationPolicyRequest) (*service.SetKeyRotationPolicyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) GetKeyRotationPolicy(ctx context.Context, req *service.GetKeyRotationPolicyRequest) (*service.GetKeyRotationPolicyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) DeleteKeyRotationPolicy(ctx context.Context, req *service.DeleteKeyRotationPolicyRequest) (*service.DeleteKeyRotationPolicyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) CreateDEK(ctx context.Context, req *service.CreateDEKRequest) (*service.CreateDEKResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) GetDEK(ctx context.Context, req *service.GetDEKRequest) (*service.GetDEKResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) ListDEKs(ctx context.Context, req *service.ListDEKsRequest) (*service.ListDEKsResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) RotateDEK(ctx context.Context, req *service.RotateDEKRequest) (*service.RotateDEKResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) DeleteDEK(ctx context.Context, req *service.DeleteDEKRequest) (*service.DeleteDEKResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) GetDEKStatus(ctx context.Context, req *service.GetDEKStatusRequest) (*service.GetDEKStatusResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) SetDefaultDEK(ctx context.Context, req *service.SetDefaultDEKRequest) (*service.SetDefaultDEKResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) SetDEKSafety(ctx context.Context, req *service.SetDEKSafetyRequest) (*service.SetDEKSafetyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) ClearDEKSafety(ctx context.Context, req *service.ClearDEKSafetyRequest) (*service.ClearDEKSafetyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) StartReencryption(ctx context.Context, req *service.StartReencryptionRequest) (*service.StartReencryptionResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) GetReencryptionProgress(ctx context.Context, req *service.GetReencryptionProgressRequest) (*service.GetReencryptionProgressResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) BackendStatus(ctx context.Context) (*service.BackendStatusResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) BackendTest(ctx context.Context) (*service.BackendTestResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) ExportKey(ctx context.Context, req *service.ExportKeyRequest) (*service.ExportKeyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) UnwrapKey(ctx context.Context, req *service.UnwrapKeyRequest) (*service.UnwrapKeyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) SetKeySafety(ctx context.Context, req *service.SetKeySafetyRequest) (*service.SetKeySafetyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) ClearKeySafety(ctx context.Context, req *service.ClearKeySafetyRequest) (*service.ClearKeySafetyResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) SafetyCheck(ctx context.Context, req *service.SafetyCheckRequest) (*service.SafetyCheckResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) SafetyReport(ctx context.Context, req *service.SafetyReportRequest) (*service.SafetyReportResponse, error) {
	return nil, errors.New("not implemented")
}
func (m *mockKMSServiceForMCPTests) SetDefaultKey(ctx context.Context, req *service.SetDefaultKeyRequest) (*service.SetDefaultKeyResponse, error) {
	return nil, errors.New("not implemented")
}

// =============================================================================
// Mock Crypto Service for MCP Service Provider Tests
// =============================================================================

// mockCryptoServiceForMCPTests implements service.CryptoService for testing
type mockCryptoServiceForMCPTests struct {
	encryptFunc                func(ctx context.Context, req *service.EncryptRequest) (*service.EncryptResponse, error)
	decryptFunc                func(ctx context.Context, req *service.DecryptRequest) (*service.DecryptResponse, error)
	signFunc                   func(ctx context.Context, req *service.SignRequest) (*service.SignResponse, error)
	verifyFunc                 func(ctx context.Context, req *service.VerifyRequest) (*service.VerifyResponse, error)
	generateDataKeyFunc        func(ctx context.Context, req *service.GenerateDataKeyRequest) (*service.GenerateDataKeyResponse, error)
	generateWrappedDataKeyFunc func(ctx context.Context, req *service.GenerateWrappedDataKeyRequest) (*service.GenerateWrappedDataKeyResponse, error)
	generateRandomFunc         func(ctx context.Context, req *service.GenerateRandomRequest) (*service.GenerateRandomResponse, error)
}

func (m *mockCryptoServiceForMCPTests) Encrypt(ctx context.Context, req *service.EncryptRequest) (*service.EncryptResponse, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(ctx, req)
	}
	return &service.EncryptResponse{
		KeyID:      req.KeyID,
		Ciphertext: []byte("encrypted-" + string(req.Plaintext)),
		Nonce:      []byte("mock-nonce"),
		KeyVersion: 1,
	}, nil
}

func (m *mockCryptoServiceForMCPTests) Decrypt(ctx context.Context, req *service.DecryptRequest) (*service.DecryptResponse, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(ctx, req)
	}
	return &service.DecryptResponse{
		KeyID:      req.KeyID,
		Plaintext:  []byte("decrypted-data"),
		KeyVersion: 1,
	}, nil
}

func (m *mockCryptoServiceForMCPTests) Rewrap(ctx context.Context, req *service.RewrapRequest) (*service.RewrapResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCryptoServiceForMCPTests) EncryptBatch(ctx context.Context, req *service.EncryptBatchRequest) (*service.EncryptBatchResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCryptoServiceForMCPTests) DecryptBatch(ctx context.Context, req *service.DecryptBatchRequest) (*service.DecryptBatchResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCryptoServiceForMCPTests) Sign(ctx context.Context, req *service.SignRequest) (*service.SignResponse, error) {
	if m.signFunc != nil {
		return m.signFunc(ctx, req)
	}
	return &service.SignResponse{
		KeyID:      req.KeyID,
		Signature:  []byte("mock-signature"),
		KeyVersion: 1,
	}, nil
}

func (m *mockCryptoServiceForMCPTests) Verify(ctx context.Context, req *service.VerifyRequest) (*service.VerifyResponse, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(ctx, req)
	}
	return &service.VerifyResponse{
		KeyID:      req.KeyID,
		Valid:      true,
		KeyVersion: 1,
	}, nil
}

func (m *mockCryptoServiceForMCPTests) GenerateDataKey(ctx context.Context, req *service.GenerateDataKeyRequest) (*service.GenerateDataKeyResponse, error) {
	if m.generateDataKeyFunc != nil {
		return m.generateDataKeyFunc(ctx, req)
	}
	return &service.GenerateDataKeyResponse{
		KeyID:          req.KeyID,
		Plaintext:      []byte("plaintext-dek"),
		CiphertextBlob: []byte("encrypted-dek"),
		Timestamp:      time.Now(),
	}, nil
}

func (m *mockCryptoServiceForMCPTests) GenerateWrappedDataKey(ctx context.Context, req *service.GenerateWrappedDataKeyRequest) (*service.GenerateWrappedDataKeyResponse, error) {
	if m.generateWrappedDataKeyFunc != nil {
		return m.generateWrappedDataKeyFunc(ctx, req)
	}
	return &service.GenerateWrappedDataKeyResponse{
		KeyID:          req.KeyID,
		CiphertextBlob: []byte("wrapped-dek"),
		Timestamp:      time.Now(),
	}, nil
}

func (m *mockCryptoServiceForMCPTests) GenerateHMAC(ctx context.Context, req *service.HMACRequest) (*service.HMACResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCryptoServiceForMCPTests) VerifyHMAC(ctx context.Context, req *service.VerifyHMACRequest) (*service.VerifyHMACResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCryptoServiceForMCPTests) GenerateRandom(ctx context.Context, req *service.GenerateRandomRequest) (*service.GenerateRandomResponse, error) {
	if m.generateRandomFunc != nil {
		return m.generateRandomFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockCryptoServiceForMCPTests) Hash(ctx context.Context, req *service.HashRequest) (*service.HashResponse, error) {
	return nil, errors.New("not implemented")
}

// =============================================================================
// KMSCreateKey Tests - Parameter Validation and Success/Error Paths
// =============================================================================

func TestKMSCreateKey_MissingName(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSCreateKey(ctx, &mcp.KMSCreateKeyRequest{
		Name:      "",
		Algorithm: "AES-256-GCM",
		KeyUsage:  []string{"ENCRYPT"},
	})
	if err == nil {
		t.Fatal("expected error for missing name")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "name" {
		t.Errorf("expected parameter='name', got %q", paramErr.Parameter)
	}
}

func TestKMSCreateKey_MissingAlgorithm(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSCreateKey(ctx, &mcp.KMSCreateKeyRequest{
		Name:      "test-key",
		Algorithm: "",
		KeyUsage:  []string{"ENCRYPT"},
	})
	if err == nil {
		t.Fatal("expected error for missing algorithm")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "algorithm" {
		t.Errorf("expected parameter='algorithm', got %q", paramErr.Parameter)
	}
}

func TestKMSCreateKey_MissingKeyUsage(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSCreateKey(ctx, &mcp.KMSCreateKeyRequest{
		Name:      "test-key",
		Algorithm: "AES-256-GCM",
		KeyUsage:  []string{},
	})
	if err == nil {
		t.Fatal("expected error for missing key_usage")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "key_usage" {
		t.Errorf("expected parameter='key_usage', got %q", paramErr.Parameter)
	}
}

func TestKMSCreateKey_InvalidKeyUsage(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSCreateKey(ctx, &mcp.KMSCreateKeyRequest{
		Name:      "test-key",
		Algorithm: "AES-256-GCM",
		KeyUsage:  []string{"INVALID_USAGE"},
	})
	if err == nil {
		t.Fatal("expected error for invalid key_usage")
	}

	_, ok := err.(ErrKMSInvalidKeyUsage)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidKeyUsage, got %T: %v", err, err)
	}
}

func TestKMSCreateKey_Success(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{
		generateKeyFunc: func(ctx context.Context, req *service.GenerateKeyRequest) (*service.GenerateKeyResponse, error) {
			key := &service.KeyHandle{
				KeyID:     "generated-key-123",
				Algorithm: service.KeyAlgAES256GCM,
				Status:    service.KeyStatusEnabled,
				CreatedAt: time.Now(),
				Version:   1,
			}
			return &service.GenerateKeyResponse{Key: key}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	result, err := provider.KMSCreateKey(ctx, &mcp.KMSCreateKeyRequest{
		Name:        "test-encryption-key",
		Description: "Test key for encryption",
		Algorithm:   "AES-256-GCM",
		KeyUsage:    []string{"ENCRYPT", "DECRYPT"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	keyHandle, ok := result.(*service.KeyHandle)
	if !ok {
		t.Fatalf("expected *service.KeyHandle, got %T", result)
	}
	if keyHandle.KeyID != "generated-key-123" {
		t.Errorf("expected KeyID='generated-key-123', got %q", keyHandle.KeyID)
	}
}

func TestKMSCreateKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{
		generateKeyFunc: func(ctx context.Context, req *service.GenerateKeyRequest) (*service.GenerateKeyResponse, error) {
			return nil, errors.New("key generation failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSCreateKey(ctx, &mcp.KMSCreateKeyRequest{
		Name:      "test-key",
		Algorithm: "AES-256-GCM",
		KeyUsage:  []string{"ENCRYPT"},
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrKMSOperationFailed)
	if !ok {
		t.Fatalf("expected ErrKMSOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "CreateKey" {
		t.Errorf("expected Operation='CreateKey', got %q", opErr.Operation)
	}
}

// =============================================================================
// KMSDeleteKey Tests - Parameter Validation and Success/Error Paths
// =============================================================================

func TestKMSDeleteKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	err := provider.KMSDeleteKey(ctx, "")
	if err == nil {
		t.Fatal("expected error for missing key_id")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "key_id" {
		t.Errorf("expected parameter='key_id', got %q", paramErr.Parameter)
	}
}

func TestKMSDeleteKey_Success(t *testing.T) {
	ctx := context.Background()
	deletedKeyID := ""
	mockKMS := &mockKMSServiceForMCPTests{
		deleteKeyFunc: func(ctx context.Context, req *service.DeleteKeyRequest) (*service.DeleteKeyResponse, error) {
			deletedKeyID = req.KeyID
			return &service.DeleteKeyResponse{
				KeyID:  req.KeyID,
				Status: service.KeyStatusDeleted,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	err := provider.KMSDeleteKey(ctx, "key-to-delete")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deletedKeyID != "key-to-delete" {
		t.Errorf("expected key_id='key-to-delete', got %q", deletedKeyID)
	}
}

func TestKMSDeleteKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{
		deleteKeyFunc: func(ctx context.Context, req *service.DeleteKeyRequest) (*service.DeleteKeyResponse, error) {
			return nil, errors.New("deletion failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	err := provider.KMSDeleteKey(ctx, "key-123")
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrKMSOperationFailed)
	if !ok {
		t.Fatalf("expected ErrKMSOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "DeleteKey" {
		t.Errorf("expected Operation='DeleteKey', got %q", opErr.Operation)
	}
}

// =============================================================================
// KMSGetKey Tests - Parameter Validation and Success/Error Paths
// =============================================================================

func TestKMSGetKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSGetKey(ctx, "", 0)
	if err == nil {
		t.Fatal("expected error for missing key_id")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "key_id" {
		t.Errorf("expected parameter='key_id', got %q", paramErr.Parameter)
	}
}

func TestKMSGetKey_Success(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{
		getKeyFunc: func(ctx context.Context, req *service.GetKeyRequest) (*service.GetKeyResponse, error) {
			key := &service.KeyHandle{
				KeyID:     req.KeyID,
				Algorithm: service.KeyAlgAES256GCM,
				Status:    service.KeyStatusEnabled,
				CreatedAt: time.Now(),
				Version:   1,
			}
			return &service.GetKeyResponse{Key: key}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	result, err := provider.KMSGetKey(ctx, "existing-key-123", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	keyHandle, ok := result.(*service.KeyHandle)
	if !ok {
		t.Fatalf("expected *service.KeyHandle, got %T", result)
	}
	if keyHandle.KeyID != "existing-key-123" {
		t.Errorf("expected KeyID='existing-key-123', got %q", keyHandle.KeyID)
	}
}

func TestKMSGetKey_NotFound(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{
		getKeyFunc: func(ctx context.Context, req *service.GetKeyRequest) (*service.GetKeyResponse, error) {
			return nil, sdkerrors.NewNotFound("kms", "no key "+req.KeyID)
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSGetKey(ctx, "nonexistent-key", 0)
	if err == nil {
		t.Fatal("expected error for key not found")
	}

	notFoundErr, ok := err.(ErrKMSKeyNotFound)
	if !ok {
		t.Fatalf("expected ErrKMSKeyNotFound, got %T: %v", err, err)
	}
	if notFoundErr.KeyID != "nonexistent-key" {
		t.Errorf("expected KeyID='nonexistent-key', got %q", notFoundErr.KeyID)
	}
}

// =============================================================================
// KMSListKeys Tests - Success/Error Paths
// =============================================================================

func TestKMSListKeys_DefaultLimit(t *testing.T) {
	ctx := context.Background()
	capturedLimit := 0
	mockKMS := &mockKMSServiceForMCPTests{
		listKeysFunc: func(ctx context.Context, req *service.ListKeysRequest) (*service.ListKeysResponse, error) {
			capturedLimit = req.Limit
			return &service.ListKeysResponse{
				Keys:       []*service.KeyHandle{},
				HasMore:    false,
				TotalCount: 0,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSListKeys(ctx, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedLimit != 50 {
		t.Errorf("expected default limit=50, got %d", capturedLimit)
	}
}

func TestKMSListKeys_Success(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{
		listKeysFunc: func(ctx context.Context, req *service.ListKeysRequest) (*service.ListKeysResponse, error) {
			keys := []*service.KeyHandle{
				{KeyID: "key-1", Algorithm: service.KeyAlgAES256GCM, Status: service.KeyStatusEnabled},
				{KeyID: "key-2", Algorithm: service.KeyAlgRSA2048, Status: service.KeyStatusEnabled},
			}
			return &service.ListKeysResponse{
				Keys:       keys,
				HasMore:    false,
				TotalCount: 2,
				NextCursor: "",
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	result, err := provider.KMSListKeys(ctx, 10, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	keys, ok := resultMap["keys"].([]*service.KeyHandle)
	if !ok {
		t.Fatalf("expected []*service.KeyHandle for keys, got %T", resultMap["keys"])
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestKMSListKeys_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{
		listKeysFunc: func(ctx context.Context, req *service.ListKeysRequest) (*service.ListKeysResponse, error) {
			return nil, errors.New("database error")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSListKeys(ctx, 10, 0)
	if err == nil {
		t.Fatal("expected error from service")
	}

	opErr, ok := err.(ErrKMSOperationFailed)
	if !ok {
		t.Fatalf("expected ErrKMSOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != "ListKeys" {
		t.Errorf("expected Operation='ListKeys', got %q", opErr.Operation)
	}
}

// =============================================================================
// KMSRotateKey Tests - Parameter Validation and Success/Error Paths
// =============================================================================

func TestKMSRotateKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSRotateKey(ctx, "")
	if err == nil {
		t.Fatal("expected error for missing key_id")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "key_id" {
		t.Errorf("expected parameter='key_id', got %q", paramErr.Parameter)
	}
}

func TestKMSRotateKey_Success(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{
		rotateKeyFunc: func(ctx context.Context, req *service.RotateKeyRequest) (*service.RotateKeyResponse, error) {
			return &service.RotateKeyResponse{
				KeyID:      req.KeyID,
				OldVersion: 1,
				NewVersion: 2,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	result, err := provider.KMSRotateKey(ctx, "key-to-rotate")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rotateResp, ok := result.(*service.RotateKeyResponse)
	if !ok {
		t.Fatalf("expected *service.RotateKeyResponse, got %T", result)
	}
	if rotateResp.OldVersion != 1 {
		t.Errorf("expected OldVersion=1, got %d", rotateResp.OldVersion)
	}
	if rotateResp.NewVersion != 2 {
		t.Errorf("expected NewVersion=2, got %d", rotateResp.NewVersion)
	}
}

func TestKMSRotateKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{
		rotateKeyFunc: func(ctx context.Context, req *service.RotateKeyRequest) (*service.RotateKeyResponse, error) {
			return nil, errors.New("rotation failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSRotateKey(ctx, "key-123")
	if err == nil {
		t.Fatal("expected error from service")
	}

	rotateErr, ok := err.(ErrKMSKeyRotationFailed)
	if !ok {
		t.Fatalf("expected ErrKMSKeyRotationFailed, got %T: %v", err, err)
	}
	if rotateErr.KeyID != "key-123" {
		t.Errorf("expected KeyID='key-123', got %q", rotateErr.KeyID)
	}
}

// =============================================================================
// KMSEncrypt Tests - Parameter Validation and Success/Error Paths
// =============================================================================

func TestKMSEncrypt_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSEncrypt(ctx, &mcp.KMSEncryptRequest{
		KeyID:     "",
		Plaintext: []byte("secret data"),
	})
	if err == nil {
		t.Fatal("expected error for missing key_id")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "key_id" {
		t.Errorf("expected parameter='key_id', got %q", paramErr.Parameter)
	}
}

func TestKMSEncrypt_MissingPlaintext(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSEncrypt(ctx, &mcp.KMSEncryptRequest{
		KeyID:     "key-123",
		Plaintext: []byte{},
	})
	if err == nil {
		t.Fatal("expected error for missing plaintext")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "plaintext" {
		t.Errorf("expected parameter='plaintext', got %q", paramErr.Parameter)
	}
}

func TestKMSEncrypt_Success(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		encryptFunc: func(ctx context.Context, req *service.EncryptRequest) (*service.EncryptResponse, error) {
			return &service.EncryptResponse{
				KeyID:      req.KeyID,
				Ciphertext: []byte("encrypted-data"),
				Nonce:      []byte("iv-12-bytes!"),
				KeyVersion: 1,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	result, err := provider.KMSEncrypt(ctx, &mcp.KMSEncryptRequest{
		KeyID:     "encryption-key",
		Plaintext: []byte("secret data"),
		Context:   []byte("additional-auth-data"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if string(resultMap["ciphertext"].([]byte)) != "encrypted-data" {
		t.Errorf("unexpected ciphertext")
	}
}

func TestKMSEncrypt_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		encryptFunc: func(ctx context.Context, req *service.EncryptRequest) (*service.EncryptResponse, error) {
			return nil, errors.New("encryption failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSEncrypt(ctx, &mcp.KMSEncryptRequest{
		KeyID:     "key-123",
		Plaintext: []byte("secret"),
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	encErr, ok := err.(ErrKMSEncryptionFailed)
	if !ok {
		t.Fatalf("expected ErrKMSEncryptionFailed, got %T: %v", err, err)
	}
	if encErr.KeyID != "key-123" {
		t.Errorf("expected KeyID='key-123', got %q", encErr.KeyID)
	}
}

// =============================================================================
// KMSDecrypt Tests - Parameter Validation and Success/Error Paths
// =============================================================================

func TestKMSDecrypt_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSDecrypt(ctx, &mcp.KMSDecryptRequest{
		KeyID:      "",
		Ciphertext: []byte("encrypted-data"),
	})
	if err == nil {
		t.Fatal("expected error for missing key_id")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "key_id" {
		t.Errorf("expected parameter='key_id', got %q", paramErr.Parameter)
	}
}

func TestKMSDecrypt_MissingCiphertext(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSDecrypt(ctx, &mcp.KMSDecryptRequest{
		KeyID:      "key-123",
		Ciphertext: []byte{},
	})
	if err == nil {
		t.Fatal("expected error for missing ciphertext")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "ciphertext" {
		t.Errorf("expected parameter='ciphertext', got %q", paramErr.Parameter)
	}
}

func TestKMSDecrypt_Success(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		decryptFunc: func(ctx context.Context, req *service.DecryptRequest) (*service.DecryptResponse, error) {
			return &service.DecryptResponse{
				KeyID:      req.KeyID,
				Plaintext:  []byte("decrypted-secret"),
				KeyVersion: 1,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	result, err := provider.KMSDecrypt(ctx, &mcp.KMSDecryptRequest{
		KeyID:      "decryption-key",
		Ciphertext: []byte("encrypted-data"),
		Nonce:      []byte("iv-12-bytes!"),
		Context:    []byte("aad"),
		KeyVersion: 1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if string(resultMap["plaintext"].([]byte)) != "decrypted-secret" {
		t.Errorf("unexpected plaintext")
	}
}

func TestKMSDecrypt_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		decryptFunc: func(ctx context.Context, req *service.DecryptRequest) (*service.DecryptResponse, error) {
			return nil, errors.New("decryption failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSDecrypt(ctx, &mcp.KMSDecryptRequest{
		KeyID:      "key-123",
		Ciphertext: []byte("encrypted"),
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	decErr, ok := err.(ErrKMSDecryptionFailed)
	if !ok {
		t.Fatalf("expected ErrKMSDecryptionFailed, got %T: %v", err, err)
	}
	if decErr.KeyID != "key-123" {
		t.Errorf("expected KeyID='key-123', got %q", decErr.KeyID)
	}
}

// =============================================================================
// KMSGenerateRandom Tests
// =============================================================================

// randomProvider builds a provider whose SDK crypto service answers
// GenerateRandom with generate.
func randomProvider(generate func(ctx context.Context, req *service.GenerateRandomRequest) (*service.GenerateRandomResponse, error)) *MCPServiceProvider {
	return NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: &mockCryptoServiceForMCPTests{generateRandomFunc: generate},
		Logger:        slog.Default(),
	})
}

// failIfCalled is a GenerateRandom that fails the test when reached.
func failIfCalled(t *testing.T) func(context.Context, *service.GenerateRandomRequest) (*service.GenerateRandomResponse, error) {
	return func(context.Context, *service.GenerateRandomRequest) (*service.GenerateRandomResponse, error) {
		t.Error("GenerateRandom must not reach the SDK for an invalid num_bytes")
		return nil, errors.New("unexpected call")
	}
}

func TestKMSGenerateRandom_InvalidNumBytes_Zero(t *testing.T) {
	_, err := randomProvider(failIfCalled(t)).KMSGenerateRandom(context.Background(), 0)
	if err == nil {
		t.Fatal("expected error for num_bytes=0")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "num_bytes" {
		t.Errorf("expected parameter='num_bytes', got %q", paramErr.Parameter)
	}
}

func TestKMSGenerateRandom_InvalidNumBytes_Negative(t *testing.T) {
	_, err := randomProvider(failIfCalled(t)).KMSGenerateRandom(context.Background(), -10)
	if err == nil {
		t.Fatal("expected error for negative num_bytes")
	}

	_, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
}

// TestKMSGenerateRandom_AnswersFromSDK proves kms_random returns the bytes
// the KMS generated, as gRPC GenerateRandom does, instead of drawing its own
// (#304). A request above the old local 1024-byte cap reaches the SDK too.
func TestKMSGenerateRandom_AnswersFromSDK(t *testing.T) {
	for _, numBytes := range []int{32, 2048} {
		want := bytes.Repeat([]byte{0xA5}, numBytes)
		var gotReq *service.GenerateRandomRequest
		provider := randomProvider(func(_ context.Context, req *service.GenerateRandomRequest) (*service.GenerateRandomResponse, error) {
			gotReq = req
			return &service.GenerateRandomResponse{RandomBytes: want}, nil
		})

		result, err := provider.KMSGenerateRandom(context.Background(), numBytes)
		if err != nil {
			t.Fatalf("num_bytes=%d: unexpected error: %v", numBytes, err)
		}
		if gotReq == nil || gotReq.NumBytes != numBytes {
			t.Fatalf("num_bytes=%d: SDK request = %+v", numBytes, gotReq)
		}
		if !bytes.Equal(result, want) {
			t.Errorf("num_bytes=%d: result is not the SDK's bytes", numBytes)
		}
	}
}

func TestKMSGenerateRandom_SDKErrorPropagates(t *testing.T) {
	sdkErr := errors.New("rng unavailable")
	provider := randomProvider(func(context.Context, *service.GenerateRandomRequest) (*service.GenerateRandomResponse, error) {
		return nil, sdkErr
	})

	_, err := provider.KMSGenerateRandom(context.Background(), 16)
	var genErr ErrKMSRandomGenerationFailed
	if !errors.As(err, &genErr) {
		t.Fatalf("expected ErrKMSRandomGenerationFailed, got %T: %v", err, err)
	}
	if !errors.Is(err, sdkErr) {
		t.Errorf("the SDK error must be the cause, got %v", err)
	}
}

func TestKMSGenerateRandom_NoCryptoService(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{Logger: slog.Default()})

	_, err := provider.KMSGenerateRandom(context.Background(), 16)
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// KMSSign Tests - Parameter Validation and Success/Error Paths
// =============================================================================

func TestKMSSign_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSSign(ctx, &mcp.KMSSignRequest{
		KeyID:   "",
		Message: []byte("message"),
	})
	if err == nil {
		t.Fatal("expected error for missing key_id")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "key_id" {
		t.Errorf("expected parameter='key_id', got %q", paramErr.Parameter)
	}
}

func TestKMSSign_MissingMessage(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSSign(ctx, &mcp.KMSSignRequest{
		KeyID:   "key-123",
		Message: []byte{},
	})
	if err == nil {
		t.Fatal("expected error for missing message")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "message" {
		t.Errorf("expected parameter='message', got %q", paramErr.Parameter)
	}
}

func TestKMSSign_Success(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		signFunc: func(ctx context.Context, req *service.SignRequest) (*service.SignResponse, error) {
			return &service.SignResponse{
				KeyID:      req.KeyID,
				Signature:  []byte("digital-signature"),
				KeyVersion: 1,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	result, err := provider.KMSSign(ctx, &mcp.KMSSignRequest{
		KeyID:         "signing-key",
		Message:       []byte("message to sign"),
		HashAlgorithm: "SHA256",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if string(resultMap["signature"].([]byte)) != "digital-signature" {
		t.Errorf("unexpected signature")
	}
}

func TestKMSSign_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		signFunc: func(ctx context.Context, req *service.SignRequest) (*service.SignResponse, error) {
			return nil, errors.New("signing failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSSign(ctx, &mcp.KMSSignRequest{
		KeyID:   "key-123",
		Message: []byte("message"),
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	signErr, ok := err.(ErrKMSSigningFailed)
	if !ok {
		t.Fatalf("expected ErrKMSSigningFailed, got %T: %v", err, err)
	}
	if signErr.KeyID != "key-123" {
		t.Errorf("expected KeyID='key-123', got %q", signErr.KeyID)
	}
}

// =============================================================================
// KMSVerify Tests - Parameter Validation and Success/Error Paths
// =============================================================================

func TestKMSVerify_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSVerify(ctx, &mcp.KMSVerifyRequest{
		KeyID:     "",
		Message:   []byte("message"),
		Signature: []byte("signature"),
	})
	if err == nil {
		t.Fatal("expected error for missing key_id")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "key_id" {
		t.Errorf("expected parameter='key_id', got %q", paramErr.Parameter)
	}
}

func TestKMSVerify_MissingMessage(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSVerify(ctx, &mcp.KMSVerifyRequest{
		KeyID:     "key-123",
		Message:   []byte{},
		Signature: []byte("signature"),
	})
	if err == nil {
		t.Fatal("expected error for missing message")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "message" {
		t.Errorf("expected parameter='message', got %q", paramErr.Parameter)
	}
}

func TestKMSVerify_MissingSignature(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSVerify(ctx, &mcp.KMSVerifyRequest{
		KeyID:     "key-123",
		Message:   []byte("message"),
		Signature: []byte{},
	})
	if err == nil {
		t.Fatal("expected error for missing signature")
	}

	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "signature" {
		t.Errorf("expected parameter='signature', got %q", paramErr.Parameter)
	}
}

func TestKMSVerify_Success_Valid(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		verifyFunc: func(ctx context.Context, req *service.VerifyRequest) (*service.VerifyResponse, error) {
			return &service.VerifyResponse{
				KeyID:      req.KeyID,
				Valid:      true,
				KeyVersion: 1,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	result, err := provider.KMSVerify(ctx, &mcp.KMSVerifyRequest{
		KeyID:         "verify-key",
		Message:       []byte("message"),
		Signature:     []byte("valid-signature"),
		HashAlgorithm: "SHA256",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["valid"] != true {
		t.Errorf("expected valid=true, got %v", resultMap["valid"])
	}
}

func TestKMSVerify_Success_Invalid(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		verifyFunc: func(ctx context.Context, req *service.VerifyRequest) (*service.VerifyResponse, error) {
			return &service.VerifyResponse{
				KeyID:      req.KeyID,
				Valid:      false,
				KeyVersion: 1,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	result, err := provider.KMSVerify(ctx, &mcp.KMSVerifyRequest{
		KeyID:     "verify-key",
		Message:   []byte("message"),
		Signature: []byte("invalid-signature"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["valid"] != false {
		t.Errorf("expected valid=false, got %v", resultMap["valid"])
	}
}

func TestKMSVerify_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		verifyFunc: func(ctx context.Context, req *service.VerifyRequest) (*service.VerifyResponse, error) {
			return nil, errors.New("verification failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSVerify(ctx, &mcp.KMSVerifyRequest{
		KeyID:     "key-123",
		Message:   []byte("message"),
		Signature: []byte("signature"),
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	verifyErr, ok := err.(ErrKMSVerificationFailed)
	if !ok {
		t.Fatalf("expected ErrKMSVerificationFailed, got %T: %v", err, err)
	}
	if verifyErr.KeyID != "key-123" {
		t.Errorf("expected KeyID='key-123', got %q", verifyErr.KeyID)
	}
}

// =============================================================================
// KMSGenerateDataKey Tests - Success/Error Paths
// =============================================================================

func TestKMSGenerateDataKey_Success(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		generateDataKeyFunc: func(ctx context.Context, req *service.GenerateDataKeyRequest) (*service.GenerateDataKeyResponse, error) {
			return &service.GenerateDataKeyResponse{
				KeyID:          req.KeyID,
				Plaintext:      []byte("plaintext-dek-32-bytes-long!!!!"),
				CiphertextBlob: []byte("wrapped-dek-ciphertext"),
				Timestamp:      time.Now(),
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	result, err := provider.KMSGenerateDataKey(ctx, &mcp.KMSGenerateDataKeyRequest{
		KeyID:     "kek-123",
		Algorithm: "aes-256-gcm",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["plaintext"] == nil {
		t.Error("expected plaintext to be present")
	}
	if resultMap["ciphertext_blob"] == nil {
		t.Error("expected ciphertext_blob to be present")
	}
}

func TestKMSGenerateDataKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		generateDataKeyFunc: func(ctx context.Context, req *service.GenerateDataKeyRequest) (*service.GenerateDataKeyResponse, error) {
			return nil, errors.New("data key generation failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSGenerateDataKey(ctx, &mcp.KMSGenerateDataKeyRequest{
		KeyID: "kek-123",
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	dataKeyErr, ok := err.(ErrKMSDataKeyGenerationFailed)
	if !ok {
		t.Fatalf("expected ErrKMSDataKeyGenerationFailed, got %T: %v", err, err)
	}
	if dataKeyErr.KeyID != "kek-123" {
		t.Errorf("expected KeyID='kek-123', got %q", dataKeyErr.KeyID)
	}
}

// =============================================================================
// KMSGenerateWrappedDataKey Tests - Success/Error Paths
// =============================================================================

func TestKMSGenerateWrappedDataKey_Success(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		generateWrappedDataKeyFunc: func(ctx context.Context, req *service.GenerateWrappedDataKeyRequest) (*service.GenerateWrappedDataKeyResponse, error) {
			return &service.GenerateWrappedDataKeyResponse{
				KeyID:          req.KeyID,
				CiphertextBlob: []byte("wrapped-only-dek"),
				Timestamp:      time.Now(),
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	result, err := provider.KMSGenerateWrappedDataKey(ctx, &mcp.KMSGenerateWrappedDataKeyRequest{
		KeyID:     "kek-456",
		Algorithm: "aes-256-gcm",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["ciphertext_blob"] == nil {
		t.Error("expected ciphertext_blob to be present")
	}
}

func TestKMSGenerateWrappedDataKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	mockCrypto := &mockCryptoServiceForMCPTests{
		generateWrappedDataKeyFunc: func(ctx context.Context, req *service.GenerateWrappedDataKeyRequest) (*service.GenerateWrappedDataKeyResponse, error) {
			return nil, errors.New("wrapped data key generation failed")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		CryptoService: mockCrypto,
		Logger:        slog.Default(),
	})

	_, err := provider.KMSGenerateWrappedDataKey(ctx, &mcp.KMSGenerateWrappedDataKeyRequest{
		KeyID: "kek-456",
	})
	if err == nil {
		t.Fatal("expected error from service")
	}

	dataKeyErr, ok := err.(ErrKMSDataKeyGenerationFailed)
	if !ok {
		t.Fatalf("expected ErrKMSDataKeyGenerationFailed, got %T: %v", err, err)
	}
	if dataKeyErr.KeyID != "kek-456" {
		t.Errorf("expected KeyID='kek-456', got %q", dataKeyErr.KeyID)
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestParseKMSKeyUsageHelper(t *testing.T) {
	testCases := []struct {
		input       string
		expected    service.KeyUsage
		expectError bool
	}{
		{"ENCRYPT", service.KeyUsageEncrypt, false},
		{"DECRYPT", service.KeyUsageDecrypt, false},
		{"SIGN", service.KeyUsageSign, false},
		{"VERIFY", service.KeyUsageVerify, false},
		{"WRAP", service.KeyUsageWrapKey, false},
		{"UNWRAP", service.KeyUsageWrapKey, false},
		{"DERIVE", service.KeyUsageDeriveKey, false},
		{"GENERATE_MAC", service.KeyUsageGenerateMAC, false},
		{"VERIFY_MAC", service.KeyUsageVerifyMAC, false},
		{"INVALID", service.KeyUsageEncrypt, true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result, err := parseKMSKeyUsage(tc.input)
			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tc.expected {
					t.Errorf("expected %v, got %v", tc.expected, result)
				}
			}
		})
	}
}

func TestBuildKeyAttributesHelper(t *testing.T) {
	testCases := []struct {
		name        string
		req         *mcp.KMSCreateKeyRequest
		expectError bool
		checkResult func(*xkmssdk.KeyAttributes) bool
	}{
		{
			name: "AES-256-GCM",
			req: &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: "AES-256-GCM",
				KeyUsage:  []string{"ENCRYPT"},
			},
			expectError: false,
			checkResult: func(attrs *xkmssdk.KeyAttributes) bool {
				return attrs != nil
			},
		},
		{
			name: "RSA-2048",
			req: &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: "RSA-2048",
				KeyUsage:  []string{"SIGN"},
				KeySize:   2048,
			},
			expectError: false,
			checkResult: func(attrs *xkmssdk.KeyAttributes) bool {
				return attrs != nil && attrs.RSAAttributes != nil
			},
		},
		{
			name: "ECDSA-P256",
			req: &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: "ECDSA-P256",
				KeyUsage:  []string{"SIGN"},
			},
			expectError: false,
			checkResult: func(attrs *xkmssdk.KeyAttributes) bool {
				return attrs != nil && attrs.ECCAttributes != nil
			},
		},
		{
			name: "Invalid algorithm",
			req: &mcp.KMSCreateKeyRequest{
				Name:      "test-key",
				Algorithm: "INVALID-ALGORITHM",
				KeyUsage:  []string{"ENCRYPT"},
			},
			expectError: true,
			checkResult: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := buildKeyAttributes(tc.req)
			if tc.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tc.checkResult != nil && !tc.checkResult(result) {
					t.Error("result check failed")
				}
			}
		})
	}
}

// =============================================================================
// KMSExportPublicKey Tests - Parameter Validation and Success/Error Paths
// =============================================================================

func TestKMSExportPublicKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: &mockKMSServiceForMCPTests{},
		Logger:     slog.Default(),
	})

	_, err := provider.KMSExportPublicKey(ctx, &mcp.KMSExportPublicKeyRequest{})
	if err == nil {
		t.Fatal("expected error for missing key_id")
	}
	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "key_id" {
		t.Errorf("expected parameter='key_id', got %q", paramErr.Parameter)
	}
}

func TestKMSExportPublicKey_InvalidFormat(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: &mockKMSServiceForMCPTests{},
		Logger:     slog.Default(),
	})

	_, err := provider.KMSExportPublicKey(ctx, &mcp.KMSExportPublicKeyRequest{
		KeyID:  "key-123",
		Format: "JWK",
	})
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	paramErr, ok := err.(ErrKMSInvalidParameter)
	if !ok {
		t.Fatalf("expected ErrKMSInvalidParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "format" {
		t.Errorf("expected parameter='format', got %q", paramErr.Parameter)
	}
}

func TestKMSExportPublicKey_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.KMSExportPublicKey(ctx, &mcp.KMSExportPublicKeyRequest{KeyID: "key-123"})
	if err == nil {
		t.Fatal("expected error when KMS service is unavailable")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestKMSExportPublicKey_PEMDefault(t *testing.T) {
	ctx := context.Background()
	der := []byte{0x30, 0x82, 0x01, 0x22}
	mockKMS := &mockKMSServiceForMCPTests{
		getPublicKeyFunc: func(ctx context.Context, req *service.GetPublicKeyRequest) (*service.GetPublicKeyResponse, error) {
			if req.KeyID != "key-123" {
				t.Errorf("expected KeyID='key-123', got %q", req.KeyID)
			}
			if req.Version != 2 {
				t.Errorf("expected Version=2, got %d", req.Version)
			}
			return &service.GetPublicKeyResponse{
				KeyID:     req.KeyID,
				PublicKey: der,
				Algorithm: service.KeyAlgECDSAP256,
				Version:   req.Version,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	result, err := provider.KMSExportPublicKey(ctx, &mcp.KMSExportPublicKeyRequest{
		KeyID:   "key-123",
		Version: 2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	if resultMap["format"] != "PEM" {
		t.Errorf("expected format='PEM' by default, got %v", resultMap["format"])
	}
	pemStr, ok := resultMap["public_key"].(string)
	if !ok {
		t.Fatalf("expected string public_key for PEM, got %T", resultMap["public_key"])
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("public_key is not a valid PUBLIC KEY PEM block: %q", pemStr)
	}
	if !bytes.Equal(block.Bytes, der) {
		t.Errorf("PEM payload = %x, want %x", block.Bytes, der)
	}
}

func TestKMSExportPublicKey_DER(t *testing.T) {
	ctx := context.Background()
	der := []byte{0x30, 0x82, 0x01, 0x22}
	mockKMS := &mockKMSServiceForMCPTests{
		getPublicKeyFunc: func(ctx context.Context, req *service.GetPublicKeyRequest) (*service.GetPublicKeyResponse, error) {
			return &service.GetPublicKeyResponse{
				KeyID:     req.KeyID,
				PublicKey: der,
				Algorithm: service.KeyAlgECDSAP256,
				Version:   1,
			}, nil
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	result, err := provider.KMSExportPublicKey(ctx, &mcp.KMSExportPublicKeyRequest{
		KeyID:  "key-123",
		Format: "der",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	if resultMap["format"] != "DER" {
		t.Errorf("expected format='DER', got %v", resultMap["format"])
	}
	derOut, ok := resultMap["public_key"].([]byte)
	if !ok {
		t.Fatalf("expected []byte public_key for DER, got %T", resultMap["public_key"])
	}
	if !bytes.Equal(derOut, der) {
		t.Errorf("DER payload = %x, want %x", derOut, der)
	}
}

func TestKMSExportPublicKey_BackendError(t *testing.T) {
	ctx := context.Background()
	mockKMS := &mockKMSServiceForMCPTests{
		getPublicKeyFunc: func(ctx context.Context, req *service.GetPublicKeyRequest) (*service.GetPublicKeyResponse, error) {
			return nil, errors.New("symmetric key has no public part")
		},
	}
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		KMSService: mockKMS,
		Logger:     slog.Default(),
	})

	_, err := provider.KMSExportPublicKey(ctx, &mcp.KMSExportPublicKeyRequest{KeyID: "sym-key"})
	if err == nil {
		t.Fatal("expected error from backend")
	}
	if _, ok := err.(ErrKMSOperationFailed); !ok {
		t.Fatalf("expected ErrKMSOperationFailed, got %T: %v", err, err)
	}
}
