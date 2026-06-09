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

package caquicbaas

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock Implementations for SDK Interfaces
// =============================================================================

// mockSDKKMSClient implements the SDK kms.Client interface for testing.
type mockSDKKMSClient struct {
	generateKeyFunc  func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error)
	getKeyFunc       func(ctx context.Context, keyID string) (*kms.KeyInfo, error)
	getPublicKeyFunc func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error)
	listKeysFunc     func(ctx context.Context) (*kms.ListKeysResponse, error)
	rotateKeyFunc    func(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error)
	deleteKeyFunc    func(ctx context.Context, keyID string) error

	setKeyRotationPolicyFunc    func(ctx context.Context, req *kms.SetKeyRotationPolicyRequest) (*kms.KeyRotationPolicy, error)
	getKeyRotationPolicyFunc    func(ctx context.Context, keyID string) (*kms.KeyRotationPolicy, error)
	deleteKeyRotationPolicyFunc func(ctx context.Context, keyID string) error
}

func (m *mockSDKKMSClient) GenerateKey(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
	if m.generateKeyFunc != nil {
		return m.generateKeyFunc(ctx, req)
	}
	return nil, errors.New("generateKey not implemented")
}

func (m *mockSDKKMSClient) GetKey(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
	if m.getKeyFunc != nil {
		return m.getKeyFunc(ctx, keyID)
	}
	return nil, errors.New("getKey not implemented")
}

func (m *mockSDKKMSClient) GetPublicKey(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
	if m.getPublicKeyFunc != nil {
		return m.getPublicKeyFunc(ctx, keyID)
	}
	return nil, errors.New("getPublicKey not implemented")
}

func (m *mockSDKKMSClient) ListKeys(ctx context.Context) (*kms.ListKeysResponse, error) {
	if m.listKeysFunc != nil {
		return m.listKeysFunc(ctx)
	}
	return nil, errors.New("listKeys not implemented")
}

func (m *mockSDKKMSClient) RotateKey(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
	if m.rotateKeyFunc != nil {
		return m.rotateKeyFunc(ctx, keyID)
	}
	return nil, errors.New("rotateKey not implemented")
}

func (m *mockSDKKMSClient) DeleteKey(ctx context.Context, keyID string) error {
	if m.deleteKeyFunc != nil {
		return m.deleteKeyFunc(ctx, keyID)
	}
	return errors.New("deleteKey not implemented")
}

func (m *mockSDKKMSClient) SetKeyRotationPolicy(ctx context.Context, req *kms.SetKeyRotationPolicyRequest) (*kms.KeyRotationPolicy, error) {
	if m.setKeyRotationPolicyFunc != nil {
		return m.setKeyRotationPolicyFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockSDKKMSClient) GetKeyRotationPolicy(ctx context.Context, keyID string) (*kms.KeyRotationPolicy, error) {
	if m.getKeyRotationPolicyFunc != nil {
		return m.getKeyRotationPolicyFunc(ctx, keyID)
	}
	return nil, nil
}

func (m *mockSDKKMSClient) DeleteKeyRotationPolicy(ctx context.Context, keyID string) error {
	if m.deleteKeyRotationPolicyFunc != nil {
		return m.deleteKeyRotationPolicyFunc(ctx, keyID)
	}
	return nil
}

func (m *mockSDKKMSClient) ImportKey(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error) {
	return nil, errors.New("importKey not implemented")
}

func (m *mockSDKKMSClient) ExportKey(ctx context.Context, req *kms.ExportKeyRequest) (*kms.ExportKeyResponse, error) {
	return nil, errors.New("exportKey not implemented")
}

func (m *mockSDKKMSClient) RevokeKey(ctx context.Context, keyID string) error {
	return errors.New("revokeKey not implemented")
}

func (m *mockSDKKMSClient) ListKeyVersions(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error) {
	return nil, errors.New("listKeyVersions not implemented")
}

func (m *mockSDKKMSClient) UpdateKeyStatus(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
	return nil, errors.New("updateKeyStatus not implemented")
}

func (m *mockSDKKMSClient) GetKeyMetadata(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
	return nil, errors.New("getKeyMetadata not implemented")
}

func (m *mockSDKKMSClient) UpdateKeyMetadata(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
	return nil, errors.New("updateKeyMetadata not implemented")
}

func (m *mockSDKKMSClient) SetKeyPolicy(ctx context.Context, req *kms.SetKeyPolicyRequest) error {
	return errors.New("setKeyPolicy not implemented")
}

func (m *mockSDKKMSClient) GetKeyPolicy(ctx context.Context, keyID string) (*kms.KeyPolicy, error) {
	return nil, errors.New("getKeyPolicy not implemented")
}

func (m *mockSDKKMSClient) GetSupportedAlgorithms(ctx context.Context) (*kms.SupportedAlgorithmsResponse, error) {
	return nil, errors.New("getSupportedAlgorithms not implemented")
}

func (m *mockSDKKMSClient) BackendStatus(ctx context.Context) (*kms.BackendStatusResponse, error) {
	return nil, errors.New("backendStatus not implemented")
}

func (m *mockSDKKMSClient) UnwrapKey(ctx context.Context, req *kms.UnwrapKeyRequest) (*kms.UnwrapKeyResponse, error) {
	return nil, errors.New("unwrapKey not implemented")
}

// =============================================================================
// KMSAdapter Tests
// =============================================================================

func TestNewKMSAdapter(t *testing.T) {
	t.Run("creates adapter with kms client", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{}
		adapter := NewKMSAdapter(mockKMS)

		require.NotNil(t, adapter)
		assert.Equal(t, mockKMS, adapter.kms)
	})

	t.Run("creates adapter with nil kms client", func(t *testing.T) {
		adapter := NewKMSAdapter(nil)

		require.NotNil(t, adapter)
		assert.Nil(t, adapter.kms)
	})
}

func TestKMSAdapter_GenerateKey_Success(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		generateKeyFunc: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
			assert.Equal(t, "test-signing-key", req.Name)
			assert.Equal(t, kms.AlgorithmRSA2048, req.Algorithm)
			assert.Contains(t, req.Usage, kms.KeyUsageSign)
			return &kms.GenerateKeyResponse{
				KeyID:     "key-123",
				Version:   1,
				Algorithm: kms.AlgorithmRSA2048,
			}, nil
		},
	}

	adapter := NewKMSAdapter(mockKMS)
	ctx := context.Background()

	resp, err := adapter.GenerateKey(ctx, &trustedca.CAKMSGenerateKeyRequest{
		Name:      "test-signing-key",
		Algorithm: trustedca.CAKMSAlgorithmRSA2048,
		Usage:     []trustedca.CAKMSKeyUsage{trustedca.CAKMSKeyUsageSign},
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "key-123", resp.KeyID)
	assert.Equal(t, 1, resp.Version)
}

func TestKMSAdapter_GenerateKey_NilRequest(t *testing.T) {
	adapter := NewKMSAdapter(&mockSDKKMSClient{})
	ctx := context.Background()

	resp, err := adapter.GenerateKey(ctx, nil)

	require.Error(t, err)
	assert.Nil(t, resp)

	var inputErr ErrInvalidInput
	assert.True(t, errors.As(err, &inputErr))
	assert.Equal(t, "request", inputErr.Field)
}

func TestKMSAdapter_GenerateKey_EmptyName(t *testing.T) {
	adapter := NewKMSAdapter(&mockSDKKMSClient{})
	ctx := context.Background()

	resp, err := adapter.GenerateKey(ctx, &trustedca.CAKMSGenerateKeyRequest{
		Name:      "",
		Algorithm: trustedca.CAKMSAlgorithmRSA2048,
	})

	require.Error(t, err)
	assert.Nil(t, resp)

	var inputErr ErrInvalidInput
	assert.True(t, errors.As(err, &inputErr))
	assert.Equal(t, "name", inputErr.Field)
}

func TestKMSAdapter_GenerateKey_NilKMS(t *testing.T) {
	adapter := NewKMSAdapter(nil)
	ctx := context.Background()

	resp, err := adapter.GenerateKey(ctx, &trustedca.CAKMSGenerateKeyRequest{
		Name:      "test-key",
		Algorithm: trustedca.CAKMSAlgorithmRSA2048,
	})

	require.Error(t, err)
	assert.Nil(t, resp)

	var unavailErr ErrQuicBaaSUnavailable
	assert.True(t, errors.As(err, &unavailErr))
}

func TestKMSAdapter_GenerateKey_KMSError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		generateKeyFunc: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
			return nil, errors.New("generation failed")
		},
	}

	adapter := NewKMSAdapter(mockKMS)
	ctx := context.Background()

	resp, err := adapter.GenerateKey(ctx, &trustedca.CAKMSGenerateKeyRequest{
		Name:      "test-key",
		Algorithm: trustedca.CAKMSAlgorithmRSA2048,
	})

	require.Error(t, err)
	assert.Nil(t, resp)

	var opErr ErrOperationFailed
	assert.True(t, errors.As(err, &opErr))
	assert.Equal(t, "GenerateKey", opErr.Operation)
}

func TestKMSAdapter_GetKey_Success(t *testing.T) {
	createdAt := time.Now()
	mockKMS := &mockSDKKMSClient{
		getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
			assert.Equal(t, "key-123", keyID)
			return &kms.KeyInfo{
				KeyID:     "key-123",
				Name:      "test-key",
				Algorithm: kms.AlgorithmRSA2048,
				Version:   1,
				Usage:     []kms.KeyUsage{kms.KeyUsageSign, kms.KeyUsageVerify},
				CreatedAt: createdAt,
			}, nil
		},
	}

	adapter := NewKMSAdapter(mockKMS)
	ctx := context.Background()

	info, err := adapter.GetKey(ctx, "key-123")

	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "key-123", info.KeyID)
	assert.Equal(t, "test-key", info.Name)
	assert.Equal(t, trustedca.CAKMSAlgorithmRSA2048, info.Algorithm)
	assert.Equal(t, 1, info.Version)
	assert.Contains(t, info.Usage, trustedca.CAKMSKeyUsageSign)
	assert.Contains(t, info.Usage, trustedca.CAKMSKeyUsageVerify)
}

func TestKMSAdapter_GetKey_EmptyKeyID(t *testing.T) {
	adapter := NewKMSAdapter(&mockSDKKMSClient{})
	ctx := context.Background()

	info, err := adapter.GetKey(ctx, "")

	require.Error(t, err)
	assert.Nil(t, info)

	var inputErr ErrInvalidInput
	assert.True(t, errors.As(err, &inputErr))
	assert.Equal(t, "keyID", inputErr.Field)
}

func TestKMSAdapter_GetKey_NilKMS(t *testing.T) {
	adapter := NewKMSAdapter(nil)
	ctx := context.Background()

	info, err := adapter.GetKey(ctx, "key-123")

	require.Error(t, err)
	assert.Nil(t, info)

	var unavailErr ErrQuicBaaSUnavailable
	assert.True(t, errors.As(err, &unavailErr))
}

func TestKMSAdapter_GetKey_NotFound(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
			return nil, errors.New("key not found")
		},
	}

	adapter := NewKMSAdapter(mockKMS)
	ctx := context.Background()

	info, err := adapter.GetKey(ctx, "nonexistent")

	require.Error(t, err)
	assert.Nil(t, info)

	var notFoundErr ErrKeyNotFound
	assert.True(t, errors.As(err, &notFoundErr))
	assert.Equal(t, "nonexistent", notFoundErr.KeyID)
}

func TestKMSAdapter_ListKeys_Success(t *testing.T) {
	createdAt := time.Now()
	mockKMS := &mockSDKKMSClient{
		listKeysFunc: func(ctx context.Context) (*kms.ListKeysResponse, error) {
			return &kms.ListKeysResponse{
				Keys: []kms.KeyInfo{
					{
						KeyID:     "key-1",
						Name:      "signing-key-1",
						Algorithm: kms.AlgorithmRSA2048,
						Version:   1,
						Usage:     []kms.KeyUsage{kms.KeyUsageSign},
						CreatedAt: createdAt,
					},
					{
						KeyID:     "key-2",
						Name:      "signing-key-2",
						Algorithm: kms.AlgorithmECDSAP256,
						Version:   2,
						Usage:     []kms.KeyUsage{kms.KeyUsageSign, kms.KeyUsageVerify},
						CreatedAt: createdAt,
					},
				},
			}, nil
		},
	}

	adapter := NewKMSAdapter(mockKMS)
	ctx := context.Background()

	resp, err := adapter.ListKeys(ctx)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Keys, 2)
	assert.Equal(t, "key-1", resp.Keys[0].KeyID)
	assert.Equal(t, trustedca.CAKMSAlgorithmRSA2048, resp.Keys[0].Algorithm)
	assert.Equal(t, "key-2", resp.Keys[1].KeyID)
	assert.Equal(t, trustedca.CAKMSAlgorithmECDSAP256, resp.Keys[1].Algorithm)
}

func TestKMSAdapter_ListKeys_NilKMS(t *testing.T) {
	adapter := NewKMSAdapter(nil)
	ctx := context.Background()

	resp, err := adapter.ListKeys(ctx)

	require.Error(t, err)
	assert.Nil(t, resp)

	var unavailErr ErrQuicBaaSUnavailable
	assert.True(t, errors.As(err, &unavailErr))
}

func TestKMSAdapter_ListKeys_KMSError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		listKeysFunc: func(ctx context.Context) (*kms.ListKeysResponse, error) {
			return nil, errors.New("list failed")
		},
	}

	adapter := NewKMSAdapter(mockKMS)
	ctx := context.Background()

	resp, err := adapter.ListKeys(ctx)

	require.Error(t, err)
	assert.Nil(t, resp)

	var opErr ErrOperationFailed
	assert.True(t, errors.As(err, &opErr))
	assert.Equal(t, "ListKeys", opErr.Operation)
}

func TestKMSAdapter_RotateKey_Success(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		rotateKeyFunc: func(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
			assert.Equal(t, "key-123", keyID)
			return &kms.RotateKeyResponse{
				KeyID:      "key-123",
				NewVersion: 2,
			}, nil
		},
	}

	adapter := NewKMSAdapter(mockKMS)
	ctx := context.Background()

	resp, err := adapter.RotateKey(ctx, "key-123")

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "key-123", resp.KeyID)
	assert.Equal(t, 2, resp.NewVersion)
}

func TestKMSAdapter_RotateKey_EmptyKeyID(t *testing.T) {
	adapter := NewKMSAdapter(&mockSDKKMSClient{})
	ctx := context.Background()

	resp, err := adapter.RotateKey(ctx, "")

	require.Error(t, err)
	assert.Nil(t, resp)

	var inputErr ErrInvalidInput
	assert.True(t, errors.As(err, &inputErr))
	assert.Equal(t, "keyID", inputErr.Field)
}

func TestKMSAdapter_RotateKey_NilKMS(t *testing.T) {
	adapter := NewKMSAdapter(nil)
	ctx := context.Background()

	resp, err := adapter.RotateKey(ctx, "key-123")

	require.Error(t, err)
	assert.Nil(t, resp)

	var unavailErr ErrQuicBaaSUnavailable
	assert.True(t, errors.As(err, &unavailErr))
}

func TestKMSAdapter_RotateKey_KMSError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		rotateKeyFunc: func(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
			return nil, errors.New("rotation failed")
		},
	}

	adapter := NewKMSAdapter(mockKMS)
	ctx := context.Background()

	resp, err := adapter.RotateKey(ctx, "key-123")

	require.Error(t, err)
	assert.Nil(t, resp)

	var opErr ErrOperationFailed
	assert.True(t, errors.As(err, &opErr))
	assert.Equal(t, "RotateKey", opErr.Operation)
}

func TestKMSAdapter_DeleteKey_Success(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		deleteKeyFunc: func(ctx context.Context, keyID string) error {
			assert.Equal(t, "key-123", keyID)
			return nil
		},
	}

	adapter := NewKMSAdapter(mockKMS)
	ctx := context.Background()

	err := adapter.DeleteKey(ctx, "key-123")

	require.NoError(t, err)
}

func TestKMSAdapter_DeleteKey_EmptyKeyID(t *testing.T) {
	adapter := NewKMSAdapter(&mockSDKKMSClient{})
	ctx := context.Background()

	err := adapter.DeleteKey(ctx, "")

	require.Error(t, err)

	var inputErr ErrInvalidInput
	assert.True(t, errors.As(err, &inputErr))
	assert.Equal(t, "keyID", inputErr.Field)
}

func TestKMSAdapter_DeleteKey_NilKMS(t *testing.T) {
	adapter := NewKMSAdapter(nil)
	ctx := context.Background()

	err := adapter.DeleteKey(ctx, "key-123")

	require.Error(t, err)

	var unavailErr ErrQuicBaaSUnavailable
	assert.True(t, errors.As(err, &unavailErr))
}

func TestKMSAdapter_DeleteKey_KMSError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		deleteKeyFunc: func(ctx context.Context, keyID string) error {
			return errors.New("delete failed")
		},
	}

	adapter := NewKMSAdapter(mockKMS)
	ctx := context.Background()

	err := adapter.DeleteKey(ctx, "key-123")

	require.Error(t, err)

	var opErr ErrOperationFailed
	assert.True(t, errors.As(err, &opErr))
	assert.Equal(t, "DeleteKey", opErr.Operation)
}

// =============================================================================
// Algorithm Mapping Tests
// =============================================================================

func TestMapAlgorithmToSDK(t *testing.T) {
	tests := []struct {
		input    trustedca.CAKMSKeyAlgorithm
		expected kms.KeyAlgorithm
	}{
		{trustedca.CAKMSAlgorithmRSA2048, kms.AlgorithmRSA2048},
		{trustedca.CAKMSAlgorithmRSA4096, kms.AlgorithmRSA4096},
		{trustedca.CAKMSAlgorithmECDSAP256, kms.AlgorithmECDSAP256},
		{trustedca.CAKMSAlgorithmECDSAP384, kms.AlgorithmECDSAP384},
		{trustedca.CAKMSAlgorithmED25519, kms.AlgorithmED25519},
		{"EC-P256", kms.AlgorithmECDSAP256},
		{"EC-P384", kms.AlgorithmECDSAP384},
		{"unknown", kms.AlgorithmECDSAP256}, // default
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := mapAlgorithmToSDK(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapAlgorithmFromSDK(t *testing.T) {
	tests := []struct {
		input    kms.KeyAlgorithm
		expected trustedca.CAKMSKeyAlgorithm
	}{
		{kms.AlgorithmRSA2048, trustedca.CAKMSAlgorithmRSA2048},
		{kms.AlgorithmRSA4096, trustedca.CAKMSAlgorithmRSA4096},
		{kms.AlgorithmECDSAP256, trustedca.CAKMSAlgorithmECDSAP256},
		{kms.AlgorithmECDSAP384, trustedca.CAKMSAlgorithmECDSAP384},
		{kms.AlgorithmED25519, trustedca.CAKMSAlgorithmED25519},
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			result := mapAlgorithmFromSDK(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapUsageToSDK(t *testing.T) {
	usages := []trustedca.CAKMSKeyUsage{
		trustedca.CAKMSKeyUsageSign,
		trustedca.CAKMSKeyUsageVerify,
		trustedca.CAKMSKeyUsageEncrypt,
		trustedca.CAKMSKeyUsageDecrypt,
	}

	result := mapUsageToSDK(usages)

	require.Len(t, result, 4)
	assert.Contains(t, result, kms.KeyUsageSign)
	assert.Contains(t, result, kms.KeyUsageVerify)
	assert.Contains(t, result, kms.KeyUsageEncrypt)
	assert.Contains(t, result, kms.KeyUsageDecrypt)
}

func TestMapUsageFromSDK(t *testing.T) {
	usages := []kms.KeyUsage{
		kms.KeyUsageSign,
		kms.KeyUsageVerify,
		kms.KeyUsageEncrypt,
		kms.KeyUsageDecrypt,
	}

	result := mapUsageFromSDK(usages)

	require.Len(t, result, 4)
	assert.Contains(t, result, trustedca.CAKMSKeyUsageSign)
	assert.Contains(t, result, trustedca.CAKMSKeyUsageVerify)
	assert.Contains(t, result, trustedca.CAKMSKeyUsageEncrypt)
	assert.Contains(t, result, trustedca.CAKMSKeyUsageDecrypt)
}

// =============================================================================
// Error Types Tests
// =============================================================================

func TestErrAdapterNotInitialized(t *testing.T) {
	err := ErrAdapterNotInitialized{}
	assert.Equal(t, "caquicbaas: adapter not initialized", err.Error())
}

func TestErrKeyConversionFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("parse error")
		err := ErrKeyConversionFailed{Key: "test-key", Cause: cause}
		assert.Contains(t, err.Error(), "test-key")
		assert.Contains(t, err.Error(), "parse error")
		assert.ErrorIs(t, err.Unwrap(), cause)
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrKeyConversionFailed{Key: "test-key"}
		assert.Contains(t, err.Error(), "test-key")
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrUnsupportedOperation(t *testing.T) {
	t.Run("with reason", func(t *testing.T) {
		err := ErrUnsupportedOperation{Operation: "Watch", Reason: "not implemented"}
		assert.Contains(t, err.Error(), "Watch")
		assert.Contains(t, err.Error(), "not implemented")
	})

	t.Run("without reason", func(t *testing.T) {
		err := ErrUnsupportedOperation{Operation: "Watch"}
		assert.Contains(t, err.Error(), "Watch")
	})
}

func TestErrQuicBaaSUnavailable(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := ErrQuicBaaSUnavailable{Cause: cause}
		assert.Contains(t, err.Error(), "connection refused")
		assert.ErrorIs(t, err.Unwrap(), cause)
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrQuicBaaSUnavailable{}
		assert.Contains(t, err.Error(), "unavailable")
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrInvalidInput(t *testing.T) {
	err := ErrInvalidInput{Field: "tenantID", Reason: "cannot be empty"}
	assert.Contains(t, err.Error(), "tenantID")
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestErrKeyNotFound(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("not in database")
		err := ErrKeyNotFound{KeyID: "key-123", Cause: cause}
		assert.Contains(t, err.Error(), "key-123")
		assert.Contains(t, err.Error(), "not in database")
		assert.ErrorIs(t, err.Unwrap(), cause)
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrKeyNotFound{KeyID: "key-123"}
		assert.Contains(t, err.Error(), "key-123")
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrKeyDisabled(t *testing.T) {
	err := ErrKeyDisabled{KeyID: "key-123"}
	assert.Contains(t, err.Error(), "key-123")
	assert.Contains(t, err.Error(), "disabled")
}

func TestErrOperationFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("timeout")
		err := ErrOperationFailed{Operation: "GenerateKey", Cause: cause}
		assert.Contains(t, err.Error(), "GenerateKey")
		assert.Contains(t, err.Error(), "timeout")
		assert.ErrorIs(t, err.Unwrap(), cause)
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrOperationFailed{Operation: "GenerateKey"}
		assert.Contains(t, err.Error(), "GenerateKey")
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrTenantMismatch(t *testing.T) {
	err := ErrTenantMismatch{ExpectedTenant: "tenant-a", ActualTenant: "tenant-b"}
	assert.Contains(t, err.Error(), "tenant-a")
	assert.Contains(t, err.Error(), "tenant-b")
}

func TestErrOperationNotSupported(t *testing.T) {
	err := ErrOperationNotSupported{Operation: "StoreCertificate"}
	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "StoreCertificate")
	assert.Contains(t, errorMsg, "not supported")
	assert.Contains(t, errorMsg, "cluster storage")
}

// =============================================================================
// Interface Compliance Tests
// =============================================================================

func TestInterfaceCompliance(t *testing.T) {
	t.Run("KMSAdapter implements KMSClient", func(t *testing.T) {
		var _ trustedca.CAKMSClient = (*QuicBaaSKMSAdapter)(nil)
	})
}

func TestErrCertNotFound(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrCertNotFound{CertID: "test-cert-123", Cause: cause}
		assert.Contains(t, err.Error(), "test-cert-123")
		assert.Contains(t, err.Error(), "underlying error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrCertNotFound{CertID: "test-cert-456"}
		assert.Contains(t, err.Error(), "test-cert-456")
		assert.NotContains(t, err.Error(), "<nil>")
		assert.Nil(t, err.Unwrap())
	})
}
