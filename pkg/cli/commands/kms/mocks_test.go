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
	"context"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"google.golang.org/grpc"
)

// ErrMockClientOperation is returned when a mock client operation fails
type ErrMockClientOperation struct {
	Operation string
	Reason    string
}

func (e ErrMockClientOperation) Error() string {
	return e.Operation + ": " + e.Reason
}

// MockKeyManagementClient implements pb.KeyManagementClient for testing
type MockKeyManagementClient struct {
	GenerateKeyFunc            func(ctx context.Context, in *pb.GenerateKeyRequest, opts ...grpc.CallOption) (*pb.GenerateKeyResponse, error)
	GetKeyFunc                 func(ctx context.Context, in *pb.GetKeyRequest, opts ...grpc.CallOption) (*pb.GetKeyResponse, error)
	ListKeysFunc               func(ctx context.Context, in *pb.ListKeysRequest, opts ...grpc.CallOption) (*pb.ListKeysResponse, error)
	DeleteKeyFunc              func(ctx context.Context, in *pb.DeleteKeyRequest, opts ...grpc.CallOption) (*pb.DeleteKeyResponse, error)
	RotateKeyFunc              func(ctx context.Context, in *pb.RotateKeyRequest, opts ...grpc.CallOption) (*pb.RotateKeyResponse, error)
	BackendStatusFunc          func(ctx context.Context, in *pb.BackendStatusRequest, opts ...grpc.CallOption) (*pb.BackendStatusResponse, error)
	ImportKeyFunc              func(ctx context.Context, in *pb.ImportKeyRequest, opts ...grpc.CallOption) (*pb.ImportKeyResponse, error)
	ListKeyVersionsFunc        func(ctx context.Context, in *pb.ListKeyVersionsRequest, opts ...grpc.CallOption) (*pb.ListKeyVersionsResponse, error)
	RevokeKeyFunc              func(ctx context.Context, in *pb.RevokeKeyRequest, opts ...grpc.CallOption) (*pb.RevokeKeyResponse, error)
	UpdateKeyStatusFunc        func(ctx context.Context, in *pb.UpdateKeyStatusRequest, opts ...grpc.CallOption) (*pb.UpdateKeyStatusResponse, error)
	GetKeyMetadataFunc         func(ctx context.Context, in *pb.GetKeyMetadataRequest, opts ...grpc.CallOption) (*pb.GetKeyMetadataResponse, error)
	UpdateKeyMetadataFunc      func(ctx context.Context, in *pb.UpdateKeyMetadataRequest, opts ...grpc.CallOption) (*pb.UpdateKeyMetadataResponse, error)
	SetKeyPolicyFunc           func(ctx context.Context, in *pb.SetKeyPolicyRequest, opts ...grpc.CallOption) (*pb.SetKeyPolicyResponse, error)
	GetKeyPolicyFunc           func(ctx context.Context, in *pb.GetKeyPolicyRequest, opts ...grpc.CallOption) (*pb.GetKeyPolicyResponse, error)
	GetSupportedAlgorithmsFunc func(ctx context.Context, in *pb.GetSupportedAlgorithmsRequest, opts ...grpc.CallOption) (*pb.GetSupportedAlgorithmsResponse, error)
	BackendTestFunc            func(ctx context.Context, in *pb.BackendTestRequest, opts ...grpc.CallOption) (*pb.BackendTestResponse, error)
	ExportKeyFunc              func(ctx context.Context, in *pb.ExportKeyRequest, opts ...grpc.CallOption) (*pb.ExportKeyResponse, error)
	UnwrapKeyFunc              func(ctx context.Context, in *pb.UnwrapKeyRequest, opts ...grpc.CallOption) (*pb.UnwrapKeyResponse, error)
	// NOTE: SetKeySafetyFunc, ClearKeySafetyFunc, SafetyCheckFunc, SafetyReportFunc
	// require go-quicbaas API features that are not yet released. Enable with key_safety build tag.
}

func (m *MockKeyManagementClient) GenerateKey(ctx context.Context, in *pb.GenerateKeyRequest, opts ...grpc.CallOption) (*pb.GenerateKeyResponse, error) {
	if m.GenerateKeyFunc != nil {
		return m.GenerateKeyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GenerateKey", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) GetKey(ctx context.Context, in *pb.GetKeyRequest, opts ...grpc.CallOption) (*pb.GetKeyResponse, error) {
	if m.GetKeyFunc != nil {
		return m.GetKeyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GetKey", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) ListKeys(ctx context.Context, in *pb.ListKeysRequest, opts ...grpc.CallOption) (*pb.ListKeysResponse, error) {
	if m.ListKeysFunc != nil {
		return m.ListKeysFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "ListKeys", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) DeleteKey(ctx context.Context, in *pb.DeleteKeyRequest, opts ...grpc.CallOption) (*pb.DeleteKeyResponse, error) {
	if m.DeleteKeyFunc != nil {
		return m.DeleteKeyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "DeleteKey", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) RotateKey(ctx context.Context, in *pb.RotateKeyRequest, opts ...grpc.CallOption) (*pb.RotateKeyResponse, error) {
	if m.RotateKeyFunc != nil {
		return m.RotateKeyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "RotateKey", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) BackendStatus(ctx context.Context, in *pb.BackendStatusRequest, opts ...grpc.CallOption) (*pb.BackendStatusResponse, error) {
	if m.BackendStatusFunc != nil {
		return m.BackendStatusFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "BackendStatus", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) ImportKey(ctx context.Context, in *pb.ImportKeyRequest, opts ...grpc.CallOption) (*pb.ImportKeyResponse, error) {
	if m.ImportKeyFunc != nil {
		return m.ImportKeyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "ImportKey", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) ListKeyVersions(ctx context.Context, in *pb.ListKeyVersionsRequest, opts ...grpc.CallOption) (*pb.ListKeyVersionsResponse, error) {
	if m.ListKeyVersionsFunc != nil {
		return m.ListKeyVersionsFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "ListKeyVersions", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) RevokeKey(ctx context.Context, in *pb.RevokeKeyRequest, opts ...grpc.CallOption) (*pb.RevokeKeyResponse, error) {
	if m.RevokeKeyFunc != nil {
		return m.RevokeKeyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "RevokeKey", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) UpdateKeyStatus(ctx context.Context, in *pb.UpdateKeyStatusRequest, opts ...grpc.CallOption) (*pb.UpdateKeyStatusResponse, error) {
	if m.UpdateKeyStatusFunc != nil {
		return m.UpdateKeyStatusFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "UpdateKeyStatus", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) GetKeyMetadata(ctx context.Context, in *pb.GetKeyMetadataRequest, opts ...grpc.CallOption) (*pb.GetKeyMetadataResponse, error) {
	if m.GetKeyMetadataFunc != nil {
		return m.GetKeyMetadataFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GetKeyMetadata", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) UpdateKeyMetadata(ctx context.Context, in *pb.UpdateKeyMetadataRequest, opts ...grpc.CallOption) (*pb.UpdateKeyMetadataResponse, error) {
	if m.UpdateKeyMetadataFunc != nil {
		return m.UpdateKeyMetadataFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "UpdateKeyMetadata", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) SetKeyPolicy(ctx context.Context, in *pb.SetKeyPolicyRequest, opts ...grpc.CallOption) (*pb.SetKeyPolicyResponse, error) {
	if m.SetKeyPolicyFunc != nil {
		return m.SetKeyPolicyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "SetKeyPolicy", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) GetKeyPolicy(ctx context.Context, in *pb.GetKeyPolicyRequest, opts ...grpc.CallOption) (*pb.GetKeyPolicyResponse, error) {
	if m.GetKeyPolicyFunc != nil {
		return m.GetKeyPolicyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GetKeyPolicy", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) GetSupportedAlgorithms(ctx context.Context, in *pb.GetSupportedAlgorithmsRequest, opts ...grpc.CallOption) (*pb.GetSupportedAlgorithmsResponse, error) {
	if m.GetSupportedAlgorithmsFunc != nil {
		return m.GetSupportedAlgorithmsFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GetSupportedAlgorithms", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) BackendTest(ctx context.Context, in *pb.BackendTestRequest, opts ...grpc.CallOption) (*pb.BackendTestResponse, error) {
	if m.BackendTestFunc != nil {
		return m.BackendTestFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "BackendTest", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) ExportKey(ctx context.Context, in *pb.ExportKeyRequest, opts ...grpc.CallOption) (*pb.ExportKeyResponse, error) {
	if m.ExportKeyFunc != nil {
		return m.ExportKeyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "ExportKey", Reason: "not implemented"}
}

func (m *MockKeyManagementClient) UnwrapKey(ctx context.Context, in *pb.UnwrapKeyRequest, opts ...grpc.CallOption) (*pb.UnwrapKeyResponse, error) {
	if m.UnwrapKeyFunc != nil {
		return m.UnwrapKeyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "UnwrapKey", Reason: "not implemented"}
}

// NOTE: SetKeySafety, ClearKeySafety, SafetyCheck, SafetyReport methods
// require go-quicbaas API features that are not yet released. Enable with key_safety build tag.

// MockDEKManagementClient implements pb.DEKManagementClient for testing
type MockDEKManagementClient struct {
	CreateDEKFunc     func(ctx context.Context, in *pb.CreateDEKRequest, opts ...grpc.CallOption) (*pb.CreateDEKResponse, error)
	GetDEKFunc        func(ctx context.Context, in *pb.GetDEKRequest, opts ...grpc.CallOption) (*pb.GetDEKResponse, error)
	ListDEKsFunc      func(ctx context.Context, in *pb.ListDEKsRequest, opts ...grpc.CallOption) (*pb.ListDEKsResponse, error)
	DeleteDEKFunc     func(ctx context.Context, in *pb.DeleteDEKRequest, opts ...grpc.CallOption) (*pb.DeleteDEKResponse, error)
	RotateDEKFunc     func(ctx context.Context, in *pb.RotateDEKRequest, opts ...grpc.CallOption) (*pb.RotateDEKResponse, error)
	GetDEKStatusFunc  func(ctx context.Context, in *pb.GetDEKStatusRequest, opts ...grpc.CallOption) (*pb.GetDEKStatusResponse, error)
	SetDefaultDEKFunc func(ctx context.Context, in *pb.SetDefaultDEKRequest, opts ...grpc.CallOption) (*pb.SetDefaultDEKResponse, error)
	// NOTE: SetDEKSafetyFunc, ClearDEKSafetyFunc require go-quicbaas API features
	// that are not yet released. Enable with key_safety build tag.
}

func (m *MockDEKManagementClient) CreateDEK(ctx context.Context, in *pb.CreateDEKRequest, opts ...grpc.CallOption) (*pb.CreateDEKResponse, error) {
	if m.CreateDEKFunc != nil {
		return m.CreateDEKFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "CreateDEK", Reason: "not implemented"}
}

func (m *MockDEKManagementClient) GetDEK(ctx context.Context, in *pb.GetDEKRequest, opts ...grpc.CallOption) (*pb.GetDEKResponse, error) {
	if m.GetDEKFunc != nil {
		return m.GetDEKFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GetDEK", Reason: "not implemented"}
}

func (m *MockDEKManagementClient) ListDEKs(ctx context.Context, in *pb.ListDEKsRequest, opts ...grpc.CallOption) (*pb.ListDEKsResponse, error) {
	if m.ListDEKsFunc != nil {
		return m.ListDEKsFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "ListDEKs", Reason: "not implemented"}
}

func (m *MockDEKManagementClient) DeleteDEK(ctx context.Context, in *pb.DeleteDEKRequest, opts ...grpc.CallOption) (*pb.DeleteDEKResponse, error) {
	if m.DeleteDEKFunc != nil {
		return m.DeleteDEKFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "DeleteDEK", Reason: "not implemented"}
}

func (m *MockDEKManagementClient) RotateDEK(ctx context.Context, in *pb.RotateDEKRequest, opts ...grpc.CallOption) (*pb.RotateDEKResponse, error) {
	if m.RotateDEKFunc != nil {
		return m.RotateDEKFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "RotateDEK", Reason: "not implemented"}
}

func (m *MockDEKManagementClient) GetDEKStatus(ctx context.Context, in *pb.GetDEKStatusRequest, opts ...grpc.CallOption) (*pb.GetDEKStatusResponse, error) {
	if m.GetDEKStatusFunc != nil {
		return m.GetDEKStatusFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GetDEKStatus", Reason: "not implemented"}
}

func (m *MockDEKManagementClient) SetDefaultDEK(ctx context.Context, in *pb.SetDefaultDEKRequest, opts ...grpc.CallOption) (*pb.SetDefaultDEKResponse, error) {
	if m.SetDefaultDEKFunc != nil {
		return m.SetDefaultDEKFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "SetDefaultDEK", Reason: "not implemented"}
}

// NOTE: SetDEKSafety, ClearDEKSafety methods require go-quicbaas API features
// that are not yet released. Enable with key_safety build tag.

// MockSecretsManagementClient implements pb.SecretsManagementClient for testing
type MockSecretsManagementClient struct {
	StoreSecretFunc          func(ctx context.Context, in *pb.StoreSecretRequest, opts ...grpc.CallOption) (*pb.StoreSecretResponse, error)
	GetSecretFunc            func(ctx context.Context, in *pb.GetSecretRequest, opts ...grpc.CallOption) (*pb.GetSecretResponse, error)
	ListSecretsFunc          func(ctx context.Context, in *pb.ListSecretsRequest, opts ...grpc.CallOption) (*pb.ListSecretsResponse, error)
	DeleteSecretFunc         func(ctx context.Context, in *pb.DeleteSecretRequest, opts ...grpc.CallOption) (*pb.DeleteSecretResponse, error)
	RotateSecretFunc         func(ctx context.Context, in *pb.RotateSecretRequest, opts ...grpc.CallOption) (*pb.RotateSecretResponse, error)
	GetSecretVersionFunc     func(ctx context.Context, in *pb.GetSecretVersionRequest, opts ...grpc.CallOption) (*pb.GetSecretVersionResponse, error)
	ListSecretVersionsFunc   func(ctx context.Context, in *pb.ListSecretVersionsRequest, opts ...grpc.CallOption) (*pb.ListSecretVersionsResponse, error)
	RollbackSecretFunc       func(ctx context.Context, in *pb.RollbackSecretRequest, opts ...grpc.CallOption) (*pb.RollbackSecretResponse, error)
	UpdateSecretStatusFunc   func(ctx context.Context, in *pb.UpdateSecretStatusRequest, opts ...grpc.CallOption) (*pb.UpdateSecretStatusResponse, error)
	SetRotationPolicyFunc    func(ctx context.Context, in *pb.SetRotationPolicyRequest, opts ...grpc.CallOption) (*pb.SetRotationPolicyResponse, error)
	GetRotationPolicyFunc    func(ctx context.Context, in *pb.GetRotationPolicyRequest, opts ...grpc.CallOption) (*pb.GetRotationPolicyResponse, error)
	GetSecretsByPrefixFunc   func(ctx context.Context, in *pb.GetSecretsByPrefixRequest, opts ...grpc.CallOption) (*pb.GetSecretsByPrefixResponse, error)
	WatchSecretsByPrefixFunc func(ctx context.Context, in *pb.WatchSecretsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pb.SecretChange], error)
}

func (m *MockSecretsManagementClient) StoreSecret(ctx context.Context, in *pb.StoreSecretRequest, opts ...grpc.CallOption) (*pb.StoreSecretResponse, error) {
	if m.StoreSecretFunc != nil {
		return m.StoreSecretFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "StoreSecret", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) GetSecret(ctx context.Context, in *pb.GetSecretRequest, opts ...grpc.CallOption) (*pb.GetSecretResponse, error) {
	if m.GetSecretFunc != nil {
		return m.GetSecretFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GetSecret", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) ListSecrets(ctx context.Context, in *pb.ListSecretsRequest, opts ...grpc.CallOption) (*pb.ListSecretsResponse, error) {
	if m.ListSecretsFunc != nil {
		return m.ListSecretsFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "ListSecrets", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) DeleteSecret(ctx context.Context, in *pb.DeleteSecretRequest, opts ...grpc.CallOption) (*pb.DeleteSecretResponse, error) {
	if m.DeleteSecretFunc != nil {
		return m.DeleteSecretFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "DeleteSecret", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) GetSecretVersion(ctx context.Context, in *pb.GetSecretVersionRequest, opts ...grpc.CallOption) (*pb.GetSecretVersionResponse, error) {
	if m.GetSecretVersionFunc != nil {
		return m.GetSecretVersionFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GetSecretVersion", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) ListSecretVersions(ctx context.Context, in *pb.ListSecretVersionsRequest, opts ...grpc.CallOption) (*pb.ListSecretVersionsResponse, error) {
	if m.ListSecretVersionsFunc != nil {
		return m.ListSecretVersionsFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "ListSecretVersions", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) RollbackSecret(ctx context.Context, in *pb.RollbackSecretRequest, opts ...grpc.CallOption) (*pb.RollbackSecretResponse, error) {
	if m.RollbackSecretFunc != nil {
		return m.RollbackSecretFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "RollbackSecret", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) RotateSecret(ctx context.Context, in *pb.RotateSecretRequest, opts ...grpc.CallOption) (*pb.RotateSecretResponse, error) {
	if m.RotateSecretFunc != nil {
		return m.RotateSecretFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "RotateSecret", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) UpdateSecretStatus(ctx context.Context, in *pb.UpdateSecretStatusRequest, opts ...grpc.CallOption) (*pb.UpdateSecretStatusResponse, error) {
	if m.UpdateSecretStatusFunc != nil {
		return m.UpdateSecretStatusFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "UpdateSecretStatus", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) SetRotationPolicy(ctx context.Context, in *pb.SetRotationPolicyRequest, opts ...grpc.CallOption) (*pb.SetRotationPolicyResponse, error) {
	if m.SetRotationPolicyFunc != nil {
		return m.SetRotationPolicyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "SetRotationPolicy", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) GetRotationPolicy(ctx context.Context, in *pb.GetRotationPolicyRequest, opts ...grpc.CallOption) (*pb.GetRotationPolicyResponse, error) {
	if m.GetRotationPolicyFunc != nil {
		return m.GetRotationPolicyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GetRotationPolicy", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) GetSecretsByPrefix(ctx context.Context, in *pb.GetSecretsByPrefixRequest, opts ...grpc.CallOption) (*pb.GetSecretsByPrefixResponse, error) {
	if m.GetSecretsByPrefixFunc != nil {
		return m.GetSecretsByPrefixFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GetSecretsByPrefix", Reason: "not implemented"}
}

func (m *MockSecretsManagementClient) WatchSecretsByPrefix(ctx context.Context, in *pb.WatchSecretsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[pb.SecretChange], error) {
	if m.WatchSecretsByPrefixFunc != nil {
		return m.WatchSecretsByPrefixFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "WatchSecretsByPrefix", Reason: "not implemented"}
}

// MockCryptoClient implements pb.CryptoClient for testing
type MockCryptoClient struct {
	EncryptFunc                func(ctx context.Context, in *pb.CryptoEncryptRequest, opts ...grpc.CallOption) (*pb.CryptoEncryptResponse, error)
	DecryptFunc                func(ctx context.Context, in *pb.CryptoDecryptRequest, opts ...grpc.CallOption) (*pb.CryptoDecryptResponse, error)
	RewrapFunc                 func(ctx context.Context, in *pb.RewrapRequest, opts ...grpc.CallOption) (*pb.RewrapResponse, error)
	EncryptBatchFunc           func(ctx context.Context, in *pb.EncryptBatchRequest, opts ...grpc.CallOption) (*pb.EncryptBatchResponse, error)
	DecryptBatchFunc           func(ctx context.Context, in *pb.DecryptBatchRequest, opts ...grpc.CallOption) (*pb.DecryptBatchResponse, error)
	GenerateDataKeyFunc        func(ctx context.Context, in *pb.GenerateDataKeyRequest, opts ...grpc.CallOption) (*pb.GenerateDataKeyResponse, error)
	GenerateWrappedDataKeyFunc func(ctx context.Context, in *pb.GenerateWrappedDataKeyRequest, opts ...grpc.CallOption) (*pb.GenerateWrappedDataKeyResponse, error)
	SignFunc                   func(ctx context.Context, in *pb.SignRequest, opts ...grpc.CallOption) (*pb.SignResponse, error)
	VerifyFunc                 func(ctx context.Context, in *pb.VerifyRequest, opts ...grpc.CallOption) (*pb.VerifyResponse, error)
	GenerateHMACFunc           func(ctx context.Context, in *pb.HMACRequest, opts ...grpc.CallOption) (*pb.HMACResponse, error)
	VerifyHMACFunc             func(ctx context.Context, in *pb.VerifyHMACRequest, opts ...grpc.CallOption) (*pb.VerifyHMACResponse, error)
	GenerateRandomFunc         func(ctx context.Context, in *pb.GenerateRandomRequest, opts ...grpc.CallOption) (*pb.GenerateRandomResponse, error)
	HashFunc                   func(ctx context.Context, in *pb.HashRequest, opts ...grpc.CallOption) (*pb.HashResponse, error)
}

func (m *MockCryptoClient) Encrypt(ctx context.Context, in *pb.CryptoEncryptRequest, opts ...grpc.CallOption) (*pb.CryptoEncryptResponse, error) {
	if m.EncryptFunc != nil {
		return m.EncryptFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "Encrypt", Reason: "not implemented"}
}

func (m *MockCryptoClient) Decrypt(ctx context.Context, in *pb.CryptoDecryptRequest, opts ...grpc.CallOption) (*pb.CryptoDecryptResponse, error) {
	if m.DecryptFunc != nil {
		return m.DecryptFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "Decrypt", Reason: "not implemented"}
}

func (m *MockCryptoClient) Rewrap(ctx context.Context, in *pb.RewrapRequest, opts ...grpc.CallOption) (*pb.RewrapResponse, error) {
	if m.RewrapFunc != nil {
		return m.RewrapFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "Rewrap", Reason: "not implemented"}
}

func (m *MockCryptoClient) EncryptBatch(ctx context.Context, in *pb.EncryptBatchRequest, opts ...grpc.CallOption) (*pb.EncryptBatchResponse, error) {
	if m.EncryptBatchFunc != nil {
		return m.EncryptBatchFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "EncryptBatch", Reason: "not implemented"}
}

func (m *MockCryptoClient) DecryptBatch(ctx context.Context, in *pb.DecryptBatchRequest, opts ...grpc.CallOption) (*pb.DecryptBatchResponse, error) {
	if m.DecryptBatchFunc != nil {
		return m.DecryptBatchFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "DecryptBatch", Reason: "not implemented"}
}

func (m *MockCryptoClient) GenerateDataKey(ctx context.Context, in *pb.GenerateDataKeyRequest, opts ...grpc.CallOption) (*pb.GenerateDataKeyResponse, error) {
	if m.GenerateDataKeyFunc != nil {
		return m.GenerateDataKeyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GenerateDataKey", Reason: "not implemented"}
}

func (m *MockCryptoClient) GenerateWrappedDataKey(ctx context.Context, in *pb.GenerateWrappedDataKeyRequest, opts ...grpc.CallOption) (*pb.GenerateWrappedDataKeyResponse, error) {
	if m.GenerateWrappedDataKeyFunc != nil {
		return m.GenerateWrappedDataKeyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GenerateWrappedDataKey", Reason: "not implemented"}
}

func (m *MockCryptoClient) Sign(ctx context.Context, in *pb.SignRequest, opts ...grpc.CallOption) (*pb.SignResponse, error) {
	if m.SignFunc != nil {
		return m.SignFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "Sign", Reason: "not implemented"}
}

func (m *MockCryptoClient) Verify(ctx context.Context, in *pb.VerifyRequest, opts ...grpc.CallOption) (*pb.VerifyResponse, error) {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "Verify", Reason: "not implemented"}
}

func (m *MockCryptoClient) GenerateHMAC(ctx context.Context, in *pb.HMACRequest, opts ...grpc.CallOption) (*pb.HMACResponse, error) {
	if m.GenerateHMACFunc != nil {
		return m.GenerateHMACFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GenerateHMAC", Reason: "not implemented"}
}

func (m *MockCryptoClient) VerifyHMAC(ctx context.Context, in *pb.VerifyHMACRequest, opts ...grpc.CallOption) (*pb.VerifyHMACResponse, error) {
	if m.VerifyHMACFunc != nil {
		return m.VerifyHMACFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "VerifyHMAC", Reason: "not implemented"}
}

func (m *MockCryptoClient) GenerateRandom(ctx context.Context, in *pb.GenerateRandomRequest, opts ...grpc.CallOption) (*pb.GenerateRandomResponse, error) {
	if m.GenerateRandomFunc != nil {
		return m.GenerateRandomFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "GenerateRandom", Reason: "not implemented"}
}

func (m *MockCryptoClient) Hash(ctx context.Context, in *pb.HashRequest, opts ...grpc.CallOption) (*pb.HashResponse, error) {
	if m.HashFunc != nil {
		return m.HashFunc(ctx, in, opts...)
	}
	return nil, ErrMockClientOperation{Operation: "Hash", Reason: "not implemented"}
}
