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

package grpc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockKMSService implements KMSService for testing.
type mockKMSService struct {
	generateKeyResp     *KMSGenerateKeyResponse
	generateKeyErr      error
	importKeyResp       *KMSImportKeyResponse
	importKeyErr        error
	getKeyResp          *KMSGetKeyResponse
	getKeyErr           error
	listKeysResp        *KMSListKeysResponse
	listKeysErr         error
	deleteKeyResp       *KMSDeleteKeyResponse
	deleteKeyErr        error
	rotateKeyResp       *KMSRotateKeyResponse
	rotateKeyErr        error
	updateKeyStatusResp *KMSUpdateKeyStatusResponse
	updateKeyStatusErr  error
	exportKeyResp       *KMSExportKeyResponse
	exportKeyErr        error
	getKeyVersionsResp  *KMSGetKeyVersionsResponse
	getKeyVersionsErr   error
	backendStatusResp   *KMSBackendStatusResponse
	backendStatusErr    error
	encryptResp         *KMSEncryptResponse
	encryptErr          error
	decryptResp         *KMSDecryptResponse
	decryptErr          error
	batchEncryptResp    *KMSBatchEncryptResponse
	batchEncryptErr     error
	batchDecryptResp    *KMSBatchDecryptResponse
	batchDecryptErr     error
	rewrapResp          *KMSRewrapResponse
	rewrapErr           error
	signResp            *KMSSignResponse
	signErr             error
	verifyResp          *KMSVerifyResponse
	verifyErr           error
	generateRandomResp  *KMSGenerateRandomResponse
	generateRandomErr   error
	hashResp            *KMSHashResponse
	hashErr             error
	hmacResp            *KMSHMACResponse
	hmacErr             error
	verifyHMACResp      *KMSVerifyHMACResponse
	verifyHMACErr       error
}

func newMockKMSService() *mockKMSService {
	now := time.Now().UTC().Unix()
	return &mockKMSService{
		generateKeyResp: &KMSGenerateKeyResponse{
			Key: &KMSKeyHandle{
				KeyID:     "test-key-id",
				Version:   1,
				Algorithm: 22, // AES-256
				Status:    1,  // Enabled
				CreatedAt: now,
			},
			Metadata: &KMSKeyMetadata{
				KeyID:     "test-key-id",
				Name:      "test-key",
				Algorithm: 22,
				Status:    1,
				Version:   1,
				CreatedAt: now,
			},
			Timestamp: now,
		},
		importKeyResp: &KMSImportKeyResponse{
			Key: &KMSKeyHandle{
				KeyID:     "imported-key-id",
				Version:   1,
				Algorithm: 22,
				Status:    1,
				CreatedAt: now,
			},
			Timestamp: now,
		},
		getKeyResp: &KMSGetKeyResponse{
			Key: &KMSKeyHandle{
				KeyID:     "test-key-id",
				Version:   1,
				Algorithm: 22,
				Status:    1,
				CreatedAt: now,
			},
			Metadata: &KMSKeyMetadata{
				KeyID:     "test-key-id",
				Name:      "test-key",
				Algorithm: 22,
				Status:    1,
				Version:   1,
				CreatedAt: now,
			},
			Timestamp: now,
		},
		listKeysResp: &KMSListKeysResponse{
			Keys: []*KMSKeyHandle{
				{KeyID: "key-1", Version: 1, Algorithm: 22, Status: 1},
				{KeyID: "key-2", Version: 1, Algorithm: 4, Status: 1},
			},
			TotalCount: 2,
			HasMore:    false,
			Timestamp:  now,
		},
		deleteKeyResp: &KMSDeleteKeyResponse{
			KeyID:        "test-key-id",
			Status:       3, // Pending deletion
			DeletionDate: now + 7*24*60*60,
			Timestamp:    now,
		},
		rotateKeyResp: &KMSRotateKeyResponse{
			KeyID:      "test-key-id",
			OldVersion: 1,
			NewVersion: 2,
			Timestamp:  now,
		},
		updateKeyStatusResp: &KMSUpdateKeyStatusResponse{
			KeyID:     "test-key-id",
			Version:   1,
			Status:    2, // Disabled
			Timestamp: now,
		},
		exportKeyResp: &KMSExportKeyResponse{
			KeyID:           "test-key-id",
			Format:          1, // RAW
			WrappedMaterial: []byte("wrapped-key-material"),
			Version:         1,
			Timestamp:       now,
		},
		getKeyVersionsResp: &KMSGetKeyVersionsResponse{
			KeyID: "test-key-id",
			Versions: []*KMSKeyVersionInfo{
				{Version: 1, Status: 1, Algorithm: 22, CreatedAt: now - 86400},
				{Version: 2, Status: 1, Algorithm: 22, CreatedAt: now},
			},
			HasMore:   false,
			Timestamp: now,
		},
		backendStatusResp: &KMSBackendStatusResponse{
			BackendType: "software",
			Status:      "healthy",
			Capabilities: map[string]bool{
				"encrypt": true,
				"decrypt": true,
				"sign":    true,
				"verify":  true,
			},
			Timestamp: now,
		},
		encryptResp: &KMSEncryptResponse{
			KeyID:      "test-key-id",
			KeyVersion: 1,
			Ciphertext: []byte("encrypted-data"),
			Nonce:      []byte("random-nonce"),
			Timestamp:  now,
		},
		decryptResp: &KMSDecryptResponse{
			KeyID:      "test-key-id",
			KeyVersion: 1,
			Plaintext:  []byte("decrypted-data"),
			Timestamp:  now,
		},
		batchEncryptResp: &KMSBatchEncryptResponse{
			KeyID: "test-key-id",
			Results: []*KMSBatchEncryptResultItem{
				{
					ItemID:     "item-1",
					Success:    true,
					Message:    "encryption successful",
					Ciphertext: []byte("encrypted-data-1"),
					Nonce:      []byte("nonce-1"),
					KeyVersion: 1,
				},
				{
					ItemID:     "item-2",
					Success:    true,
					Message:    "encryption successful",
					Ciphertext: []byte("encrypted-data-2"),
					Nonce:      []byte("nonce-2"),
					KeyVersion: 1,
				},
			},
			SuccessCount: 2,
			FailureCount: 0,
			Timestamp:    now,
		},
		batchDecryptResp: &KMSBatchDecryptResponse{
			KeyID: "test-key-id",
			Results: []*KMSBatchDecryptResultItem{
				{
					ItemID:     "item-1",
					Success:    true,
					Message:    "decryption successful",
					Plaintext:  []byte("decrypted-data-1"),
					KeyVersion: 1,
				},
				{
					ItemID:     "item-2",
					Success:    true,
					Message:    "decryption successful",
					Plaintext:  []byte("decrypted-data-2"),
					KeyVersion: 1,
				},
			},
			SuccessCount: 2,
			FailureCount: 0,
			Timestamp:    now,
		},
		rewrapResp: &KMSRewrapResponse{
			KeyID:         "test-key-id",
			SourceVersion: 1,
			TargetVersion: 2,
			Ciphertext:    []byte("rewrapped-ciphertext"),
			Nonce:         []byte("new-nonce"),
			Timestamp:     now,
		},
		signResp: &KMSSignResponse{
			KeyID:         "test-key-id",
			KeyVersion:    1,
			Signature:     []byte("signature-data"),
			HashAlgorithm: 2, // SHA256
			Timestamp:     now,
		},
		verifyResp: &KMSVerifyResponse{
			KeyID:      "test-key-id",
			KeyVersion: 1,
			Valid:      true,
			Timestamp:  now,
		},
		generateRandomResp: &KMSGenerateRandomResponse{
			RandomBytes: []byte("random-bytes-data-32bytes-long!!"),
			Timestamp:   now,
		},
		hashResp: &KMSHashResponse{
			Algorithm: 2, // SHA256
			Hash:      []byte("hash-result"),
			Timestamp: now,
		},
		hmacResp: &KMSHMACResponse{
			KeyID:         "test-key-id",
			KeyVersion:    1,
			HMAC:          []byte("hmac-result"),
			HashAlgorithm: 2,
			Timestamp:     now,
		},
		verifyHMACResp: &KMSVerifyHMACResponse{
			KeyID:      "test-key-id",
			KeyVersion: 1,
			Valid:      true,
			Timestamp:  now,
		},
	}
}

func (m *mockKMSService) GenerateKey(ctx context.Context, req *KMSGenerateKeyRequest) (*KMSGenerateKeyResponse, error) {
	if m.generateKeyErr != nil {
		return nil, m.generateKeyErr
	}
	return m.generateKeyResp, nil
}

func (m *mockKMSService) ImportKey(ctx context.Context, req *KMSImportKeyRequest) (*KMSImportKeyResponse, error) {
	if m.importKeyErr != nil {
		return nil, m.importKeyErr
	}
	return m.importKeyResp, nil
}

func (m *mockKMSService) GetKey(ctx context.Context, req *KMSGetKeyRequest) (*KMSGetKeyResponse, error) {
	if m.getKeyErr != nil {
		return nil, m.getKeyErr
	}
	return m.getKeyResp, nil
}

func (m *mockKMSService) ListKeys(ctx context.Context, req *KMSListKeysRequest) (*KMSListKeysResponse, error) {
	if m.listKeysErr != nil {
		return nil, m.listKeysErr
	}
	return m.listKeysResp, nil
}

func (m *mockKMSService) DeleteKey(ctx context.Context, req *KMSDeleteKeyRequest) (*KMSDeleteKeyResponse, error) {
	if m.deleteKeyErr != nil {
		return nil, m.deleteKeyErr
	}
	return m.deleteKeyResp, nil
}

func (m *mockKMSService) RotateKey(ctx context.Context, req *KMSRotateKeyRequest) (*KMSRotateKeyResponse, error) {
	if m.rotateKeyErr != nil {
		return nil, m.rotateKeyErr
	}
	return m.rotateKeyResp, nil
}

func (m *mockKMSService) UpdateKeyStatus(ctx context.Context, req *KMSUpdateKeyStatusRequest) (*KMSUpdateKeyStatusResponse, error) {
	if m.updateKeyStatusErr != nil {
		return nil, m.updateKeyStatusErr
	}
	return m.updateKeyStatusResp, nil
}

func (m *mockKMSService) ExportKey(ctx context.Context, req *KMSExportKeyRequest) (*KMSExportKeyResponse, error) {
	if m.exportKeyErr != nil {
		return nil, m.exportKeyErr
	}
	return m.exportKeyResp, nil
}

func (m *mockKMSService) GetKeyVersions(ctx context.Context, req *KMSGetKeyVersionsRequest) (*KMSGetKeyVersionsResponse, error) {
	if m.getKeyVersionsErr != nil {
		return nil, m.getKeyVersionsErr
	}
	return m.getKeyVersionsResp, nil
}

func (m *mockKMSService) BackendStatus(ctx context.Context) (*KMSBackendStatusResponse, error) {
	if m.backendStatusErr != nil {
		return nil, m.backendStatusErr
	}
	return m.backendStatusResp, nil
}

func (m *mockKMSService) Encrypt(ctx context.Context, req *KMSEncryptRequest) (*KMSEncryptResponse, error) {
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	return m.encryptResp, nil
}

func (m *mockKMSService) Decrypt(ctx context.Context, req *KMSDecryptRequest) (*KMSDecryptResponse, error) {
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	return m.decryptResp, nil
}

func (m *mockKMSService) BatchEncrypt(ctx context.Context, req *KMSBatchEncryptRequest) (*KMSBatchEncryptResponse, error) {
	if m.batchEncryptErr != nil {
		return nil, m.batchEncryptErr
	}
	return m.batchEncryptResp, nil
}

func (m *mockKMSService) BatchDecrypt(ctx context.Context, req *KMSBatchDecryptRequest) (*KMSBatchDecryptResponse, error) {
	if m.batchDecryptErr != nil {
		return nil, m.batchDecryptErr
	}
	return m.batchDecryptResp, nil
}

func (m *mockKMSService) Rewrap(ctx context.Context, req *KMSRewrapRequest) (*KMSRewrapResponse, error) {
	if m.rewrapErr != nil {
		return nil, m.rewrapErr
	}
	return m.rewrapResp, nil
}

func (m *mockKMSService) Sign(ctx context.Context, req *KMSSignRequest) (*KMSSignResponse, error) {
	if m.signErr != nil {
		return nil, m.signErr
	}
	return m.signResp, nil
}

func (m *mockKMSService) Verify(ctx context.Context, req *KMSVerifyRequest) (*KMSVerifyResponse, error) {
	if m.verifyErr != nil {
		return nil, m.verifyErr
	}
	return m.verifyResp, nil
}

func (m *mockKMSService) GenerateRandom(ctx context.Context, req *KMSGenerateRandomRequest) (*KMSGenerateRandomResponse, error) {
	if m.generateRandomErr != nil {
		return nil, m.generateRandomErr
	}
	return m.generateRandomResp, nil
}

func (m *mockKMSService) Hash(ctx context.Context, req *KMSHashRequest) (*KMSHashResponse, error) {
	if m.hashErr != nil {
		return nil, m.hashErr
	}
	return m.hashResp, nil
}

func (m *mockKMSService) HMAC(ctx context.Context, req *KMSHMACRequest) (*KMSHMACResponse, error) {
	if m.hmacErr != nil {
		return nil, m.hmacErr
	}
	return m.hmacResp, nil
}

func (m *mockKMSService) VerifyHMAC(ctx context.Context, req *KMSVerifyHMACRequest) (*KMSVerifyHMACResponse, error) {
	if m.verifyHMACErr != nil {
		return nil, m.verifyHMACErr
	}
	return m.verifyHMACResp, nil
}

// Ensure mockKMSService implements KMSService at compile time.
var _ KMSService = (*mockKMSService)(nil)

func newTestKMSService() (*KMSGRPCService, *mockKMSService) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	mock := newMockKMSService()
	service := NewKMSGRPCService(logger, mock)
	return service, mock
}

// Test GenerateKey

func TestKMSGRPCService_GenerateKey_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GenerateKeyRequest{
		KeySpec: &platformv1.KMSKeySpec{
			Algorithm:  platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
			KeySize:    256,
			Usage:      []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_ENCRYPT, platformv1.KeyUsage_KEY_USAGE_DECRYPT},
			Exportable: false,
		},
		Name:        "test-key",
		Description: "Test encryption key",
	}

	resp, err := service.GenerateKey(ctx, req)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetKey() == nil {
		t.Error("Expected key handle in response")
	}

	if resp.GetKey().GetKeyId() != "test-key-id" {
		t.Errorf("Expected key ID 'test-key-id', got '%s'", resp.GetKey().GetKeyId())
	}
}

func TestKMSGRPCService_GenerateKey_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.GenerateKeyRequest{
		KeySpec: &platformv1.KMSKeySpec{Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256},
	}

	_, err := service.GenerateKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_GenerateKey_MissingKeySpec(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GenerateKeyRequest{
		Name: "test-key",
	}

	_, err := service.GenerateKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key spec")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_GenerateKey_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.generateKeyErr = ErrKMSOperationFailed{Operation: "GenerateKey", Reason: "backend error"}
	ctx := context.Background()

	req := &platformv1.GenerateKeyRequest{
		KeySpec: &platformv1.KMSKeySpec{Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256},
	}

	_, err := service.GenerateKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal error, got %v", st.Code())
	}
}

// Test ImportKey

func TestKMSGRPCService_ImportKey_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.ImportKeyRequest{
		KeyMaterial: []byte("key-material-data"),
		KeySpec: &platformv1.KMSKeySpec{
			Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
		},
		Name: "imported-key",
	}

	resp, err := service.ImportKey(ctx, req)
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if resp.GetKey() == nil || resp.GetKey().GetKeyId() != "imported-key-id" {
		t.Error("Expected imported key in response")
	}
}

func TestKMSGRPCService_ImportKey_MissingKeyMaterial(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.ImportKeyRequest{
		KeySpec: &platformv1.KMSKeySpec{Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256},
	}

	_, err := service.ImportKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key material")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_ImportKey_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.ImportKeyRequest{
		KeyMaterial: []byte("material"),
		KeySpec:     &platformv1.KMSKeySpec{Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256},
	}

	_, err := service.ImportKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_ImportKey_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.importKeyErr = errors.New("import failed")
	ctx := context.Background()

	req := &platformv1.ImportKeyRequest{
		KeyMaterial: []byte("material"),
		KeySpec:     &platformv1.KMSKeySpec{Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256},
	}

	_, err := service.ImportKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

// Test GetKey

func TestKMSGRPCService_GetKey_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GetKeyRequest{
		KeyId: "test-key-id",
	}

	resp, err := service.GetKey(ctx, req)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if resp.GetKey() == nil || resp.GetKey().GetKeyId() != "test-key-id" {
		t.Error("Expected key in response")
	}
}

func TestKMSGRPCService_GetKey_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GetKeyRequest{}

	_, err := service.GetKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_GetKey_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.GetKeyRequest{KeyId: "test"}

	_, err := service.GetKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_GetKey_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.getKeyErr = errors.New("key not found")
	ctx := context.Background()

	req := &platformv1.GetKeyRequest{KeyId: "test"}

	_, err := service.GetKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test ListKeys

func TestKMSGRPCService_ListKeys_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.ListKeysRequest{
		Limit: 10,
	}

	resp, err := service.ListKeys(ctx, req)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(resp.GetKeys()) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(resp.GetKeys()))
	}

	if resp.GetTotalCount() != 2 {
		t.Errorf("Expected total count 2, got %d", resp.GetTotalCount())
	}
}

func TestKMSGRPCService_ListKeys_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.ListKeysRequest{}

	_, err := service.ListKeys(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_ListKeys_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.listKeysErr = errors.New("list failed")
	ctx := context.Background()

	req := &platformv1.ListKeysRequest{}

	_, err := service.ListKeys(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test DeleteKey

func TestKMSGRPCService_DeleteKey_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.DeleteKeyRequest{
		KeyId:             "test-key-id",
		PendingWindowDays: 7,
	}

	resp, err := service.DeleteKey(ctx, req)
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	if resp.GetKeyId() != "test-key-id" {
		t.Errorf("Expected key ID 'test-key-id', got '%s'", resp.GetKeyId())
	}

	if resp.GetKeyStatus() != platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION {
		t.Errorf("Expected pending deletion status")
	}
}

func TestKMSGRPCService_DeleteKey_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.DeleteKeyRequest{}

	_, err := service.DeleteKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_DeleteKey_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.DeleteKeyRequest{KeyId: "test"}

	_, err := service.DeleteKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_DeleteKey_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.deleteKeyErr = errors.New("delete failed")
	ctx := context.Background()

	req := &platformv1.DeleteKeyRequest{KeyId: "test"}

	_, err := service.DeleteKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test RotateKey

func TestKMSGRPCService_RotateKey_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.RotateKeyRequest{
		KeyId:            "test-key-id",
		RetainOldVersion: true,
	}

	resp, err := service.RotateKey(ctx, req)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	if resp.GetOldVersion() != 1 || resp.GetNewVersion() != 2 {
		t.Errorf("Expected version 1 -> 2, got %d -> %d", resp.GetOldVersion(), resp.GetNewVersion())
	}
}

func TestKMSGRPCService_RotateKey_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.RotateKeyRequest{KeyId: "test"}

	_, err := service.RotateKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_RotateKey_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.RotateKeyRequest{}

	_, err := service.RotateKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_RotateKey_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.rotateKeyErr = errors.New("rotate failed")
	ctx := context.Background()

	req := &platformv1.RotateKeyRequest{KeyId: "test"}

	_, err := service.RotateKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test UpdateKeyStatus

func TestKMSGRPCService_UpdateKeyStatus_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.UpdateKeyStatusRequest{
		KeyId:  "test-key-id",
		Status: platformv1.KeyStatus_KEY_STATUS_DISABLED,
	}

	resp, err := service.UpdateKeyStatus(ctx, req)
	if err != nil {
		t.Fatalf("UpdateKeyStatus failed: %v", err)
	}

	if resp.GetKeyStatus() != platformv1.KeyStatus_KEY_STATUS_DISABLED {
		t.Errorf("Expected disabled status")
	}
}

func TestKMSGRPCService_UpdateKeyStatus_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.UpdateKeyStatusRequest{KeyId: "test"}

	_, err := service.UpdateKeyStatus(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_UpdateKeyStatus_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.UpdateKeyStatusRequest{}

	_, err := service.UpdateKeyStatus(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_UpdateKeyStatus_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.updateKeyStatusErr = errors.New("update failed")
	ctx := context.Background()

	req := &platformv1.UpdateKeyStatusRequest{KeyId: "test"}

	_, err := service.UpdateKeyStatus(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test ExportKey

func TestKMSGRPCService_ExportKey_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.ExportKeyRequest{
		KeyId:  "test-key-id",
		Format: platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_RAW,
	}

	resp, err := service.ExportKey(ctx, req)
	if err != nil {
		t.Fatalf("ExportKey failed: %v", err)
	}

	if len(resp.GetWrappedMaterial()) == 0 {
		t.Error("Expected wrapped material in response")
	}
}

func TestKMSGRPCService_ExportKey_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.ExportKeyRequest{KeyId: "test"}

	_, err := service.ExportKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_ExportKey_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.ExportKeyRequest{}

	_, err := service.ExportKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_ExportKey_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.exportKeyErr = errors.New("export failed")
	ctx := context.Background()

	req := &platformv1.ExportKeyRequest{KeyId: "test"}

	_, err := service.ExportKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test GetKeyVersions

func TestKMSGRPCService_GetKeyVersions_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GetKeyVersionsRequest{
		KeyId: "test-key-id",
	}

	resp, err := service.GetKeyVersions(ctx, req)
	if err != nil {
		t.Fatalf("GetKeyVersions failed: %v", err)
	}

	if len(resp.GetVersions()) != 2 {
		t.Errorf("Expected 2 versions, got %d", len(resp.GetVersions()))
	}
}

func TestKMSGRPCService_GetKeyVersions_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.GetKeyVersionsRequest{KeyId: "test"}

	_, err := service.GetKeyVersions(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_GetKeyVersions_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GetKeyVersionsRequest{}

	_, err := service.GetKeyVersions(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_GetKeyVersions_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.getKeyVersionsErr = errors.New("versions failed")
	ctx := context.Background()

	req := &platformv1.GetKeyVersionsRequest{KeyId: "test"}

	_, err := service.GetKeyVersions(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test Encrypt

func TestKMSGRPCService_Encrypt_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.EncryptRequest{
		KeyId:     "test-key-id",
		Plaintext: []byte("secret data"),
	}

	resp, err := service.Encrypt(ctx, req)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(resp.GetCiphertext()) == 0 {
		t.Error("Expected ciphertext in response")
	}
}

func TestKMSGRPCService_Encrypt_MissingPlaintext(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.EncryptRequest{
		KeyId: "test-key-id",
	}

	_, err := service.Encrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing plaintext")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Encrypt_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.EncryptRequest{KeyId: "test", Plaintext: []byte("data")}

	_, err := service.Encrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_Encrypt_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.EncryptRequest{Plaintext: []byte("data")}

	_, err := service.Encrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Encrypt_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.encryptErr = errors.New("encrypt failed")
	ctx := context.Background()

	req := &platformv1.EncryptRequest{KeyId: "test", Plaintext: []byte("data")}

	_, err := service.Encrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test Decrypt

func TestKMSGRPCService_Decrypt_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.DecryptRequest{
		KeyId:      "test-key-id",
		Ciphertext: []byte("encrypted-data"),
	}

	resp, err := service.Decrypt(ctx, req)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(resp.GetPlaintext()) == 0 {
		t.Error("Expected plaintext in response")
	}
}

func TestKMSGRPCService_Decrypt_MissingCiphertext(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.DecryptRequest{
		KeyId: "test-key-id",
	}

	_, err := service.Decrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ciphertext")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Decrypt_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.DecryptRequest{KeyId: "test", Ciphertext: []byte("data")}

	_, err := service.Decrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_Decrypt_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.DecryptRequest{Ciphertext: []byte("data")}

	_, err := service.Decrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Decrypt_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.decryptErr = errors.New("decrypt failed")
	ctx := context.Background()

	req := &platformv1.DecryptRequest{KeyId: "test", Ciphertext: []byte("data")}

	_, err := service.Decrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test BatchEncrypt

func TestKMSGRPCService_BatchEncrypt_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.BatchEncryptRequest{
		KeyId: "test-key-id",
		Items: []*platformv1.BatchEncryptItem{
			{ItemId: "item-1", Plaintext: []byte("secret data 1")},
			{ItemId: "item-2", Plaintext: []byte("secret data 2")},
		},
	}

	resp, err := service.BatchEncrypt(ctx, req)
	if err != nil {
		t.Fatalf("BatchEncrypt failed: %v", err)
	}

	if resp.GetSuccessCount() != 2 {
		t.Errorf("Expected 2 successful items, got %d", resp.GetSuccessCount())
	}

	if len(resp.GetResults()) != 2 {
		t.Errorf("Expected 2 results, got %d", len(resp.GetResults()))
	}
}

func TestKMSGRPCService_BatchEncrypt_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.BatchEncryptRequest{
		KeyId: "test-key-id",
		Items: []*platformv1.BatchEncryptItem{
			{ItemId: "item-1", Plaintext: []byte("data")},
		},
	}

	_, err := service.BatchEncrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_BatchEncrypt_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.BatchEncryptRequest{
		Items: []*platformv1.BatchEncryptItem{
			{ItemId: "item-1", Plaintext: []byte("data")},
		},
	}

	_, err := service.BatchEncrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_BatchEncrypt_MissingItems(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.BatchEncryptRequest{
		KeyId: "test-key-id",
	}

	_, err := service.BatchEncrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing items")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_BatchEncrypt_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.batchEncryptErr = errors.New("batch encrypt failed")
	ctx := context.Background()

	req := &platformv1.BatchEncryptRequest{
		KeyId: "test-key-id",
		Items: []*platformv1.BatchEncryptItem{
			{ItemId: "item-1", Plaintext: []byte("data")},
		},
	}

	_, err := service.BatchEncrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test BatchDecrypt

func TestKMSGRPCService_BatchDecrypt_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.BatchDecryptRequest{
		KeyId: "test-key-id",
		Items: []*platformv1.BatchDecryptItem{
			{ItemId: "item-1", Ciphertext: []byte("encrypted-data-1")},
			{ItemId: "item-2", Ciphertext: []byte("encrypted-data-2")},
		},
	}

	resp, err := service.BatchDecrypt(ctx, req)
	if err != nil {
		t.Fatalf("BatchDecrypt failed: %v", err)
	}

	if resp.GetSuccessCount() != 2 {
		t.Errorf("Expected 2 successful items, got %d", resp.GetSuccessCount())
	}

	if len(resp.GetResults()) != 2 {
		t.Errorf("Expected 2 results, got %d", len(resp.GetResults()))
	}
}

func TestKMSGRPCService_BatchDecrypt_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.BatchDecryptRequest{
		KeyId: "test-key-id",
		Items: []*platformv1.BatchDecryptItem{
			{ItemId: "item-1", Ciphertext: []byte("data")},
		},
	}

	_, err := service.BatchDecrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_BatchDecrypt_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.BatchDecryptRequest{
		Items: []*platformv1.BatchDecryptItem{
			{ItemId: "item-1", Ciphertext: []byte("data")},
		},
	}

	_, err := service.BatchDecrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_BatchDecrypt_MissingItems(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.BatchDecryptRequest{
		KeyId: "test-key-id",
	}

	_, err := service.BatchDecrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing items")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_BatchDecrypt_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.batchDecryptErr = errors.New("batch decrypt failed")
	ctx := context.Background()

	req := &platformv1.BatchDecryptRequest{
		KeyId: "test-key-id",
		Items: []*platformv1.BatchDecryptItem{
			{ItemId: "item-1", Ciphertext: []byte("data")},
		},
	}

	_, err := service.BatchDecrypt(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test Rewrap

func TestKMSGRPCService_Rewrap_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.RewrapRequest{
		KeyId:         "test-key-id",
		Ciphertext:    []byte("old-ciphertext"),
		SourceVersion: 1,
	}

	resp, err := service.Rewrap(ctx, req)
	if err != nil {
		t.Fatalf("Rewrap failed: %v", err)
	}

	if resp.GetSourceVersion() != 1 {
		t.Errorf("Expected source version 1, got %d", resp.GetSourceVersion())
	}

	if resp.GetTargetVersion() != 2 {
		t.Errorf("Expected target version 2, got %d", resp.GetTargetVersion())
	}

	if len(resp.GetCiphertext()) == 0 {
		t.Error("Expected rewrapped ciphertext in response")
	}
}

func TestKMSGRPCService_Rewrap_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.RewrapRequest{
		KeyId:      "test-key-id",
		Ciphertext: []byte("ciphertext"),
	}

	_, err := service.Rewrap(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_Rewrap_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.RewrapRequest{
		Ciphertext: []byte("ciphertext"),
	}

	_, err := service.Rewrap(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Rewrap_MissingCiphertext(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.RewrapRequest{
		KeyId: "test-key-id",
	}

	_, err := service.Rewrap(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ciphertext")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Rewrap_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.rewrapErr = errors.New("rewrap failed")
	ctx := context.Background()

	req := &platformv1.RewrapRequest{
		KeyId:      "test-key-id",
		Ciphertext: []byte("ciphertext"),
	}

	_, err := service.Rewrap(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test Sign

func TestKMSGRPCService_Sign_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.SignRequest{
		KeyId:         "test-key-id",
		Message:       []byte("message to sign"),
		HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	}

	resp, err := service.Sign(ctx, req)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(resp.GetSignature()) == 0 {
		t.Error("Expected signature in response")
	}
}

func TestKMSGRPCService_Sign_MissingMessage(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.SignRequest{
		KeyId: "test-key-id",
	}

	_, err := service.Sign(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing message")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Sign_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.SignRequest{KeyId: "test", Message: []byte("msg")}

	_, err := service.Sign(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_Sign_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.SignRequest{Message: []byte("msg")}

	_, err := service.Sign(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Sign_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.signErr = errors.New("sign failed")
	ctx := context.Background()

	req := &platformv1.SignRequest{KeyId: "test", Message: []byte("msg")}

	_, err := service.Sign(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test Verify

func TestKMSGRPCService_Verify_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.VerifyRequest{
		KeyId:     "test-key-id",
		Message:   []byte("message to verify"),
		Signature: []byte("signature-data"),
	}

	resp, err := service.Verify(ctx, req)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !resp.GetValid() {
		t.Error("Expected valid signature")
	}
}

func TestKMSGRPCService_Verify_MissingSignature(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.VerifyRequest{
		KeyId:   "test-key-id",
		Message: []byte("message"),
	}

	_, err := service.Verify(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing signature")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Verify_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.VerifyRequest{KeyId: "test", Message: []byte("msg"), Signature: []byte("sig")}

	_, err := service.Verify(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_Verify_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.VerifyRequest{Message: []byte("msg"), Signature: []byte("sig")}

	_, err := service.Verify(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Verify_MissingMessage(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.VerifyRequest{KeyId: "test", Signature: []byte("sig")}

	_, err := service.Verify(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing message")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Verify_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.verifyErr = errors.New("verify failed")
	ctx := context.Background()

	req := &platformv1.VerifyRequest{KeyId: "test", Message: []byte("msg"), Signature: []byte("sig")}

	_, err := service.Verify(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test Hash

func TestKMSGRPCService_Hash_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.HashRequest{
		Data:      []byte("data to hash"),
		Algorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	}

	resp, err := service.Hash(ctx, req)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if len(resp.GetHash()) == 0 {
		t.Error("Expected hash in response")
	}
}

func TestKMSGRPCService_Hash_MissingData(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.HashRequest{
		Algorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	}

	_, err := service.Hash(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing data")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_Hash_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.HashRequest{Data: []byte("data")}

	_, err := service.Hash(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_Hash_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.hashErr = errors.New("hash failed")
	ctx := context.Background()

	req := &platformv1.HashRequest{Data: []byte("data")}

	_, err := service.Hash(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test HMAC

func TestKMSGRPCService_HMAC_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.HMACRequest{
		KeyId:         "test-key-id",
		Message:       []byte("message for hmac"),
		HashAlgorithm: platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	}

	resp, err := service.HMAC(ctx, req)
	if err != nil {
		t.Fatalf("HMAC failed: %v", err)
	}

	if len(resp.GetHmac()) == 0 {
		t.Error("Expected HMAC in response")
	}
}

func TestKMSGRPCService_HMAC_MissingMessage(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.HMACRequest{
		KeyId: "test-key-id",
	}

	_, err := service.HMAC(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing message")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_HMAC_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.HMACRequest{KeyId: "test", Message: []byte("msg")}

	_, err := service.HMAC(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_HMAC_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.HMACRequest{Message: []byte("msg")}

	_, err := service.HMAC(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_HMAC_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.hmacErr = errors.New("hmac failed")
	ctx := context.Background()

	req := &platformv1.HMACRequest{KeyId: "test", Message: []byte("msg")}

	_, err := service.HMAC(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test VerifyHMAC

func TestKMSGRPCService_VerifyHMAC_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.VerifyHMACRequest{
		KeyId:   "test-key-id",
		Message: []byte("message"),
		Hmac:    []byte("hmac-value"),
	}

	resp, err := service.VerifyHMAC(ctx, req)
	if err != nil {
		t.Fatalf("VerifyHMAC failed: %v", err)
	}

	if !resp.GetValid() {
		t.Error("Expected valid HMAC")
	}
}

func TestKMSGRPCService_VerifyHMAC_MissingHMAC(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.VerifyHMACRequest{
		KeyId:   "test-key-id",
		Message: []byte("message"),
	}

	_, err := service.VerifyHMAC(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing HMAC")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_VerifyHMAC_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.VerifyHMACRequest{KeyId: "test", Message: []byte("msg"), Hmac: []byte("hmac")}

	_, err := service.VerifyHMAC(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_VerifyHMAC_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.VerifyHMACRequest{Message: []byte("msg"), Hmac: []byte("hmac")}

	_, err := service.VerifyHMAC(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_VerifyHMAC_MissingMessage(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.VerifyHMACRequest{KeyId: "test", Hmac: []byte("hmac")}

	_, err := service.VerifyHMAC(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing message")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_VerifyHMAC_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.verifyHMACErr = errors.New("verify hmac failed")
	ctx := context.Background()

	req := &platformv1.VerifyHMACRequest{KeyId: "test", Message: []byte("msg"), Hmac: []byte("hmac")}

	_, err := service.VerifyHMAC(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test GenerateRandom

func TestKMSGRPCService_GenerateRandom_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GenerateRandomRequest{
		NumBytes: 32,
	}

	resp, err := service.GenerateRandom(ctx, req)
	if err != nil {
		t.Fatalf("GenerateRandom failed: %v", err)
	}

	if len(resp.GetRandomBytes()) == 0 {
		t.Error("Expected random bytes in response")
	}
}

func TestKMSGRPCService_GenerateRandom_InvalidNumBytes(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GenerateRandomRequest{
		NumBytes: 0,
	}

	_, err := service.GenerateRandom(ctx, req)
	if err == nil {
		t.Fatal("Expected error for invalid num_bytes")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_GenerateRandom_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.GenerateRandomRequest{NumBytes: 32}

	_, err := service.GenerateRandom(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_GenerateRandom_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.generateRandomErr = errors.New("random failed")
	ctx := context.Background()

	req := &platformv1.GenerateRandomRequest{NumBytes: 32}

	_, err := service.GenerateRandom(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test GenerateDataKey

func TestKMSGRPCService_GenerateDataKey_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GenerateDataKeyRequest{
		KeyId:   "test-key-id",
		KeySize: 32,
	}

	resp, err := service.GenerateDataKey(ctx, req)
	if err != nil {
		t.Fatalf("GenerateDataKey failed: %v", err)
	}

	if len(resp.GetPlaintextKey()) == 0 {
		t.Error("Expected plaintext key in response")
	}

	if len(resp.GetEncryptedKey()) == 0 {
		t.Error("Expected encrypted key in response")
	}
}

func TestKMSGRPCService_GenerateDataKey_MissingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GenerateDataKeyRequest{
		KeySize: 32,
	}

	_, err := service.GenerateDataKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_GenerateDataKey_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.GenerateDataKeyRequest{KeyId: "test"}

	_, err := service.GenerateDataKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_GenerateDataKey_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.encryptErr = errors.New("encrypt failed")
	ctx := context.Background()

	req := &platformv1.GenerateDataKeyRequest{KeyId: "test"}

	_, err := service.GenerateDataKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test GenerateWrappedDataKey

func TestKMSGRPCService_GenerateWrappedDataKey_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GenerateWrappedDataKeyRequest{
		WrappingKeyId: "wrapping-key-id",
		KeySize:       32,
	}

	resp, err := service.GenerateWrappedDataKey(ctx, req)
	if err != nil {
		t.Fatalf("GenerateWrappedDataKey failed: %v", err)
	}

	if len(resp.GetWrappedKey()) == 0 {
		t.Error("Expected wrapped key in response")
	}
}

func TestKMSGRPCService_GenerateWrappedDataKey_MissingWrappingKeyID(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.GenerateWrappedDataKeyRequest{
		KeySize: 32,
	}

	_, err := service.GenerateWrappedDataKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing wrapping key ID")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestKMSGRPCService_GenerateWrappedDataKey_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.GenerateWrappedDataKeyRequest{WrappingKeyId: "test"}

	_, err := service.GenerateWrappedDataKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_GenerateWrappedDataKey_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.encryptErr = errors.New("encrypt failed")
	ctx := context.Background()

	req := &platformv1.GenerateWrappedDataKeyRequest{WrappingKeyId: "test"}

	_, err := service.GenerateWrappedDataKey(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test BackendStatus

func TestKMSGRPCService_BackendStatus_Success(t *testing.T) {
	service, _ := newTestKMSService()
	ctx := context.Background()

	req := &platformv1.BackendStatusRequest{}

	resp, err := service.BackendStatus(ctx, req)
	if err != nil {
		t.Fatalf("BackendStatus failed: %v", err)
	}

	if resp.GetBackendType() != "software" {
		t.Errorf("Expected backend type 'software', got '%s'", resp.GetBackendType())
	}

	if resp.GetBackendStatus() != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", resp.GetBackendStatus())
	}
}

func TestKMSGRPCService_BackendStatus_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewKMSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.BackendStatusRequest{}

	_, err := service.BackendStatus(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestKMSGRPCService_BackendStatus_ServiceError(t *testing.T) {
	service, mock := newTestKMSService()
	mock.backendStatusErr = errors.New("status failed")
	ctx := context.Background()

	req := &platformv1.BackendStatusRequest{}

	_, err := service.BackendStatus(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test helper functions

func TestProtoKeySpecToUnix_Nil(t *testing.T) {
	result := protoKeySpecToKMS(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestProtoKeySpecToUnix_Success(t *testing.T) {
	spec := &platformv1.KMSKeySpec{
		Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
		KeySize:   256,
		Usage:     []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_ENCRYPT},
	}

	result := protoKeySpecToKMS(spec)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Algorithm != int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256) {
		t.Errorf("Unexpected algorithm: %d", result.Algorithm)
	}

	if result.KeySize != 256 {
		t.Errorf("Unexpected key size: %d", result.KeySize)
	}
}

func TestUnixKeyHandleToProto_Nil(t *testing.T) {
	result := kmsKeyHandleToProto(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestUnixKeyHandleToProto_Success(t *testing.T) {
	handle := &KMSKeyHandle{
		KeyID:     "key-123",
		Version:   2,
		Algorithm: 22,
		Status:    1,
		CreatedAt: 1234567890,
	}

	result := kmsKeyHandleToProto(handle)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.KeyId != "key-123" {
		t.Errorf("Unexpected key ID: %s", result.KeyId)
	}

	if result.Version != 2 {
		t.Errorf("Unexpected version: %d", result.Version)
	}
}

func TestUnixKeyMetadataToProto_Nil(t *testing.T) {
	result := kmsKeyMetadataToProto(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestUnixKeyMetadataToProto_Success(t *testing.T) {
	meta := &KMSKeyMetadata{
		KeyID:       "key-123",
		Name:        "test-key",
		Description: "Test key",
		Algorithm:   22,
		Status:      1,
		Usage:       []int32{1, 2},
		Version:     1,
		CreatedAt:   1234567890,
	}

	result := kmsKeyMetadataToProto(meta)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.KeyId != "key-123" {
		t.Errorf("Unexpected key ID: %s", result.KeyId)
	}

	if len(result.Usage) != 2 {
		t.Errorf("Unexpected usage count: %d", len(result.Usage))
	}
}

// Test mapError

func TestKMSGRPCService_mapError_NilError(t *testing.T) {
	service, _ := newTestKMSService()
	result := service.mapError("test", nil)
	if result != nil {
		t.Error("Expected nil result for nil error")
	}
}

func TestKMSGRPCService_mapError_KMSOperationFailed(t *testing.T) {
	service, _ := newTestKMSService()
	err := ErrKMSOperationFailed{Operation: "test", Reason: "failed"}

	result := service.mapError("test", err)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

func TestKMSGRPCService_mapError_GenericError(t *testing.T) {
	service, _ := newTestKMSService()
	err := errors.New("generic error")

	result := service.mapError("test", err)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

// Test error type definitions

func TestErrNilKMSService_Error(t *testing.T) {
	err := ErrNilKMSService{}
	expected := "kms service is nil"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingKeyID_Error(t *testing.T) {
	err := ErrMissingKeyID{}
	expected := "key ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingKeySpec_Error(t *testing.T) {
	err := ErrMissingKeySpec{}
	expected := "key specification is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingKeyMaterial_Error(t *testing.T) {
	err := ErrMissingKeyMaterial{}
	expected := "key material is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingPlaintext_Error(t *testing.T) {
	err := ErrMissingPlaintext{}
	expected := "plaintext is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingCiphertext_Error(t *testing.T) {
	err := ErrMissingCiphertext{}
	expected := "ciphertext is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingMessage_Error(t *testing.T) {
	err := ErrMissingMessage{}
	expected := "message is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingSignature_Error(t *testing.T) {
	err := ErrMissingSignature{}
	expected := "signature is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingData_Error(t *testing.T) {
	err := ErrMissingData{}
	expected := "data is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingHMAC_Error(t *testing.T) {
	err := ErrMissingHMAC{}
	expected := "hmac is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrInvalidNumBytes_Error(t *testing.T) {
	err := ErrInvalidNumBytes{}
	expected := "num_bytes must be greater than 0"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingWrappingKeyID_Error(t *testing.T) {
	err := ErrMissingWrappingKeyID{}
	expected := "wrapping key ID is required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrMissingItems_Error(t *testing.T) {
	err := ErrMissingItems{}
	expected := "items are required"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestErrTooManyItems_Error(t *testing.T) {
	err := ErrTooManyItems{Max: 100}
	expected := "too many items in batch request"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}
