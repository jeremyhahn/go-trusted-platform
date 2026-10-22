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
	"context"
	"log/slog"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"google.golang.org/grpc/codes"
)

// errKMSLifecycleMock is the typed error returned by the lifecycle mocks
// for methods that have no behavior configured or when a test forces a
// backend failure.
type errKMSLifecycleMock struct {
	method string
}

func (e errKMSLifecycleMock) Error() string {
	return "kms lifecycle mock: " + e.method + " failed"
}

// mockSDKKMSClient implements the full quicbaas.KMSClient interface. The
// methods under test delegate to configurable function fields; all other
// methods return errKMSLifecycleMock.
type mockSDKKMSClient struct {
	importKeyFn       func(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error)
	exportKeyFn       func(ctx context.Context, req *kms.ExportKeyRequest) (*kms.ExportKeyResponse, error)
	updateKeyStatusFn func(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error)
	listKeyVersionsFn func(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error)
	getPublicKeyFn    func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error)
	listKeysFn        func(ctx context.Context) (*kms.ListKeysResponse, error)
	rotateKeyFn       func(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error)

	lastImportReq       *kms.ImportKeyRequest
	lastPublicKeyID     string
	lastExportReq       *kms.ExportKeyRequest
	lastUpdateStatusReq *kms.UpdateKeyStatusRequest
	lastListVersionsKey string
}

var _ quicbaas.KMSClient = (*mockSDKKMSClient)(nil)

func (m *mockSDKKMSClient) GenerateKey(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
	return nil, errKMSLifecycleMock{method: "GenerateKey"}
}

func (m *mockSDKKMSClient) GetKey(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
	return nil, errKMSLifecycleMock{method: "GetKey"}
}

func (m *mockSDKKMSClient) GetPublicKey(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
	m.lastPublicKeyID = keyID
	if m.getPublicKeyFn != nil {
		return m.getPublicKeyFn(ctx, keyID)
	}
	return nil, errKMSLifecycleMock{method: "GetPublicKey"}
}

func (m *mockSDKKMSClient) ListKeys(ctx context.Context) (*kms.ListKeysResponse, error) {
	if m.listKeysFn != nil {
		return m.listKeysFn(ctx)
	}
	return nil, errKMSLifecycleMock{method: "ListKeys"}
}

func (m *mockSDKKMSClient) RotateKey(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
	if m.rotateKeyFn != nil {
		return m.rotateKeyFn(ctx, keyID)
	}
	return nil, errKMSLifecycleMock{method: "RotateKey"}
}

func (m *mockSDKKMSClient) DeleteKey(ctx context.Context, keyID string) error {
	return errKMSLifecycleMock{method: "DeleteKey"}
}

func (m *mockSDKKMSClient) ImportKey(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error) {
	m.lastImportReq = req
	if m.importKeyFn != nil {
		return m.importKeyFn(ctx, req)
	}
	return nil, errKMSLifecycleMock{method: "ImportKey"}
}

func (m *mockSDKKMSClient) ExportKey(ctx context.Context, req *kms.ExportKeyRequest) (*kms.ExportKeyResponse, error) {
	m.lastExportReq = req
	if m.exportKeyFn != nil {
		return m.exportKeyFn(ctx, req)
	}
	return nil, errKMSLifecycleMock{method: "ExportKey"}
}

func (m *mockSDKKMSClient) RevokeKey(ctx context.Context, keyID, _ string) error {
	return errKMSLifecycleMock{method: "RevokeKey"}
}

func (m *mockSDKKMSClient) ListKeyVersions(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error) {
	m.lastListVersionsKey = keyID
	if m.listKeyVersionsFn != nil {
		return m.listKeyVersionsFn(ctx, keyID)
	}
	return nil, errKMSLifecycleMock{method: "ListKeyVersions"}
}

func (m *mockSDKKMSClient) UpdateKeyStatus(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
	m.lastUpdateStatusReq = req
	if m.updateKeyStatusFn != nil {
		return m.updateKeyStatusFn(ctx, req)
	}
	return nil, errKMSLifecycleMock{method: "UpdateKeyStatus"}
}

func (m *mockSDKKMSClient) GetKeyMetadata(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
	return nil, errKMSLifecycleMock{method: "GetKeyMetadata"}
}

func (m *mockSDKKMSClient) UpdateKeyMetadata(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
	return nil, errKMSLifecycleMock{method: "UpdateKeyMetadata"}
}

func (m *mockSDKKMSClient) SetKeyPolicy(ctx context.Context, req *kms.SetKeyPolicyRequest) error {
	return errKMSLifecycleMock{method: "SetKeyPolicy"}
}

func (m *mockSDKKMSClient) GetKeyPolicy(ctx context.Context, keyID string) (*kms.KeyPolicy, error) {
	return nil, errKMSLifecycleMock{method: "GetKeyPolicy"}
}

func (m *mockSDKKMSClient) SetKeyRotationPolicy(ctx context.Context, req *kms.SetKeyRotationPolicyRequest) (*kms.KeyRotationPolicy, error) {
	return nil, errKMSLifecycleMock{method: "SetKeyRotationPolicy"}
}

func (m *mockSDKKMSClient) GetKeyRotationPolicy(ctx context.Context, keyID string) (*kms.KeyRotationPolicy, error) {
	return nil, errKMSLifecycleMock{method: "GetKeyRotationPolicy"}
}

func (m *mockSDKKMSClient) DeleteKeyRotationPolicy(ctx context.Context, keyID string) error {
	return errKMSLifecycleMock{method: "DeleteKeyRotationPolicy"}
}

func (m *mockSDKKMSClient) GetSupportedAlgorithms(ctx context.Context) (*kms.SupportedAlgorithmsResponse, error) {
	return nil, errKMSLifecycleMock{method: "GetSupportedAlgorithms"}
}

func (m *mockSDKKMSClient) BackendStatus(ctx context.Context) (*kms.BackendStatusResponse, error) {
	return nil, errKMSLifecycleMock{method: "BackendStatus"}
}

func (m *mockSDKKMSClient) UnwrapKey(ctx context.Context, req *kms.UnwrapKeyRequest) (*kms.UnwrapKeyResponse, error) {
	return nil, errKMSLifecycleMock{method: "UnwrapKey"}
}

// mockSDKCryptoClient implements the full quicbaas.CryptoClient interface.
// Only Hash delegates to a configurable function field; all other methods
// return errKMSLifecycleMock.
type mockSDKCryptoClient struct {
	hashFn              func(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error)
	lastHashReq         *quicbaas.HashRequest
	generateHMACFn      func(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error)
	lastGenerateHMACReq *quicbaas.GenerateHMACRequest
	verifyHMACFn        func(ctx context.Context, req *quicbaas.VerifyHMACRequest) (*quicbaas.VerifyHMACResponse, error)
	lastVerifyHMACReq   *quicbaas.VerifyHMACRequest
}

var _ quicbaas.CryptoClient = (*mockSDKCryptoClient)(nil)

func (m *mockSDKCryptoClient) Encrypt(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
	return nil, errKMSLifecycleMock{method: "Encrypt"}
}

func (m *mockSDKCryptoClient) Decrypt(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
	return nil, errKMSLifecycleMock{method: "Decrypt"}
}

func (m *mockSDKCryptoClient) Sign(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
	return nil, errKMSLifecycleMock{method: "Sign"}
}

func (m *mockSDKCryptoClient) Verify(ctx context.Context, req *quicbaas.VerifyRequest) (*quicbaas.VerifyResponse, error) {
	return nil, errKMSLifecycleMock{method: "Verify"}
}

func (m *mockSDKCryptoClient) Rewrap(ctx context.Context, req *quicbaas.RewrapRequest) (*quicbaas.RewrapResponse, error) {
	return nil, errKMSLifecycleMock{method: "Rewrap"}
}

func (m *mockSDKCryptoClient) EncryptBatch(ctx context.Context, req *quicbaas.EncryptBatchRequest) (*quicbaas.EncryptBatchResponse, error) {
	return nil, errKMSLifecycleMock{method: "EncryptBatch"}
}

func (m *mockSDKCryptoClient) DecryptBatch(ctx context.Context, req *quicbaas.DecryptBatchRequest) (*quicbaas.DecryptBatchResponse, error) {
	return nil, errKMSLifecycleMock{method: "DecryptBatch"}
}

func (m *mockSDKCryptoClient) GenerateDataKey(ctx context.Context, req *quicbaas.GenerateDataKeyRequest) (*quicbaas.GenerateDataKeyResponse, error) {
	return nil, errKMSLifecycleMock{method: "GenerateDataKey"}
}

func (m *mockSDKCryptoClient) GenerateWrappedDataKey(ctx context.Context, req *quicbaas.GenerateWrappedDataKeyRequest) (*quicbaas.GenerateWrappedDataKeyResponse, error) {
	return nil, errKMSLifecycleMock{method: "GenerateWrappedDataKey"}
}

func (m *mockSDKCryptoClient) GenerateHMAC(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error) {
	m.lastGenerateHMACReq = req
	if m.generateHMACFn != nil {
		return m.generateHMACFn(ctx, req)
	}
	return nil, errKMSLifecycleMock{method: "GenerateHMAC"}
}

func (m *mockSDKCryptoClient) VerifyHMAC(ctx context.Context, req *quicbaas.VerifyHMACRequest) (*quicbaas.VerifyHMACResponse, error) {
	m.lastVerifyHMACReq = req
	if m.verifyHMACFn != nil {
		return m.verifyHMACFn(ctx, req)
	}
	return nil, errKMSLifecycleMock{method: "VerifyHMAC"}
}

func (m *mockSDKCryptoClient) GenerateRandom(ctx context.Context, req *quicbaas.GenerateRandomRequest) (*quicbaas.GenerateRandomResponse, error) {
	return nil, errKMSLifecycleMock{method: "GenerateRandom"}
}

func (m *mockSDKCryptoClient) Hash(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error) {
	m.lastHashReq = req
	if m.hashFn != nil {
		return m.hashFn(ctx, req)
	}
	return nil, errKMSLifecycleMock{method: "Hash"}
}

// =============================================================================
// KMSServerAdapter.ImportKey
// =============================================================================

func TestKMSServerAdapterImportKey(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKKMSClient{
			importKeyFn: func(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error) {
				return &kms.ImportKeyResponse{
					KeyID:     "imported-key",
					Version:   3,
					Algorithm: kms.AlgorithmECDSAP256,
				}, nil
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyMaterial:   []byte("raw-key-material"),
			WrappingKeyId: "wrap-key",
			Name:          "import-1",
			Description:   "imported key",
			Tags:          map[string]string{"env": "test"},
			KeySpec: &pb.KeySpec{
				Algorithm: pb.KeyAlgorithm_KEY_ALG_ECDSA_P256,
				Usage:     []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_SIGN, pb.KeyUsage_KEY_USAGE_VERIFY},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mock.lastImportReq == nil {
			t.Fatal("expected SDK ImportKey to be called")
		}
		if string(mock.lastImportReq.KeyMaterial) != "raw-key-material" {
			t.Errorf("KeyMaterial = %q, want %q", mock.lastImportReq.KeyMaterial, "raw-key-material")
		}
		if mock.lastImportReq.WrappingKeyID != "wrap-key" {
			t.Errorf("WrappingKeyID = %q, want %q", mock.lastImportReq.WrappingKeyID, "wrap-key")
		}
		if mock.lastImportReq.Name != "import-1" {
			t.Errorf("Name = %q, want %q", mock.lastImportReq.Name, "import-1")
		}
		if mock.lastImportReq.Algorithm != kms.AlgorithmECDSAP256 {
			t.Errorf("Algorithm = %v, want %v", mock.lastImportReq.Algorithm, kms.AlgorithmECDSAP256)
		}
		if len(mock.lastImportReq.Usage) != 2 {
			t.Errorf("Usage length = %d, want 2", len(mock.lastImportReq.Usage))
		}

		if resp.GetKey().GetKeyId() != "imported-key" {
			t.Errorf("KeyId = %q, want %q", resp.GetKey().GetKeyId(), "imported-key")
		}
		if resp.GetKey().GetVersion() != 3 {
			t.Errorf("Version = %d, want 3", resp.GetKey().GetVersion())
		}
		if resp.GetKey().GetAlgorithm() != pb.KeyAlgorithm_KEY_ALG_ECDSA_P256 {
			t.Errorf("Algorithm = %v, want ECDSA_P256", resp.GetKey().GetAlgorithm())
		}
		if resp.GetTimestamp() <= 0 {
			t.Error("expected positive timestamp")
		}
	})

	t.Run("NilClient", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(nil, slog.Default())
		_, err := adapter.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyMaterial: []byte("material"),
			Name:        "k",
		})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("MissingKeyMaterial", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.ImportKey(context.Background(), &pb.ImportKeyRequest{Name: "k"})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("MissingName", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyMaterial: []byte("material"),
		})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("SDKError", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.ImportKey(context.Background(), &pb.ImportKeyRequest{
			KeyMaterial: []byte("material"),
			Name:        "k",
		})
		assertGRPCStatusCode(t, err, codes.Internal)
	})
}

// =============================================================================
// KMSServerAdapter.UpdateKeyStatus
// =============================================================================

func TestKMSServerAdapterUpdateKeyStatus(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKKMSClient{
			updateKeyStatusFn: func(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
				return &kms.UpdateKeyStatusResponse{
					KeyID:   req.KeyID,
					Version: req.Version,
					Status:  req.Status,
				}, nil
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.UpdateKeyStatus(context.Background(), &pb.UpdateKeyStatusRequest{
			KeyId:   "key-1",
			Version: 2,
			Status:  pb.KeyStatus_KEY_STATUS_DISABLED,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mock.lastUpdateStatusReq.KeyID != "key-1" {
			t.Errorf("KeyID = %q, want %q", mock.lastUpdateStatusReq.KeyID, "key-1")
		}
		if mock.lastUpdateStatusReq.Version != 2 {
			t.Errorf("Version = %d, want 2", mock.lastUpdateStatusReq.Version)
		}
		if mock.lastUpdateStatusReq.Status != kms.KeyStatusDisabled {
			t.Errorf("Status = %v, want %v", mock.lastUpdateStatusReq.Status, kms.KeyStatusDisabled)
		}

		if resp.GetKeyId() != "key-1" {
			t.Errorf("KeyId = %q, want %q", resp.GetKeyId(), "key-1")
		}
		if resp.GetVersion() != 2 {
			t.Errorf("Version = %d, want 2", resp.GetVersion())
		}
		if resp.GetStatus() != pb.KeyStatus_KEY_STATUS_DISABLED {
			t.Errorf("Status = %v, want DISABLED", resp.GetStatus())
		}
		if resp.GetTimestamp() <= 0 {
			t.Error("expected positive timestamp")
		}
	})

	t.Run("NilClient", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(nil, slog.Default())
		_, err := adapter.UpdateKeyStatus(context.Background(), &pb.UpdateKeyStatusRequest{
			KeyId:  "key-1",
			Status: pb.KeyStatus_KEY_STATUS_ENABLED,
		})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.UpdateKeyStatus(context.Background(), &pb.UpdateKeyStatusRequest{
			Status: pb.KeyStatus_KEY_STATUS_ENABLED,
		})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("UnspecifiedStatus", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.UpdateKeyStatus(context.Background(), &pb.UpdateKeyStatusRequest{
			KeyId: "key-1",
		})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("SDKError", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.UpdateKeyStatus(context.Background(), &pb.UpdateKeyStatusRequest{
			KeyId:  "key-1",
			Status: pb.KeyStatus_KEY_STATUS_ENABLED,
		})
		assertGRPCStatusCode(t, err, codes.Internal)
	})
}

// =============================================================================
// KMSServerAdapter.ExportKey
// =============================================================================

func TestKMSServerAdapterExportKey(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKKMSClient{
			exportKeyFn: func(ctx context.Context, req *kms.ExportKeyRequest) (*kms.ExportKeyResponse, error) {
				return &kms.ExportKeyResponse{
					KeyID:             req.KeyID,
					Format:            req.Format,
					WrappingKeyID:     req.WrappingKeyID,
					WrappingAlgorithm: req.WrappingAlgorithm,
					WrappedMaterial:   []byte("wrapped-bytes"),
					Version:           5,
				}, nil
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.ExportKey(context.Background(), &pb.ExportKeyRequest{
			KeyId:             "key-1",
			WrappingKeyId:     "wrap-key",
			WrappingAlgorithm: pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256,
			Format:            pb.ExportFormat_EXPORT_FORMAT_PEM,
			Version:           5,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mock.lastExportReq.KeyID != "key-1" {
			t.Errorf("KeyID = %q, want %q", mock.lastExportReq.KeyID, "key-1")
		}
		if mock.lastExportReq.WrappingKeyID != "wrap-key" {
			t.Errorf("WrappingKeyID = %q, want %q", mock.lastExportReq.WrappingKeyID, "wrap-key")
		}
		if mock.lastExportReq.WrappingAlgorithm != kms.WrapAlgRSAOAEPSHA256 {
			t.Errorf("WrappingAlgorithm = %v, want %v", mock.lastExportReq.WrappingAlgorithm, kms.WrapAlgRSAOAEPSHA256)
		}
		if mock.lastExportReq.Format != kms.ExportFormatPEM {
			t.Errorf("Format = %v, want %v", mock.lastExportReq.Format, kms.ExportFormatPEM)
		}
		if mock.lastExportReq.Version != 5 {
			t.Errorf("Version = %d, want 5", mock.lastExportReq.Version)
		}

		if resp.GetKeyId() != "key-1" {
			t.Errorf("KeyId = %q, want %q", resp.GetKeyId(), "key-1")
		}
		if resp.GetFormat() != pb.ExportFormat_EXPORT_FORMAT_PEM {
			t.Errorf("Format = %v, want PEM", resp.GetFormat())
		}
		if resp.GetWrappingAlgorithm() != pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256 {
			t.Errorf("WrappingAlgorithm = %v, want RSA_OAEP_SHA256", resp.GetWrappingAlgorithm())
		}
		if string(resp.GetWrappedMaterial()) != "wrapped-bytes" {
			t.Errorf("WrappedMaterial = %q, want %q", resp.GetWrappedMaterial(), "wrapped-bytes")
		}
		if resp.GetVersion() != 5 {
			t.Errorf("Version = %d, want 5", resp.GetVersion())
		}
		if resp.GetTimestamp() <= 0 {
			t.Error("expected positive timestamp")
		}
	})

	t.Run("NilClient", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(nil, slog.Default())
		_, err := adapter.ExportKey(context.Background(), &pb.ExportKeyRequest{
			KeyId:         "key-1",
			WrappingKeyId: "wrap-key",
		})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.ExportKey(context.Background(), &pb.ExportKeyRequest{
			WrappingKeyId: "wrap-key",
		})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("MissingWrappingKeyID", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.ExportKey(context.Background(), &pb.ExportKeyRequest{
			KeyId: "key-1",
		})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("SDKError", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.ExportKey(context.Background(), &pb.ExportKeyRequest{
			KeyId:         "key-1",
			WrappingKeyId: "wrap-key",
		})
		assertGRPCStatusCode(t, err, codes.Internal)
	})
}

// =============================================================================
// KMSServerAdapter.ListKeyVersions
// =============================================================================

func TestKMSServerAdapterListKeyVersions(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		created := time.Unix(1700000000, 0)
		disabled := time.Unix(1700003600, 0)
		mock := &mockSDKKMSClient{
			listKeyVersionsFn: func(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error) {
				return &kms.ListKeyVersionsResponse{
					KeyID: keyID,
					Versions: []kms.KeyVersionInfo{
						{
							Version:   1,
							Status:    kms.KeyStatusDisabled,
							Algorithm: kms.AlgorithmAES256GCM,
							CreatedAt: created,
						},
						{
							Version:    2,
							Status:     kms.KeyStatusEnabled,
							Algorithm:  kms.AlgorithmAES256GCM,
							CreatedAt:  created,
							DisabledAt: disabled,
						},
					},
				}, nil
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.ListKeyVersions(context.Background(), &pb.ListKeyVersionsRequest{
			KeyId: "key-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mock.lastListVersionsKey != "key-1" {
			t.Errorf("keyID = %q, want %q", mock.lastListVersionsKey, "key-1")
		}
		if resp.GetKeyId() != "key-1" {
			t.Errorf("KeyId = %q, want %q", resp.GetKeyId(), "key-1")
		}
		if len(resp.GetVersions()) != 2 {
			t.Fatalf("versions length = %d, want 2", len(resp.GetVersions()))
		}

		v1 := resp.GetVersions()[0]
		if v1.GetVersion() != 1 {
			t.Errorf("v1 Version = %d, want 1", v1.GetVersion())
		}
		if v1.GetStatus() != pb.KeyStatus_KEY_STATUS_DISABLED {
			t.Errorf("v1 Status = %v, want DISABLED", v1.GetStatus())
		}
		if v1.GetAlgorithm() != pb.KeyAlgorithm_KEY_ALG_AES_256_GCM {
			t.Errorf("v1 Algorithm = %v, want AES_256_GCM", v1.GetAlgorithm())
		}
		if v1.GetCreatedAt() != created.Unix() {
			t.Errorf("v1 CreatedAt = %d, want %d", v1.GetCreatedAt(), created.Unix())
		}
		if v1.GetDisabledAt() != 0 {
			t.Errorf("v1 DisabledAt = %d, want 0", v1.GetDisabledAt())
		}

		v2 := resp.GetVersions()[1]
		if v2.GetDisabledAt() != disabled.Unix() {
			t.Errorf("v2 DisabledAt = %d, want %d", v2.GetDisabledAt(), disabled.Unix())
		}
		if resp.GetTimestamp() <= 0 {
			t.Error("expected positive timestamp")
		}
	})

	t.Run("NilClient", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(nil, slog.Default())
		_, err := adapter.ListKeyVersions(context.Background(), &pb.ListKeyVersionsRequest{KeyId: "key-1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.ListKeyVersions(context.Background(), &pb.ListKeyVersionsRequest{})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("SDKError", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.ListKeyVersions(context.Background(), &pb.ListKeyVersionsRequest{KeyId: "key-1"})
		assertGRPCStatusCode(t, err, codes.Internal)
	})
}

func TestKMSServerAdapterListKeysPagination(t *testing.T) {
	t.Parallel()

	threeKeys := func(ctx context.Context) (*kms.ListKeysResponse, error) {
		return &kms.ListKeysResponse{Keys: []kms.KeyInfo{
			{KeyID: "key-a", Version: 1, Algorithm: kms.AlgorithmAES256GCM},
			{KeyID: "key-b", Version: 1, Algorithm: kms.AlgorithmAES256GCM},
			{KeyID: "key-c", Version: 2, Algorithm: kms.AlgorithmAES256GCM},
		}}, nil
	}

	t.Run("LimitAndCursor", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{listKeysFn: threeKeys}, slog.Default())

		first, err := adapter.ListKeys(context.Background(), &pb.ListKeysRequest{Limit: 2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(first.GetKeys()) != 2 {
			t.Fatalf("first page length = %d, want 2", len(first.GetKeys()))
		}
		if !first.GetHasMore() || first.GetNextCursor() != "2" || first.GetTotalCount() != 3 {
			t.Errorf("first page HasMore=%v NextCursor=%q TotalCount=%d, want true \"2\" 3",
				first.GetHasMore(), first.GetNextCursor(), first.GetTotalCount())
		}

		second, err := adapter.ListKeys(context.Background(), &pb.ListKeysRequest{Limit: 2, Cursor: first.GetNextCursor()})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(second.GetKeys()) != 1 || second.GetKeys()[0].GetKeyId() != "key-c" {
			t.Fatalf("second page = %v, want [key-c]", second.GetKeys())
		}
		if second.GetHasMore() || second.GetNextCursor() != "" {
			t.Errorf("second page HasMore=%v NextCursor=%q, want false \"\"", second.GetHasMore(), second.GetNextCursor())
		}
	})

	t.Run("NoLimitReturnsAll", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{listKeysFn: threeKeys}, slog.Default())
		resp, err := adapter.ListKeys(context.Background(), &pb.ListKeysRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.GetKeys()) != 3 || resp.GetHasMore() {
			t.Errorf("length=%d HasMore=%v, want 3 false", len(resp.GetKeys()), resp.GetHasMore())
		}
	})

	t.Run("InvalidCursor", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{listKeysFn: threeKeys}, slog.Default())
		_, err := adapter.ListKeys(context.Background(), &pb.ListKeysRequest{Cursor: "not-a-number"})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("UnsupportedFilter", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{listKeysFn: threeKeys}, slog.Default())
		_, err := adapter.ListKeys(context.Background(), &pb.ListKeysRequest{Filter: map[string]string{"status": "enabled"}})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("SDKError", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.ListKeys(context.Background(), &pb.ListKeysRequest{Limit: 2})
		assertGRPCStatusCode(t, err, codes.Internal)
	})
}

func TestKMSServerAdapterRotateKeyVersions(t *testing.T) {
	t.Parallel()

	t.Run("ReportsReplacedVersion", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKKMSClient{
			rotateKeyFn: func(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
				return &kms.RotateKeyResponse{KeyID: keyID, NewVersion: 2}, nil
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.RotateKey(context.Background(), &pb.RotateKeyRequest{KeyId: "key-1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.GetOldVersion() != 1 || resp.GetNewVersion() != 2 {
			t.Errorf("OldVersion=%d NewVersion=%d, want 1 2", resp.GetOldVersion(), resp.GetNewVersion())
		}
		if resp.GetTimestamp() <= 0 {
			t.Error("expected positive timestamp")
		}
	})

	t.Run("SDKError", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.RotateKey(context.Background(), &pb.RotateKeyRequest{KeyId: "key-1"})
		assertGRPCStatusCode(t, err, codes.Internal)
	})
}

func TestRotatedFromVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		newVersion int
		want       uint64
	}{
		{newVersion: 2, want: 1},
		{newVersion: 1, want: 0},
		{newVersion: 0, want: 0},
		{newVersion: -1, want: 0},
	}
	for _, tt := range tests {
		if got := rotatedFromVersion(tt.newVersion); got != tt.want {
			t.Errorf("rotatedFromVersion(%d) = %d, want %d", tt.newVersion, got, tt.want)
		}
	}
}

func TestKMSServerAdapterGetPublicKey(t *testing.T) {
	t.Parallel()

	der := []byte{0x30, 0x59, 0x30, 0x13}
	currentKey := func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
		return &kms.GetPublicKeyResponse{
			KeyID:     keyID,
			PublicKey: der,
			Algorithm: kms.AlgorithmECDSAP256,
			Version:   3,
		}, nil
	}

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKKMSClient{getPublicKeyFn: currentKey}
		adapter := NewKMSServerAdapter(mock, slog.Default())

		resp, err := adapter.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyId: "key-1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mock.lastPublicKeyID != "key-1" {
			t.Errorf("keyID = %q, want %q", mock.lastPublicKeyID, "key-1")
		}
		if resp.GetKeyId() != "key-1" {
			t.Errorf("KeyId = %q, want %q", resp.GetKeyId(), "key-1")
		}
		if string(resp.GetPublicKey()) != string(der) {
			t.Errorf("PublicKey = %x, want %x", resp.GetPublicKey(), der)
		}
		if resp.GetAlgorithm() != pb.KeyAlgorithm_KEY_ALG_ECDSA_P256 {
			t.Errorf("Algorithm = %v, want ECDSA_P256", resp.GetAlgorithm())
		}
		if resp.GetVersion() != 3 {
			t.Errorf("Version = %d, want 3", resp.GetVersion())
		}
		if resp.GetTimestamp() <= 0 {
			t.Error("expected positive timestamp")
		}
	})

	t.Run("CurrentVersionRequested", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{getPublicKeyFn: currentKey}, slog.Default())
		resp, err := adapter.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyId: "key-1", Version: 3})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.GetVersion() != 3 {
			t.Errorf("Version = %d, want 3", resp.GetVersion())
		}
	})

	t.Run("OlderVersionRefused", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{getPublicKeyFn: currentKey}, slog.Default())
		_, err := adapter.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyId: "key-1", Version: 2})
		assertGRPCStatusCode(t, err, codes.NotFound)
	})

	t.Run("NilClient", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(nil, slog.Default())
		_, err := adapter.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyId: "key-1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("UnknownKeyIsNotFound", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKKMSClient{
			getPublicKeyFn: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return nil, sdkerrors.NewNotFound("key", keyID)
			},
		}
		adapter := NewKMSServerAdapter(mock, slog.Default())
		_, err := adapter.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyId: "missing"})
		assertGRPCStatusCode(t, err, codes.NotFound)
	})

	t.Run("SDKError", func(t *testing.T) {
		t.Parallel()
		adapter := NewKMSServerAdapter(&mockSDKKMSClient{}, slog.Default())
		_, err := adapter.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{KeyId: "key-1"})
		assertGRPCStatusCode(t, err, codes.Internal)
	})
}

// =============================================================================
// CryptoServerAdapter.Hash
// =============================================================================

func TestCryptoServerAdapterHash(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKCryptoClient{
			hashFn: func(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error) {
				return &quicbaas.HashResponse{
					HashAlg: req.HashAlg,
					Hash:    []byte("digest-bytes"),
				}, nil
			},
		}
		adapter := NewCryptoServerAdapter(mock, slog.Default())

		resp, err := adapter.Hash(context.Background(), &pb.HashRequest{
			Data:      []byte("payload"),
			Algorithm: pb.HashAlgorithm_HASH_ALG_SHA384,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if string(mock.lastHashReq.Data) != "payload" {
			t.Errorf("Data = %q, want %q", mock.lastHashReq.Data, "payload")
		}
		if mock.lastHashReq.HashAlg != quicbaas.HashSHA384 {
			t.Errorf("HashAlg = %v, want SHA384", mock.lastHashReq.HashAlg)
		}
		if resp.GetAlgorithm() != pb.HashAlgorithm_HASH_ALG_SHA384 {
			t.Errorf("Algorithm = %v, want SHA384", resp.GetAlgorithm())
		}
		if string(resp.GetHash()) != "digest-bytes" {
			t.Errorf("Hash = %q, want %q", resp.GetHash(), "digest-bytes")
		}
		if resp.GetTimestamp() <= 0 {
			t.Error("expected positive timestamp")
		}
	})

	t.Run("UnspecifiedAlgorithmDefaultsToSHA256", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKCryptoClient{
			hashFn: func(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error) {
				return &quicbaas.HashResponse{HashAlg: req.HashAlg, Hash: []byte("d")}, nil
			},
		}
		adapter := NewCryptoServerAdapter(mock, slog.Default())

		resp, err := adapter.Hash(context.Background(), &pb.HashRequest{Data: []byte("payload")})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mock.lastHashReq.HashAlg != quicbaas.HashSHA256 {
			t.Errorf("HashAlg = %v, want SHA256", mock.lastHashReq.HashAlg)
		}
		if resp.GetAlgorithm() != pb.HashAlgorithm_HASH_ALG_SHA256 {
			t.Errorf("Algorithm = %v, want SHA256", resp.GetAlgorithm())
		}
	})

	t.Run("NilClient", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(nil, slog.Default())
		_, err := adapter.Hash(context.Background(), &pb.HashRequest{Data: []byte("payload")})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("MissingData", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.Hash(context.Background(), &pb.HashRequest{})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.Hash(context.Background(), &pb.HashRequest{
			Data:      []byte("payload"),
			Algorithm: pb.HashAlgorithm_HASH_ALG_SHA3_256,
		})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("SDKError", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.Hash(context.Background(), &pb.HashRequest{Data: []byte("payload")})
		assertGRPCStatusCode(t, err, codes.Internal)
	})
}

// =============================================================================
// CryptoServerAdapter.GenerateHMAC
// =============================================================================

func TestCryptoServerAdapterGenerateHMAC(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKCryptoClient{
			generateHMACFn: func(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error) {
				return &quicbaas.GenerateHMACResponse{
					KeyID:      req.KeyID,
					KeyVersion: 4,
					HMAC:       []byte("mac-bytes"),
					HashAlg:    req.HashAlg,
				}, nil
			},
		}
		adapter := NewCryptoServerAdapter(mock, slog.Default())

		resp, err := adapter.GenerateHMAC(context.Background(), &pb.HMACRequest{
			KeyId:         "hmac-key",
			Message:       []byte("payload"),
			HashAlgorithm: pb.HashAlgorithm_HASH_ALG_SHA384,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mock.lastGenerateHMACReq.KeyID != "hmac-key" {
			t.Errorf("KeyID = %q, want %q", mock.lastGenerateHMACReq.KeyID, "hmac-key")
		}
		if string(mock.lastGenerateHMACReq.Message) != "payload" {
			t.Errorf("Message = %q, want %q", mock.lastGenerateHMACReq.Message, "payload")
		}
		if mock.lastGenerateHMACReq.HashAlg != quicbaas.HashSHA384 {
			t.Errorf("HashAlg = %v, want SHA384", mock.lastGenerateHMACReq.HashAlg)
		}
		if resp.GetKeyId() != "hmac-key" || resp.GetKeyVersion() != 4 {
			t.Errorf("response = %q/%d, want hmac-key/4", resp.GetKeyId(), resp.GetKeyVersion())
		}
		if string(resp.GetHmac()) != "mac-bytes" {
			t.Errorf("Hmac = %q, want %q", resp.GetHmac(), "mac-bytes")
		}
		if resp.GetHashAlgorithm() != pb.HashAlgorithm_HASH_ALG_SHA384 {
			t.Errorf("HashAlgorithm = %v, want SHA384", resp.GetHashAlgorithm())
		}
		if resp.GetTimestamp() <= 0 {
			t.Error("expected positive timestamp")
		}
	})

	t.Run("UnspecifiedAlgorithmDefaultsToSHA256", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKCryptoClient{
			generateHMACFn: func(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error) {
				return &quicbaas.GenerateHMACResponse{KeyID: req.KeyID, HMAC: []byte("m"), HashAlg: req.HashAlg}, nil
			},
		}
		adapter := NewCryptoServerAdapter(mock, slog.Default())

		resp, err := adapter.GenerateHMAC(context.Background(), &pb.HMACRequest{
			KeyId:   "hmac-key",
			Message: []byte("payload"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mock.lastGenerateHMACReq.HashAlg != quicbaas.HashSHA256 {
			t.Errorf("HashAlg = %v, want SHA256", mock.lastGenerateHMACReq.HashAlg)
		}
		if resp.GetHashAlgorithm() != pb.HashAlgorithm_HASH_ALG_SHA256 {
			t.Errorf("HashAlgorithm = %v, want SHA256", resp.GetHashAlgorithm())
		}
	})

	t.Run("NilClient", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(nil, slog.Default())
		_, err := adapter.GenerateHMAC(context.Background(), &pb.HMACRequest{KeyId: "k", Message: []byte("p")})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.GenerateHMAC(context.Background(), &pb.HMACRequest{Message: []byte("p")})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("MissingMessage", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.GenerateHMAC(context.Background(), &pb.HMACRequest{KeyId: "k"})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.GenerateHMAC(context.Background(), &pb.HMACRequest{
			KeyId:         "k",
			Message:       []byte("p"),
			HashAlgorithm: pb.HashAlgorithm_HASH_ALG_BLAKE2B_256,
		})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("SDKError", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.GenerateHMAC(context.Background(), &pb.HMACRequest{KeyId: "k", Message: []byte("p")})
		assertGRPCStatusCode(t, err, codes.Internal)
	})
}

// =============================================================================
// CryptoServerAdapter.VerifyHMAC
// =============================================================================

func TestCryptoServerAdapterVerifyHMAC(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		mock := &mockSDKCryptoClient{
			verifyHMACFn: func(ctx context.Context, req *quicbaas.VerifyHMACRequest) (*quicbaas.VerifyHMACResponse, error) {
				return &quicbaas.VerifyHMACResponse{Valid: true}, nil
			},
		}
		adapter := NewCryptoServerAdapter(mock, slog.Default())

		resp, err := adapter.VerifyHMAC(context.Background(), &pb.VerifyHMACRequest{
			KeyId:         "hmac-key",
			Message:       []byte("payload"),
			Hmac:          []byte("mac-bytes"),
			HashAlgorithm: pb.HashAlgorithm_HASH_ALG_SHA512,
			KeyVersion:    2,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mock.lastVerifyHMACReq.KeyID != "hmac-key" {
			t.Errorf("KeyID = %q, want %q", mock.lastVerifyHMACReq.KeyID, "hmac-key")
		}
		if string(mock.lastVerifyHMACReq.HMAC) != "mac-bytes" {
			t.Errorf("HMAC = %q, want %q", mock.lastVerifyHMACReq.HMAC, "mac-bytes")
		}
		if mock.lastVerifyHMACReq.HashAlg != quicbaas.HashSHA512 {
			t.Errorf("HashAlg = %v, want SHA512", mock.lastVerifyHMACReq.HashAlg)
		}
		if mock.lastVerifyHMACReq.KeyVersion != 2 {
			t.Errorf("KeyVersion = %d, want 2", mock.lastVerifyHMACReq.KeyVersion)
		}
		if !resp.GetValid() {
			t.Error("Valid = false, want true")
		}
		if resp.GetKeyId() != "hmac-key" || resp.GetKeyVersion() != 2 {
			t.Errorf("response = %q/%d, want hmac-key/2", resp.GetKeyId(), resp.GetKeyVersion())
		}
	})

	t.Run("NilClient", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(nil, slog.Default())
		_, err := adapter.VerifyHMAC(context.Background(), &pb.VerifyHMACRequest{KeyId: "k", Message: []byte("p"), Hmac: []byte("m")})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("MissingKeyID", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.VerifyHMAC(context.Background(), &pb.VerifyHMACRequest{Message: []byte("p"), Hmac: []byte("m")})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("MissingMessage", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.VerifyHMAC(context.Background(), &pb.VerifyHMACRequest{KeyId: "k", Hmac: []byte("m")})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("MissingHmac", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.VerifyHMAC(context.Background(), &pb.VerifyHMACRequest{KeyId: "k", Message: []byte("p")})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("UnsupportedAlgorithm", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.VerifyHMAC(context.Background(), &pb.VerifyHMACRequest{
			KeyId:         "k",
			Message:       []byte("p"),
			Hmac:          []byte("m"),
			HashAlgorithm: pb.HashAlgorithm_HASH_ALG_SHA3_512,
		})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("SDKError", func(t *testing.T) {
		t.Parallel()
		adapter := NewCryptoServerAdapter(&mockSDKCryptoClient{}, slog.Default())
		_, err := adapter.VerifyHMAC(context.Background(), &pb.VerifyHMACRequest{KeyId: "k", Message: []byte("p"), Hmac: []byte("m")})
		assertGRPCStatusCode(t, err, codes.Internal)
	})
}

// =============================================================================
// kmsQUICAdapter delegation for the newly implemented operations
// =============================================================================

func TestKMSQUICAdapterLifecycleDelegation(t *testing.T) {
	t.Parallel()

	kmsMock := &mockSDKKMSClient{
		importKeyFn: func(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error) {
			return &kms.ImportKeyResponse{KeyID: "k", Version: 1, Algorithm: kms.AlgorithmAES256GCM}, nil
		},
		exportKeyFn: func(ctx context.Context, req *kms.ExportKeyRequest) (*kms.ExportKeyResponse, error) {
			return &kms.ExportKeyResponse{KeyID: req.KeyID, WrappedMaterial: []byte("w"), Version: 1}, nil
		},
		updateKeyStatusFn: func(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
			return &kms.UpdateKeyStatusResponse{KeyID: req.KeyID, Version: req.Version, Status: req.Status}, nil
		},
		listKeyVersionsFn: func(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error) {
			return &kms.ListKeyVersionsResponse{KeyID: keyID, Versions: []kms.KeyVersionInfo{{Version: 1}}}, nil
		},
	}
	cryptoMock := &mockSDKCryptoClient{
		hashFn: func(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error) {
			return &quicbaas.HashResponse{HashAlg: req.HashAlg, Hash: []byte("d")}, nil
		},
		generateHMACFn: func(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error) {
			return &quicbaas.GenerateHMACResponse{KeyID: req.KeyID, KeyVersion: 1, HMAC: []byte("m"), HashAlg: req.HashAlg}, nil
		},
		verifyHMACFn: func(ctx context.Context, req *quicbaas.VerifyHMACRequest) (*quicbaas.VerifyHMACResponse, error) {
			return &quicbaas.VerifyHMACResponse{Valid: true}, nil
		},
	}
	adapter := newKMSQUICAdapter(
		NewKMSServerAdapter(kmsMock, slog.Default()),
		NewCryptoServerAdapter(cryptoMock, slog.Default()),
	)
	ctx := context.Background()

	t.Run("ImportKey", func(t *testing.T) {
		t.Parallel()
		resp, err := adapter.ImportKey(ctx, &pb.ImportKeyRequest{
			KeyMaterial: []byte("m"),
			Name:        "k",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.GetKey().GetKeyId() != "k" {
			t.Errorf("KeyId = %q, want %q", resp.GetKey().GetKeyId(), "k")
		}
	})

	t.Run("ImportKeyInvalidInput", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.ImportKey(ctx, &pb.ImportKeyRequest{})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("GenerateHMAC", func(t *testing.T) {
		t.Parallel()
		resp, err := adapter.GenerateHMAC(ctx, &pb.HMACRequest{KeyId: "k", Message: []byte("p")})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(resp.GetHmac()) != "m" {
			t.Errorf("Hmac = %q, want %q", resp.GetHmac(), "m")
		}
	})

	t.Run("GenerateHMACInvalidInput", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.GenerateHMAC(ctx, &pb.HMACRequest{})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("VerifyHMAC", func(t *testing.T) {
		t.Parallel()
		resp, err := adapter.VerifyHMAC(ctx, &pb.VerifyHMACRequest{KeyId: "k", Message: []byte("p"), Hmac: []byte("m")})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.GetValid() {
			t.Error("Valid = false, want true")
		}
	})

	t.Run("VerifyHMACInvalidInput", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.VerifyHMAC(ctx, &pb.VerifyHMACRequest{})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("UpdateKeyStatus", func(t *testing.T) {
		t.Parallel()
		resp, err := adapter.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{
			KeyId:  "k",
			Status: pb.KeyStatus_KEY_STATUS_DISABLED,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.GetStatus() != pb.KeyStatus_KEY_STATUS_DISABLED {
			t.Errorf("Status = %v, want DISABLED", resp.GetStatus())
		}
	})

	t.Run("UpdateKeyStatusInvalidInput", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("ExportKey", func(t *testing.T) {
		t.Parallel()
		resp, err := adapter.ExportKey(ctx, &pb.ExportKeyRequest{
			KeyId:         "k",
			WrappingKeyId: "w",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(resp.GetWrappedMaterial()) != "w" {
			t.Errorf("WrappedMaterial = %q, want %q", resp.GetWrappedMaterial(), "w")
		}
	})

	t.Run("ExportKeyInvalidInput", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.ExportKey(ctx, &pb.ExportKeyRequest{})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("ListKeyVersions", func(t *testing.T) {
		t.Parallel()
		resp, err := adapter.ListKeyVersions(ctx, &pb.ListKeyVersionsRequest{KeyId: "k"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.GetVersions()) != 1 {
			t.Errorf("versions length = %d, want 1", len(resp.GetVersions()))
		}
	})

	t.Run("ListKeyVersionsInvalidInput", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.ListKeyVersions(ctx, &pb.ListKeyVersionsRequest{})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("Hash", func(t *testing.T) {
		t.Parallel()
		resp, err := adapter.Hash(ctx, &pb.HashRequest{Data: []byte("payload")})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(resp.GetHash()) != "d" {
			t.Errorf("Hash = %q, want %q", resp.GetHash(), "d")
		}
	})

	t.Run("HashInvalidInput", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Hash(ctx, &pb.HashRequest{})
		assertGRPCStatusCode(t, err, codes.InvalidArgument)
	})
}

// =============================================================================
// Conversion helpers
// =============================================================================

func TestPbWrappingAlgorithmToSDK(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   pb.WrappingAlgorithm
		want kms.WrappingAlgorithm
	}{
		{"Unspecified", pb.WrappingAlgorithm_WRAP_ALG_UNSPECIFIED, kms.WrapAlgAESKW},
		{"AESKW", pb.WrappingAlgorithm_WRAP_ALG_AES_KW, kms.WrapAlgAESKW},
		{"AESKWP", pb.WrappingAlgorithm_WRAP_ALG_AES_KWP, kms.WrapAlgAESKWP},
		{"AESGCM", pb.WrappingAlgorithm_WRAP_ALG_AES_GCM, kms.WrapAlgAESGCM},
		{"RSAOAEPSHA256", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256, kms.WrapAlgRSAOAEPSHA256},
		{"RSAOAEPSHA384", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384, kms.WrapAlgRSAOAEPSHA384},
		{"RSAOAEPSHA512", pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512, kms.WrapAlgRSAOAEPSHA512},
		{"ECDHESA256KW", pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW, kms.WrapAlgECDHESA256KW},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pbWrappingAlgorithmToSDK(tt.in); got != tt.want {
				t.Errorf("pbWrappingAlgorithmToSDK(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSdkWrappingAlgorithmToPb(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   kms.WrappingAlgorithm
		want pb.WrappingAlgorithm
	}{
		{"AESKW", kms.WrapAlgAESKW, pb.WrappingAlgorithm_WRAP_ALG_AES_KW},
		{"AESKWP", kms.WrapAlgAESKWP, pb.WrappingAlgorithm_WRAP_ALG_AES_KWP},
		{"AESGCM", kms.WrapAlgAESGCM, pb.WrappingAlgorithm_WRAP_ALG_AES_GCM},
		{"RSAOAEPSHA256", kms.WrapAlgRSAOAEPSHA256, pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256},
		{"RSAOAEPSHA384", kms.WrapAlgRSAOAEPSHA384, pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384},
		{"RSAOAEPSHA512", kms.WrapAlgRSAOAEPSHA512, pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512},
		{"ECDHESA256KW", kms.WrapAlgECDHESA256KW, pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW},
		{"Unknown", kms.WrappingAlgorithm(99), pb.WrappingAlgorithm_WRAP_ALG_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sdkWrappingAlgorithmToPb(tt.in); got != tt.want {
				t.Errorf("sdkWrappingAlgorithmToPb(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestPbExportFormatToSDK(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   pb.ExportFormat
		want kms.ExportFormat
	}{
		{"Unspecified", pb.ExportFormat_EXPORT_FORMAT_UNSPECIFIED, kms.ExportFormatRaw},
		{"Raw", pb.ExportFormat_EXPORT_FORMAT_RAW, kms.ExportFormatRaw},
		{"JWK", pb.ExportFormat_EXPORT_FORMAT_JWK, kms.ExportFormatJWK},
		{"PEM", pb.ExportFormat_EXPORT_FORMAT_PEM, kms.ExportFormatPEM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pbExportFormatToSDK(tt.in); got != tt.want {
				t.Errorf("pbExportFormatToSDK(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSdkExportFormatToPb(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   kms.ExportFormat
		want pb.ExportFormat
	}{
		{"Raw", kms.ExportFormatRaw, pb.ExportFormat_EXPORT_FORMAT_RAW},
		{"JWK", kms.ExportFormatJWK, pb.ExportFormat_EXPORT_FORMAT_JWK},
		{"PEM", kms.ExportFormatPEM, pb.ExportFormat_EXPORT_FORMAT_PEM},
		{"Unknown", kms.ExportFormat(99), pb.ExportFormat_EXPORT_FORMAT_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sdkExportFormatToPb(tt.in); got != tt.want {
				t.Errorf("sdkExportFormatToPb(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSdkHashAlgorithmToPb(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   quicbaas.HashAlgorithm
		want pb.HashAlgorithm
	}{
		{"SHA256", quicbaas.HashSHA256, pb.HashAlgorithm_HASH_ALG_SHA256},
		{"SHA384", quicbaas.HashSHA384, pb.HashAlgorithm_HASH_ALG_SHA384},
		{"SHA512", quicbaas.HashSHA512, pb.HashAlgorithm_HASH_ALG_SHA512},
		{"Unknown", quicbaas.HashAlgorithm(99), pb.HashAlgorithm_HASH_ALG_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sdkHashAlgorithmToPb(tt.in); got != tt.want {
				t.Errorf("sdkHashAlgorithmToPb(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
