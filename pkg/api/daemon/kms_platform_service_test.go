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
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkcrypto "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errPlatformKMSTest is the sentinel error returned by the mock SDK clients.
var errPlatformKMSTest = errors.New("platform kms test error")

// =============================================================================
// Mock SDK KMS Client
// =============================================================================

// platformMockKMSClient implements kms.Client with overridable functions.
type platformMockKMSClient struct {
	generateKeyFn    func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error)
	importKeyFn      func(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error)
	getKeyMetadataFn func(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error)
	// updateKeyMetadataFn answers UpdateKeyMetadata; unset, the call fails.
	updateKeyMetadataFn func(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error)
	listKeysFn          func(ctx context.Context) (*kms.ListKeysResponse, error)
	deleteKeyFn         func(ctx context.Context, keyID string) error
	rotateKeyFn         func(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error)
	updateKeyStatusFn   func(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error)
	exportKeyFn         func(ctx context.Context, req *kms.ExportKeyRequest) (*kms.ExportKeyResponse, error)
	listKeyVersionsFn   func(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error)
	backendStatusFn     func(ctx context.Context) (*kms.BackendStatusResponse, error)
}

func (m *platformMockKMSClient) GenerateKey(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
	if m.generateKeyFn != nil {
		return m.generateKeyFn(ctx, req)
	}
	return &kms.GenerateKeyResponse{KeyID: "key-1", Version: 1, Algorithm: req.Algorithm}, nil
}

func (m *platformMockKMSClient) GetKey(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
	return nil, errPlatformKMSTest
}

func (m *platformMockKMSClient) GetPublicKey(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
	return nil, errPlatformKMSTest
}

func (m *platformMockKMSClient) ListKeys(ctx context.Context) (*kms.ListKeysResponse, error) {
	if m.listKeysFn != nil {
		return m.listKeysFn(ctx)
	}
	return &kms.ListKeysResponse{}, nil
}

func (m *platformMockKMSClient) RotateKey(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
	if m.rotateKeyFn != nil {
		return m.rotateKeyFn(ctx, keyID)
	}
	return &kms.RotateKeyResponse{KeyID: keyID, NewVersion: 2}, nil
}

func (m *platformMockKMSClient) DeleteKey(ctx context.Context, keyID string) error {
	if m.deleteKeyFn != nil {
		return m.deleteKeyFn(ctx, keyID)
	}
	return nil
}

func (m *platformMockKMSClient) ImportKey(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error) {
	if m.importKeyFn != nil {
		return m.importKeyFn(ctx, req)
	}
	return &kms.ImportKeyResponse{KeyID: "imported-1", Version: 1, Algorithm: req.Algorithm}, nil
}

func (m *platformMockKMSClient) ExportKey(ctx context.Context, req *kms.ExportKeyRequest) (*kms.ExportKeyResponse, error) {
	if m.exportKeyFn != nil {
		return m.exportKeyFn(ctx, req)
	}
	return &kms.ExportKeyResponse{KeyID: req.KeyID, WrappingKeyID: req.WrappingKeyID, WrappedMaterial: []byte("wrapped"), Version: 1}, nil
}

func (m *platformMockKMSClient) RevokeKey(ctx context.Context, keyID, _ string) error {
	return errPlatformKMSTest
}

func (m *platformMockKMSClient) ListKeyVersions(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error) {
	if m.listKeyVersionsFn != nil {
		return m.listKeyVersionsFn(ctx, keyID)
	}
	return &kms.ListKeyVersionsResponse{KeyID: keyID}, nil
}

func (m *platformMockKMSClient) UpdateKeyStatus(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
	if m.updateKeyStatusFn != nil {
		return m.updateKeyStatusFn(ctx, req)
	}
	return &kms.UpdateKeyStatusResponse{KeyID: req.KeyID, Version: req.Version, Status: req.Status}, nil
}

func (m *platformMockKMSClient) GetKeyMetadata(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
	if m.getKeyMetadataFn != nil {
		return m.getKeyMetadataFn(ctx, keyID)
	}
	return &kms.KeyMetadataResponse{KeyID: keyID, Algorithm: kms.AlgorithmAES256GCM, Version: 1}, nil
}

func (m *platformMockKMSClient) UpdateKeyMetadata(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
	if m.updateKeyMetadataFn != nil {
		return m.updateKeyMetadataFn(ctx, req)
	}
	return nil, errPlatformKMSTest
}

func (m *platformMockKMSClient) SetKeyPolicy(ctx context.Context, req *kms.SetKeyPolicyRequest) error {
	return errPlatformKMSTest
}

func (m *platformMockKMSClient) GetKeyPolicy(ctx context.Context, keyID string) (*kms.KeyPolicy, error) {
	return nil, errPlatformKMSTest
}

func (m *platformMockKMSClient) SetKeyRotationPolicy(ctx context.Context, req *kms.SetKeyRotationPolicyRequest) (*kms.KeyRotationPolicy, error) {
	return nil, errPlatformKMSTest
}

func (m *platformMockKMSClient) GetKeyRotationPolicy(ctx context.Context, keyID string) (*kms.KeyRotationPolicy, error) {
	return nil, errPlatformKMSTest
}

func (m *platformMockKMSClient) DeleteKeyRotationPolicy(ctx context.Context, keyID string) error {
	return errPlatformKMSTest
}

func (m *platformMockKMSClient) GetSupportedAlgorithms(ctx context.Context) (*kms.SupportedAlgorithmsResponse, error) {
	return nil, errPlatformKMSTest
}

func (m *platformMockKMSClient) BackendStatus(ctx context.Context) (*kms.BackendStatusResponse, error) {
	if m.backendStatusFn != nil {
		return m.backendStatusFn(ctx)
	}
	return &kms.BackendStatusResponse{BackendType: "software", Status: "healthy"}, nil
}

func (m *platformMockKMSClient) UnwrapKey(ctx context.Context, req *kms.UnwrapKeyRequest) (*kms.UnwrapKeyResponse, error) {
	return nil, errPlatformKMSTest
}

var _ quicbaas.KMSClient = (*platformMockKMSClient)(nil)

// =============================================================================
// Mock SDK Crypto Client
// =============================================================================

// platformMockCryptoClient implements crypto.Client with overridable functions.
type platformMockCryptoClient struct {
	encryptFn        func(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error)
	decryptFn        func(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error)
	signFn           func(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error)
	verifyFn         func(ctx context.Context, req *quicbaas.VerifyRequest) (*quicbaas.VerifyResponse, error)
	rewrapFn         func(ctx context.Context, req *quicbaas.RewrapRequest) (*quicbaas.RewrapResponse, error)
	encryptBatchFn   func(ctx context.Context, req *quicbaas.EncryptBatchRequest) (*quicbaas.EncryptBatchResponse, error)
	decryptBatchFn   func(ctx context.Context, req *quicbaas.DecryptBatchRequest) (*quicbaas.DecryptBatchResponse, error)
	generateHMACFn   func(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error)
	verifyHMACFn     func(ctx context.Context, req *quicbaas.VerifyHMACRequest) (*quicbaas.VerifyHMACResponse, error)
	generateRandomFn func(ctx context.Context, req *quicbaas.GenerateRandomRequest) (*quicbaas.GenerateRandomResponse, error)
	hashFn           func(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error)
}

func (m *platformMockCryptoClient) Encrypt(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
	if m.encryptFn != nil {
		return m.encryptFn(ctx, req)
	}
	return &quicbaas.EncryptResponse{Ciphertext: []byte("ciphertext"), KeyVersion: 1}, nil
}

func (m *platformMockCryptoClient) Decrypt(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
	if m.decryptFn != nil {
		return m.decryptFn(ctx, req)
	}
	return &quicbaas.DecryptResponse{Plaintext: []byte("plaintext")}, nil
}

func (m *platformMockCryptoClient) Sign(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
	if m.signFn != nil {
		return m.signFn(ctx, req)
	}
	return &quicbaas.SignResponse{Signature: []byte("signature"), KeyVersion: 1}, nil
}

func (m *platformMockCryptoClient) Verify(ctx context.Context, req *quicbaas.VerifyRequest) (*quicbaas.VerifyResponse, error) {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, req)
	}
	return &quicbaas.VerifyResponse{Valid: true}, nil
}

func (m *platformMockCryptoClient) Rewrap(ctx context.Context, req *quicbaas.RewrapRequest) (*quicbaas.RewrapResponse, error) {
	if m.rewrapFn != nil {
		return m.rewrapFn(ctx, req)
	}
	return &quicbaas.RewrapResponse{KeyID: req.KeyID, OldKeyVersion: 1, NewKeyVersion: 2, Ciphertext: []byte("rewrapped")}, nil
}

func (m *platformMockCryptoClient) EncryptBatch(ctx context.Context, req *quicbaas.EncryptBatchRequest) (*quicbaas.EncryptBatchResponse, error) {
	if m.encryptBatchFn != nil {
		return m.encryptBatchFn(ctx, req)
	}
	return &quicbaas.EncryptBatchResponse{KeyID: req.KeyID}, nil
}

func (m *platformMockCryptoClient) DecryptBatch(ctx context.Context, req *quicbaas.DecryptBatchRequest) (*quicbaas.DecryptBatchResponse, error) {
	if m.decryptBatchFn != nil {
		return m.decryptBatchFn(ctx, req)
	}
	return &quicbaas.DecryptBatchResponse{KeyID: req.KeyID}, nil
}

func (m *platformMockCryptoClient) GenerateDataKey(ctx context.Context, req *quicbaas.GenerateDataKeyRequest) (*quicbaas.GenerateDataKeyResponse, error) {
	return nil, errPlatformKMSTest
}

func (m *platformMockCryptoClient) GenerateWrappedDataKey(ctx context.Context, req *quicbaas.GenerateWrappedDataKeyRequest) (*quicbaas.GenerateWrappedDataKeyResponse, error) {
	return nil, errPlatformKMSTest
}

func (m *platformMockCryptoClient) GenerateHMAC(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error) {
	if m.generateHMACFn != nil {
		return m.generateHMACFn(ctx, req)
	}
	return &quicbaas.GenerateHMACResponse{KeyID: req.KeyID, KeyVersion: 1, HMAC: []byte("hmac"), HashAlg: req.HashAlg}, nil
}

func (m *platformMockCryptoClient) VerifyHMAC(ctx context.Context, req *quicbaas.VerifyHMACRequest) (*quicbaas.VerifyHMACResponse, error) {
	if m.verifyHMACFn != nil {
		return m.verifyHMACFn(ctx, req)
	}
	return &quicbaas.VerifyHMACResponse{Valid: true}, nil
}

func (m *platformMockCryptoClient) GenerateRandom(ctx context.Context, req *quicbaas.GenerateRandomRequest) (*quicbaas.GenerateRandomResponse, error) {
	if m.generateRandomFn != nil {
		return m.generateRandomFn(ctx, req)
	}
	return &quicbaas.GenerateRandomResponse{RandomBytes: make([]byte, req.NumBytes)}, nil
}

func (m *platformMockCryptoClient) Hash(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error) {
	if m.hashFn != nil {
		return m.hashFn(ctx, req)
	}
	return &quicbaas.HashResponse{HashAlg: req.HashAlg, Hash: []byte("digest")}, nil
}

var _ quicbaas.CryptoClient = (*platformMockCryptoClient)(nil)

// newTestPlatformKMSBackend creates a backend with both mock clients.
func newTestPlatformKMSBackend(kmsClient quicbaas.KMSClient, cryptoClient quicbaas.CryptoClient) *PlatformKMSBackend {
	return NewPlatformKMSBackend(kmsClient, cryptoClient, boostSlogLogger())
}

// =============================================================================
// Key Management Tests
// =============================================================================

func TestPlatformKMSBackendGenerateKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps request and response", func(t *testing.T) {
		t.Parallel()
		var got *kms.GenerateKeyRequest
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			generateKeyFn: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
				got = req
				return &kms.GenerateKeyResponse{
					KeyID:      "key-1",
					Version:    1,
					Algorithm:  req.Algorithm,
					Exportable: req.Exportable,
				}, nil
			},
			updateKeyMetadataFn: func(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
				return &kms.KeyMetadataResponse{
					KeyID:       req.KeyID,
					Description: req.Description,
					Algorithm:   kms.AlgorithmRSA2048,
					Version:     1,
					Exportable:  true,
					Tags:        req.Tags,
					Owner:       "kms-recorded-owner",
				}, nil
			},
		}, &platformMockCryptoClient{})

		resp, err := backend.GenerateKey(ctx, &grpcapi.KMSGenerateKeyRequest{
			KeySpec: &grpcapi.KMSKeySpec{
				Algorithm:  int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048),
				Usage:      []int32{int32(platformv1.KeyUsage_KEY_USAGE_SIGN), int32(platformv1.KeyUsage_KEY_USAGE_VERIFY)},
				Exportable: true,
			},
			Name:        "test-key",
			Description: "test description",
			Tags:        map[string]string{"env": "test"},
			Owner:       "tester",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Name != "test-key" {
			t.Errorf("expected name test-key, got %s", got.Name)
		}
		if got.Algorithm != kms.AlgorithmRSA2048 {
			t.Errorf("expected RSA2048, got %v", got.Algorithm)
		}
		if len(got.Usage) != 2 || got.Usage[0] != kms.KeyUsageSign || got.Usage[1] != kms.KeyUsageVerify {
			t.Errorf("unexpected usage: %v", got.Usage)
		}
		if !got.Exportable {
			t.Error("expected exportable to be threaded through")
		}
		if resp.Key.KeyID != "key-1" || resp.Key.Version != 1 {
			t.Errorf("unexpected key handle: %+v", resp.Key)
		}
		if resp.Key.Algorithm != int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048) {
			t.Errorf("unexpected algorithm: %d", resp.Key.Algorithm)
		}
		// The owner is the one the KMS recorded: the SDK cannot carry the
		// requested one.
		if resp.Metadata.Owner != "kms-recorded-owner" || resp.Metadata.Tags["env"] != "test" ||
			resp.Metadata.Description != "test description" || !resp.Metadata.Exportable {
			t.Errorf("unexpected metadata: %+v", resp.Metadata)
		}
	})

	t.Run("nil client returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(nil, &platformMockCryptoClient{})
		_, err := backend.GenerateKey(ctx, &grpcapi.KMSGenerateKeyRequest{KeySpec: &grpcapi.KMSKeySpec{}})
		if _, ok := err.(ErrKMSClientUnavailable); !ok {
			t.Fatalf("expected ErrKMSClientUnavailable, got %T: %v", err, err)
		}
	})

	t.Run("nil request returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{})
		_, err := backend.GenerateKey(ctx, nil)
		if _, ok := err.(ErrKMSMissingRequest); !ok {
			t.Fatalf("expected ErrKMSMissingRequest, got %T: %v", err, err)
		}
	})

	t.Run("nil key spec returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{})
		_, err := backend.GenerateKey(ctx, &grpcapi.KMSGenerateKeyRequest{Name: "k"})
		if _, ok := err.(ErrKMSMissingKeySpec); !ok {
			t.Fatalf("expected ErrKMSMissingKeySpec, got %T: %v", err, err)
		}
	})

	t.Run("unsupported algorithm returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{})
		_, err := backend.GenerateKey(ctx, &grpcapi.KMSGenerateKeyRequest{
			KeySpec: &grpcapi.KMSKeySpec{
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM2),
			},
		})
		if _, ok := err.(ErrKMSUnsupportedValue); !ok {
			t.Fatalf("expected ErrKMSUnsupportedValue, got %T: %v", err, err)
		}
	})

	t.Run("unsupported usage returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{})
		_, err := backend.GenerateKey(ctx, &grpcapi.KMSGenerateKeyRequest{
			KeySpec: &grpcapi.KMSKeySpec{
				Usage: []int32{int32(platformv1.KeyUsage_KEY_USAGE_DERIVE)},
			},
		})
		if _, ok := err.(ErrKMSUnsupportedValue); !ok {
			t.Fatalf("expected ErrKMSUnsupportedValue, got %T: %v", err, err)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			generateKeyFn: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
				return nil, errPlatformKMSTest
			},
		}, &platformMockCryptoClient{})
		_, err := backend.GenerateKey(ctx, &grpcapi.KMSGenerateKeyRequest{KeySpec: &grpcapi.KMSKeySpec{}})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendImportKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps request and response", func(t *testing.T) {
		t.Parallel()
		var got *kms.ImportKeyRequest
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			importKeyFn: func(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error) {
				got = req
				return &kms.ImportKeyResponse{KeyID: "imported-1", Version: 1, Algorithm: req.Algorithm}, nil
			},
		}, &platformMockCryptoClient{})

		resp, err := backend.ImportKey(ctx, &grpcapi.KMSImportKeyRequest{
			KeyMaterial:   []byte("material"),
			WrappingKeyID: "wrap-1",
			KeySpec: &grpcapi.KMSKeySpec{
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519),
				Usage:     []int32{int32(platformv1.KeyUsage_KEY_USAGE_SIGN)},
			},
			Name: "imported",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(got.KeyMaterial, []byte("material")) || got.WrappingKeyID != "wrap-1" {
			t.Errorf("unexpected sdk request: %+v", got)
		}
		if got.Algorithm != kms.AlgorithmED25519 {
			t.Errorf("expected ED25519, got %v", got.Algorithm)
		}
		if resp.Key.KeyID != "imported-1" {
			t.Errorf("unexpected key: %+v", resp.Key)
		}
		if resp.Key.Algorithm != int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519) {
			t.Errorf("unexpected algorithm: %d", resp.Key.Algorithm)
		}
	})

	t.Run("nil key spec returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{})
		_, err := backend.ImportKey(ctx, &grpcapi.KMSImportKeyRequest{KeyMaterial: []byte("m")})
		if _, ok := err.(ErrKMSMissingKeySpec); !ok {
			t.Fatalf("expected ErrKMSMissingKeySpec, got %T: %v", err, err)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			importKeyFn: func(ctx context.Context, req *kms.ImportKeyRequest) (*kms.ImportKeyResponse, error) {
				return nil, errPlatformKMSTest
			},
		}, &platformMockCryptoClient{})
		_, err := backend.ImportKey(ctx, &grpcapi.KMSImportKeyRequest{
			KeyMaterial: []byte("m"),
			KeySpec:     &grpcapi.KMSKeySpec{},
		})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendGetKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps full metadata", func(t *testing.T) {
		t.Parallel()
		created := time.Unix(1000, 0)
		updated := time.Unix(2000, 0)
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			getKeyMetadataFn: func(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
				return &kms.KeyMetadataResponse{
					KeyID:      keyID,
					Name:       "my-key",
					Algorithm:  kms.AlgorithmECDSAP384,
					Status:     kms.KeyStatusDisabled,
					Usage:      []kms.KeyUsage{kms.KeyUsageSign},
					Version:    3,
					Exportable: true,
					CreatedAt:  created,
					UpdatedAt:  updated,
					Tags:       map[string]string{"a": "b"},
					Owner:      "owner-1",
				}, nil
			},
		}, &platformMockCryptoClient{})

		resp, err := backend.GetKey(ctx, &grpcapi.KMSGetKeyRequest{KeyID: "key-1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Key.KeyID != "key-1" || resp.Key.Version != 3 {
			t.Errorf("unexpected handle: %+v", resp.Key)
		}
		if resp.Key.Algorithm != int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384) {
			t.Errorf("unexpected algorithm: %d", resp.Key.Algorithm)
		}
		if resp.Key.Status != int32(platformv1.KeyStatus_KEY_STATUS_DISABLED) {
			t.Errorf("unexpected status: %d", resp.Key.Status)
		}
		if resp.Metadata.CreatedAt != 1000 || resp.Metadata.UpdatedAt != 2000 {
			t.Errorf("unexpected timestamps: %+v", resp.Metadata)
		}
		if len(resp.Metadata.Usage) != 1 || resp.Metadata.Usage[0] != int32(platformv1.KeyUsage_KEY_USAGE_SIGN) {
			t.Errorf("unexpected usage: %v", resp.Metadata.Usage)
		}
		if resp.Metadata.Owner != "owner-1" || !resp.Metadata.Exportable {
			t.Errorf("unexpected metadata: %+v", resp.Metadata)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			getKeyMetadataFn: func(ctx context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
				return nil, errPlatformKMSTest
			},
		}, &platformMockCryptoClient{})
		_, err := backend.GetKey(ctx, &grpcapi.KMSGetKeyRequest{KeyID: "missing"})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendListKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fiveKeys := func(ctx context.Context) (*kms.ListKeysResponse, error) {
		keys := make([]kms.KeyInfo, 5)
		for i := range keys {
			keys[i] = kms.KeyInfo{
				KeyID:     "key-" + string(rune('a'+i)),
				Name:      "name-" + string(rune('a'+i)),
				Algorithm: kms.AlgorithmAES256GCM,
				Version:   1,
			}
		}
		return &kms.ListKeysResponse{Keys: keys}, nil
	}

	t.Run("success with limit paginates", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{listKeysFn: fiveKeys}, &platformMockCryptoClient{})
		resp, err := backend.ListKeys(ctx, &grpcapi.KMSListKeysRequest{Limit: 2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Keys) != 2 || !resp.HasMore || resp.NextCursor != "2" || resp.TotalCount != 5 {
			t.Errorf("unexpected pagination: keys=%d hasMore=%v cursor=%q total=%d",
				len(resp.Keys), resp.HasMore, resp.NextCursor, resp.TotalCount)
		}
	})

	t.Run("success with cursor resumes", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{listKeysFn: fiveKeys}, &platformMockCryptoClient{})
		resp, err := backend.ListKeys(ctx, &grpcapi.KMSListKeysRequest{Limit: 3, Cursor: "3"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Keys) != 2 || resp.HasMore || resp.NextCursor != "" {
			t.Errorf("unexpected resume page: keys=%d hasMore=%v cursor=%q", len(resp.Keys), resp.HasMore, resp.NextCursor)
		}
		if resp.Keys[0].KeyID != "key-d" {
			t.Errorf("unexpected first key: %s", resp.Keys[0].KeyID)
		}
	})

	t.Run("success with name filter", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{listKeysFn: fiveKeys}, &platformMockCryptoClient{})
		resp, err := backend.ListKeys(ctx, &grpcapi.KMSListKeysRequest{
			Filter: map[string]string{"name": "name-b"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Keys) != 1 || resp.Keys[0].KeyID != "key-b" {
			t.Errorf("unexpected filtered keys: %+v", resp.Keys)
		}
	})

	t.Run("invalid cursor returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{listKeysFn: fiveKeys}, &platformMockCryptoClient{})
		_, err := backend.ListKeys(ctx, &grpcapi.KMSListKeysRequest{Cursor: "not-a-number"})
		if _, ok := err.(ErrKMSInvalidCursor); !ok {
			t.Fatalf("expected ErrKMSInvalidCursor, got %T: %v", err, err)
		}
	})

	t.Run("unsupported filter returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{listKeysFn: fiveKeys}, &platformMockCryptoClient{})
		_, err := backend.ListKeys(ctx, &grpcapi.KMSListKeysRequest{
			Filter: map[string]string{"owner": "someone"},
		})
		if _, ok := err.(ErrKMSUnsupportedFilter); !ok {
			t.Fatalf("expected ErrKMSUnsupportedFilter, got %T: %v", err, err)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			listKeysFn: func(ctx context.Context) (*kms.ListKeysResponse, error) {
				return nil, errPlatformKMSTest
			},
		}, &platformMockCryptoClient{})
		_, err := backend.ListKeys(ctx, &grpcapi.KMSListKeysRequest{})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendDeleteKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success reports destroyed status", func(t *testing.T) {
		t.Parallel()
		var deleted string
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			deleteKeyFn: func(ctx context.Context, keyID string) error {
				deleted = keyID
				return nil
			},
		}, &platformMockCryptoClient{})
		resp, err := backend.DeleteKey(ctx, &grpcapi.KMSDeleteKeyRequest{KeyID: "key-1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if deleted != "key-1" {
			t.Errorf("expected delete of key-1, got %s", deleted)
		}
		if resp.Status != int32(platformv1.KeyStatus_KEY_STATUS_DESTROYED) {
			t.Errorf("expected destroyed status, got %d", resp.Status)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			deleteKeyFn: func(ctx context.Context, keyID string) error {
				return errPlatformKMSTest
			},
		}, &platformMockCryptoClient{})
		_, err := backend.DeleteKey(ctx, &grpcapi.KMSDeleteKeyRequest{KeyID: "key-1"})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendRotateKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success computes old version", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			rotateKeyFn: func(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
				return &kms.RotateKeyResponse{KeyID: keyID, NewVersion: 4}, nil
			},
		}, &platformMockCryptoClient{})
		resp, err := backend.RotateKey(ctx, &grpcapi.KMSRotateKeyRequest{KeyID: "key-1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.NewVersion != 4 || resp.OldVersion != 3 {
			t.Errorf("unexpected versions: old=%d new=%d", resp.OldVersion, resp.NewVersion)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			rotateKeyFn: func(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
				return nil, errPlatformKMSTest
			},
		}, &platformMockCryptoClient{})
		_, err := backend.RotateKey(ctx, &grpcapi.KMSRotateKeyRequest{KeyID: "key-1"})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendUpdateKeyStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps status both directions", func(t *testing.T) {
		t.Parallel()
		var got *kms.UpdateKeyStatusRequest
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			updateKeyStatusFn: func(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
				got = req
				return &kms.UpdateKeyStatusResponse{KeyID: req.KeyID, Version: req.Version, Status: req.Status}, nil
			},
		}, &platformMockCryptoClient{})
		resp, err := backend.UpdateKeyStatus(ctx, &grpcapi.KMSUpdateKeyStatusRequest{
			KeyID:   "key-1",
			Version: 2,
			Status:  int32(platformv1.KeyStatus_KEY_STATUS_DISABLED),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != kms.KeyStatusDisabled || got.Version != 2 {
			t.Errorf("unexpected sdk request: %+v", got)
		}
		if resp.Status != int32(platformv1.KeyStatus_KEY_STATUS_DISABLED) {
			t.Errorf("unexpected status: %d", resp.Status)
		}
	})

	t.Run("unsupported status returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{})
		_, err := backend.UpdateKeyStatus(ctx, &grpcapi.KMSUpdateKeyStatusRequest{
			KeyID:  "key-1",
			Status: int32(platformv1.KeyStatus_KEY_STATUS_PENDING_IMPORT),
		})
		if _, ok := err.(ErrKMSUnsupportedValue); !ok {
			t.Fatalf("expected ErrKMSUnsupportedValue, got %T: %v", err, err)
		}
	})
}

func TestPlatformKMSBackendExportKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps format and wrapping algorithm", func(t *testing.T) {
		t.Parallel()
		var got *kms.ExportKeyRequest
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			exportKeyFn: func(ctx context.Context, req *kms.ExportKeyRequest) (*kms.ExportKeyResponse, error) {
				got = req
				return &kms.ExportKeyResponse{
					KeyID:           req.KeyID,
					WrappingKeyID:   req.WrappingKeyID,
					WrappedMaterial: []byte("wrapped"),
					Version:         2,
				}, nil
			},
		}, &platformMockCryptoClient{})
		resp, err := backend.ExportKey(ctx, &grpcapi.KMSExportKeyRequest{
			KeyID:             "key-1",
			WrappingKeyID:     "wrap-1",
			WrappingAlgorithm: int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM),
			Format:            int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM),
			Version:           2,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.WrappingAlgorithm != kms.WrapAlgAESGCM || got.Format != kms.ExportFormatPEM {
			t.Errorf("unexpected sdk request: %+v", got)
		}
		if !bytes.Equal(resp.WrappedMaterial, []byte("wrapped")) || resp.Version != 2 {
			t.Errorf("unexpected response: %+v", resp)
		}
		if resp.Format != int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM) {
			t.Errorf("expected format echoed, got %d", resp.Format)
		}
	})

	t.Run("unsupported format returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{})
		_, err := backend.ExportKey(ctx, &grpcapi.KMSExportKeyRequest{
			KeyID:  "key-1",
			Format: int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PKCS8),
		})
		if _, ok := err.(ErrKMSUnsupportedValue); !ok {
			t.Fatalf("expected ErrKMSUnsupportedValue, got %T: %v", err, err)
		}
	})
}

func TestPlatformKMSBackendGetKeyVersions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps versions", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			listKeyVersionsFn: func(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error) {
				return &kms.ListKeyVersionsResponse{
					KeyID: keyID,
					Versions: []kms.KeyVersionInfo{
						{Version: 1, Status: kms.KeyStatusDisabled, Algorithm: kms.AlgorithmAES256GCM, CreatedAt: time.Unix(100, 0), DisabledAt: time.Unix(200, 0)},
						{Version: 2, Status: kms.KeyStatusEnabled, Algorithm: kms.AlgorithmAES256GCM, CreatedAt: time.Unix(150, 0)},
					},
				}, nil
			},
		}, &platformMockCryptoClient{})
		resp, err := backend.GetKeyVersions(ctx, &grpcapi.KMSGetKeyVersionsRequest{KeyID: "key-1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Versions) != 2 {
			t.Fatalf("expected 2 versions, got %d", len(resp.Versions))
		}
		if resp.Versions[0].Status != int32(platformv1.KeyStatus_KEY_STATUS_DISABLED) || resp.Versions[0].DisabledAt != 200 {
			t.Errorf("unexpected version 0: %+v", resp.Versions[0])
		}
		if resp.Versions[1].Status != int32(platformv1.KeyStatus_KEY_STATUS_ENABLED) || resp.Versions[1].DisabledAt != 0 {
			t.Errorf("unexpected version 1: %+v", resp.Versions[1])
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			listKeyVersionsFn: func(ctx context.Context, keyID string) (*kms.ListKeyVersionsResponse, error) {
				return nil, errPlatformKMSTest
			},
		}, &platformMockCryptoClient{})
		_, err := backend.GetKeyVersions(ctx, &grpcapi.KMSGetKeyVersionsRequest{KeyID: "key-1"})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

// =============================================================================
// Cryptographic Operation Tests
// =============================================================================

func TestPlatformKMSBackendEncryptDecrypt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("encrypt success", func(t *testing.T) {
		t.Parallel()
		var got *quicbaas.EncryptRequest
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			encryptFn: func(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
				got = req
				return &quicbaas.EncryptResponse{Ciphertext: []byte("ct"), KeyVersion: 5}, nil
			},
		})
		resp, err := backend.Encrypt(ctx, &grpcapi.KMSEncryptRequest{
			KeyID:     "key-1",
			Plaintext: []byte("pt"),
			Context:   []byte("aad"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.KeyID != "key-1" || !bytes.Equal(got.Plaintext, []byte("pt")) || !bytes.Equal(got.Context, []byte("aad")) {
			t.Errorf("unexpected sdk request: %+v", got)
		}
		if resp.KeyVersion != 5 || !bytes.Equal(resp.Ciphertext, []byte("ct")) {
			t.Errorf("unexpected response: %+v", resp)
		}
	})

	t.Run("encrypt nil client returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, nil)
		_, err := backend.Encrypt(ctx, &grpcapi.KMSEncryptRequest{KeyID: "key-1"})
		if _, ok := err.(ErrKMSClientUnavailable); !ok {
			t.Fatalf("expected ErrKMSClientUnavailable, got %T: %v", err, err)
		}
	})

	t.Run("decrypt success", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			decryptFn: func(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
				return &quicbaas.DecryptResponse{Plaintext: []byte("pt")}, nil
			},
		})
		resp, err := backend.Decrypt(ctx, &grpcapi.KMSDecryptRequest{KeyID: "key-1", Ciphertext: []byte("ct"), KeyVersion: 2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(resp.Plaintext, []byte("pt")) || resp.KeyVersion != 2 {
			t.Errorf("unexpected response: %+v", resp)
		}
	})

	t.Run("decrypt sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			decryptFn: func(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := backend.Decrypt(ctx, &grpcapi.KMSDecryptRequest{KeyID: "key-1", Ciphertext: []byte("ct")})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendBatchEncrypt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps per-item results", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			encryptBatchFn: func(ctx context.Context, req *quicbaas.EncryptBatchRequest) (*quicbaas.EncryptBatchResponse, error) {
				return &quicbaas.EncryptBatchResponse{
					KeyID:      req.KeyID,
					KeyVersion: 7,
					Results: []sdkcrypto.BatchEncryptResult{
						{Ciphertext: []byte("ct-1")},
						{Error: "encryption failed"},
					},
				}, nil
			},
		})
		resp, err := backend.BatchEncrypt(ctx, &grpcapi.KMSBatchEncryptRequest{
			KeyID: "key-1",
			Items: []*grpcapi.KMSBatchEncryptItem{
				{ItemID: "a", Plaintext: []byte("p1")},
				{ItemID: "b", Plaintext: []byte("p2")},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.SuccessCount != 1 || resp.FailureCount != 1 {
			t.Errorf("unexpected counts: %d/%d", resp.SuccessCount, resp.FailureCount)
		}
		if !resp.Results[0].Success || resp.Results[0].ItemID != "a" || resp.Results[0].KeyVersion != 7 {
			t.Errorf("unexpected result 0: %+v", resp.Results[0])
		}
		if resp.Results[1].Success || resp.Results[1].Message != "encryption failed" || resp.Results[1].ItemID != "b" {
			t.Errorf("unexpected result 1: %+v", resp.Results[1])
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			encryptBatchFn: func(ctx context.Context, req *quicbaas.EncryptBatchRequest) (*quicbaas.EncryptBatchResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := backend.BatchEncrypt(ctx, &grpcapi.KMSBatchEncryptRequest{
			KeyID: "key-1",
			Items: []*grpcapi.KMSBatchEncryptItem{{ItemID: "a"}},
		})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendBatchDecrypt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps per-item results", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			decryptBatchFn: func(ctx context.Context, req *quicbaas.DecryptBatchRequest) (*quicbaas.DecryptBatchResponse, error) {
				return &quicbaas.DecryptBatchResponse{
					KeyID: req.KeyID,
					Results: []sdkcrypto.BatchDecryptResult{
						{Plaintext: []byte("p1")},
						{Error: "decryption failed"},
					},
				}, nil
			},
		})
		resp, err := backend.BatchDecrypt(ctx, &grpcapi.KMSBatchDecryptRequest{
			KeyID: "key-1",
			Items: []*grpcapi.KMSBatchDecryptItem{
				{ItemID: "a", Ciphertext: []byte("c1"), KeyVersion: 3},
				{ItemID: "b", Ciphertext: []byte("c2")},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.SuccessCount != 1 || resp.FailureCount != 1 {
			t.Errorf("unexpected counts: %d/%d", resp.SuccessCount, resp.FailureCount)
		}
		if !resp.Results[0].Success || resp.Results[0].KeyVersion != 3 {
			t.Errorf("unexpected result 0: %+v", resp.Results[0])
		}
		if resp.Results[1].Success || resp.Results[1].Message != "decryption failed" {
			t.Errorf("unexpected result 1: %+v", resp.Results[1])
		}
	})

	t.Run("nil client returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, nil)
		_, err := backend.BatchDecrypt(ctx, &grpcapi.KMSBatchDecryptRequest{KeyID: "key-1"})
		if _, ok := err.(ErrKMSClientUnavailable); !ok {
			t.Fatalf("expected ErrKMSClientUnavailable, got %T: %v", err, err)
		}
	})
}

func TestPlatformKMSBackendRewrap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps versions", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			rewrapFn: func(ctx context.Context, req *quicbaas.RewrapRequest) (*quicbaas.RewrapResponse, error) {
				return &quicbaas.RewrapResponse{
					KeyID:         req.KeyID,
					OldKeyVersion: 1,
					NewKeyVersion: 3,
					Ciphertext:    []byte("new-ct"),
				}, nil
			},
		})
		resp, err := backend.Rewrap(ctx, &grpcapi.KMSRewrapRequest{KeyID: "key-1", Ciphertext: []byte("old-ct")})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.SourceVersion != 1 || resp.TargetVersion != 3 || !bytes.Equal(resp.Ciphertext, []byte("new-ct")) {
			t.Errorf("unexpected response: %+v", resp)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			rewrapFn: func(ctx context.Context, req *quicbaas.RewrapRequest) (*quicbaas.RewrapResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := backend.Rewrap(ctx, &grpcapi.KMSRewrapRequest{KeyID: "key-1", Ciphertext: []byte("ct")})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendSign(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success threads PreHashed and hash algorithm", func(t *testing.T) {
		t.Parallel()
		var got *quicbaas.SignRequest
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			signFn: func(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
				got = req
				return &quicbaas.SignResponse{Signature: []byte("sig"), KeyVersion: 2}, nil
			},
		})
		resp, err := backend.Sign(ctx, &grpcapi.KMSSignRequest{
			KeyID:         "key-1",
			Message:       []byte("digest"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384),
			PreHashed:     true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.PreHashed {
			t.Error("expected PreHashed to be threaded through to the SDK request")
		}
		if got.HashAlg != quicbaas.HashSHA384 {
			t.Errorf("expected SHA384, got %v", got.HashAlg)
		}
		if !bytes.Equal(got.Data, []byte("digest")) {
			t.Errorf("unexpected data: %s", got.Data)
		}
		if resp.KeyVersion != 2 || !bytes.Equal(resp.Signature, []byte("sig")) {
			t.Errorf("unexpected response: %+v", resp)
		}
		if resp.HashAlgorithm != int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384) {
			t.Errorf("unexpected hash algorithm: %d", resp.HashAlgorithm)
		}
	})

	t.Run("PreHashed false is preserved", func(t *testing.T) {
		t.Parallel()
		var got *quicbaas.SignRequest
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			signFn: func(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
				got = req
				return &quicbaas.SignResponse{Signature: []byte("sig"), KeyVersion: 1}, nil
			},
		})
		if _, err := backend.Sign(ctx, &grpcapi.KMSSignRequest{
			KeyID:         "key-1",
			Message:       []byte("msg"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256),
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.PreHashed {
			t.Error("expected PreHashed false")
		}
	})

	t.Run("unsupported hash returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{})
		_, err := backend.Sign(ctx, &grpcapi.KMSSignRequest{
			KeyID:         "key-1",
			Message:       []byte("msg"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA1),
		})
		if _, ok := err.(ErrKMSUnsupportedValue); !ok {
			t.Fatalf("expected ErrKMSUnsupportedValue, got %T: %v", err, err)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			signFn: func(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := backend.Sign(ctx, &grpcapi.KMSSignRequest{KeyID: "key-1", Message: []byte("msg")})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendVerify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success returns validity", func(t *testing.T) {
		t.Parallel()
		var got *quicbaas.VerifyRequest
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			verifyFn: func(ctx context.Context, req *quicbaas.VerifyRequest) (*quicbaas.VerifyResponse, error) {
				got = req
				return &quicbaas.VerifyResponse{Valid: true}, nil
			},
		})
		resp, err := backend.Verify(ctx, &grpcapi.KMSVerifyRequest{
			KeyID:         "key-1",
			Message:       []byte("msg"),
			Signature:     []byte("sig"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.HashAlg != quicbaas.HashSHA512 || !bytes.Equal(got.Signature, []byte("sig")) {
			t.Errorf("unexpected sdk request: %+v", got)
		}
		if !resp.Valid {
			t.Error("expected valid signature")
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			verifyFn: func(ctx context.Context, req *quicbaas.VerifyRequest) (*quicbaas.VerifyResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := backend.Verify(ctx, &grpcapi.KMSVerifyRequest{KeyID: "key-1", Message: []byte("m"), Signature: []byte("s")})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendHash(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps algorithm", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			hashFn: func(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error) {
				return &quicbaas.HashResponse{HashAlg: req.HashAlg, Hash: []byte("digest")}, nil
			},
		})
		resp, err := backend.Hash(ctx, &grpcapi.KMSHashRequest{
			Data:      []byte("data"),
			Algorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Algorithm != int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512) {
			t.Errorf("unexpected algorithm: %d", resp.Algorithm)
		}
		if !bytes.Equal(resp.Hash, []byte("digest")) {
			t.Errorf("unexpected hash: %s", resp.Hash)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			hashFn: func(ctx context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := backend.Hash(ctx, &grpcapi.KMSHashRequest{Data: []byte("data")})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendHMAC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps request and response", func(t *testing.T) {
		t.Parallel()
		var got *quicbaas.GenerateHMACRequest
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			generateHMACFn: func(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error) {
				got = req
				return &quicbaas.GenerateHMACResponse{KeyID: req.KeyID, KeyVersion: 4, HMAC: []byte("mac"), HashAlg: req.HashAlg}, nil
			},
		})
		resp, err := backend.HMAC(ctx, &grpcapi.KMSHMACRequest{
			KeyID:         "key-1",
			Message:       []byte("msg"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.HashAlg != quicbaas.HashSHA384 {
			t.Errorf("expected SHA384, got %v", got.HashAlg)
		}
		if resp.KeyVersion != 4 || !bytes.Equal(resp.HMAC, []byte("mac")) {
			t.Errorf("unexpected response: %+v", resp)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			generateHMACFn: func(ctx context.Context, req *quicbaas.GenerateHMACRequest) (*quicbaas.GenerateHMACResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := backend.HMAC(ctx, &grpcapi.KMSHMACRequest{KeyID: "key-1", Message: []byte("msg")})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendVerifyHMAC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success threads key version", func(t *testing.T) {
		t.Parallel()
		var got *quicbaas.VerifyHMACRequest
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			verifyHMACFn: func(ctx context.Context, req *quicbaas.VerifyHMACRequest) (*quicbaas.VerifyHMACResponse, error) {
				got = req
				return &quicbaas.VerifyHMACResponse{Valid: true}, nil
			},
		})
		resp, err := backend.VerifyHMAC(ctx, &grpcapi.KMSVerifyHMACRequest{
			KeyID:      "key-1",
			Message:    []byte("msg"),
			HMAC:       []byte("mac"),
			KeyVersion: 6,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.KeyVersion != 6 {
			t.Errorf("expected key version 6, got %d", got.KeyVersion)
		}
		if !resp.Valid || resp.KeyVersion != 6 {
			t.Errorf("unexpected response: %+v", resp)
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			verifyHMACFn: func(ctx context.Context, req *quicbaas.VerifyHMACRequest) (*quicbaas.VerifyHMACResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := backend.VerifyHMAC(ctx, &grpcapi.KMSVerifyHMACRequest{KeyID: "key-1", Message: []byte("m"), HMAC: []byte("h")})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendGenerateRandom(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success returns bytes", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			generateRandomFn: func(ctx context.Context, req *quicbaas.GenerateRandomRequest) (*quicbaas.GenerateRandomResponse, error) {
				return &quicbaas.GenerateRandomResponse{RandomBytes: make([]byte, req.NumBytes)}, nil
			},
		})
		resp, err := backend.GenerateRandom(ctx, &grpcapi.KMSGenerateRandomRequest{NumBytes: 16})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.RandomBytes) != 16 {
			t.Errorf("expected 16 bytes, got %d", len(resp.RandomBytes))
		}
	})

	t.Run("sdk error is propagated", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{
			generateRandomFn: func(ctx context.Context, req *quicbaas.GenerateRandomRequest) (*quicbaas.GenerateRandomResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := backend.GenerateRandom(ctx, &grpcapi.KMSGenerateRandomRequest{NumBytes: 16})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected sdk error, got %v", err)
		}
	})
}

func TestPlatformKMSBackendBackendStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps status fields", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(&platformMockKMSClient{
			backendStatusFn: func(ctx context.Context) (*kms.BackendStatusResponse, error) {
				return &kms.BackendStatusResponse{
					BackendType:  "tpm2",
					Status:       "healthy",
					Device:       "/dev/tpmrm0",
					PCRBanks:     []string{"sha256"},
					PCRRegisters: []int{0, 7},
					Capabilities: map[string]bool{"seal": true},
				}, nil
			},
		}, &platformMockCryptoClient{})
		resp, err := backend.BackendStatus(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.BackendType != "tpm2" || resp.Status != "healthy" || resp.Device != "/dev/tpmrm0" {
			t.Errorf("unexpected response: %+v", resp)
		}
		if len(resp.PcrRegisters) != 2 || resp.PcrRegisters[1] != 7 {
			t.Errorf("unexpected pcr registers: %v", resp.PcrRegisters)
		}
		if !resp.Capabilities["seal"] {
			t.Error("expected seal capability")
		}
	})

	t.Run("nil client returns typed error", func(t *testing.T) {
		t.Parallel()
		backend := newTestPlatformKMSBackend(nil, &platformMockCryptoClient{})
		_, err := backend.BackendStatus(ctx)
		if _, ok := err.(ErrKMSClientUnavailable); !ok {
			t.Fatalf("expected ErrKMSClientUnavailable, got %T: %v", err, err)
		}
	})
}

// =============================================================================
// Accessor Tests
// =============================================================================

func TestKMSServicePlatformKMSBackend(t *testing.T) {
	t.Parallel()

	t.Run("uninitialized quicbaas factory returns error", func(t *testing.T) {
		t.Parallel()
		svc := &KMSService{app: &app.App{}, logger: boostSlogLogger()}
		backend, err := svc.PlatformKMSBackend()
		if err == nil {
			t.Fatal("expected error for app without QuicBaaS factory")
		}
		if backend != nil {
			t.Error("expected nil backend on error")
		}
		if _, ok := err.(ErrInvalidConfig); !ok {
			t.Errorf("expected ErrInvalidConfig, got %T: %v", err, err)
		}
	})

	t.Run("constructor wires clients and logger", func(t *testing.T) {
		t.Parallel()
		kmsClient := &platformMockKMSClient{}
		cryptoClient := &platformMockCryptoClient{}
		backend := NewPlatformKMSBackend(kmsClient, cryptoClient, boostSlogLogger())
		if backend.kmsClient != quicbaas.KMSClient(kmsClient) {
			t.Error("expected kms client to be wired")
		}
		if backend.cryptoClient != quicbaas.CryptoClient(cryptoClient) {
			t.Error("expected crypto client to be wired")
		}
	})
}

// =============================================================================
// Conversion and Helper Tests
// =============================================================================

func TestPlatformKMSEnumConversions(t *testing.T) {
	t.Parallel()

	t.Run("algorithm round trip", func(t *testing.T) {
		t.Parallel()
		supported := []int32{
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256),
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305),
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048),
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096),
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256),
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384),
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519),
		}
		for _, alg := range supported {
			sdk, err := platformKMSAlgorithmToSDK(alg)
			if err != nil {
				t.Fatalf("algorithm %d: unexpected error: %v", alg, err)
			}
			if back := sdkAlgorithmToPlatformKMS(sdk); back != alg {
				t.Errorf("algorithm %d: round trip produced %d", alg, back)
			}
		}
	})

	t.Run("unspecified algorithm maps to sdk zero value", func(t *testing.T) {
		t.Parallel()
		sdk, err := platformKMSAlgorithmToSDK(int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sdk != kms.AlgorithmAES256GCM {
			t.Errorf("expected AES256GCM, got %v", sdk)
		}
	})

	t.Run("unsupported algorithm returns typed error", func(t *testing.T) {
		t.Parallel()
		for _, alg := range []int32{
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_3072),
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P521),
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM5),
			int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256),
		} {
			if _, err := platformKMSAlgorithmToSDK(alg); err == nil {
				t.Errorf("algorithm %d: expected error", alg)
			}
		}
	})

	t.Run("hash algorithm mappings", func(t *testing.T) {
		t.Parallel()
		sdk, err := platformKMSHashToSDK(int32(platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED))
		if err != nil || sdk != quicbaas.HashSHA256 {
			t.Errorf("unspecified: expected SHA256, got %v err=%v", sdk, err)
		}
		if _, err := platformKMSHashToSDK(int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA1)); err == nil {
			t.Error("SHA1: expected error")
		}
		if got := sdkHashToPlatformKMS(quicbaas.HashSHA512); got != int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512) {
			t.Errorf("SHA512 reverse: got %d", got)
		}
	})

	t.Run("status mappings", func(t *testing.T) {
		t.Parallel()
		if got := sdkStatusToPlatformKMS(kms.KeyStatusRotating); got != int32(platformv1.KeyStatus_KEY_STATUS_ENABLED) {
			t.Errorf("rotating: expected enabled, got %d", got)
		}
		if got := sdkStatusToPlatformKMS(kms.KeyStatusCompromised); got != int32(platformv1.KeyStatus_KEY_STATUS_DISABLED) {
			t.Errorf("compromised: expected disabled, got %d", got)
		}
		if _, err := platformKMSStatusToSDK(int32(platformv1.KeyStatus_KEY_STATUS_UNSPECIFIED)); err == nil {
			t.Error("unspecified status: expected error")
		}
		sdk, err := platformKMSStatusToSDK(int32(platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION))
		if err != nil || sdk != kms.KeyStatusPendingDeletion {
			t.Errorf("pending deletion: got %v err=%v", sdk, err)
		}
	})

	t.Run("wrapping algorithm mappings", func(t *testing.T) {
		t.Parallel()
		sdk, err := platformKMSWrappingToSDK(int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA512))
		if err != nil || sdk != kms.WrapAlgRSAOAEPSHA512 {
			t.Errorf("RSA-OAEP-SHA512: got %v err=%v", sdk, err)
		}
		sdk, err = platformKMSWrappingToSDK(int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_UNSPECIFIED))
		if err != nil || sdk != kms.WrapAlgAESKW {
			t.Errorf("unspecified: expected AESKW, got %v err=%v", sdk, err)
		}
		if _, err := platformKMSWrappingToSDK(99); err == nil {
			t.Error("unknown wrapping algorithm: expected error")
		}
	})

	t.Run("export format mappings", func(t *testing.T) {
		t.Parallel()
		sdk, err := platformKMSExportFormatToSDK(int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_JWK))
		if err != nil || sdk != kms.ExportFormatJWK {
			t.Errorf("JWK: got %v err=%v", sdk, err)
		}
		if _, err := platformKMSExportFormatToSDK(int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PKCS8)); err == nil {
			t.Error("PKCS8: expected error")
		}
	})

	t.Run("usage reverse mapping", func(t *testing.T) {
		t.Parallel()
		got := sdkUsagesToPlatformKMS([]kms.KeyUsage{kms.KeyUsageWrap, kms.KeyUsageUnwrap})
		if len(got) != 2 ||
			got[0] != int32(platformv1.KeyUsage_KEY_USAGE_WRAP) ||
			got[1] != int32(platformv1.KeyUsage_KEY_USAGE_UNWRAP) {
			t.Errorf("unexpected usages: %v", got)
		}
	})
}

func TestPaginateKMSOffset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		total     int
		limit     int32
		cursor    string
		wantStart int
		wantEnd   int
		wantNext  string
		wantMore  bool
		wantErr   bool
	}{
		{name: "no limit returns all", total: 5, limit: 0, wantStart: 0, wantEnd: 5},
		{name: "limit smaller than total", total: 5, limit: 2, wantStart: 0, wantEnd: 2, wantNext: "2", wantMore: true},
		{name: "cursor resumes", total: 5, limit: 2, cursor: "2", wantStart: 2, wantEnd: 4, wantNext: "4", wantMore: true},
		{name: "cursor at final page", total: 5, limit: 2, cursor: "4", wantStart: 4, wantEnd: 5},
		{name: "cursor beyond total clamps", total: 3, limit: 2, cursor: "10", wantStart: 3, wantEnd: 3},
		{name: "invalid cursor errors", total: 3, cursor: "bogus", wantErr: true},
		{name: "negative cursor errors", total: 3, cursor: "-1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			start, end, next, more, err := paginateKMSOffset(tt.total, tt.limit, tt.cursor)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if _, ok := err.(ErrKMSInvalidCursor); !ok {
					t.Fatalf("expected ErrKMSInvalidCursor, got %T", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if start != tt.wantStart || end != tt.wantEnd || next != tt.wantNext || more != tt.wantMore {
				t.Errorf("got start=%d end=%d next=%q more=%v", start, end, next, more)
			}
		})
	}
}

func TestFilterKeyInfos(t *testing.T) {
	t.Parallel()

	keys := []kms.KeyInfo{
		{KeyID: "k1", Name: "alpha", Algorithm: kms.AlgorithmRSA2048},
		{KeyID: "k2", Name: "beta", Algorithm: kms.AlgorithmAES256GCM},
	}

	t.Run("algorithm filter is case-insensitive", func(t *testing.T) {
		t.Parallel()
		result, err := filterKeyInfos(keys, map[string]string{"algorithm": "rsa-2048"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 1 || result[0].KeyID != "k1" {
			t.Errorf("unexpected result: %+v", result)
		}
	})

	t.Run("unsupported filter key errors", func(t *testing.T) {
		t.Parallel()
		_, err := filterKeyInfos(keys, map[string]string{"status": "enabled"})
		if _, ok := err.(ErrKMSUnsupportedFilter); !ok {
			t.Fatalf("expected ErrKMSUnsupportedFilter, got %T: %v", err, err)
		}
	})
}

// TestPlatformKMSBackendErrorClasses covers each typed backend error: it
// carries its own class, so every transport answers it the same way (#304).
func TestPlatformKMSBackendErrorClasses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"client unavailable", ErrKMSClientUnavailable{Client: "kms"}, codes.Unavailable},
		{"unsupported value", ErrKMSUnsupportedValue{Kind: "algorithm", Value: 9999}, codes.InvalidArgument},
		{"invalid cursor", ErrKMSInvalidCursor{Cursor: "x"}, codes.InvalidArgument},
		{"unsupported filter", ErrKMSUnsupportedFilter{Key: "status"}, codes.InvalidArgument},
		{"missing request", ErrKMSMissingRequest{Operation: "ListKeys"}, codes.InvalidArgument},
		{"missing key spec", ErrKMSMissingKeySpec{Operation: "GenerateKey"}, codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := status.Code(tt.err); got != tt.want {
				t.Errorf("status.Code(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestPlatformKMSBackendErrorClassesOverGRPC asks the platform.v1 gRPC
// service questions the backend refuses, and checks each answer's class.
func TestPlatformKMSBackendErrorClassesOverGRPC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rpc := grpcapi.NewKMSGRPCService(logging.DefaultLogger(),
		newTestPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{}))
	unwired := grpcapi.NewKMSGRPCService(logging.DefaultLogger(), newTestPlatformKMSBackend(nil, nil))

	t.Run("bad cursor is InvalidArgument", func(t *testing.T) {
		t.Parallel()
		_, err := rpc.ListKeys(ctx, &platformv1.ListKeysRequest{Cursor: "not-a-number"})
		if got := status.Code(err); got != codes.InvalidArgument {
			t.Errorf("ListKeys(bad cursor) = %v, want InvalidArgument: %v", got, err)
		}
	})

	t.Run("unsupported filter is InvalidArgument", func(t *testing.T) {
		t.Parallel()
		_, err := rpc.ListKeys(ctx, &platformv1.ListKeysRequest{Filter: map[string]string{"status": "enabled"}})
		if got := status.Code(err); got != codes.InvalidArgument {
			t.Errorf("ListKeys(bad filter) = %v, want InvalidArgument: %v", got, err)
		}
	})

	t.Run("unsupported algorithm is InvalidArgument", func(t *testing.T) {
		t.Parallel()
		_, err := rpc.GenerateKey(ctx, &platformv1.GenerateKeyRequest{
			KeySpec: &platformv1.KMSKeySpec{Algorithm: platformv1.KMSKeyAlgorithm(9999)},
		})
		if got := status.Code(err); got != codes.InvalidArgument {
			t.Errorf("GenerateKey(bad algorithm) = %v, want InvalidArgument: %v", got, err)
		}
	})

	t.Run("missing SDK client is Unavailable", func(t *testing.T) {
		t.Parallel()
		_, err := unwired.ListKeys(ctx, &platformv1.ListKeysRequest{})
		if got := status.Code(err); got != codes.Unavailable {
			t.Errorf("ListKeys(no client) = %v, want Unavailable: %v", got, err)
		}
	})
}
