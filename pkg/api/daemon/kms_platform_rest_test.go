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

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkcrypto "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newTestPlatformKMSRESTFacade creates a facade over a backend with the
// supplied mock clients.
func newTestPlatformKMSRESTFacade(kmsClient quicbaas.KMSClient, cryptoClient quicbaas.CryptoClient) *PlatformKMSRESTFacade {
	return NewPlatformKMSRESTFacade(newTestPlatformKMSBackend(kmsClient, cryptoClient))
}

func TestPlatformKMSRESTFacadeGenerateKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps rest request through backend", func(t *testing.T) {
		t.Parallel()
		var got *kms.GenerateKeyRequest
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{
			generateKeyFn: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
				got = req
				return &kms.GenerateKeyResponse{KeyID: "key-1", Version: 1, Algorithm: req.Algorithm}, nil
			},
			updateKeyMetadataFn: func(ctx context.Context, req *kms.UpdateKeyMetadataRequest) (*kms.KeyMetadataResponse, error) {
				return &kms.KeyMetadataResponse{
					KeyID:     req.KeyID,
					Algorithm: kms.AlgorithmECDSAP256,
					Version:   1,
					Tags:      req.Tags,
					Owner:     "kms-recorded-owner",
				}, nil
			},
		}, &platformMockCryptoClient{})

		resp, err := facade.GenerateKey(ctx, &restapi.KMSGenerateKeyServiceRequest{
			KeySpec: &restapi.KMSKeySpec{
				Algorithm: int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256),
				Usage:     []int32{int32(platformv1.KeyUsage_KEY_USAGE_SIGN)},
			},
			Name:  "rest-key",
			Owner: "rest-owner",
			Tags:  map[string]string{"proto": "rest"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Name != "rest-key" || got.Algorithm != kms.AlgorithmECDSAP256 {
			t.Errorf("unexpected sdk request: %+v", got)
		}
		if resp.Key.KeyID != "key-1" {
			t.Errorf("unexpected key: %+v", resp.Key)
		}
		if resp.Key.Algorithm != int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256) {
			t.Errorf("unexpected algorithm: %d", resp.Key.Algorithm)
		}
		if resp.Metadata.Owner != "kms-recorded-owner" || resp.Metadata.Tags["proto"] != "rest" {
			t.Errorf("unexpected metadata: %+v", resp.Metadata)
		}
	})

	t.Run("nil backend returns typed error", func(t *testing.T) {
		t.Parallel()
		facade := NewPlatformKMSRESTFacade(nil)
		_, err := facade.GenerateKey(ctx, &restapi.KMSGenerateKeyServiceRequest{})
		if _, ok := err.(restapi.ErrKMSServiceUnavailable); !ok {
			t.Fatalf("expected ErrKMSServiceUnavailable, got %T: %v", err, err)
		}
	})

	t.Run("nil request returns typed error", func(t *testing.T) {
		t.Parallel()
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{}, &platformMockCryptoClient{})
		_, err := facade.GenerateKey(ctx, nil)
		if _, ok := err.(ErrKMSMissingRequest); !ok {
			t.Fatalf("expected ErrKMSMissingRequest, got %T: %v", err, err)
		}
	})

	t.Run("backend error is propagated", func(t *testing.T) {
		t.Parallel()
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{
			generateKeyFn: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
				return nil, errPlatformKMSTest
			},
		}, &platformMockCryptoClient{})
		_, err := facade.GenerateKey(ctx, &restapi.KMSGenerateKeyServiceRequest{
			KeySpec: &restapi.KMSKeySpec{},
		})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected backend error, got %v", err)
		}
	})
}

func TestPlatformKMSRESTFacadeSign(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success threads PreHashed through backend to SDK", func(t *testing.T) {
		t.Parallel()
		var got *quicbaas.SignRequest
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{}, &platformMockCryptoClient{
			signFn: func(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
				got = req
				return &quicbaas.SignResponse{Signature: []byte("sig"), KeyVersion: 9}, nil
			},
		})
		resp, err := facade.Sign(ctx, &restapi.KMSSignServiceRequest{
			KeyID:         "key-1",
			Message:       []byte("digest"),
			HashAlgorithm: int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512),
			PreHashed:     true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.PreHashed {
			t.Error("expected PreHashed to be threaded through the REST facade")
		}
		if got.HashAlg != quicbaas.HashSHA512 {
			t.Errorf("expected SHA512, got %v", got.HashAlg)
		}
		if resp.KeyVersion != 9 || !bytes.Equal(resp.Signature, []byte("sig")) {
			t.Errorf("unexpected response: %+v", resp)
		}
		if resp.HashAlgorithm != int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512) {
			t.Errorf("unexpected hash algorithm: %d", resp.HashAlgorithm)
		}
	})

	t.Run("nil backend returns typed error", func(t *testing.T) {
		t.Parallel()
		facade := NewPlatformKMSRESTFacade(nil)
		_, err := facade.Sign(ctx, &restapi.KMSSignServiceRequest{KeyID: "key-1"})
		if _, ok := err.(restapi.ErrKMSServiceUnavailable); !ok {
			t.Fatalf("expected ErrKMSServiceUnavailable, got %T: %v", err, err)
		}
	})

	t.Run("backend error is propagated", func(t *testing.T) {
		t.Parallel()
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{}, &platformMockCryptoClient{
			signFn: func(ctx context.Context, req *quicbaas.SignRequest) (*quicbaas.SignResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := facade.Sign(ctx, &restapi.KMSSignServiceRequest{KeyID: "key-1", Message: []byte("m")})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected backend error, got %v", err)
		}
	})
}

func TestPlatformKMSRESTFacadeRewrap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("same key uses sdk rewrap", func(t *testing.T) {
		t.Parallel()
		var rewrapCalled bool
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{}, &platformMockCryptoClient{
			rewrapFn: func(ctx context.Context, req *quicbaas.RewrapRequest) (*quicbaas.RewrapResponse, error) {
				rewrapCalled = true
				return &quicbaas.RewrapResponse{
					KeyID:         req.KeyID,
					OldKeyVersion: 1,
					NewKeyVersion: 2,
					Ciphertext:    []byte("new-ct"),
				}, nil
			},
		})
		resp, err := facade.Rewrap(ctx, &restapi.KMSRewrapServiceRequest{
			SourceKeyID: "key-1",
			Ciphertext:  []byte("old-ct"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !rewrapCalled {
			t.Error("expected SDK rewrap to be used for same-key rewrap")
		}
		if resp.SourceKeyID != "key-1" || resp.DestinationKeyID != "key-1" {
			t.Errorf("unexpected key IDs: %+v", resp)
		}
		if resp.SourceKeyVersion != 1 || resp.DestKeyVersion != 2 {
			t.Errorf("unexpected versions: %+v", resp)
		}
	})

	t.Run("cross key decrypts then encrypts under destination", func(t *testing.T) {
		t.Parallel()
		var decryptKey, encryptKey string
		var encryptPlaintext []byte
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{}, &platformMockCryptoClient{
			decryptFn: func(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
				decryptKey = req.KeyID
				return &quicbaas.DecryptResponse{Plaintext: []byte("secret")}, nil
			},
			encryptFn: func(ctx context.Context, req *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
				encryptKey = req.KeyID
				encryptPlaintext = req.Plaintext
				return &quicbaas.EncryptResponse{Ciphertext: []byte("dest-ct"), KeyVersion: 5}, nil
			},
		})
		resp, err := facade.Rewrap(ctx, &restapi.KMSRewrapServiceRequest{
			SourceKeyID:      "key-src",
			DestinationKeyID: "key-dst",
			Ciphertext:       []byte("src-ct"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decryptKey != "key-src" || encryptKey != "key-dst" {
			t.Errorf("unexpected key routing: decrypt=%s encrypt=%s", decryptKey, encryptKey)
		}
		if !bytes.Equal(encryptPlaintext, []byte("secret")) {
			t.Error("expected decrypted plaintext to be re-encrypted")
		}
		if resp.DestKeyVersion != 5 || !bytes.Equal(resp.Ciphertext, []byte("dest-ct")) {
			t.Errorf("unexpected response: %+v", resp)
		}
	})

	t.Run("cross key decrypt error is propagated", func(t *testing.T) {
		t.Parallel()
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{}, &platformMockCryptoClient{
			decryptFn: func(ctx context.Context, req *quicbaas.DecryptRequest) (*quicbaas.DecryptResponse, error) {
				return nil, errPlatformKMSTest
			},
		})
		_, err := facade.Rewrap(ctx, &restapi.KMSRewrapServiceRequest{
			SourceKeyID:      "key-src",
			DestinationKeyID: "key-dst",
			Ciphertext:       []byte("ct"),
		})
		if !errors.Is(err, errPlatformKMSTest) {
			t.Fatalf("expected backend error, got %v", err)
		}
	})
}

func TestPlatformKMSRESTFacadeBatchEncrypt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success maps results and key version", func(t *testing.T) {
		t.Parallel()
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{}, &platformMockCryptoClient{
			encryptBatchFn: func(ctx context.Context, req *quicbaas.EncryptBatchRequest) (*quicbaas.EncryptBatchResponse, error) {
				return &quicbaas.EncryptBatchResponse{
					KeyID:      req.KeyID,
					KeyVersion: 3,
					Results: []sdkcrypto.BatchEncryptResult{
						{Ciphertext: []byte("ct-1")},
						{Error: "boom"},
					},
				}, nil
			},
		})
		resp, err := facade.BatchEncrypt(ctx, &restapi.KMSBatchEncryptServiceRequest{
			KeyID: "key-1",
			Items: []*restapi.KMSBatchEncryptItem{
				{ItemID: "a", Plaintext: []byte("p1")},
				{ItemID: "b", Plaintext: []byte("p2")},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.KeyVersion != 3 || resp.SuccessCount != 1 || resp.FailureCount != 1 {
			t.Errorf("unexpected response: %+v", resp)
		}
		if resp.Results[0].ItemID != "a" || resp.Results[1].ItemID != "b" {
			t.Errorf("item ids not carried through: %q, %q", resp.Results[0].ItemID, resp.Results[1].ItemID)
		}
		if !bytes.Equal(resp.Results[0].Ciphertext, []byte("ct-1")) || resp.Results[0].Error != "" {
			t.Errorf("unexpected result 0: %+v", resp.Results[0])
		}
		if resp.Results[1].Error != "boom" {
			t.Errorf("unexpected result 1: %+v", resp.Results[1])
		}
	})

	t.Run("nil backend returns typed error", func(t *testing.T) {
		t.Parallel()
		facade := NewPlatformKMSRESTFacade(nil)
		_, err := facade.BatchEncrypt(ctx, &restapi.KMSBatchEncryptServiceRequest{KeyID: "key-1"})
		if _, ok := err.(restapi.ErrKMSServiceUnavailable); !ok {
			t.Fatalf("expected ErrKMSServiceUnavailable, got %T: %v", err, err)
		}
	})
}

func TestPlatformKMSRESTFacadeKeyManagement(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("get list delete rotate update export versions succeed", func(t *testing.T) {
		t.Parallel()
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{
			listKeysFn: func(ctx context.Context) (*kms.ListKeysResponse, error) {
				return &kms.ListKeysResponse{Keys: []kms.KeyInfo{{KeyID: "k1", Version: 1}}}, nil
			},
		}, &platformMockCryptoClient{})

		if resp, err := facade.GetKey(ctx, &restapi.KMSGetKeyServiceRequest{KeyID: "k1"}); err != nil || resp.Key.KeyID != "k1" {
			t.Errorf("GetKey: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.ListKeys(ctx, &restapi.KMSListKeysServiceRequest{}); err != nil || len(resp.Keys) != 1 {
			t.Errorf("ListKeys: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.DeleteKey(ctx, &restapi.KMSDeleteKeyServiceRequest{KeyID: "k1"}); err != nil ||
			resp.Status != int32(platformv1.KeyStatus_KEY_STATUS_DESTROYED) {
			t.Errorf("DeleteKey: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.RotateKey(ctx, &restapi.KMSRotateKeyServiceRequest{KeyID: "k1"}); err != nil || resp.NewVersion != 2 {
			t.Errorf("RotateKey: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.UpdateKeyStatus(ctx, &restapi.KMSUpdateKeyStatusServiceRequest{
			KeyID:  "k1",
			Status: int32(platformv1.KeyStatus_KEY_STATUS_DISABLED),
		}); err != nil || resp.Status != int32(platformv1.KeyStatus_KEY_STATUS_DISABLED) {
			t.Errorf("UpdateKeyStatus: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.ExportKey(ctx, &restapi.KMSExportKeyServiceRequest{
			KeyID:         "k1",
			WrappingKeyID: "wrap-1",
		}); err != nil || !bytes.Equal(resp.WrappedMaterial, []byte("wrapped")) {
			t.Errorf("ExportKey: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.GetKeyVersions(ctx, &restapi.KMSGetKeyVersionsServiceRequest{KeyID: "k1"}); err != nil || resp.KeyID != "k1" {
			t.Errorf("GetKeyVersions: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.ImportKey(ctx, &restapi.KMSImportKeyServiceRequest{
			KeyMaterial: []byte("m"),
			KeySpec:     &restapi.KMSKeySpec{},
			Name:        "imp",
		}); err != nil || resp.Key.KeyID != "imported-1" {
			t.Errorf("ImportKey: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.BackendStatus(ctx); err != nil || resp.BackendType != "software" {
			t.Errorf("BackendStatus: resp=%+v err=%v", resp, err)
		}
	})

	t.Run("nil backend errors on every key management method", func(t *testing.T) {
		t.Parallel()
		facade := NewPlatformKMSRESTFacade(nil)
		assertUnavailable := func(name string, err error) {
			if _, ok := err.(restapi.ErrKMSServiceUnavailable); !ok {
				t.Errorf("%s: expected ErrKMSServiceUnavailable, got %T: %v", name, err, err)
			}
		}
		_, err := facade.GetKey(ctx, &restapi.KMSGetKeyServiceRequest{KeyID: "k"})
		assertUnavailable("GetKey", err)
		_, err = facade.ListKeys(ctx, &restapi.KMSListKeysServiceRequest{})
		assertUnavailable("ListKeys", err)
		_, err = facade.DeleteKey(ctx, &restapi.KMSDeleteKeyServiceRequest{KeyID: "k"})
		assertUnavailable("DeleteKey", err)
		_, err = facade.RotateKey(ctx, &restapi.KMSRotateKeyServiceRequest{KeyID: "k"})
		assertUnavailable("RotateKey", err)
		_, err = facade.UpdateKeyStatus(ctx, &restapi.KMSUpdateKeyStatusServiceRequest{KeyID: "k"})
		assertUnavailable("UpdateKeyStatus", err)
		_, err = facade.ExportKey(ctx, &restapi.KMSExportKeyServiceRequest{KeyID: "k"})
		assertUnavailable("ExportKey", err)
		_, err = facade.GetKeyVersions(ctx, &restapi.KMSGetKeyVersionsServiceRequest{KeyID: "k"})
		assertUnavailable("GetKeyVersions", err)
		_, err = facade.ImportKey(ctx, &restapi.KMSImportKeyServiceRequest{})
		assertUnavailable("ImportKey", err)
		_, err = facade.BackendStatus(ctx)
		assertUnavailable("BackendStatus", err)
	})
}

func TestPlatformKMSRESTFacadeCrypto(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("encrypt decrypt verify random hash hmac succeed", func(t *testing.T) {
		t.Parallel()
		facade := newTestPlatformKMSRESTFacade(&platformMockKMSClient{}, &platformMockCryptoClient{})

		if resp, err := facade.Encrypt(ctx, &restapi.KMSEncryptServiceRequest{
			KeyID:     "k1",
			Plaintext: []byte("pt"),
		}); err != nil || !bytes.Equal(resp.Ciphertext, []byte("ciphertext")) {
			t.Errorf("Encrypt: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.Decrypt(ctx, &restapi.KMSDecryptServiceRequest{
			KeyID:      "k1",
			Ciphertext: []byte("ct"),
		}); err != nil || !bytes.Equal(resp.Plaintext, []byte("plaintext")) {
			t.Errorf("Decrypt: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.Verify(ctx, &restapi.KMSVerifyServiceRequest{
			KeyID:     "k1",
			Message:   []byte("m"),
			Signature: []byte("s"),
		}); err != nil || !resp.Valid {
			t.Errorf("Verify: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.GenerateRandom(ctx, &restapi.KMSGenerateRandomServiceRequest{
			NumBytes: 8,
		}); err != nil || len(resp.RandomBytes) != 8 {
			t.Errorf("GenerateRandom: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.Hash(ctx, &restapi.KMSHashServiceRequest{
			Data: []byte("data"),
		}); err != nil || !bytes.Equal(resp.Hash, []byte("digest")) {
			t.Errorf("Hash: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.HMAC(ctx, &restapi.KMSHMACServiceRequest{
			KeyID:   "k1",
			Message: []byte("m"),
		}); err != nil || !bytes.Equal(resp.HMAC, []byte("hmac")) {
			t.Errorf("HMAC: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.VerifyHMAC(ctx, &restapi.KMSVerifyHMACServiceRequest{
			KeyID:   "k1",
			Message: []byte("m"),
			HMAC:    []byte("h"),
		}); err != nil || !resp.Valid {
			t.Errorf("VerifyHMAC: resp=%+v err=%v", resp, err)
		}
		if resp, err := facade.BatchDecrypt(ctx, &restapi.KMSBatchDecryptServiceRequest{
			KeyID: "k1",
			Items: []*restapi.KMSBatchDecryptItem{{Ciphertext: []byte("c")}},
		}); err != nil || resp.KeyID != "k1" {
			t.Errorf("BatchDecrypt: resp=%+v err=%v", resp, err)
		}
	})

	t.Run("nil backend errors on every crypto method", func(t *testing.T) {
		t.Parallel()
		facade := NewPlatformKMSRESTFacade(nil)
		assertUnavailable := func(name string, err error) {
			if _, ok := err.(restapi.ErrKMSServiceUnavailable); !ok {
				t.Errorf("%s: expected ErrKMSServiceUnavailable, got %T: %v", name, err, err)
			}
		}
		_, err := facade.Encrypt(ctx, &restapi.KMSEncryptServiceRequest{KeyID: "k"})
		assertUnavailable("Encrypt", err)
		_, err = facade.Decrypt(ctx, &restapi.KMSDecryptServiceRequest{KeyID: "k"})
		assertUnavailable("Decrypt", err)
		_, err = facade.Verify(ctx, &restapi.KMSVerifyServiceRequest{KeyID: "k"})
		assertUnavailable("Verify", err)
		_, err = facade.GenerateRandom(ctx, &restapi.KMSGenerateRandomServiceRequest{NumBytes: 8})
		assertUnavailable("GenerateRandom", err)
		_, err = facade.Hash(ctx, &restapi.KMSHashServiceRequest{Data: []byte("d")})
		assertUnavailable("Hash", err)
		_, err = facade.HMAC(ctx, &restapi.KMSHMACServiceRequest{KeyID: "k"})
		assertUnavailable("HMAC", err)
		_, err = facade.VerifyHMAC(ctx, &restapi.KMSVerifyHMACServiceRequest{KeyID: "k"})
		assertUnavailable("VerifyHMAC", err)
		_, err = facade.BatchDecrypt(ctx, &restapi.KMSBatchDecryptServiceRequest{KeyID: "k"})
		assertUnavailable("BatchDecrypt", err)
		_, err = facade.Rewrap(ctx, &restapi.KMSRewrapServiceRequest{SourceKeyID: "k"})
		assertUnavailable("Rewrap", err)
	})
}
