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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	quicbaascrypto "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock Crypto Client
// =============================================================================

type mockSDKCryptoClient struct {
	signFunc    func(ctx context.Context, req *quicbaascrypto.SignRequest) (*quicbaascrypto.SignResponse, error)
	decryptFunc func(ctx context.Context, req *quicbaascrypto.DecryptRequest) (*quicbaascrypto.DecryptResponse, error)
	encryptFunc func(ctx context.Context, req *quicbaascrypto.EncryptRequest) (*quicbaascrypto.EncryptResponse, error)
	verifyFunc  func(ctx context.Context, req *quicbaascrypto.VerifyRequest) (*quicbaascrypto.VerifyResponse, error)
}

func (m *mockSDKCryptoClient) Sign(ctx context.Context, req *quicbaascrypto.SignRequest) (*quicbaascrypto.SignResponse, error) {
	if m.signFunc != nil {
		return m.signFunc(ctx, req)
	}
	return nil, errors.New("sign not implemented")
}

func (m *mockSDKCryptoClient) Decrypt(ctx context.Context, req *quicbaascrypto.DecryptRequest) (*quicbaascrypto.DecryptResponse, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(ctx, req)
	}
	return nil, errors.New("decrypt not implemented")
}

func (m *mockSDKCryptoClient) Encrypt(ctx context.Context, req *quicbaascrypto.EncryptRequest) (*quicbaascrypto.EncryptResponse, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(ctx, req)
	}
	return nil, errors.New("encrypt not implemented")
}

func (m *mockSDKCryptoClient) Verify(ctx context.Context, req *quicbaascrypto.VerifyRequest) (*quicbaascrypto.VerifyResponse, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(ctx, req)
	}
	return nil, errors.New("verify not implemented")
}

func (m *mockSDKCryptoClient) Rewrap(ctx context.Context, req *quicbaascrypto.RewrapRequest) (*quicbaascrypto.RewrapResponse, error) {
	return nil, errors.New("rewrap not implemented")
}

func (m *mockSDKCryptoClient) EncryptBatch(ctx context.Context, req *quicbaascrypto.EncryptBatchRequest) (*quicbaascrypto.EncryptBatchResponse, error) {
	return nil, errors.New("encryptBatch not implemented")
}

func (m *mockSDKCryptoClient) DecryptBatch(ctx context.Context, req *quicbaascrypto.DecryptBatchRequest) (*quicbaascrypto.DecryptBatchResponse, error) {
	return nil, errors.New("decryptBatch not implemented")
}

func (m *mockSDKCryptoClient) GenerateDataKey(ctx context.Context, req *quicbaascrypto.GenerateDataKeyRequest) (*quicbaascrypto.GenerateDataKeyResponse, error) {
	return nil, errors.New("generateDataKey not implemented")
}

func (m *mockSDKCryptoClient) GenerateWrappedDataKey(ctx context.Context, req *quicbaascrypto.GenerateWrappedDataKeyRequest) (*quicbaascrypto.GenerateWrappedDataKeyResponse, error) {
	return nil, errors.New("generateWrappedDataKey not implemented")
}

func (m *mockSDKCryptoClient) GenerateHMAC(ctx context.Context, req *quicbaascrypto.GenerateHMACRequest) (*quicbaascrypto.GenerateHMACResponse, error) {
	return nil, errors.New("generateHMAC not implemented")
}

func (m *mockSDKCryptoClient) VerifyHMAC(ctx context.Context, req *quicbaascrypto.VerifyHMACRequest) (*quicbaascrypto.VerifyHMACResponse, error) {
	return nil, errors.New("verifyHMAC not implemented")
}

func (m *mockSDKCryptoClient) GenerateRandom(ctx context.Context, req *quicbaascrypto.GenerateRandomRequest) (*quicbaascrypto.GenerateRandomResponse, error) {
	return nil, errors.New("generateRandom not implemented")
}

func (m *mockSDKCryptoClient) Hash(ctx context.Context, req *quicbaascrypto.HashRequest) (*quicbaascrypto.HashResponse, error) {
	return nil, errors.New("hash not implemented")
}

// =============================================================================
// Mock CertStore
// =============================================================================

type mockCertStore struct {
	storeCertFunc  func(cert *x509.Certificate) error
	getCertFunc    func(cn string) (*x509.Certificate, error)
	deleteCertFunc func(cn string) error
	listCertsFunc  func() ([]*x509.Certificate, error)
	storeChainFunc func(chain []*x509.Certificate) error
	getChainFunc   func(cn string) ([]*x509.Certificate, error)
	storeCRLFunc   func(crl *x509.RevocationList) error
	getCRLFunc     func(issuer string) (*x509.RevocationList, error)
	verifyCertFunc func(cert *x509.Certificate, roots *x509.CertPool) error
	isRevokedFunc  func(cert *x509.Certificate) (bool, error)
	closeFunc      func() error
}

func (m *mockCertStore) StoreCertificate(cert *x509.Certificate) error {
	if m.storeCertFunc != nil {
		return m.storeCertFunc(cert)
	}
	return nil
}

func (m *mockCertStore) GetCertificate(cn string) (*x509.Certificate, error) {
	if m.getCertFunc != nil {
		return m.getCertFunc(cn)
	}
	return nil, errors.New("certificate not found")
}

func (m *mockCertStore) DeleteCertificate(cn string) error {
	if m.deleteCertFunc != nil {
		return m.deleteCertFunc(cn)
	}
	return nil
}

func (m *mockCertStore) ListCertificates() ([]*x509.Certificate, error) {
	if m.listCertsFunc != nil {
		return m.listCertsFunc()
	}
	return nil, nil
}

func (m *mockCertStore) StoreCertificateChain(chain []*x509.Certificate) error {
	if m.storeChainFunc != nil {
		return m.storeChainFunc(chain)
	}
	return nil
}

func (m *mockCertStore) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	if m.getChainFunc != nil {
		return m.getChainFunc(cn)
	}
	return nil, errors.New("chain not found")
}

func (m *mockCertStore) StoreCRL(crl *x509.RevocationList) error {
	if m.storeCRLFunc != nil {
		return m.storeCRLFunc(crl)
	}
	return nil
}

func (m *mockCertStore) GetCRL(issuer string) (*x509.RevocationList, error) {
	if m.getCRLFunc != nil {
		return m.getCRLFunc(issuer)
	}
	return nil, errors.New("CRL not found")
}

func (m *mockCertStore) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	if m.verifyCertFunc != nil {
		return m.verifyCertFunc(cert, roots)
	}
	return nil
}

func (m *mockCertStore) IsRevoked(cert *x509.Certificate) (bool, error) {
	if m.isRevokedFunc != nil {
		return m.isRevokedFunc(cert)
	}
	return false, nil
}

func (m *mockCertStore) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func testGenerateECDSAKey(t *testing.T) (*ecdsa.PrivateKey, error) {
	t.Helper()
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func testGenerateRSAKey(t *testing.T) (*rsa.PrivateKey, error) {
	t.Helper()
	return rsa.GenerateKey(rand.Reader, 2048)
}

func testGenerateEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	t.Helper()
	return ed25519.GenerateKey(rand.Reader)
}

// =============================================================================
// NewQuicBaaSKeyStore Tests
// =============================================================================

func TestNewQuicBaaSKeyStore(t *testing.T) {
	t.Run("creates keystore with valid config", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{}
		mockCrypto := &mockSDKCryptoClient{}
		mockCerts := &mockCertStore{}

		ks, err := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       mockKMS,
			Crypto:    mockCrypto,
			CertStore: mockCerts,
			Prefix:    "ca.root.",
		})

		require.NoError(t, err)
		require.NotNil(t, ks)
		assert.Equal(t, mockKMS, ks.kms)
		assert.Equal(t, mockCrypto, ks.crypto)
		assert.Equal(t, mockCerts, ks.certStore)
		assert.Equal(t, "ca.root.", ks.prefix)
	})

	t.Run("nil config returns error", func(t *testing.T) {
		ks, err := NewQuicBaaSKeyStore(nil)

		require.Error(t, err)
		assert.Nil(t, ks)

		var inputErr ErrInvalidInput
		assert.True(t, errors.As(err, &inputErr))
		assert.Equal(t, "config", inputErr.Field)
	})

	t.Run("nil KMS returns error", func(t *testing.T) {
		mockCrypto := &mockSDKCryptoClient{}

		ks, err := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    nil,
			Crypto: mockCrypto,
		})

		require.Error(t, err)
		assert.Nil(t, ks)

		var inputErr ErrInvalidInput
		assert.True(t, errors.As(err, &inputErr))
		assert.Equal(t, "kms", inputErr.Field)
	})

	t.Run("nil Crypto returns error", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{}

		ks, err := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: nil,
		})

		require.Error(t, err)
		assert.Nil(t, ks)

		var inputErr ErrInvalidInput
		assert.True(t, errors.As(err, &inputErr))
		assert.Equal(t, "crypto", inputErr.Field)
	})

	t.Run("nil CertStore is allowed", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{}
		mockCrypto := &mockSDKCryptoClient{}

		ks, err := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       mockKMS,
			Crypto:    mockCrypto,
			CertStore: nil,
		})

		require.NoError(t, err)
		require.NotNil(t, ks)
		assert.Nil(t, ks.certStore)
	})
}

// =============================================================================
// GenerateRSA Tests
// =============================================================================

func TestQuicBaaSKeyStore_GenerateRSA(t *testing.T) {
	t.Run("generates RSA 2048 key", func(t *testing.T) {
		// Generate a test RSA key for the public key response
		rsaKey, err := testGenerateRSAKey(t)
		require.NoError(t, err)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		require.NoError(t, err)

		mockKMS := &mockSDKKMSClient{
			generateKeyFunc: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
				assert.Equal(t, "ca.root.test-key", req.Name)
				assert.Equal(t, kms.AlgorithmRSA2048, req.Algorithm)
				assert.Contains(t, req.Usage, kms.KeyUsageSign)
				return &kms.GenerateKeyResponse{
					KeyID:     "key-123",
					Algorithm: kms.AlgorithmRSA2048,
					Version:   1,
				}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmRSA2048,
				}, nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
			Prefix: "ca.root.",
		})

		key, err := ks.GenerateRSA(&xkmssdk.KeyAttributes{
			CN: "test-key",
		})

		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("generates RSA 4096 key", func(t *testing.T) {
		// Generate a test RSA key for the public key response
		rsaKey, err := testGenerateRSAKey(t)
		require.NoError(t, err)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		require.NoError(t, err)

		mockKMS := &mockSDKKMSClient{
			generateKeyFunc: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
				assert.Equal(t, kms.AlgorithmRSA4096, req.Algorithm)
				return &kms.GenerateKeyResponse{
					KeyID:     "key-456",
					Algorithm: kms.AlgorithmRSA4096,
					Version:   1,
				}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmRSA4096,
				}, nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
			Prefix: "ca.root.",
		})

		key, err := ks.GenerateRSA(&xkmssdk.KeyAttributes{
			CN: "test-key",
			RSAAttributes: &xkmssdk.RSAAttributes{
				KeySize: 4096,
			},
		})

		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("nil attrs returns error", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.GenerateRSA(nil)

		require.Error(t, err)
		assert.Nil(t, key)

		var inputErr ErrInvalidInput
		assert.True(t, errors.As(err, &inputErr))
	})

	t.Run("KMS error is propagated", func(t *testing.T) {
		kmsError := errors.New("key generation failed")
		mockKMS := &mockSDKKMSClient{
			generateKeyFunc: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
				return nil, kmsError
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.GenerateRSA(&xkmssdk.KeyAttributes{CN: "test"})

		require.Error(t, err)
		assert.Nil(t, key)

		var opErr ErrOperationFailed
		assert.True(t, errors.As(err, &opErr))
		assert.Equal(t, "GenerateRSA", opErr.Operation)
	})
}

// =============================================================================
// GenerateECDSA Tests
// =============================================================================

func TestQuicBaaSKeyStore_GenerateECDSA(t *testing.T) {
	t.Run("generates ECDSA P-256 key", func(t *testing.T) {
		// Generate a test ECDSA key for the public key response
		ecdsaKey, err := testGenerateECDSAKey(t)
		require.NoError(t, err)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
		require.NoError(t, err)

		mockKMS := &mockSDKKMSClient{
			generateKeyFunc: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
				assert.Equal(t, kms.AlgorithmECDSAP256, req.Algorithm)
				return &kms.GenerateKeyResponse{
					KeyID:     "ecdsa-key",
					Algorithm: kms.AlgorithmECDSAP256,
					Version:   1,
				}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmECDSAP256,
				}, nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.GenerateECDSA(&xkmssdk.KeyAttributes{CN: "ecdsa-test"})

		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("nil attrs returns error", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.GenerateECDSA(nil)

		require.Error(t, err)
		assert.Nil(t, key)
	})
}

// =============================================================================
// GenerateEd25519 Tests
// =============================================================================

func TestQuicBaaSKeyStore_GenerateEd25519(t *testing.T) {
	t.Run("generates Ed25519 key", func(t *testing.T) {
		// Generate a test Ed25519 key for the public key response
		ed25519PubKey, _, err := testGenerateEd25519Key(t)
		require.NoError(t, err)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(ed25519PubKey)
		require.NoError(t, err)

		mockKMS := &mockSDKKMSClient{
			generateKeyFunc: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
				assert.Equal(t, kms.AlgorithmED25519, req.Algorithm)
				return &kms.GenerateKeyResponse{
					KeyID:     "ed25519-key",
					Algorithm: kms.AlgorithmED25519,
					Version:   1,
				}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmED25519,
				}, nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.GenerateEd25519(&xkmssdk.KeyAttributes{CN: "ed25519-test"})

		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("nil attrs returns error", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.GenerateEd25519(nil)

		require.Error(t, err)
		assert.Nil(t, key)
	})
}

// =============================================================================
// GetKey Tests
// =============================================================================

func TestQuicBaaSKeyStore_GetKey(t *testing.T) {
	t.Run("gets existing key", func(t *testing.T) {
		// Generate a test RSA key for the public key response
		rsaKey, err := testGenerateRSAKey(t)
		require.NoError(t, err)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		require.NoError(t, err)

		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				assert.Equal(t, "ca.root.existing-key", keyID)
				return &kms.KeyInfo{
					KeyID:     keyID,
					Name:      "existing-key",
					Algorithm: kms.AlgorithmRSA2048,
					Version:   1,
				}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmRSA2048,
				}, nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
			Prefix: "ca.root.",
		})

		key, err := ks.GetKey(&xkmssdk.KeyAttributes{CN: "existing-key"})

		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("key not found", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				return nil, errors.New("key not found")
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.GetKey(&xkmssdk.KeyAttributes{CN: "nonexistent"})

		require.Error(t, err)
		assert.Nil(t, key)

		var notFoundErr ErrKeyNotFound
		assert.True(t, errors.As(err, &notFoundErr))
	})

	t.Run("nil attrs returns error", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.GetKey(nil)

		require.Error(t, err)
		assert.Nil(t, key)
	})
}

// =============================================================================
// GetKeyByID Tests
// =============================================================================

func TestQuicBaaSKeyStore_GetKeyByID(t *testing.T) {
	t.Run("gets key by ID", func(t *testing.T) {
		// Generate a test ECDSA key for the public key response
		ecdsaKey, err := testGenerateECDSAKey(t)
		require.NoError(t, err)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
		require.NoError(t, err)

		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				return &kms.KeyInfo{KeyID: keyID}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmECDSAP256,
				}, nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.GetKeyByID("my-key")

		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("empty key ID returns error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		key, err := ks.GetKeyByID("")

		require.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("applies prefix when not present", func(t *testing.T) {
		// Generate a test ECDSA key for the public key response
		ecdsaKey, err := testGenerateECDSAKey(t)
		require.NoError(t, err)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
		require.NoError(t, err)

		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				assert.Equal(t, "ca.root.my-key", keyID)
				return &kms.KeyInfo{KeyID: keyID}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmECDSAP256,
				}, nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: &mockSDKCryptoClient{},
			Prefix: "ca.root.",
		})

		key, err := ks.GetKeyByID("my-key")

		require.NoError(t, err)
		require.NotNil(t, key)
	})
}

// =============================================================================
// GetSignerByID Tests
// =============================================================================

func TestQuicBaaSKeyStore_GetSignerByID(t *testing.T) {
	t.Run("gets signer by ID", func(t *testing.T) {
		// Generate a test ECDSA key for the public key response
		ecdsaKey, err := testGenerateECDSAKey(t)
		require.NoError(t, err)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
		require.NoError(t, err)

		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				return &kms.KeyInfo{KeyID: keyID}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmECDSAP256,
				}, nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: &mockSDKCryptoClient{},
		})

		signer, err := ks.GetSignerByID("signing-key")

		require.NoError(t, err)
		require.NotNil(t, signer)
	})

	t.Run("empty key ID returns error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		signer, err := ks.GetSignerByID("")

		require.Error(t, err)
		assert.Nil(t, signer)
	})
}

// =============================================================================
// GetDecrypterByID Tests
// =============================================================================

func TestQuicBaaSKeyStore_GetDecrypterByID(t *testing.T) {
	t.Run("gets decrypter by ID", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				return &kms.KeyInfo{KeyID: keyID}, nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: &mockSDKCryptoClient{},
		})

		decrypter, err := ks.GetDecrypterByID("decrypt-key")

		require.NoError(t, err)
		require.NotNil(t, decrypter)
	})

	t.Run("empty key ID returns error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		decrypter, err := ks.GetDecrypterByID("")

		require.Error(t, err)
		assert.Nil(t, decrypter)
	})
}

// =============================================================================
// DeleteKey Tests
// =============================================================================

func TestQuicBaaSKeyStore_DeleteKey(t *testing.T) {
	t.Run("deletes key successfully", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{
			deleteKeyFunc: func(ctx context.Context, keyID string) error {
				assert.Equal(t, "test-key", keyID)
				return nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		err := ks.DeleteKey(&xkmssdk.KeyAttributes{CN: "test-key"})

		require.NoError(t, err)
	})

	t.Run("nil attrs returns error", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		err := ks.DeleteKey(nil)

		require.Error(t, err)
	})
}

// =============================================================================
// ListKeys Tests
// =============================================================================

func TestQuicBaaSKeyStore_ListKeys(t *testing.T) {
	t.Run("lists keys successfully", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{
			listKeysFunc: func(ctx context.Context) (*kms.ListKeysResponse, error) {
				return &kms.ListKeysResponse{
					Keys: []kms.KeyInfo{
						{KeyID: "key-1", Algorithm: kms.AlgorithmRSA2048},
						{KeyID: "key-2", Algorithm: kms.AlgorithmECDSAP256},
					},
				}, nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		keys, err := ks.ListKeys()

		require.NoError(t, err)
		assert.Len(t, keys, 2)
		assert.Equal(t, "key-1", keys[0].CN)
		assert.Equal(t, x509.RSA, keys[0].KeyAlgorithm)
		assert.Equal(t, "key-2", keys[1].CN)
		assert.Equal(t, x509.ECDSA, keys[1].KeyAlgorithm)
	})

	t.Run("strips prefix from key IDs", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{
			listKeysFunc: func(ctx context.Context) (*kms.ListKeysResponse, error) {
				return &kms.ListKeysResponse{
					Keys: []kms.KeyInfo{
						{KeyID: "ca.root.key-1", Algorithm: kms.AlgorithmRSA2048},
					},
				}, nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: &mockSDKCryptoClient{},
			Prefix: "ca.root.",
		})

		keys, err := ks.ListKeys()

		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Equal(t, "key-1", keys[0].CN)
	})

	t.Run("KMS error is propagated", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{
			listKeysFunc: func(ctx context.Context) (*kms.ListKeysResponse, error) {
				return nil, errors.New("list failed")
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		keys, err := ks.ListKeys()

		require.Error(t, err)
		assert.Nil(t, keys)
	})
}

// =============================================================================
// ListCerts Tests
// =============================================================================

func TestQuicBaaSKeyStore_ListCerts(t *testing.T) {
	t.Run("lists certificate IDs successfully", func(t *testing.T) {
		mockCerts := &mockCertStore{
			listCertsFunc: func() ([]*x509.Certificate, error) {
				return []*x509.Certificate{
					createTestCertificate(t, "cert-1"),
					createTestCertificate(t, "cert-2"),
				}, nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       &mockSDKKMSClient{},
			Crypto:    &mockSDKCryptoClient{},
			CertStore: mockCerts,
		})

		ids, err := ks.ListCerts()

		require.NoError(t, err)
		assert.Len(t, ids, 2)
		assert.Equal(t, "cert-1", ids[0])
		assert.Equal(t, "cert-2", ids[1])
	})

	t.Run("nil certstore returns error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		ids, err := ks.ListCerts()

		require.Error(t, err)
		assert.Nil(t, ids)
	})
}

// =============================================================================
// CertExists Tests
// =============================================================================

func TestQuicBaaSKeyStore_CertExists(t *testing.T) {
	t.Run("returns true when cert exists", func(t *testing.T) {
		mockCerts := &mockCertStore{
			getCertFunc: func(cn string) (*x509.Certificate, error) {
				return createTestCertificate(t, cn), nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       &mockSDKKMSClient{},
			Crypto:    &mockSDKCryptoClient{},
			CertStore: mockCerts,
		})

		exists, err := ks.CertExists("test-cert")

		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false when cert not found", func(t *testing.T) {
		mockCerts := &mockCertStore{
			getCertFunc: func(cn string) (*x509.Certificate, error) {
				return nil, errors.New("not found")
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       &mockSDKKMSClient{},
			Crypto:    &mockSDKCryptoClient{},
			CertStore: mockCerts,
		})

		exists, err := ks.CertExists("nonexistent")

		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("nil certstore returns error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		exists, err := ks.CertExists("test-cert")

		require.Error(t, err)
		assert.False(t, exists)
	})
}

// =============================================================================
// RotateKey Tests
// =============================================================================

func TestQuicBaaSKeyStore_RotateKey(t *testing.T) {
	t.Run("rotates key successfully", func(t *testing.T) {
		// Generate a test ECDSA key for the public key response
		ecdsaKey, err := testGenerateECDSAKey(t)
		require.NoError(t, err)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
		require.NoError(t, err)

		mockKMS := &mockSDKKMSClient{
			rotateKeyFunc: func(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
				assert.Equal(t, "rotate-key", keyID)
				return &kms.RotateKeyResponse{
					KeyID:      keyID,
					NewVersion: 2,
				}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmECDSAP256,
				}, nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.RotateKey(&xkmssdk.KeyAttributes{CN: "rotate-key"})

		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("nil attrs returns error", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		key, err := ks.RotateKey(nil)

		require.Error(t, err)
		assert.Nil(t, key)
	})
}

// =============================================================================
// Signer Tests
// =============================================================================

func TestQuicBaaSKeyStore_Signer(t *testing.T) {
	t.Run("returns signer for existing key", func(t *testing.T) {
		// Generate a test ECDSA key pair
		privKey, _ := testGenerateECDSAKey(t)
		pubKeyDER, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)

		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				return &kms.KeyInfo{KeyID: keyID, Algorithm: kms.AlgorithmECDSAP256}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmECDSAP256,
				}, nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		signer, err := ks.Signer(&xkmssdk.KeyAttributes{CN: "signing-key"})

		require.NoError(t, err)
		require.NotNil(t, signer)
	})

	t.Run("key not found returns error", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				return nil, errors.New("not found")
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		signer, err := ks.Signer(&xkmssdk.KeyAttributes{CN: "nonexistent"})

		require.Error(t, err)
		assert.Nil(t, signer)
	})
}

// =============================================================================
// Decrypter Tests
// =============================================================================

func TestQuicBaaSKeyStore_Decrypter(t *testing.T) {
	t.Run("returns decrypter for existing key", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				return &kms.KeyInfo{KeyID: keyID}, nil
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		decrypter, err := ks.Decrypter(&xkmssdk.KeyAttributes{CN: "encryption-key"})

		require.NoError(t, err)
		require.NotNil(t, decrypter)
	})

	t.Run("key not found returns error", func(t *testing.T) {
		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				return nil, errors.New("not found")
			},
		}
		mockCrypto := &mockSDKCryptoClient{}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    mockKMS,
			Crypto: mockCrypto,
		})

		decrypter, err := ks.Decrypter(&xkmssdk.KeyAttributes{CN: "nonexistent"})

		require.Error(t, err)
		assert.Nil(t, decrypter)
	})
}

// =============================================================================
// Certificate Operations Tests
// =============================================================================

func TestQuicBaaSKeyStore_SaveCert(t *testing.T) {
	t.Run("saves certificate successfully", func(t *testing.T) {
		mockCerts := &mockCertStore{
			storeCertFunc: func(cert *x509.Certificate) error {
				return nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       &mockSDKKMSClient{},
			Crypto:    &mockSDKCryptoClient{},
			CertStore: mockCerts,
		})

		cert := createTestCertificate(t, "test-cert")
		err := ks.SaveCert("test-cert", cert)

		require.NoError(t, err)
	})

	t.Run("nil certstore returns error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       &mockSDKKMSClient{},
			Crypto:    &mockSDKCryptoClient{},
			CertStore: nil,
		})

		err := ks.SaveCert("test-cert", nil)

		require.Error(t, err)

		var inputErr ErrInvalidInput
		assert.True(t, errors.As(err, &inputErr))
	})
}

func TestQuicBaaSKeyStore_GetCert(t *testing.T) {
	t.Run("gets certificate successfully", func(t *testing.T) {
		testCert := createTestCertificate(t, "test-cert")
		mockCerts := &mockCertStore{
			getCertFunc: func(cn string) (*x509.Certificate, error) {
				assert.Equal(t, "test-cert", cn)
				return testCert, nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       &mockSDKKMSClient{},
			Crypto:    &mockSDKCryptoClient{},
			CertStore: mockCerts,
		})

		cert, err := ks.GetCert("test-cert")

		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.Equal(t, testCert, cert)
	})

	t.Run("nil certstore returns error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       &mockSDKKMSClient{},
			Crypto:    &mockSDKCryptoClient{},
			CertStore: nil,
		})

		cert, err := ks.GetCert("test-cert")

		require.Error(t, err)
		assert.Nil(t, cert)
	})
}

func TestQuicBaaSKeyStore_DeleteCert(t *testing.T) {
	t.Run("deletes certificate successfully", func(t *testing.T) {
		mockCerts := &mockCertStore{
			deleteCertFunc: func(cn string) error {
				assert.Equal(t, "test-cert", cn)
				return nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       &mockSDKKMSClient{},
			Crypto:    &mockSDKCryptoClient{},
			CertStore: mockCerts,
		})

		err := ks.DeleteCert("test-cert")

		require.NoError(t, err)
	})
}

func TestQuicBaaSKeyStore_SaveCertChain(t *testing.T) {
	t.Run("saves chain successfully", func(t *testing.T) {
		mockCerts := &mockCertStore{
			storeChainFunc: func(chain []*x509.Certificate) error {
				assert.Len(t, chain, 2)
				return nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       &mockSDKKMSClient{},
			Crypto:    &mockSDKCryptoClient{},
			CertStore: mockCerts,
		})

		chain := []*x509.Certificate{
			createTestCertificate(t, "leaf"),
			createTestCertificate(t, "root"),
		}
		err := ks.SaveCertChain("leaf", chain)

		require.NoError(t, err)
	})
}

func TestQuicBaaSKeyStore_GetCertChain(t *testing.T) {
	t.Run("gets chain successfully", func(t *testing.T) {
		expectedChain := []*x509.Certificate{
			createTestCertificate(t, "leaf"),
			createTestCertificate(t, "root"),
		}
		mockCerts := &mockCertStore{
			getChainFunc: func(cn string) ([]*x509.Certificate, error) {
				return expectedChain, nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       &mockSDKKMSClient{},
			Crypto:    &mockSDKCryptoClient{},
			CertStore: mockCerts,
		})

		chain, err := ks.GetCertChain("leaf")

		require.NoError(t, err)
		assert.Len(t, chain, 2)
	})
}

// =============================================================================
// GetTLSCertificate Tests
// =============================================================================

func TestQuicBaaSKeyStore_GetTLSCertificate(t *testing.T) {
	t.Run("returns TLS certificate successfully", func(t *testing.T) {
		cert := createTestCertificate(t, "tls-cert")

		// Generate a test ECDSA key for the public key response
		privKey, err := testGenerateECDSAKey(t)
		require.NoError(t, err)
		pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		require.NoError(t, err)

		mockKMS := &mockSDKKMSClient{
			getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
				return &kms.KeyInfo{KeyID: keyID}, nil
			},
			getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
				return &kms.GetPublicKeyResponse{
					KeyID:     keyID,
					PublicKey: pubKeyDER,
					Algorithm: kms.AlgorithmECDSAP256,
				}, nil
			},
		}
		mockCerts := &mockCertStore{
			getChainFunc: func(cn string) ([]*x509.Certificate, error) {
				return []*x509.Certificate{cert}, nil
			},
		}

		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:       mockKMS,
			Crypto:    &mockSDKCryptoClient{},
			CertStore: mockCerts,
		})

		tlsCert, err := ks.GetTLSCertificate("tls-cert", &xkmssdk.KeyAttributes{CN: "tls-cert"})

		require.NoError(t, err)
		require.NotNil(t, tlsCert.PrivateKey)
		require.NotNil(t, tlsCert.Leaf)
		assert.Len(t, tlsCert.Certificate, 1)
	})

	t.Run("empty keyID returns error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		_, err := ks.GetTLSCertificate("", &xkmssdk.KeyAttributes{CN: "test"})

		require.Error(t, err)
	})

	t.Run("nil attrs returns error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		_, err := ks.GetTLSCertificate("test", nil)

		require.Error(t, err)
	})
}

// =============================================================================
// quicbaasSigner Tests
// =============================================================================

func TestQuicBaaSSigner_Sign(t *testing.T) {
	t.Run("signs data successfully", func(t *testing.T) {
		expectedSignature := []byte("test-signature")
		mockCrypto := &mockSDKCryptoClient{
			signFunc: func(ctx context.Context, req *quicbaascrypto.SignRequest) (*quicbaascrypto.SignResponse, error) {
				assert.Equal(t, "test-key", req.KeyID)
				assert.Equal(t, []byte("test-digest"), req.Data)
				return &quicbaascrypto.SignResponse{
					Signature: expectedSignature,
				}, nil
			},
		}

		signer := &quicbaasSigner{
			keyID:  "test-key",
			kms:    &mockSDKKMSClient{},
			crypto: mockCrypto,
		}

		signature, err := signer.Sign(rand.Reader, []byte("test-digest"), crypto.SHA256)

		require.NoError(t, err)
		assert.Equal(t, expectedSignature, signature)
	})

	t.Run("signing error is propagated", func(t *testing.T) {
		mockCrypto := &mockSDKCryptoClient{
			signFunc: func(ctx context.Context, req *quicbaascrypto.SignRequest) (*quicbaascrypto.SignResponse, error) {
				return nil, errors.New("signing failed")
			},
		}

		signer := &quicbaasSigner{
			keyID:  "test-key",
			kms:    &mockSDKKMSClient{},
			crypto: mockCrypto,
		}

		signature, err := signer.Sign(rand.Reader, []byte("test-digest"), crypto.SHA256)

		require.Error(t, err)
		assert.Nil(t, signature)
	})
}

func TestQuicBaaSSigner_Public(t *testing.T) {
	t.Run("returns cached public key", func(t *testing.T) {
		signer := &quicbaasSigner{
			keyID:     "test-key",
			publicKey: nil, // No public key cached
		}

		pubKey := signer.Public()
		assert.Nil(t, pubKey)
	})
}

// =============================================================================
// quicbaasDecrypter Tests
// =============================================================================

func TestQuicBaaSDecrypter_Decrypt(t *testing.T) {
	t.Run("decrypts data successfully", func(t *testing.T) {
		expectedPlaintext := []byte("decrypted-data")
		mockCrypto := &mockSDKCryptoClient{
			decryptFunc: func(ctx context.Context, req *quicbaascrypto.DecryptRequest) (*quicbaascrypto.DecryptResponse, error) {
				assert.Equal(t, "test-key", req.KeyID)
				assert.Equal(t, []byte("ciphertext"), req.Ciphertext)
				return &quicbaascrypto.DecryptResponse{
					Plaintext: expectedPlaintext,
				}, nil
			},
		}

		decrypter := &quicbaasDecrypter{
			keyID:  "test-key",
			kms:    &mockSDKKMSClient{},
			crypto: mockCrypto,
		}

		plaintext, err := decrypter.Decrypt(rand.Reader, []byte("ciphertext"), nil)

		require.NoError(t, err)
		assert.Equal(t, expectedPlaintext, plaintext)
	})

	t.Run("decryption error is propagated", func(t *testing.T) {
		mockCrypto := &mockSDKCryptoClient{
			decryptFunc: func(ctx context.Context, req *quicbaascrypto.DecryptRequest) (*quicbaascrypto.DecryptResponse, error) {
				return nil, errors.New("decryption failed")
			},
		}

		decrypter := &quicbaasDecrypter{
			keyID:  "test-key",
			crypto: mockCrypto,
		}

		plaintext, err := decrypter.Decrypt(rand.Reader, []byte("ciphertext"), nil)

		require.Error(t, err)
		assert.Nil(t, plaintext)
	})
}

// =============================================================================
// Seal/Unseal Tests
// =============================================================================

func TestQuicBaaSKeyStore_Seal(t *testing.T) {
	t.Run("seal returns not supported error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		data, err := ks.Seal(context.Background(), []byte("data"), nil)

		require.Error(t, err)
		assert.Nil(t, data)
		assert.Contains(t, err.Error(), "sealing")
	})
}

func TestQuicBaaSKeyStore_Unseal(t *testing.T) {
	t.Run("unseal returns not supported error", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		data, err := ks.Unseal(context.Background(), nil, nil)

		require.Error(t, err)
		assert.Nil(t, data)
		assert.Contains(t, err.Error(), "unsealing")
	})
}

func TestQuicBaaSKeyStore_CanSeal(t *testing.T) {
	t.Run("returns false", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		assert.False(t, ks.CanSeal())
	})
}

// =============================================================================
// KeyProvider/CertStorage Tests
// =============================================================================

func TestQuicBaaSKeyStore_KeyProvider(t *testing.T) {
	t.Run("returns nil", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		backend := ks.KeyProvider()
		assert.Nil(t, backend)
	})
}

func TestQuicBaaSKeyStore_CertStorage(t *testing.T) {
	t.Run("returns nil", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		storage := ks.CertStorage()
		assert.Nil(t, storage)
	})
}

func TestQuicBaaSKeyStore_Close(t *testing.T) {
	t.Run("returns nil", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		err := ks.Close()
		require.NoError(t, err)
	})
}

// =============================================================================
// KeyID Tests
// =============================================================================

func TestQuicBaaSKeyStore_KeyID(t *testing.T) {
	t.Run("RSA algorithm uses rsa suffix", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
			Prefix: "ca.root-ca.example.com.",
		})

		attrs := &xkmssdk.KeyAttributes{
			CN:           "root-ca.example.com", // CN should not be duplicated
			KeyAlgorithm: x509.RSA,
		}
		keyID := ks.KeyID(attrs)
		// Key ID should use algorithm, not CN to avoid duplication
		assert.Equal(t, "ca.root-ca.example.com.rsa", keyID)
	})

	t.Run("ECDSA algorithm uses ecdsa suffix", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
			Prefix: "ca.intermediate.",
		})

		attrs := &xkmssdk.KeyAttributes{
			CN:           "intermediate",
			KeyAlgorithm: x509.ECDSA,
		}
		keyID := ks.KeyID(attrs)
		assert.Equal(t, "ca.intermediate.ecdsa", keyID)
	})

	t.Run("Ed25519 algorithm uses ed25519 suffix", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
			Prefix: "ca.signing.",
		})

		attrs := &xkmssdk.KeyAttributes{
			CN:           "signing",
			KeyAlgorithm: x509.Ed25519,
		}
		keyID := ks.KeyID(attrs)
		assert.Equal(t, "ca.signing.ed25519", keyID)
	})

	t.Run("unknown algorithm falls back to CN", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
			Prefix: "ca.root.",
		})

		// When algorithm is not set (default 0), fallback to CN
		keyID := ks.KeyID(&xkmssdk.KeyAttributes{CN: "my-key"})
		assert.Equal(t, "ca.root.my-key", keyID)
	})

	t.Run("unknown algorithm without CN uses key suffix", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
			Prefix: "test.",
		})

		// When neither algorithm nor CN is set, fallback to "key"
		keyID := ks.KeyID(&xkmssdk.KeyAttributes{})
		assert.Equal(t, "test.key", keyID)
	})
}

func TestQuicBaaSKeyStore_ParseKeyID(t *testing.T) {
	t.Run("parses key ID to attributes", func(t *testing.T) {
		ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
			KMS:    &mockSDKKMSClient{},
			Crypto: &mockSDKCryptoClient{},
		})

		attrs, err := ks.ParseKeyID("my-key-id")

		require.NoError(t, err)
		require.NotNil(t, attrs)
		assert.Equal(t, "my-key-id", attrs.CN)
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

func createTestCertificate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	return template
}

// =============================================================================
// Additional coverage tests
// =============================================================================

func TestQuicBaaSDecrypter_Public(t *testing.T) {
	t.Run("returns cached public key", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		d := &quicbaasDecrypter{
			keyID:     "test-key",
			publicKey: &key.PublicKey,
		}

		pub := d.Public()
		require.NotNil(t, pub)
		rsaPub, ok := pub.(*rsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, &key.PublicKey, rsaPub)
	})

	t.Run("returns nil when no public key cached", func(t *testing.T) {
		d := &quicbaasDecrypter{
			keyID: "test-key",
		}

		pub := d.Public()
		assert.Nil(t, pub)
	})
}

func TestQuicBaaSKeyStore_DeleteCert_NilCertStore(t *testing.T) {
	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    &mockSDKKMSClient{},
		Crypto: &mockSDKCryptoClient{},
	})

	err := ks.DeleteCert("test-cert")
	require.Error(t, err)
	assert.IsType(t, ErrInvalidInput{}, err)
}

func TestQuicBaaSKeyStore_SaveCertChain_NilCertStore(t *testing.T) {
	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    &mockSDKKMSClient{},
		Crypto: &mockSDKCryptoClient{},
	})

	err := ks.SaveCertChain("test-key", []*x509.Certificate{createTestCertificate(t, "test")})
	require.Error(t, err)
	assert.IsType(t, ErrInvalidInput{}, err)
}

func TestQuicBaaSKeyStore_GetCertChain_NilCertStore(t *testing.T) {
	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    &mockSDKKMSClient{},
		Crypto: &mockSDKCryptoClient{},
	})

	chain, err := ks.GetCertChain("test-key")
	require.Error(t, err)
	assert.Nil(t, chain)
	assert.IsType(t, ErrInvalidInput{}, err)
}

func TestQuicBaaSKeyStore_sdkAlgorithmToX509_Unknown(t *testing.T) {
	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    &mockSDKKMSClient{},
		Crypto: &mockSDKCryptoClient{},
	})

	result := ks.sdkAlgorithmToX509(kms.KeyAlgorithm(999))
	assert.Equal(t, x509.UnknownPublicKeyAlgorithm, result)
}

func TestQuicBaaSKeyStore_getPublicKey_NilResponse(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
			return nil, nil
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    mockKMS,
		Crypto: &mockSDKCryptoClient{},
	})

	key, err := ks.getPublicKey(context.Background(), "test-key")
	require.Error(t, err)
	assert.Nil(t, key)
}

func TestQuicBaaSKeyStore_getPublicKey_EmptyPublicKey(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
			return &kms.GetPublicKeyResponse{PublicKey: nil}, nil
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    mockKMS,
		Crypto: &mockSDKCryptoClient{},
	})

	key, err := ks.getPublicKey(context.Background(), "test-key")
	require.Error(t, err)
	assert.Nil(t, key)
}

func TestQuicBaaSKeyStore_getPublicKey_InvalidDER(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
			return &kms.GetPublicKeyResponse{PublicKey: []byte("not-valid-der")}, nil
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    mockKMS,
		Crypto: &mockSDKCryptoClient{},
	})

	key, err := ks.getPublicKey(context.Background(), "test-key")
	require.Error(t, err)
	assert.Nil(t, key)
}

func TestQuicBaaSKeyStore_GenerateECDSA_NilAttrs(t *testing.T) {
	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    &mockSDKKMSClient{},
		Crypto: &mockSDKCryptoClient{},
	})

	key, err := ks.GenerateECDSA(nil)
	require.Error(t, err)
	assert.Nil(t, key)
	assert.IsType(t, ErrInvalidInput{}, err)
}

func TestQuicBaaSKeyStore_GenerateEd25519_NilAttrs(t *testing.T) {
	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    &mockSDKKMSClient{},
		Crypto: &mockSDKCryptoClient{},
	})

	key, err := ks.GenerateEd25519(nil)
	require.Error(t, err)
	assert.Nil(t, key)
	assert.IsType(t, ErrInvalidInput{}, err)
}

func TestQuicBaaSKeyStore_GetSignerByID_GetKeyError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
			return nil, errors.New("kms unavailable")
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    mockKMS,
		Crypto: &mockSDKCryptoClient{},
	})

	signer, err := ks.GetSignerByID("signing-key")
	require.Error(t, err)
	assert.Nil(t, signer)
	assert.IsType(t, ErrKeyNotFound{}, err)
}

func TestQuicBaaSKeyStore_GetSignerByID_GetPublicKeyError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
			return &kms.KeyInfo{KeyID: keyID}, nil
		},
		getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
			return nil, errors.New("public key error")
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    mockKMS,
		Crypto: &mockSDKCryptoClient{},
	})

	signer, err := ks.GetSignerByID("signing-key")
	require.Error(t, err)
	assert.Nil(t, signer)
	assert.IsType(t, ErrOperationFailed{}, err)
}

func TestQuicBaaSKeyStore_GetDecrypterByID_GetKeyError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
			return nil, errors.New("kms unavailable")
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    mockKMS,
		Crypto: &mockSDKCryptoClient{},
	})

	decrypter, err := ks.GetDecrypterByID("decrypt-key")
	require.Error(t, err)
	assert.Nil(t, decrypter)
	assert.IsType(t, ErrKeyNotFound{}, err)
}

func TestQuicBaaSKeyStore_GetKeyByID_GetPublicKeyError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
			return &kms.KeyInfo{KeyID: keyID}, nil
		},
		getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
			return nil, errors.New("public key retrieval failed")
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    mockKMS,
		Crypto: &mockSDKCryptoClient{},
	})

	key, err := ks.GetKeyByID("test-key")
	require.Error(t, err)
	assert.Nil(t, key)
	assert.IsType(t, ErrOperationFailed{}, err)
}

func TestQuicBaaSKeyStore_RotateKey_GetKeyError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		rotateKeyFunc: func(ctx context.Context, keyID string) (*kms.RotateKeyResponse, error) {
			return &kms.RotateKeyResponse{KeyID: keyID}, nil
		},
		getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
			return nil, errors.New("public key retrieval failed")
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    mockKMS,
		Crypto: &mockSDKCryptoClient{},
	})

	key, err := ks.RotateKey(&xkmssdk.KeyAttributes{CN: "test-key"})
	require.Error(t, err)
	assert.Nil(t, key)
}

func TestQuicBaaSKeyStore_Signer_GetKeyError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
			return nil, errors.New("key not found")
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    mockKMS,
		Crypto: &mockSDKCryptoClient{},
	})

	signer, err := ks.Signer(&xkmssdk.KeyAttributes{CN: "test-key"})
	require.Error(t, err)
	assert.Nil(t, signer)
}

func TestQuicBaaSKeyStore_Signer_GetPublicKeyError(t *testing.T) {
	mockKMS := &mockSDKKMSClient{
		getKeyFunc: func(ctx context.Context, keyID string) (*kms.KeyInfo, error) {
			return &kms.KeyInfo{KeyID: keyID}, nil
		},
		getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
			return nil, errors.New("public key retrieval failed")
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:    mockKMS,
		Crypto: &mockSDKCryptoClient{},
	})

	signer, err := ks.Signer(&xkmssdk.KeyAttributes{CN: "test-key"})
	require.Error(t, err)
	assert.Nil(t, signer)
}

func TestQuicBaaSKeyStore_ListCerts_Error(t *testing.T) {
	mockCerts := &mockCertStore{
		listCertsFunc: func() ([]*x509.Certificate, error) {
			return nil, errors.New("storage error")
		},
	}

	ks, _ := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{
		KMS:       &mockSDKKMSClient{},
		Crypto:    &mockSDKCryptoClient{},
		CertStore: mockCerts,
	})

	ids, err := ks.ListCerts()
	require.Error(t, err)
	assert.Nil(t, ids)
	assert.IsType(t, ErrOperationFailed{}, err)
}
