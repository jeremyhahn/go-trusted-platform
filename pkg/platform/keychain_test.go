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

package platform

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// =============================================================================
// Error Definition Tests
// =============================================================================

func TestXKMSErrors_ErrorMessages(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrInvalidXKMSCN", ErrInvalidXKMSCN, "xkms: invalid configuration, missing CN"},
		{"ErrInvalidPlatformKeyStore", ErrInvalidPlatformKeyStore, "xkms: invalid platform key store"},
		{"ErrInvalidStoreType", ErrInvalidStoreType, "xkms: invalid store type"},
		{"ErrBackendNotConfigured", ErrBackendNotConfigured, "xkms: backend not configured"},
		{"ErrXKMSNotInitialized", ErrXKMSNotInitialized, "xkms: not initialized"},
		{"ErrInvalidBackendType", ErrInvalidBackendType, "xkms: invalid backend type"},
		{"ErrCertStorageRequired", ErrCertStorageRequired, "xkms: certificate storage required"},
		{"ErrTPMRequired", ErrTPMRequired, "xkms: TPM required for platform key store"},
		{"ErrBackendRequired", ErrBackendRequired, "xkms: backend required for platform key store"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.Error())
		})
	}
}

// =============================================================================
// Type Alias Tests
// =============================================================================

func TestTypeAliases(t *testing.T) {
	t.Run("KeyringConfig_is_XKMSConfig", func(t *testing.T) {
		var kc XKMSConfig
		kr := kc
		assert.IsType(t, XKMSConfig{}, kr)
	})

	t.Run("Keyring_is_XKMS", func(t *testing.T) {
		// Type assertion test - Keyring is an alias for XKMS
		var kc *XKMS
		kr := kc
		assert.Nil(t, kr)
	})
}

// =============================================================================
// XKMSConfig Tests
// =============================================================================

func TestXKMSConfig_GetCN(t *testing.T) {
	cfg := &XKMSConfig{CN: "test-xkms"}
	assert.Equal(t, "test-xkms", cfg.GetCN())
}

func TestXKMSConfig_GetCN_Empty(t *testing.T) {
	cfg := &XKMSConfig{}
	assert.Equal(t, "", cfg.GetCN())
}

func TestXKMSConfig_SetCN(t *testing.T) {
	cfg := &XKMSConfig{}
	cfg.SetCN("new-cn")
	assert.Equal(t, "new-cn", cfg.GetCN())
}

func TestXKMSConfig_SetCN_Overwrite(t *testing.T) {
	cfg := &XKMSConfig{CN: "old-cn"}
	cfg.SetCN("new-cn")
	assert.Equal(t, "new-cn", cfg.GetCN())
}

// =============================================================================
// TPMSigner Tests
// =============================================================================

func TestTPMSigner_Public_ReturnsSetPublicKey(t *testing.T) {
	// Generate a test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := &TPMSigner{
		publicKey: &rsaKey.PublicKey,
	}

	assert.Equal(t, &rsaKey.PublicKey, signer.Public())
}

func TestTPMSigner_Public_ReturnsNilWhenNotSet(t *testing.T) {
	signer := &TPMSigner{}
	assert.Nil(t, signer.Public())
}

func TestTPMSigner_Public_ECDSAKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := &TPMSigner{
		publicKey: &ecKey.PublicKey,
	}

	pubKey := signer.Public()
	assert.NotNil(t, pubKey)
	_, ok := pubKey.(*ecdsa.PublicKey)
	assert.True(t, ok)
}

func TestNewTPMSigner_WithTPMAttributes(t *testing.T) {
	mockTPM := &mockTPM{
		parsePublicKeyFunc: func(publicBytes []byte) (crypto.PublicKey, error) {
			rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			return &rsaKey.PublicKey, nil
		},
	}

	attrs := &xkmssdk.KeyAttributes{
		CN: "test-key",
		TPMAttributes: &xkmssdk.TPMAttributes{
			PublicKeyBytes: []byte("mock-public-key-bytes"),
		},
	}

	signer := NewTPMSigner(mockTPM, attrs, nil)

	assert.NotNil(t, signer)
	assert.NotNil(t, signer.Public())
}

func TestNewTPMSigner_WithNilTPMAttributes(t *testing.T) {
	mockTPM := &mockTPM{}
	attrs := &xkmssdk.KeyAttributes{
		CN: "test-key",
	}

	signer := NewTPMSigner(mockTPM, attrs, nil)

	assert.NotNil(t, signer)
	assert.Nil(t, signer.Public())
}

func TestNewTPMSigner_ParsePublicKeyError(t *testing.T) {
	mockTPM := &mockTPM{
		parsePublicKeyFunc: func(publicBytes []byte) (crypto.PublicKey, error) {
			return nil, errors.New("parse error")
		},
	}

	attrs := &xkmssdk.KeyAttributes{
		CN: "test-key",
		TPMAttributes: &xkmssdk.TPMAttributes{
			PublicKeyBytes: []byte("invalid-bytes"),
		},
	}

	signer := NewTPMSigner(mockTPM, attrs, nil)

	assert.NotNil(t, signer)
	// Public key should be nil when parsing fails
	assert.Nil(t, signer.Public())
}

func TestTPMSigner_Sign(t *testing.T) {
	expectedSignature := []byte("test-signature")
	mockTPM := &mockTPM{
		signFunc: func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
			return expectedSignature, nil
		},
	}

	attrs := &xkmssdk.KeyAttributes{CN: "test-key"}
	signer := &TPMSigner{
		tpm:   mockTPM,
		attrs: attrs,
	}

	sig, err := signer.Sign(rand.Reader, []byte("test-digest"), nil)
	require.NoError(t, err)
	assert.Equal(t, expectedSignature, sig)
}

func TestTPMSigner_Sign_Error(t *testing.T) {
	signError := errors.New("signing failed")
	mockTPM := &mockTPM{
		signFunc: func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
			return nil, signError
		},
	}

	attrs := &xkmssdk.KeyAttributes{CN: "test-key"}
	signer := &TPMSigner{
		tpm:   mockTPM,
		attrs: attrs,
	}

	sig, err := signer.Sign(rand.Reader, []byte("test-digest"), nil)
	assert.Error(t, err)
	assert.Nil(t, sig)
	assert.Equal(t, signError, err)
}

// =============================================================================
// PlatformKeyStore Tests
// =============================================================================

func TestNewPlatformKeyStore_NilTPM(t *testing.T) {
	ks, err := NewPlatformKeyStore(nil, &mockKeyBackend{}, &xkmssdk.PlatformSRKConfig{
		SRKHandle: 0x81000002,
	})

	assert.Nil(t, ks)
	assert.Equal(t, ErrTPMRequired, err)
}

func TestNewPlatformKeyStore_NilBackend(t *testing.T) {
	mockTPM := &mockTPM{}
	ks, err := NewPlatformKeyStore(mockTPM, nil, &xkmssdk.PlatformSRKConfig{
		SRKHandle: 0x81000002,
	})

	assert.Nil(t, ks)
	assert.Equal(t, ErrBackendRequired, err)
}

func TestNewPlatformKeyStore_NilConfig(t *testing.T) {
	mockTPM := &mockTPM{}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, nil)

	assert.Nil(t, ks)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PlatformSRKConfig required")
}

func TestNewPlatformKeyStore_ZeroSRKHandle(t *testing.T) {
	mockTPM := &mockTPM{}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		SRKHandle: 0,
	})

	assert.Nil(t, ks)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SRKHandle must be configured")
}

func TestNewPlatformKeyStore_SRKNotExists(t *testing.T) {
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			return nil, errors.New("key not found")
		},
	}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		SRKHandle: 0x81000002,
	})

	// Should return the keystore but with ErrXKMSNotInitialized
	assert.NotNil(t, ks)
	assert.Equal(t, ErrXKMSNotInitialized, err)
}

func TestNewPlatformKeyStore_SRKExists(t *testing.T) {
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			return &xkmssdk.KeyAttributes{CN: "srk"}, nil
		},
	}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		SRKHandle: 0x81000002,
	})

	require.NoError(t, err)
	assert.NotNil(t, ks)
}

func TestPlatformKeyStore_Backend(t *testing.T) {
	mockBackend := &mockKeyBackend{}
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			return &xkmssdk.KeyAttributes{CN: "srk"}, nil
		},
	}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		SRKHandle: 0x81000002,
	})
	require.NoError(t, err)

	assert.Equal(t, mockBackend, ks.Backend())
}

func TestPlatformKeyStore_SRKAttributes_KeyExists(t *testing.T) {
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			return &xkmssdk.KeyAttributes{
				CN: "srk",
				TPMAttributes: &xkmssdk.TPMAttributes{
					Name:   tpm2.TPM2BName{Buffer: []byte("srk-name")},
					Public: tpm2.TPMTPublic{},
				},
			}, nil
		},
		ekAttributesFunc: func() (*xkmssdk.KeyAttributes, error) {
			return &xkmssdk.KeyAttributes{CN: "ek"}, nil
		},
		algIDFunc: func() tpm2.TPMAlgID {
			return tpm2.TPMAlgSHA256
		},
	}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		CN:        "test-ks",
		SRKHandle: 0x81000002,
	})
	require.NoError(t, err)

	attrs := ks.SRKAttributes()
	assert.NotNil(t, attrs)
	assert.Equal(t, "test-ks", attrs.CN)
	assert.NotNil(t, attrs.TPMAttributes)
}

func TestPlatformKeyStore_SRKAttributes_KeyNotExists(t *testing.T) {
	callCount := 0
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			callCount++
			if callCount == 1 {
				// First call during NewPlatformKeyStore
				return nil, errors.New("key not found")
			}
			// Second call during SRKAttributes
			return nil, errors.New("key not found")
		},
		algIDFunc: func() tpm2.TPMAlgID {
			return tpm2.TPMAlgSHA256
		},
	}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		CN:        "test-ks",
		SRKHandle: 0x81000002,
	})
	// Expect ErrXKMSNotInitialized since key doesn't exist
	assert.NotNil(t, ks)
	assert.Equal(t, ErrXKMSNotInitialized, err)

	attrs := ks.SRKAttributes()
	assert.NotNil(t, attrs)
	assert.Equal(t, "test-ks", attrs.CN)
}

func TestPlatformKeyStore_Initialize_MissingCN(t *testing.T) {
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			return nil, errors.New("key not found")
		},
	}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		SRKHandle: 0x81000002,
		CN:        "", // Missing CN
	})
	require.NotNil(t, ks)
	require.Equal(t, ErrXKMSNotInitialized, err)

	initErr := ks.Initialize("so-pin", "user-pin")
	assert.Error(t, initErr)
	assert.ErrorIs(t, initErr, ErrInvalidXKMSCN)
}

func TestPlatformKeyStore_Initialize_EKAttributesError(t *testing.T) {
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			return nil, errors.New("key not found")
		},
		ekAttributesFunc: func() (*xkmssdk.KeyAttributes, error) {
			return nil, errors.New("EK not found")
		},
		algIDFunc: func() tpm2.TPMAlgID {
			return tpm2.TPMAlgSHA256
		},
	}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		CN:        "test-ks",
		SRKHandle: 0x81000002,
	})
	require.NotNil(t, ks)
	require.Equal(t, ErrXKMSNotInitialized, err)

	initErr := ks.Initialize("so-pin", "user-pin")
	assert.Error(t, initErr)
	assert.Contains(t, initErr.Error(), "failed to get EK attributes")
}

func TestPlatformKeyStore_Initialize_CreateSRKError(t *testing.T) {
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			return nil, errors.New("key not found")
		},
		ekAttributesFunc: func() (*xkmssdk.KeyAttributes, error) {
			return &xkmssdk.KeyAttributes{CN: "ek"}, nil
		},
		algIDFunc: func() tpm2.TPMAlgID {
			return tpm2.TPMAlgSHA256
		},
		createSRKFunc: func(attrs *xkmssdk.KeyAttributes) error {
			return errors.New("create SRK failed")
		},
	}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		CN:        "test-ks",
		SRKHandle: 0x81000002,
	})
	require.NotNil(t, ks)
	require.Equal(t, ErrXKMSNotInitialized, err)

	initErr := ks.Initialize("so-pin", "user-pin")
	assert.Error(t, initErr)
	assert.Contains(t, initErr.Error(), "failed to create Platform KeyStore SRK")
}

func TestPlatformKeyStore_Initialize_Success(t *testing.T) {
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			return nil, errors.New("key not found")
		},
		ekAttributesFunc: func() (*xkmssdk.KeyAttributes, error) {
			return &xkmssdk.KeyAttributes{CN: "ek"}, nil
		},
		algIDFunc: func() tpm2.TPMAlgID {
			return tpm2.TPMAlgSHA256
		},
		createSRKFunc: func(attrs *xkmssdk.KeyAttributes) error {
			return nil
		},
	}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		CN:        "test-ks",
		SRKHandle: 0x81000002,
	})
	require.NotNil(t, ks)
	require.Equal(t, ErrXKMSNotInitialized, err)

	initErr := ks.Initialize("so-pin", "user-pin")
	assert.NoError(t, initErr)
}

func TestPlatformKeyStore_Initialize_WithPlatformPolicy(t *testing.T) {
	createSRKCalled := false
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			return nil, errors.New("key not found")
		},
		ekAttributesFunc: func() (*xkmssdk.KeyAttributes, error) {
			return &xkmssdk.KeyAttributes{CN: "ek"}, nil
		},
		algIDFunc: func() tpm2.TPMAlgID {
			return tpm2.TPMAlgSHA256
		},
		platformPolicyDigestFunc: func() (tpm2.TPM2BDigest, error) {
			return tpm2.TPM2BDigest{Buffer: []byte("policy-digest")}, nil
		},
		createSRKFunc: func(attrs *xkmssdk.KeyAttributes) error {
			createSRKCalled = true
			// Verify platform policy is set
			assert.True(t, attrs.PlatformPolicy)
			return nil
		},
	}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		CN:             "test-ks",
		SRKHandle:      0x81000002,
		PlatformPolicy: true,
	})
	require.NotNil(t, ks)
	require.Equal(t, ErrXKMSNotInitialized, err)

	initErr := ks.Initialize("so-pin", "user-pin")
	assert.NoError(t, initErr)
	assert.True(t, createSRKCalled)
}

// =============================================================================
// NewXKMS Tests
// =============================================================================

func TestNewXKMS_NilLogger(t *testing.T) {
	// Should use default logger when nil is passed
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(nil, cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, kc)
}

func TestNewXKMS_MissingCN(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "", // Missing CN
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	assert.Nil(t, kc)
	assert.Equal(t, ErrInvalidXKMSCN, err)
}

func TestNewXKMS_MissingCertStorage(t *testing.T) {
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, nil, nil, nil)
	assert.Nil(t, kc)
	assert.Equal(t, ErrCertStorageRequired, err)
}

func TestNewXKMS_MinimalConfig(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, kc)
	assert.Equal(t, "test-xkms", kc.Config().CN)
}

func TestNewXKMS_WithSoftwareConfig(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		DefaultBackend: "software",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, kc)

	// Software backend should be available
	backend := kc.Software()
	assert.NotNil(t, backend)

	// Cleanup
	kc.Close()
}

func TestNewXKMS_SoftwareConfigUsesProvidedKeyStorage(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	// Software config with KeyStorage already set
	softwareCfg := &xkmssdk.SoftwareBackendConfig{
		KeyStorage: keyStorage,
	}

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: softwareCfg,
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, kc)

	kc.Close()
}

// =============================================================================
// XKMS Method Tests
// =============================================================================

func TestXKMS_Config(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN:             "test-xkms",
		DefaultBackend: "software",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, cfg, kc.Config())
}

func TestXKMS_Backend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	mockBackend := &mockKeyBackend{}
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, mockBackend, nil, memStorage, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, mockBackend, kc.Backend())
}

func TestXKMS_TPM(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	mockTPM := &mockTPM{}
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, mockTPM, nil)
	require.NoError(t, err)

	assert.Equal(t, mockTPM, kc.TPM())
}

func TestXKMS_TPM_Nil(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, kc.TPM())
}

func TestXKMS_KeyStore_ByName(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	ks, err := kc.KeyStore("software")
	require.NoError(t, err)
	assert.NotNil(t, ks)
}

func TestXKMS_KeyStore_ByName_NotFound(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	ks, err := kc.KeyStore("nonexistent")
	assert.Nil(t, ks)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotConfigured)
}

func TestXKMS_KeyStore_Default(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		DefaultBackend: "software",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	ks, err := kc.KeyStore()
	require.NoError(t, err)
	assert.NotNil(t, ks)
}

func TestXKMS_KeyStore_DefaultNotConfigured(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		DefaultBackend: "nonexistent",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	ks, err := kc.KeyStore()
	assert.Nil(t, ks)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotConfigured)
}

func TestXKMS_KeyStore_NoDefaultReturnsFirst(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		DefaultBackend: "", // No default
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	ks, err := kc.KeyStore()
	require.NoError(t, err)
	assert.NotNil(t, ks)
}

func TestXKMS_KeyStore_NoKeystores(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		DefaultBackend: "", // No default and no keystores
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	ks, err := kc.KeyStore()
	assert.Nil(t, ks)
	assert.Equal(t, ErrXKMSNotInitialized, err)
}

func TestXKMS_Password_NoTPM(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{CN: "test-key"}
	pw, err := kc.Password(attrs)
	assert.Nil(t, pw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TPM not configured")
}

func TestXKMS_Password_WithTPMAndPlatformKS(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	mockTPM := &mockTPM{}
	mockPlatformKS := &mockPlatformKeyStorer{
		srkAttrsFunc: func() *xkmssdk.KeyAttributes {
			return &xkmssdk.KeyAttributes{CN: "srk"}
		},
		backendFunc: func() xkmssdk.TPMKeyBackend {
			return &mockKeyBackend{}
		},
	}

	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, mockTPM, mockPlatformKS)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{CN: "test-key"}
	pw, err := kc.Password(attrs)
	require.NoError(t, err)
	assert.NotNil(t, pw)
}

func TestXKMS_Password_SetsParentFromPlatformKS(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	mockTPM := &mockTPM{}
	srkAttrs := &xkmssdk.KeyAttributes{CN: "srk"}
	mockPlatformKS := &mockPlatformKeyStorer{
		srkAttrsFunc: func() *xkmssdk.KeyAttributes {
			return srkAttrs
		},
		backendFunc: func() xkmssdk.TPMKeyBackend {
			return &mockKeyBackend{}
		},
	}

	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, mockTPM, mockPlatformKS)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{CN: "test-key", Parent: nil}
	pw, err := kc.Password(attrs)
	require.NoError(t, err)
	assert.NotNil(t, pw)
	// Parent should be set from platformKS
	assert.Equal(t, srkAttrs, attrs.Parent)
}

func TestXKMS_Close(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)

	// Verify keystores exist before close
	assert.NotEmpty(t, kc.keystores)

	err = kc.Close()
	require.NoError(t, err)

	// Verify keystores are cleared
	assert.Empty(t, kc.keystores)
	assert.Empty(t, kc.backends)
}

func TestXKMS_Stores(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	stores := kc.Stores()
	// Should have software backend (added twice for StoreSoftware and StoreUnknown but deduped)
	assert.NotEmpty(t, stores)
	// Should be unique
	assert.Len(t, stores, 1)
}

func TestXKMS_Store(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	backend, err := kc.Store("software")
	require.NoError(t, err)
	assert.NotNil(t, backend)
}

func TestXKMS_Store_InvalidType(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	backend, err := kc.Store("invalid")
	assert.Nil(t, backend)
	assert.Equal(t, ErrInvalidStoreType, err)
}

func TestXKMS_Software(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	backend := kc.Software()
	assert.NotNil(t, backend)
}

func TestXKMS_Software_NotConfigured(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	backend := kc.Software()
	assert.Nil(t, backend)
}

// =============================================================================
// XKMS Key Operations Tests
// =============================================================================

func TestXKMS_GenerateKey_InvalidBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{
		CN:        "test-key",
		StoreType: xkmssdk.StoreTPM2, // Not configured
	}

	key, err := kc.GenerateKey(context.Background(), attrs)
	assert.Nil(t, key)
	assert.Equal(t, xkmssdk.ErrInvalidKeyStore, err)
}

func TestXKMS_GenerateKey_SoftwareBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	attrs := &xkmssdk.KeyAttributes{
		CN:           "test-key",
		StoreType:    xkmssdk.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: 2048,
		},
	}

	key, err := kc.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestXKMS_GetKey_InvalidBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{
		CN:        "test-key",
		StoreType: xkmssdk.StoreTPM2,
	}

	key, err := kc.GetKey(context.Background(), attrs)
	assert.Nil(t, key)
	assert.Equal(t, xkmssdk.ErrInvalidKeyStore, err)
}

func TestXKMS_DeleteKey_InvalidBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{
		CN:        "test-key",
		StoreType: xkmssdk.StoreTPM2,
	}

	err = kc.DeleteKey(context.Background(), attrs)
	assert.Equal(t, xkmssdk.ErrInvalidKeyStore, err)
}

func TestXKMS_Signer_TPM2Key(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	mockTPM := &mockTPM{}
	mockBackend := &mockKeyBackend{}

	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, mockBackend, nil, memStorage, mockTPM, nil)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{
		CN:        "test-key",
		StoreType: xkmssdk.StoreTPM2,
	}

	signer, err := kc.Signer(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, signer)

	// Should be a TPMSigner
	_, ok := signer.(*TPMSigner)
	assert.True(t, ok)
}

func TestXKMS_Signer_TPM2Key_NoTPM(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{
		CN:        "test-key",
		StoreType: xkmssdk.StoreTPM2,
	}

	signer, err := kc.Signer(context.Background(), attrs)
	assert.Nil(t, signer)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TPM not configured")
}

func TestXKMS_Signer_InvalidBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{
		CN:        "test-key",
		StoreType: xkmssdk.StorePKCS11, // Not configured
	}

	signer, err := kc.Signer(context.Background(), attrs)
	assert.Nil(t, signer)
	assert.Equal(t, xkmssdk.ErrInvalidKeyStore, err)
}

func TestXKMS_Decrypter_InvalidBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{
		CN:        "test-key",
		StoreType: xkmssdk.StoreTPM2,
	}

	decrypter, err := kc.Decrypter(context.Background(), attrs)
	assert.Nil(t, decrypter)
	assert.Equal(t, xkmssdk.ErrInvalidKeyStore, err)
}

func TestXKMS_RotateKey_InvalidBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, nil, nil)
	require.NoError(t, err)

	attrs := &xkmssdk.KeyAttributes{
		CN:        "test-key",
		StoreType: xkmssdk.StoreTPM2,
	}

	err = kc.RotateKey(context.Background(), attrs)
	assert.Equal(t, xkmssdk.ErrInvalidKeyStore, err)
}

func TestXKMS_GetKey_SoftwareBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	// First generate a key
	attrs := &xkmssdk.KeyAttributes{
		CN:           "test-get-key",
		StoreType:    xkmssdk.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = kc.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	// Then get the key
	key, err := kc.GetKey(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestXKMS_DeleteKey_SoftwareBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	// First generate a key
	attrs := &xkmssdk.KeyAttributes{
		CN:           "test-delete-key",
		StoreType:    xkmssdk.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = kc.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	// Then delete the key
	err = kc.DeleteKey(context.Background(), attrs)
	require.NoError(t, err)

	// Verify key is deleted - GetKey should return error
	_, err = kc.GetKey(context.Background(), attrs)
	assert.Error(t, err)
}

func TestXKMS_Signer_SoftwareBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	// First generate a key
	attrs := &xkmssdk.KeyAttributes{
		CN:           "test-signer-key",
		StoreType:    xkmssdk.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = kc.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	// Get signer for the key
	signer, err := kc.Signer(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestXKMS_Decrypter_SoftwareBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	// First generate an encryption key
	attrs := &xkmssdk.KeyAttributes{
		CN:           "test-decrypter-key",
		StoreType:    xkmssdk.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeEncryption,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = kc.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	// Get decrypter for the key
	decrypter, err := kc.Decrypter(context.Background(), attrs)
	require.NoError(t, err)
	assert.NotNil(t, decrypter)
}

func TestXKMS_RotateKey_SoftwareBackend(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)
	defer kc.Close()

	// First generate a key
	attrs := &xkmssdk.KeyAttributes{
		CN:           "test-rotate-key",
		StoreType:    xkmssdk.StoreSoftware,
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err = kc.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	// Rotate the key
	err = kc.RotateKey(context.Background(), attrs)
	require.NoError(t, err)
}

func TestXKMS_Close_WithCloseError(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	keyStorage := xkmssdk.NewStorageMemory()

	cfg := &XKMSConfig{
		CN:             "test-xkms",
		SoftwareConfig: &xkmssdk.SoftwareBackendConfig{},
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, keyStorage, memStorage, nil, nil)
	require.NoError(t, err)

	// Replace the keystore with a mock that returns an error on Close
	kc.keystores["software"] = &mockKeyStore{
		closeErr: errors.New("close error"),
	}

	err = kc.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "close error")
}

func TestXKMS_Password_WithParentAlreadySet(t *testing.T) {
	memStorage := xkmssdk.NewStorageMemory()
	mockTPM := &mockTPM{}
	parentAttrs := &xkmssdk.KeyAttributes{CN: "existing-parent"}
	mockPlatformKS := &mockPlatformKeyStorer{
		srkAttrsFunc: func() *xkmssdk.KeyAttributes {
			return &xkmssdk.KeyAttributes{CN: "srk"}
		},
		backendFunc: func() xkmssdk.TPMKeyBackend {
			return &mockKeyBackend{}
		},
	}

	cfg := &XKMSConfig{
		CN: "test-xkms",
	}

	kc, err := NewXKMS(slog.Default(), cfg, nil, nil, memStorage, mockTPM, mockPlatformKS)
	require.NoError(t, err)

	// Attrs already have parent set
	attrs := &xkmssdk.KeyAttributes{CN: "test-key", Parent: parentAttrs}
	pw, err := kc.Password(attrs)
	require.NoError(t, err)
	assert.NotNil(t, pw)
	// Parent should remain unchanged since it was already set
	assert.Equal(t, parentAttrs, attrs.Parent)
}

func TestPlatformKeyStore_SRKAttributes_EKAttributesError(t *testing.T) {
	mockTPM := &mockTPM{
		keyAttributesFunc: func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
			return &xkmssdk.KeyAttributes{
				CN: "srk",
				TPMAttributes: &xkmssdk.TPMAttributes{
					Name:   tpm2.TPM2BName{Buffer: []byte("srk-name")},
					Public: tpm2.TPMTPublic{},
				},
			}, nil
		},
		ekAttributesFunc: func() (*xkmssdk.KeyAttributes, error) {
			return nil, errors.New("EK not available")
		},
		algIDFunc: func() tpm2.TPMAlgID {
			return tpm2.TPMAlgSHA256
		},
	}
	mockBackend := &mockKeyBackend{}

	ks, err := NewPlatformKeyStore(mockTPM, mockBackend, &xkmssdk.PlatformSRKConfig{
		CN:        "test-ks",
		SRKHandle: 0x81000002,
	})
	require.NoError(t, err)

	// SRKAttributes should still work even if EKAttributes fails
	attrs := ks.SRKAttributes()
	assert.NotNil(t, attrs)
	assert.Equal(t, "test-ks", attrs.CN)
	// Parent should be nil since EKAttributes failed
	assert.Nil(t, attrs.Parent)
}

// =============================================================================
// Mock Implementations
// =============================================================================

// mockTPM implements xkmssdk.TrustedPlatformModule interface for testing
type mockTPM struct {
	parsePublicKeyFunc       func(publicBytes []byte) (crypto.PublicKey, error)
	signFunc                 func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	keyAttributesFunc        func(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error)
	ekAttributesFunc         func() (*xkmssdk.KeyAttributes, error)
	algIDFunc                func() tpm2.TPMAlgID
	platformPolicyDigestFunc func() (tpm2.TPM2BDigest, error)
	createSRKFunc            func(attrs *xkmssdk.KeyAttributes) error
}

func (m *mockTPM) ParsePublicKey(publicBytes []byte) (crypto.PublicKey, error) {
	if m.parsePublicKeyFunc != nil {
		return m.parsePublicKeyFunc(publicBytes)
	}
	return nil, errors.New("not implemented")
}

func (m *mockTPM) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if m.signFunc != nil {
		return m.signFunc(rand, digest, opts)
	}
	return nil, errors.New("not implemented")
}

func (m *mockTPM) KeyAttributes(handle tpm2.TPMHandle) (*xkmssdk.KeyAttributes, error) {
	if m.keyAttributesFunc != nil {
		return m.keyAttributesFunc(handle)
	}
	return nil, errors.New("not implemented")
}

func (m *mockTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	if m.ekAttributesFunc != nil {
		return m.ekAttributesFunc()
	}
	return nil, errors.New("not implemented")
}

func (m *mockTPM) AlgID() tpm2.TPMAlgID {
	if m.algIDFunc != nil {
		return m.algIDFunc()
	}
	return tpm2.TPMAlgSHA256
}

func (m *mockTPM) PlatformPolicyDigest() (tpm2.TPM2BDigest, error) {
	if m.platformPolicyDigestFunc != nil {
		return m.platformPolicyDigestFunc()
	}
	return tpm2.TPM2BDigest{}, nil
}

func (m *mockTPM) CreateSRK(attrs *xkmssdk.KeyAttributes) error {
	if m.createSRKFunc != nil {
		return m.createSRKFunc(attrs)
	}
	return errors.New("not implemented")
}

// Stub implementations for the rest of the TrustedPlatformModule interface
func (m *mockTPM) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) AKProfile() (xkmssdk.AKProfile, error) { return xkmssdk.AKProfile{}, nil }
func (m *mockTPM) CalculateName(algID tpm2.TPMAlgID, publicArea []byte) {
}
func (m *mockTPM) Clear(lockoutAuth []byte) error { return nil }
func (m *mockTPM) Close() error                   { return nil }
func (m *mockTPM) Config() *xkmssdk.TPMConfig     { return nil }
func (m *mockTPM) CreateECDSA(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend, overwrite bool) (*ecdsa.PublicKey, error) {
	return nil, nil
}
func (m *mockTPM) CreateEK(keyAttrs *xkmssdk.KeyAttributes) error { return nil }
func (m *mockTPM) CreateSecretKey(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend) error {
	return nil
}
func (m *mockTPM) CreateIAK(ekAttrs *xkmssdk.KeyAttributes, qualifyingData []byte) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}
func (m *mockTPM) CreateIDevID(akAttrs *xkmssdk.KeyAttributes, ekCert *x509.Certificate, qualifyingData []byte) (*xkmssdk.KeyAttributes, *xkmssdk.TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPM) CreatePlatformPolicy() error { return nil }
func (m *mockTPM) CreateRSA(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend, overwrite bool) (*rsa.PublicKey, error) {
	return nil, nil
}
func (m *mockTPM) CreateKeySession(keyAttrs *xkmssdk.KeyAttributes) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPM) CreateSession(keyAttrs *xkmssdk.KeyAttributes) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPM) CreateTCG_CSR_IDEVID(ekCert *x509.Certificate, akAttrs *xkmssdk.KeyAttributes, idevidAttrs *xkmssdk.KeyAttributes) (xkmssdk.TCG_CSR_IDEVID, error) {
	return xkmssdk.TCG_CSR_IDEVID{}, nil
}
func (m *mockTPM) DeleteKey(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend) error {
	return nil
}
func (m *mockTPM) Device() string                { return "" }
func (m *mockTPM) EK() (crypto.PublicKey, error) { return nil, nil }
func (m *mockTPM) EKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}
func (m *mockTPM) EKCertificate() (*x509.Certificate, error)          { return nil, nil }
func (m *mockTPM) EKCertificateRSA() (*x509.Certificate, error)       { return nil, nil }
func (m *mockTPM) EKCertificateEC() (*x509.Certificate, error)        { return nil, nil }
func (m *mockTPM) EKECC() (*ecdsa.PublicKey, error)                   { return nil, nil }
func (m *mockTPM) EKRSA() (*rsa.PublicKey, error)                     { return nil, nil }
func (m *mockTPM) EventLog() ([]byte, error)                          { return nil, nil }
func (m *mockTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) { return nil, nil }
func (m *mockTPM) Flush(handle tpm2.TPMHandle)                        {}
func (m *mockTPM) GoldenMeasurements() ([]byte, error)                { return nil, nil }
func (m *mockTPM) HMAC(auth []byte) tpm2.Session                      { return nil }
func (m *mockTPM) HMACSaltedSession(handle tpm2.TPMHandle, pub tpm2.TPMTPublic, auth []byte) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPM) HMACSession(auth []byte) (tpm2.Session, func() error, error)        { return nil, nil, nil }
func (m *mockTPM) IAK() (crypto.PublicKey, error)                                     { return nil, nil }
func (m *mockTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error)                     { return nil, nil }
func (m *mockTPM) IDevID() (crypto.PublicKey, error)                                  { return nil, nil }
func (m *mockTPM) IDevIDAttributes() (*xkmssdk.KeyAttributes, error)                  { return nil, nil }
func (m *mockTPM) Info() (string, error)                                              { return "", nil }
func (m *mockTPM) IsFIPS140_2() (bool, error)                                         { return false, nil }
func (m *mockTPM) IsPlatformPCRExtended() (bool, error)                               { return false, nil }
func (m *mockTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error          { return nil }
func (m *mockTPM) Install(soPIN xkmssdk.Password, opts *xkmssdk.InstallOptions) error { return nil }
func (m *mockTPM) LoadKeyPair(keyAttrs *xkmssdk.KeyAttributes, session *tpm2.Session, backend xkmssdk.TPMKeyBackend) (*tpm2.LoadResponse, error) {
	return nil, nil
}
func (m *mockTPM) MakeCredential(akName tpm2.TPM2BName, secret []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *mockTPM) MakeCredentialWithExternalEK(ekCert *x509.Certificate, iakPubBytes []byte, secret []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *mockTPM) NonceSession(secret xkmssdk.Password) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPM) NVRead(keyAttrs *xkmssdk.KeyAttributes, dataSize uint16) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) NVWrite(keyAttrs *xkmssdk.KeyAttributes) error { return nil }
func (m *mockTPM) NVDefineCounter(keyAttrs *xkmssdk.KeyAttributes) error {
	return nil
}
func (m *mockTPM) NVDefineExtend(keyAttrs *xkmssdk.KeyAttributes) error {
	return nil
}
func (m *mockTPM) NVIncrement(keyAttrs *xkmssdk.KeyAttributes) (uint64, error) { return 0, nil }
func (m *mockTPM) NVExtend(keyAttrs *xkmssdk.KeyAttributes, data []byte) error { return nil }
func (m *mockTPM) NVReadCounter(keyAttrs *xkmssdk.KeyAttributes) (uint64, error) {
	return 0, nil
}
func (m *mockTPM) NVReadExtend(keyAttrs *xkmssdk.KeyAttributes) ([]byte, error) { return nil, nil }
func (m *mockTPM) NVUndefine(keyAttrs *xkmssdk.KeyAttributes) error             { return nil }
func (m *mockTPM) Open() error                                                  { return nil }
func (m *mockTPM) ParseEKCertificate(ekCert []byte) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockTPM) ParsedEventLog() ([]xkmssdk.TPMEvent, error) { return nil, nil }
func (m *mockTPM) PlatformPolicyDigestHash() ([]byte, error)   { return nil, nil }
func (m *mockTPM) PlatformPolicySession(auth []byte) (tpm2.Session, func() error, error) {
	return nil, nil, nil
}
func (m *mockTPM) PlatformQuote(keyAttrs *xkmssdk.KeyAttributes) (xkmssdk.Quote, []byte, error) {
	return xkmssdk.Quote{}, nil, nil
}
func (m *mockTPM) Provision(soPIN xkmssdk.Password) error             { return nil }
func (m *mockTPM) ProvisionEKCert(hierarchyAuth, ekCert []byte) error { return nil }
func (m *mockTPM) ProvisionOwner(hierarchyAuth xkmssdk.Password) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}
func (m *mockTPM) Quote(pcrs []uint, nonce []byte) (xkmssdk.Quote, error) {
	return xkmssdk.Quote{}, nil
}
func (m *mockTPM) CertifyKey(keyAttrs *xkmssdk.KeyAttributes, nonce []byte, backend xkmssdk.TPMKeyBackend) (*xkmssdk.CertifyResult, error) {
	return nil, nil
}
func (m *mockTPM) Random() ([]byte, error)                     { return nil, nil }
func (m *mockTPM) RandomBytes(fixedLength int) ([]byte, error) { return nil, nil }
func (m *mockTPM) RandomHex(fixedLength int) ([]byte, error)   { return nil, nil }
func (m *mockTPM) RandomSource() io.Reader                     { return nil }
func (m *mockTPM) Read(data []byte) (n int, err error)         { return 0, nil }
func (m *mockTPM) ReadHandle(handle tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}
func (m *mockTPM) ReadPCRs(pcrList []uint) ([]xkmssdk.PCRBank, error) { return nil, nil }
func (m *mockTPM) RSADecrypt(handle tpm2.TPMHandle, name tpm2.TPM2BName, blob []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) RSAEncrypt(handle tpm2.TPMHandle, name tpm2.TPM2BName, message []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) SaveKeyPair(keyAttrs *xkmssdk.KeyAttributes, outPrivate tpm2.TPM2BPrivate, outPublic tpm2.TPM2B[tpm2.TPMTPublic, *tpm2.TPMTPublic], backend xkmssdk.TPMKeyBackend, overwrite bool) error {
	return nil
}
func (m *mockTPM) Seal(ctx context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	return nil, nil
}
func (m *mockTPM) SealKey(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend, overwrite bool) (*tpm2.CreateResponse, error) {
	return nil, nil
}
func (m *mockTPM) SetHierarchyAuth(oldSecret, newSecret xkmssdk.Password, hierarchy *tpm2.TPMHandle) error {
	return nil
}
func (m *mockTPM) SecretFromShares(shares []string) (string, error) { return "", nil }
func (m *mockTPM) ShareSecret(secret []byte, shares int) ([]string, error) {
	return nil, nil
}
func (m *mockTPM) SRKPublic() (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
}
func (m *mockTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) { return nil, nil }
func (m *mockTPM) Transport() transport.TPM                        { return nil }
func (m *mockTPM) Unseal(ctx context.Context, sealed *xkmssdk.SealedData, opts *xkmssdk.UnsealOptions) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) UnsealKey(keyAttrs *xkmssdk.KeyAttributes, backend xkmssdk.TPMKeyBackend) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) CanSeal() bool                   { return false }
func (m *mockTPM) WriteEKCert(ekCert []byte) error { return nil }
func (m *mockTPM) IDevIDCertificate() (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockTPM) ProvisionIDevIDCert(cert *x509.Certificate) error { return nil }
func (m *mockTPM) DeleteIDevIDCertificate() error                   { return nil }
func (m *mockTPM) IAKCertificate() (*x509.Certificate, error)       { return nil, nil }
func (m *mockTPM) ProvisionIAKCert(cert *x509.Certificate) error    { return nil }
func (m *mockTPM) DeleteIAKCertificate() error                      { return nil }
func (m *mockTPM) VerifyTCGCSR(csr *xkmssdk.TCG_CSR_IDEVID, sigAlgo x509.SignatureAlgorithm) (*xkmssdk.KeyAttributes, *xkmssdk.UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPM) VerifyTCG_CSR_IAK(csr *xkmssdk.TCG_CSR_IDEVID, sigAlgo x509.SignatureAlgorithm) (*xkmssdk.KeyAttributes, *xkmssdk.UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPM) VerifyTCG_CSR_IDevID(csr *xkmssdk.TCG_CSR_IDEVID, signatureAlgorithm x509.SignatureAlgorithm) (*xkmssdk.KeyAttributes, *xkmssdk.UNPACKED_TCG_CSR_IDEVID, error) {
	return nil, nil, nil
}
func (m *mockTPM) SignValidate(keyAttrs *xkmssdk.KeyAttributes, digest, validationDigest []byte) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) HashSequence(keyAttrs *xkmssdk.KeyAttributes, data []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockTPM) Hash(keyAttrs *xkmssdk.KeyAttributes, data []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockTPM) ECDHZGen(keyAttrs *xkmssdk.KeyAttributes, peerPublicKey *tpm2.TPMSECCPoint, backend xkmssdk.TPMKeyBackend) ([]byte, error) {
	return nil, nil
}
func (m *mockTPM) FactoryReset(ownerAuth []byte) error          { return nil }
func (m *mockTPM) FactoryResetWithClear(ownerAuth []byte) error { return nil }
func (m *mockTPM) ForceClear() error                            { return nil }
func (m *mockTPM) SSRK() *xkmssdk.SRKConfig                     { return nil }
func (m *mockTPM) PlatformKeyStore() xkmssdk.PlatformKeyStorer {
	return nil
}
func (m *mockTPM) SupportedAlgorithms() ([]string, error) { return nil, nil }
func (m *mockTPM) SupportedCommands() ([]string, error)   { return nil, nil }
func (m *mockTPM) SupportedECCCurves() ([]string, error)  { return nil, nil }
func (m *mockTPM) ListPersistentHandles() ([]tpm2.TPMHandle, error) {
	return nil, nil
}
func (m *mockTPM) ListTransientHandles() ([]tpm2.TPMHandle, error) {
	return nil, nil
}
func (m *mockTPM) ListNVIndexes() ([]xkmssdk.NVIndexInfo, error) { return nil, nil }
func (m *mockTPM) DictionaryAttackLockoutReset(lockoutAuth []byte) error {
	return nil
}
func (m *mockTPM) GenerateSymmetricKey(attrs *xkmssdk.KeyAttributes) (xkmssdk.SymmetricKey, error) {
	return nil, nil
}
func (m *mockTPM) GetSymmetricKey(attrs *xkmssdk.KeyAttributes) (xkmssdk.SymmetricKey, error) {
	return nil, nil
}
func (m *mockTPM) SymmetricEncrypter(attrs *xkmssdk.KeyAttributes) (xkmssdk.SymmetricEncrypter, error) {
	return nil, nil
}
func (m *mockTPM) ChangeAuth(handle tpm2.TPMHandle, currentAuth, newAuth []byte) error {
	return nil
}
func (m *mockTPM) VerifyAuth(handle tpm2.TPMHandle, authValue []byte) error {
	return nil
}
func (m *mockTPM) PlatformSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}

// mockKeyBackend implements xkmssdk.TPMKeyBackend interface for testing
type mockKeyBackend struct {
	getFunc    func(attrs *xkmssdk.KeyAttributes, fsext xkmssdk.FSExtension) ([]byte, error)
	saveFunc   func(attrs *xkmssdk.KeyAttributes, data []byte, fsext xkmssdk.FSExtension, overwrite bool) error
	deleteFunc func(attrs *xkmssdk.KeyAttributes) error
}

func (m *mockKeyBackend) Get(attrs *xkmssdk.KeyAttributes, fsext xkmssdk.FSExtension) ([]byte, error) {
	if m.getFunc != nil {
		return m.getFunc(attrs, fsext)
	}
	return nil, nil
}

func (m *mockKeyBackend) Save(attrs *xkmssdk.KeyAttributes, data []byte, fsext xkmssdk.FSExtension, overwrite bool) error {
	if m.saveFunc != nil {
		return m.saveFunc(attrs, data, fsext, overwrite)
	}
	return nil
}

func (m *mockKeyBackend) Delete(attrs *xkmssdk.KeyAttributes) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(attrs)
	}
	return nil
}

// mockPlatformKeyStorer implements xkmssdk.PlatformKeyStorer interface for testing
type mockPlatformKeyStorer struct {
	srkAttrsFunc func() *xkmssdk.KeyAttributes
	backendFunc  func() xkmssdk.TPMKeyBackend
}

func (m *mockPlatformKeyStorer) SRKAttributes() *xkmssdk.KeyAttributes {
	if m.srkAttrsFunc != nil {
		return m.srkAttrsFunc()
	}
	return nil
}

func (m *mockPlatformKeyStorer) Backend() xkmssdk.TPMKeyBackend {
	if m.backendFunc != nil {
		return m.backendFunc()
	}
	return nil
}
func (m *mockPlatformKeyStorer) Initialize(soPIN, userPIN string) error        { return nil }
func (m *mockPlatformKeyStorer) EnrollPlatformSRK(soPIN, userPIN string) error { return nil }
func (m *mockPlatformKeyStorer) InitializeWithDefaults() error                 { return nil }
func (m *mockPlatformKeyStorer) IsInitialized() bool                           { return false }
func (m *mockPlatformKeyStorer) PlatformPolicyEnabled() bool                   { return false }
func (m *mockPlatformKeyStorer) ChangeAuth(currentPIN, newPIN string) error    { return nil }
func (m *mockPlatformKeyStorer) VerifyAuth(userPIN string) error               { return nil }
func (m *mockPlatformKeyStorer) PINBackend() xkmssdk.PINBackend                { return nil }
func (m *mockPlatformKeyStorer) GetLockoutInfo() (failedAttempts, maxFail, interval, recovery int, err error) {
	return 0, 0, 0, 0, nil
}
func (m *mockPlatformKeyStorer) DictionaryAttackLockoutReset(lockoutAuth []byte) error { return nil }
func (m *mockPlatformKeyStorer) IsProvisioned() bool                                   { return false }
func (m *mockPlatformKeyStorer) IsAuthReady() bool                                     { return false }
func (m *mockPlatformKeyStorer) SetAuthReady(ready bool)                               {}

// mockKeyStore implements xkmssdk.ServiceBackend interface for testing
type mockKeyStore struct {
	closeErr error
}

func (m *mockKeyStore) Close() error {
	return m.closeErr
}

// Stub the rest of KeyStore interface
func (m *mockKeyStore) GenerateRSA(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (m *mockKeyStore) GenerateECDSA(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (m *mockKeyStore) GenerateEd25519(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (m *mockKeyStore) GetKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (m *mockKeyStore) DeleteKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) error { return nil }
func (m *mockKeyStore) ListKeys(ctx context.Context) ([]*xkmssdk.KeyAttributes, error) {
	return nil, nil
}
func (m *mockKeyStore) RotateKey(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (m *mockKeyStore) Signer(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	return nil, nil
}
func (m *mockKeyStore) Decrypter(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Decrypter, error) {
	return nil, nil
}
func (m *mockKeyStore) SaveCert(_ context.Context, keyID string, cert *x509.Certificate) error {
	return nil
}
func (m *mockKeyStore) GetCert(_ context.Context, keyID string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockKeyStore) DeleteCert(_ context.Context, keyID string) error { return nil }
func (m *mockKeyStore) SaveCertChain(_ context.Context, keyID string, chain []*x509.Certificate) error {
	return nil
}
func (m *mockKeyStore) GetCertChain(_ context.Context, keyID string) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockKeyStore) ListCerts(_ context.Context) ([]string, error)            { return nil, nil }
func (m *mockKeyStore) CertExists(_ context.Context, keyID string) (bool, error) { return false, nil }
func (m *mockKeyStore) GetTLSCertificate(ctx context.Context, keyID string, attrs *xkmssdk.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *mockKeyStore) GetKeyByID(ctx context.Context, keyID string) (crypto.PrivateKey, error) {
	return nil, nil
}
func (m *mockKeyStore) GetSignerByID(ctx context.Context, keyID string) (crypto.Signer, error) {
	return nil, nil
}
func (m *mockKeyStore) GetDecrypterByID(ctx context.Context, keyID string) (crypto.Decrypter, error) {
	return nil, nil
}
func (m *mockKeyStore) KeyProvider() xkmssdk.KeyProvider               { return nil }
func (m *mockKeyStore) CertStorage() xkmssdk.CertificateStorageAdapter { return nil }
func (m *mockKeyStore) Seal(ctx context.Context, data []byte, opts *xkmssdk.SealOptions) (*xkmssdk.SealedData, error) {
	return nil, nil
}
func (m *mockKeyStore) Unseal(ctx context.Context, sealed *xkmssdk.SealedData, opts *xkmssdk.UnsealOptions) ([]byte, error) {
	return nil, nil
}
func (m *mockKeyStore) CanSeal() bool { return false }

// Ensure mocks implement interfaces
var (
	_ xkmssdk.TrustedPlatformModule = (*mockTPM)(nil)
	_ xkmssdk.TPMKeyBackend         = (*mockKeyBackend)(nil)
	_ xkmssdk.PlatformKeyStorer     = (*mockPlatformKeyStorer)(nil)
	_ xkmssdk.ServiceBackend        = (*mockKeyStore)(nil)
)

// TestTPMSigner_SignRefusesUnparseablePublicKey asserts the failure #149
// describes reaches a caller instead of being discarded.
//
// The pairing is the point. The first case is the fix; the second is the
// guard on the fix — it fails if someone later "simplifies" this into
// erroring at construction, which would break pkg/app/heartbeat.go, where
// absent public bytes are the documented steady state and certSigner
// supplies the public half from the certificate instead.
func TestTPMSigner_SignRefusesUnparseablePublicKey(t *testing.T) {
	parseErr := errors.New("malformed TPMT_PUBLIC")

	t.Run("present but unparseable bytes: Sign returns the parse error", func(t *testing.T) {
		mockTPM := &mockTPM{
			parsePublicKeyFunc: func([]byte) (crypto.PublicKey, error) {
				return nil, parseErr
			},
			signFunc: func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
				t.Fatal("Sign reached the TPM despite an unresolved public key")
				return nil, nil
			},
		}

		signer := NewTPMSigner(mockTPM, &xkmssdk.KeyAttributes{
			CN: "test-key",
			TPMAttributes: &xkmssdk.TPMAttributes{
				PublicKeyBytes: []byte("not-a-public-area"),
			},
		}, nil)

		// Public() stays nil, as keychain_test.go's existing
		// TestNewTPMSigner_ParsePublicKeyError asserts. This adds the
		// behaviour that test does not cover.
		assert.Nil(t, signer.Public())

		_, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
		require.ErrorIs(t, err, parseErr,
			"a signer that could not parse its public key must refuse to sign; "+
				"discarding that error is what made #149 present as a bare 401")
	})

	t.Run("absent bytes: Sign is unaffected", func(t *testing.T) {
		expected := []byte("signature")
		parseCalled := false
		mockTPM := &mockTPM{
			parsePublicKeyFunc: func([]byte) (crypto.PublicKey, error) {
				parseCalled = true
				return nil, parseErr
			},
			signFunc: func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
				return expected, nil
			},
		}

		// No PublicKeyBytes — the steady-state shape on an enrolled node, and
		// what IDevIDAttributesFromConfig produces: it never sets the field.
		signer := NewTPMSigner(mockTPM, &xkmssdk.KeyAttributes{
			CN:            "test-key",
			TPMAttributes: &xkmssdk.TPMAttributes{},
		}, nil)

		assert.False(t, parseCalled, "absent bytes must not reach ParsePublicKey")

		got, err := signer.Sign(nil, []byte("digest"), crypto.SHA256)
		require.NoError(t, err,
			"absent public bytes are the documented steady state; refusing here "+
				"would break pkg/app/heartbeat.go's certSigner path (#147)")
		assert.Equal(t, expected, got)
	})
}
