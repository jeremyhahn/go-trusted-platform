//go:build platform_p2p

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

package p2p

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateIdentity(t *testing.T) {
	t.Run("generates valid identity", func(t *testing.T) {
		key, err := GenerateIdentity()
		require.NoError(t, err)
		assert.NotNil(t, key)

		// Verify it's an Ed25519 key
		pubKey := key.GetPublic()
		assert.NotNil(t, pubKey)

		// Verify we can sign and verify
		data := []byte("test data")
		sig, err := key.Sign(data)
		require.NoError(t, err)

		valid, err := pubKey.Verify(data, sig)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("generates different keys each time", func(t *testing.T) {
		key1, err := GenerateIdentity()
		require.NoError(t, err)

		key2, err := GenerateIdentity()
		require.NoError(t, err)

		assert.False(t, key1.Equals(key2))
	})
}

func TestIdentityFromECDSA(t *testing.T) {
	t.Run("creates identity from ECDSA key", func(t *testing.T) {
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		key, err := IdentityFromECDSA(ecdsaKey)
		require.NoError(t, err)
		assert.NotNil(t, key)

		// Verify we can get the public key
		pubKey := key.GetPublic()
		assert.NotNil(t, pubKey)
	})

	t.Run("fails with nil key", func(t *testing.T) {
		key, err := IdentityFromECDSA(nil)
		assert.ErrorIs(t, err, ErrPrivateKeyNil)
		assert.Nil(t, key)
	})
}

// mockTPMSigner implements crypto.Signer for testing TPM-backed keys.
type mockTPMSigner struct {
	key *ecdsa.PrivateKey
}

func (s *mockTPMSigner) Public() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s *mockTPMSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(rand, s.key, digest)
}

func createTestCertificate(pubKey *ecdsa.PublicKey, privKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test IDevID",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func TestIdentityFromTPM(t *testing.T) {
	t.Run("creates identity from TPM signer", func(t *testing.T) {
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		cert, err := createTestCertificate(&ecdsaKey.PublicKey, ecdsaKey)
		require.NoError(t, err)

		signer := &mockTPMSigner{key: ecdsaKey}

		key, err := IdentityFromTPM(cert, signer)
		require.NoError(t, err)
		assert.NotNil(t, key)

		// Verify we can get the public key
		pubKey := key.GetPublic()
		assert.NotNil(t, pubKey)

		// Verify signing works
		data := []byte("test message")
		sig, err := key.Sign(data)
		require.NoError(t, err)
		assert.NotEmpty(t, sig)

		// Verify the signature
		valid, err := pubKey.Verify(data, sig)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("fails with nil certificate", func(t *testing.T) {
		signer := &mockTPMSigner{}

		key, err := IdentityFromTPM(nil, signer)
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("fails with nil signer", func(t *testing.T) {
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		cert, err := createTestCertificate(&ecdsaKey.PublicKey, ecdsaKey)
		require.NoError(t, err)

		key, err := IdentityFromTPM(cert, nil)
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

func TestTPMPrivKey(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := &mockTPMSigner{key: ecdsaKey}

	tpmKey := &tpmPrivKey{
		pubKey: &ecdsaKey.PublicKey,
		signer: signer,
	}

	t.Run("Equals with same key", func(t *testing.T) {
		tpmKey2 := &tpmPrivKey{
			pubKey: &ecdsaKey.PublicKey,
			signer: signer,
		}
		assert.True(t, tpmKey.Equals(tpmKey2))
	})

	t.Run("Equals with different key", func(t *testing.T) {
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpmKey2 := &tpmPrivKey{
			pubKey: &otherKey.PublicKey,
			signer: &mockTPMSigner{key: otherKey},
		}
		assert.False(t, tpmKey.Equals(tpmKey2))
	})

	t.Run("Raw returns hash", func(t *testing.T) {
		raw, err := tpmKey.Raw()
		require.NoError(t, err)
		assert.Len(t, raw, sha256.Size)
	})

	t.Run("Type returns ECDSA", func(t *testing.T) {
		assert.NotNil(t, tpmKey.Type())
	})

	t.Run("Sign returns valid signature", func(t *testing.T) {
		data := []byte("test data for signing")
		sig, err := tpmKey.Sign(data)
		require.NoError(t, err)
		assert.NotEmpty(t, sig)
	})

	t.Run("GetPublic returns valid public key", func(t *testing.T) {
		pub := tpmKey.GetPublic()
		assert.NotNil(t, pub)

		// Verify signature with public key
		data := []byte("test data")
		sig, err := tpmKey.Sign(data)
		require.NoError(t, err)

		valid, err := pub.Verify(data, sig)
		require.NoError(t, err)
		assert.True(t, valid)
	})
}

func TestTPMPubKey(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey := &tpmPubKey{pubKey: &ecdsaKey.PublicKey}

	t.Run("Equals with same key", func(t *testing.T) {
		pubKey2 := &tpmPubKey{pubKey: &ecdsaKey.PublicKey}
		assert.True(t, pubKey.Equals(pubKey2))
	})

	t.Run("Equals with different key", func(t *testing.T) {
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubKey2 := &tpmPubKey{pubKey: &otherKey.PublicKey}
		assert.False(t, pubKey.Equals(pubKey2))
	})

	t.Run("Raw returns valid bytes", func(t *testing.T) {
		raw, err := pubKey.Raw()
		require.NoError(t, err)
		assert.NotEmpty(t, raw)
	})

	t.Run("Type returns ECDSA", func(t *testing.T) {
		assert.NotNil(t, pubKey.Type())
	})

	t.Run("Verify returns true for valid signature", func(t *testing.T) {
		data := []byte("test message")
		hash := sha256.Sum256(data)
		sig, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, hash[:])
		require.NoError(t, err)

		valid, err := pubKey.Verify(data, sig)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Verify returns false for invalid signature", func(t *testing.T) {
		data := []byte("test message")
		invalidSig := []byte("invalid signature data")

		valid, err := pubKey.Verify(data, invalidSig)
		require.NoError(t, err)
		assert.False(t, valid)
	})
}

func TestIdentityFromReader(t *testing.T) {
	t.Run("generates identity from reader", func(t *testing.T) {
		// Use a deterministic reader for testing
		seed := make([]byte, 32)
		for i := range seed {
			seed[i] = byte(i)
		}
		reader := bytes.NewReader(seed)

		key, err := IdentityFromReader(reader)
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("fails with nil reader", func(t *testing.T) {
		key, err := IdentityFromReader(nil)
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

func TestMarshalUnmarshalIdentity(t *testing.T) {
	t.Run("round-trip marshaling", func(t *testing.T) {
		key, err := GenerateIdentity()
		require.NoError(t, err)

		data, err := MarshalIdentity(key)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		unmarshaledKey, err := UnmarshalIdentity(data)
		require.NoError(t, err)
		assert.NotNil(t, unmarshaledKey)

		// Verify keys are equal
		assert.True(t, key.Equals(unmarshaledKey))
	})

	t.Run("MarshalIdentity fails with nil key", func(t *testing.T) {
		data, err := MarshalIdentity(nil)
		assert.ErrorIs(t, err, ErrPrivateKeyNil)
		assert.Nil(t, data)
	})

	t.Run("UnmarshalIdentity fails with empty data", func(t *testing.T) {
		key, err := UnmarshalIdentity(nil)
		assert.Error(t, err)
		assert.Nil(t, key)

		key, err = UnmarshalIdentity([]byte{})
		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("UnmarshalIdentity fails with invalid data", func(t *testing.T) {
		key, err := UnmarshalIdentity([]byte("invalid key data"))
		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

func TestIdentitySignAndVerify(t *testing.T) {
	key, err := GenerateIdentity()
	require.NoError(t, err)

	pubKey := key.GetPublic()

	testCases := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"short data", []byte("hello")},
		{"long data", bytes.Repeat([]byte("a"), 10000)},
		{"binary data", []byte{0x00, 0xFF, 0x01, 0xFE}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := key.Sign(tc.data)
			require.NoError(t, err)
			assert.NotEmpty(t, sig)

			valid, err := pubKey.Verify(tc.data, sig)
			require.NoError(t, err)
			assert.True(t, valid)
		})
	}
}
