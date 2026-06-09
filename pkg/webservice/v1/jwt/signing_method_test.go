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

package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
)

const (
	signingString = "token"
)

func TestSigningMethodRS(t *testing.T) {

	ks := createXKMS()
	defer ks.Close()

	// Unit tests use PKCS8 (software) backend only
	// TPM backend testing belongs in integration tests
	tt := []struct {
		jwtAlgo string
		hash    crypto.Hash
		sigAlgo x509.SignatureAlgorithm
	}{
		{
			jwtAlgo: "RS256",
			hash:    crypto.SHA256,
			sigAlgo: x509.SHA256WithRSA,
		},
		{
			jwtAlgo: "RS384",
			hash:    crypto.SHA384,
			sigAlgo: x509.SHA384WithRSA,
		},
		{
			jwtAlgo: "RS512",
			hash:    crypto.SHA512,
			sigAlgo: x509.SHA512WithRSA,
		},
	}

	for _, test := range tt {
		keyAttrs := &xkmssdk.KeyAttributes{
			CN:                 test.jwtAlgo,
			Debug:              true,
			Hash:               test.hash,
			KeyAlgorithm:       x509.RSA,
			KeyType:            xkmssdk.KeyTypeTLS,
			SignatureAlgorithm: test.sigAlgo,
			StoreType:          xkmssdk.StoreSoftware,
			RSAAttributes: &xkmssdk.RSAAttributes{
				KeySize: 2048,
			},
		}

		opaque, err := ks.GenerateKey(context.Background(), keyAttrs)
		assert.Nil(t, err)

		// Use go-xkms's SigningMethodSigner
		signingMethod, err := xkmssdk.NewJWTSigningMethodSigner(keyAttrs)
		assert.Nil(t, err)
		assert.NotNil(t, signingMethod)
		assert.Equal(t, test.jwtAlgo, signingMethod.Alg())

		signature, err := signingMethod.Sign(signingString, opaque)
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		digest, err := signingMethod.Digest(signingString)
		assert.Nil(t, err)

		pub := opaque.(crypto.Signer).Public().(*rsa.PublicKey)
		err = rsa.VerifyPKCS1v15(pub, keyAttrs.Hash, digest, signature)
		assert.Nil(t, err)

		err = signingMethod.Verify(signingString, signature, pub)
		assert.Nil(t, err)

		err = ks.DeleteKey(context.Background(), keyAttrs)
		assert.Nil(t, err)
	}
}

func TestSigningMethodPS(t *testing.T) {

	ks := createXKMS()
	defer ks.Close()

	// Unit tests use PKCS8 (software) backend only
	// TPM backend testing belongs in integration tests
	tt := []struct {
		jwtAlgo string
		hash    crypto.Hash
		sigAlgo x509.SignatureAlgorithm
	}{
		{
			jwtAlgo: "PS256",
			hash:    crypto.SHA256,
			sigAlgo: x509.SHA256WithRSAPSS,
		},
		{
			jwtAlgo: "PS384",
			hash:    crypto.SHA384,
			sigAlgo: x509.SHA384WithRSAPSS,
		},
		{
			jwtAlgo: "PS512",
			hash:    crypto.SHA512,
			sigAlgo: x509.SHA512WithRSAPSS,
		},
	}

	for _, test := range tt {
		keyAttrs := &xkmssdk.KeyAttributes{
			CN:                 test.jwtAlgo,
			Debug:              true,
			Hash:               test.hash,
			KeyAlgorithm:       x509.RSA,
			KeyType:            xkmssdk.KeyTypeTLS,
			SignatureAlgorithm: test.sigAlgo,
			StoreType:          xkmssdk.StoreSoftware,
			RSAAttributes: &xkmssdk.RSAAttributes{
				KeySize: 2048,
			},
		}

		opaque, err := ks.GenerateKey(context.Background(), keyAttrs)
		assert.Nil(t, err)

		// Use go-xkms's SigningMethodSigner
		signingMethod, err := xkmssdk.NewJWTSigningMethodSigner(keyAttrs)
		assert.Nil(t, err)
		assert.NotNil(t, signingMethod)
		assert.Equal(t, test.jwtAlgo, signingMethod.Alg())

		signature, err := signingMethod.Sign(signingString, opaque)
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		digest, err := signingMethod.Digest(signingString)
		assert.Nil(t, err)

		pub := opaque.(crypto.Signer).Public().(*rsa.PublicKey)
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       keyAttrs.Hash,
		}
		err = rsa.VerifyPSS(pub, keyAttrs.Hash, digest, signature, opts)
		assert.Nil(t, err)

		err = signingMethod.Verify(signingString, signature, pub)
		assert.Nil(t, err)

		err = ks.DeleteKey(context.Background(), keyAttrs)
		assert.Nil(t, err)
	}
}

func TestSigningMethodES(t *testing.T) {

	ks := createXKMS()
	defer ks.Close()

	// Unit tests use PKCS8 (software) backend only
	// TPM backend testing belongs in integration tests
	tt := []struct {
		jwtAlgo string
		hash    crypto.Hash
		sigAlgo x509.SignatureAlgorithm
		curve   elliptic.Curve
	}{
		{
			jwtAlgo: "ES256",
			hash:    crypto.SHA256,
			sigAlgo: x509.ECDSAWithSHA256,
			curve:   elliptic.P256(),
		},
		{
			jwtAlgo: "ES384",
			hash:    crypto.SHA384,
			sigAlgo: x509.ECDSAWithSHA384,
			curve:   elliptic.P384(),
		},
		{
			jwtAlgo: "ES512",
			hash:    crypto.SHA512,
			sigAlgo: x509.ECDSAWithSHA512,
			curve:   elliptic.P521(),
		},
	}

	for _, test := range tt {
		keyAttrs := &xkmssdk.KeyAttributes{
			CN:                 test.jwtAlgo,
			Debug:              true,
			Hash:               test.hash,
			KeyAlgorithm:       x509.ECDSA,
			KeyType:            xkmssdk.KeyTypeTLS,
			SignatureAlgorithm: test.sigAlgo,
			StoreType:          xkmssdk.StoreSoftware,
			ECCAttributes: &xkmssdk.ECCAttributes{
				Curve: test.curve,
			},
		}

		opaque, err := ks.GenerateKey(context.Background(), keyAttrs)
		assert.Nil(t, err)

		// Use go-xkms's SigningMethodSigner
		signingMethod, err := xkmssdk.NewJWTSigningMethodSigner(keyAttrs)
		assert.Nil(t, err)
		assert.NotNil(t, signingMethod)
		assert.Equal(t, test.jwtAlgo, signingMethod.Alg())

		signature, err := signingMethod.Sign(signingString, opaque)
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		digest, err := signingMethod.Digest(signingString)
		assert.Nil(t, err)

		pub := opaque.(crypto.Signer).Public().(*ecdsa.PublicKey)
		ok := ecdsa.VerifyASN1(pub, digest, signature)
		assert.Nil(t, err)
		assert.True(t, ok)

		err = signingMethod.Verify(signingString, signature, pub)
		assert.Nil(t, err)

		err = ks.DeleteKey(context.Background(), keyAttrs)
		assert.Nil(t, err)
	}
}

func TestSigningMethodES_Ed25519(t *testing.T) {

	ks := createXKMS()
	defer ks.Close()

	// Ed25519 uses a single test case - it doesn't use hash variants
	// Ed25519 signs raw messages internally (uses SHA-512 internally)
	keyAttrs := &xkmssdk.KeyAttributes{
		CN:                 "EdDSA-test",
		Debug:              true,
		Hash:               crypto.Hash(0), // Ed25519 is unhashed (signs raw message)
		KeyAlgorithm:       x509.Ed25519,
		KeyType:            xkmssdk.KeyTypeTLS,
		SignatureAlgorithm: x509.PureEd25519,
		StoreType:          xkmssdk.StoreSoftware,
	}

	opaque, err := ks.GenerateKey(context.Background(), keyAttrs)
	assert.Nil(t, err)

	// Use go-xkms's SigningMethodSigner
	signingMethod, err := xkmssdk.NewJWTSigningMethodSigner(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, signingMethod)
	assert.Equal(t, "EdDSA", signingMethod.Alg())

	signature, err := signingMethod.Sign(signingString, opaque)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Ed25519 verifies against raw message, not a digest
	pub := opaque.(crypto.Signer).Public().(ed25519.PublicKey)
	ok := ed25519.Verify(pub, []byte(signingString), signature)
	assert.True(t, ok)

	err = signingMethod.Verify(signingString, signature, pub)
	assert.Nil(t, err)

	err = ks.DeleteKey(context.Background(), keyAttrs)
	assert.Nil(t, err)
}
