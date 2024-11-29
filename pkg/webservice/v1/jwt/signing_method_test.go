package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

const (
	signingString = "token"
)

func TestSigningMethodRS(t *testing.T) {

	keyring := createKeyring()
	defer keyring.TPM2().Close()

	for _, store := range keyring.Stores() {

		tt := []struct {
			jwtAlgo string
			hash    crypto.Hash
			sigAlgo x509.SignatureAlgorithm
			store   keystore.StoreType
		}{
			{
				jwtAlgo: "RS256",
				hash:    crypto.SHA256,
				sigAlgo: x509.SHA256WithRSA,
				store:   store.Type(),
			},
			{
				jwtAlgo: "RS384",
				hash:    crypto.SHA384,
				sigAlgo: x509.SHA384WithRSA,
				store:   store.Type(),
			},
			{
				jwtAlgo: "RS512",
				hash:    crypto.SHA512,
				sigAlgo: x509.SHA512WithRSA,
				store:   store.Type(),
			},
		}

		for _, test := range tt {

			if test.store == keystore.STORE_TPM2 && test.hash != crypto.SHA256 {
				// TPM simulator doesn't support SHA-386 or SHA-512
				continue
			}

			keyAttrs := &keystore.KeyAttributes{
				CN:                 test.jwtAlgo,
				Debug:              true,
				Hash:               test.hash,
				KeyAlgorithm:       x509.RSA,
				KeyType:            keystore.KEY_TYPE_TLS,
				SignatureAlgorithm: test.sigAlgo,
				StoreType:          test.store,
			}

			opaque, err := keyring.GenerateKey(keyAttrs)
			assert.Nil(t, err)

			signingMethod, err := NewSigningMethod(keyAttrs)
			assert.Nil(t, err)
			assert.NotNil(t, signingMethod)
			assert.Equal(t, test.jwtAlgo, signingMethod.Alg())

			signature, err := signingMethod.Sign(signingString, opaque)
			assert.Nil(t, err)
			assert.NotNil(t, signature)

			digest, err := signingMethod.Digest(signingString)
			assert.Nil(t, err)

			pub := opaque.Public().(*rsa.PublicKey)
			err = rsa.VerifyPKCS1v15(pub, keyAttrs.Hash, digest, signature)
			assert.Nil(t, err)

			err = signingMethod.Verify(string(digest), signature, pub)
			assert.Nil(t, err)

			err = keyring.Delete(keyAttrs)
			assert.Nil(t, err)
		}
	}
}

func TestSigningMethodPS(t *testing.T) {

	keyring := createKeyring()
	defer keyring.TPM2().Close()

	for _, store := range keyring.Stores() {

		tt := []struct {
			jwtAlgo string
			hash    crypto.Hash
			sigAlgo x509.SignatureAlgorithm
			store   keystore.StoreType
		}{
			{
				jwtAlgo: "PS256",
				hash:    crypto.SHA256,
				sigAlgo: x509.SHA256WithRSAPSS,
				store:   store.Type(),
			},
			{
				jwtAlgo: "PS384",
				hash:    crypto.SHA384,
				sigAlgo: x509.SHA384WithRSAPSS,
				store:   store.Type(),
			},
			{
				jwtAlgo: "PS512",
				hash:    crypto.SHA512,
				sigAlgo: x509.SHA512WithRSAPSS,
				store:   store.Type(),
			},
		}

		for _, test := range tt {

			if test.store == keystore.STORE_TPM2 && test.hash != crypto.SHA256 {
				continue
			}

			keyAttrs := &keystore.KeyAttributes{
				CN:                 test.jwtAlgo,
				Debug:              true,
				Hash:               test.hash,
				KeyAlgorithm:       x509.RSA,
				KeyType:            keystore.KEY_TYPE_TLS,
				SignatureAlgorithm: test.sigAlgo,
				StoreType:          test.store,
			}

			opaque, err := keyring.GenerateKey(keyAttrs)
			assert.Nil(t, err)

			signingMethod, err := NewSigningMethod(keyAttrs)
			assert.Nil(t, err)
			assert.NotNil(t, signingMethod)
			assert.Equal(t, test.jwtAlgo, signingMethod.Alg())

			signature, err := signingMethod.Sign(signingString, opaque)
			assert.Nil(t, err)
			assert.NotNil(t, signature)

			digest, err := signingMethod.Digest(signingString)
			assert.Nil(t, err)

			pub := opaque.Public().(*rsa.PublicKey)
			opts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       keyAttrs.Hash,
			}
			err = rsa.VerifyPSS(pub, keyAttrs.Hash, digest, signature, opts)
			assert.Nil(t, err)

			err = signingMethod.Verify(string(digest), signature, pub)
			assert.Nil(t, err)

			err = keyring.Delete(keyAttrs)
			assert.Nil(t, err)
		}
	}
}

func TestSigningMethodES(t *testing.T) {

	keyring := createKeyring()
	defer keyring.TPM2().Close()

	for _, store := range keyring.Stores() {

		tt := []struct {
			jwtAlgo string
			hash    crypto.Hash
			sigAlgo x509.SignatureAlgorithm
			store   keystore.StoreType
		}{
			{
				jwtAlgo: "ES256",
				hash:    crypto.SHA256,
				sigAlgo: x509.ECDSAWithSHA256,
				store:   store.Type(),
			},
			{
				jwtAlgo: "ES384",
				hash:    crypto.SHA384,
				sigAlgo: x509.ECDSAWithSHA384,
				store:   store.Type(),
			},
			{
				jwtAlgo: "ES512",
				hash:    crypto.SHA512,
				sigAlgo: x509.ECDSAWithSHA512,
				store:   store.Type(),
			},
		}

		for _, test := range tt {

			if test.store == keystore.STORE_TPM2 && test.hash != crypto.SHA256 {
				continue
			}

			keyAttrs := &keystore.KeyAttributes{
				CN:                 test.jwtAlgo,
				Debug:              true,
				Hash:               test.hash,
				KeyAlgorithm:       x509.ECDSA,
				KeyType:            keystore.KEY_TYPE_TLS,
				SignatureAlgorithm: test.sigAlgo,
				StoreType:          test.store,
			}

			opaque, err := keyring.GenerateKey(keyAttrs)
			assert.Nil(t, err)

			signingMethod, err := NewSigningMethod(keyAttrs)
			assert.Nil(t, err)
			assert.NotNil(t, signingMethod)
			assert.Equal(t, test.jwtAlgo, signingMethod.Alg())

			signature, err := signingMethod.Sign(signingString, opaque)
			assert.Nil(t, err)
			assert.NotNil(t, signature)

			digest, err := signingMethod.Digest(signingString)
			assert.Nil(t, err)

			pub := opaque.Public().(*ecdsa.PublicKey)
			ok := ecdsa.VerifyASN1(pub, digest, signature)
			assert.Nil(t, err)
			assert.True(t, ok)

			err = signingMethod.Verify(string(digest), signature, pub)
			assert.Nil(t, err)

			err = keyring.Delete(keyAttrs)
			assert.Nil(t, err)
		}
	}
}

func TestSigningMethodES_Ed25519(t *testing.T) {

	keyring := createKeyring()
	defer keyring.TPM2().Close()

	tt := []struct {
		jwtAlgo string
		hash    crypto.Hash
		sigAlgo x509.SignatureAlgorithm
	}{
		{
			jwtAlgo: "EdDSA",
			hash:    crypto.SHA256,
			sigAlgo: x509.PureEd25519,
		},
		{
			jwtAlgo: "EdDSA",
			hash:    crypto.SHA384,
			sigAlgo: x509.PureEd25519,
		},
		{
			jwtAlgo: "EdDSA",
			hash:    crypto.SHA512,
			sigAlgo: x509.PureEd25519,
		},
	}

	for i, test := range tt {

		keyAttrs := &keystore.KeyAttributes{
			CN:                 fmt.Sprintf("%s-%d", test.jwtAlgo, i),
			Debug:              true,
			Hash:               test.hash,
			KeyAlgorithm:       x509.Ed25519,
			KeyType:            keystore.KEY_TYPE_TLS,
			SignatureAlgorithm: test.sigAlgo,
			StoreType:          keystore.STORE_PKCS8,
		}

		opaque, err := keyring.GenerateKey(keyAttrs)
		assert.Nil(t, err)

		signingMethod, err := NewSigningMethod(keyAttrs)
		assert.Nil(t, err)
		assert.NotNil(t, signingMethod)
		assert.Equal(t, test.jwtAlgo, signingMethod.Alg())

		signature, err := signingMethod.Sign(signingString, opaque)
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		digest, err := signingMethod.Digest(signingString)
		assert.Nil(t, err)

		pub := opaque.Public().(ed25519.PublicKey)
		ok := ed25519.Verify(pub, digest, signature)
		assert.Nil(t, err)
		assert.True(t, ok)

		err = signingMethod.Verify(string(digest), signature, pub)
		assert.Nil(t, err)

		err = keyring.Delete(keyAttrs)
		assert.Nil(t, err)
	}
}
