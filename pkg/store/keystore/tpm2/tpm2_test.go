package tpm2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

var (
	// TPM_RC_AUTH_FAIL (session 1): the authorization HMAC check failed and DA counter incremented
	ErrAuthFailWithDA = tpm2.TPMRC(0x98e)
)

func TestRotateKey(t *testing.T) {

	soPIN := []byte("so-pin")
	userPIN := []byte("testme")
	keyPass := keystore.NewClearPassword([]byte("key-pass"))

	soSecret := keystore.NewClearPassword(soPIN)
	userSecret := keystore.NewClearPassword(userPIN)

	_, tpmks, _, err := createKeyStore(true, soPIN, userPIN, false)
	defer tpmks.Close()

	assert.NotNil(t, tpmks)
	assert.Equal(t, keystore.ErrNotInitalized, err)

	err = tpmks.Initialize(soSecret, userSecret)
	assert.Nil(t, err)

	ksSRKAttrs := tpmks.(*KeyStore).SRKAttributes()
	ksSRKAttrs.Password = userSecret

	// Generate RSA child key under the key store SRK
	keyAttrs := &keystore.KeyAttributes{
		CN:           "test",
		Hash:         crypto.SHA256,
		KeyAlgorithm: x509.RSA,
		KeyType:      keystore.KEY_TYPE_TPM,
		Password:     keyPass,
		Parent:       ksSRKAttrs,
		StoreType:    keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Hierarchy:  tpm2.TPMRHOwner,
			HandleType: tpm2.TPMHTTransient,
		}}

	// Generate a new RSA test key
	opaqueRSA, err := tpmks.GenerateKey(keyAttrs)
	assert.Nil(t, err)

	// Rotate the key
	newOpaqueRSA, err := tpmks.RotateKey(keyAttrs)
	assert.Nil(t, err)

	// Make sure the keys are different
	isEqual := opaqueRSA.Equal(newOpaqueRSA.Public())
	assert.False(t, isEqual)

	// Make sure the new key is equal to itself
	wantTrue := newOpaqueRSA.Equal(newOpaqueRSA)
	assert.True(t, wantTrue)
}

func TestRSA_PKCS1v15_WithPasswordWithoutPolicy(t *testing.T) {

	soPIN := []byte("so-pin")
	userPIN := []byte("testme")
	keyPass := keystore.NewClearPassword([]byte("key-pass"))

	soSecret := keystore.NewClearPassword(soPIN)
	userSecret := keystore.NewClearPassword(userPIN)

	_, tpmks, _, err := createKeyStore(true, soPIN, userPIN, false)
	defer tpmks.Close()

	assert.NotNil(t, tpmks)
	assert.Equal(t, keystore.ErrNotInitalized, err)

	err = tpmks.Initialize(soSecret, userSecret)
	assert.Nil(t, err)

	ksSRKAttrs := tpmks.(*KeyStore).SRKAttributes()

	// Generate RSA child key under the key store SRK
	keyAttrs := &keystore.KeyAttributes{
		CN:           "test",
		Hash:         crypto.SHA256,
		KeyAlgorithm: x509.RSA,
		KeyType:      keystore.KEY_TYPE_TPM,
		Password:     keyPass,
		Parent:       ksSRKAttrs,
		StoreType:    keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Hierarchy:  tpm2.TPMRHOwner,
			HandleType: tpm2.TPMHTTransient,
		}}

	// create key without password - should fail
	signer, err := tpmks.GenerateRSA(keyAttrs)
	assert.NotNil(t, err)
	assert.Equal(t, err, ErrAuthFailWithDA)

	// create key with password - should succeed
	keyAttrs.Parent.Password = userSecret
	signer, err = tpmks.GenerateRSA(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, signer)

	// Retrieve the key without SRK password - should fail
	keyAttrs.Parent.Password = nil
	key, err := tpmks.Key(keyAttrs)
	assert.NotNil(t, err)
	assert.Equal(t, err, ErrAuthFailWithDA)

	// Retrieve the key with SRK password - should succeed
	keyAttrs.Parent.Password = userSecret
	key, err = tpmks.Key(keyAttrs)
	assert.Nil(t, err)
	assert.Equal(t, signer, key)

	// Restore the correct password and perform a signature - should work
	data := []byte("test")
	keyAttrs.Password = keyPass
	signerOpts := keystore.NewSignerOpts(keyAttrs, data)

	digest, err := signerOpts.Digest()
	assert.Nil(t, err)

	sig, err := signer.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)

	err = rsa.VerifyPKCS1v15(
		signer.Public().(*rsa.PublicKey),
		crypto.SHA256,
		digest,
		sig)
	assert.Nil(t, err)

	// Retrieve the key without key password, with SRK auth - should succeed
	keyAttrs.Password = nil
	key, err = tpmks.Key(keyAttrs)
	assert.Nil(t, err)
}

func TestRSA_PSS_WithPasswordWithoutPolicy(t *testing.T) {

	soPIN := []byte("so-pin")
	userPIN := []byte("testme")

	soSecret := keystore.NewClearPassword(soPIN)
	userSecret := keystore.NewClearPassword(userPIN)

	_, tpmks, _, err := createKeyStore(true, soPIN, userPIN, false)
	defer tpmks.Close()

	assert.NotNil(t, tpmks)
	assert.Equal(t, keystore.ErrNotInitalized, err)

	err = tpmks.Initialize(soSecret, userSecret)
	assert.Nil(t, err)

	ksSRKAttrs := tpmks.(*KeyStore).SRKAttributes()

	// Generate RSA child key under the key store SRK
	keyAttrs := &keystore.KeyAttributes{
		CN:                 "test",
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.RSA,
		KeyType:            keystore.KEY_TYPE_TPM,
		Password:           keystore.NewClearPassword([]byte("key-password")),
		Parent:             ksSRKAttrs,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		StoreType:          keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Hierarchy:  tpm2.TPMRHOwner,
			HandleType: tpm2.TPMHTTransient,
		}}

	// create key without password - should fail
	signer, err := tpmks.GenerateRSA(keyAttrs)
	assert.NotNil(t, err)
	assert.Equal(t, err, ErrAuthFailWithDA)

	// create key with password - should succeed
	keyAttrs.Parent.Password = userSecret
	signer, err = tpmks.GenerateRSA(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, signer)

	// Retrieve the key without SRK password - should fail
	keyAttrs.Parent.Password = nil
	key, err := tpmks.Key(keyAttrs)
	assert.NotNil(t, err)
	assert.Equal(t, err, ErrAuthFailWithDA)

	// Retrieve the key with SRK password - should succeed
	keyAttrs.Parent.Password = userSecret
	key, err = tpmks.Key(keyAttrs)
	assert.Nil(t, err)
	assert.Equal(t, signer, key)

	data := []byte("test")
	signerOpts := keystore.NewSignerOpts(keyAttrs, data)
	signerOpts.PSSOptions = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       keyAttrs.Hash,
	}

	digest, err := signerOpts.Digest()
	assert.Nil(t, err)

	sig, err := signer.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)

	err = rsa.VerifyPSS(
		signer.Public().(*rsa.PublicKey),
		crypto.SHA256,
		digest,
		sig,
		signerOpts.PSSOptions)
	assert.Nil(t, err)

	// Retrieve the key without key password, with SRK auth - should succeed
	keyAttrs.Password = nil
	key, err = tpmks.Key(keyAttrs)
	assert.Nil(t, err)
}

func TestKeyStoreGenerateRSAWithPolicy(t *testing.T) {

	soPIN := []byte("so-pin")
	userPIN := []byte("testme")

	hierarchyAuth := keystore.NewClearPassword(soPIN)
	userSecret := keystore.NewClearPassword(userPIN)

	_, tpmks, tpm, err := createKeyStore(true, soPIN, userPIN, true)
	defer tpmks.Close()

	assert.NotNil(t, tpm)
	assert.NotNil(t, tpmks)
	assert.Equal(t, keystore.ErrNotInitalized, err)

	err = tpmks.Initialize(hierarchyAuth, userSecret)
	assert.Nil(t, err)

	ksSRKAttrs := tpmks.(*KeyStore).SRKAttributes()

	// Generate RSA child key under the key store SRK
	keyAttrs := &keystore.KeyAttributes{
		CN:           "test",
		Hash:         crypto.SHA256,
		KeyAlgorithm: x509.RSA,
		KeyType:      keystore.KEY_TYPE_TPM,
		Password:     keystore.NewClearPassword([]byte("key-password")),
		Parent:       ksSRKAttrs,
		StoreType:    keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Hierarchy:  tpm2.TPMRHOwner,
			HandleType: tpm2.TPMHTTransient,
		}}

	// create key without password - should work
	_, err = tpmks.GenerateRSA(keyAttrs)
	assert.Nil(t, err)

	// create key without password authorization, without srk platform
	// policy - should fail
	keyAttrs.Parent.PlatformPolicy = false
	keyAttrs.PlatformPolicy = true
	_, err = tpmks.GenerateRSA(keyAttrs)
	assert.NotNil(t, err)
	assert.Equal(t, ErrAuthFailWithDA, err)

	// create key without password authorization, with srk platform
	// policy - should succeed
	keyAttrs.Parent.Password = nil
	keyAttrs.Parent.PlatformPolicy = true
	keyAttrs.Password = nil
	_, err = tpmks.GenerateRSA(keyAttrs)
	assert.True(t, strings.Contains(err.Error(), "file already exists"))

	// create key with incorrect password authorization, with platform
	// policy flag - should succeed
	keyAttrs.Parent.PlatformPolicy = true
	keyAttrs.PlatformPolicy = true
	keyAttrs.Parent.Password = keystore.NewClearPassword([]byte("foo"))
	_, err = tpmks.GenerateRSA(keyAttrs)
	assert.True(t, strings.Contains(err.Error(), "file already exists"))
}

func TestKeyStoreInitialization(t *testing.T) {

	soPIN := []byte("so-pin")
	userPIN := []byte("testme")

	hierarchyAuth := keystore.NewClearPassword(soPIN)
	userSecret := keystore.NewClearPassword(userPIN)

	_, tpmks, tpm, err := createKeyStore(true, soPIN, userPIN, false)
	defer tpmks.Close()

	assert.NotNil(t, tpm)
	assert.NotNil(t, tpmks)
	assert.Equal(t, keystore.ErrNotInitalized, err)

	err = tpmks.Initialize(hierarchyAuth, userSecret)
	assert.Nil(t, err)
}

func TestKeyStoreNotInitialized(t *testing.T) {

	soPIN := []byte("so-pin")

	_, tpmks, tpm, err := createKeyStore(false, soPIN, nil, false)
	defer tpmks.Close()

	assert.NotNil(t, tpm)
	assert.NotNil(t, tpmks)
	assert.Equal(t, keystore.ErrNotInitalized, err)
}

// func TestKeyStoreRequiresPassword(t *testing.T) {

// 	soBytes := []byte("not-default")
// 	soPIN := keystore.NewClearPassword(soBytes)
// 	_, tpmks, tpm, err := createKeyStore(true, soBytes, nil, false)
// 	defer tpmks.Close()

// 	assert.NotNil(t, tpm)
// 	assert.NotNil(t, tpmks)
// 	assert.Equal(t, keystore.ErrNotInitalized, err)

// 	err = tpmks.Initialize(nil, keystore.NewClearPassword(nil))
// 	assert.Equal(t, keystore.ErrSOPinRequired, err)

// 	err = tpmks.Initialize(nil, keystore.NewClearPassword([]byte("invalid")))
// 	assert.Equal(t, keystore.ErrSOPinRequired, err)

// 	err = tpmks.Initialize(soPIN, keystore.NewClearPassword([]byte("invalid")))
// 	assert.Nil(t, err)

// 	// err = tpmks.Initialize(soPIN, keystore.NewClearPassword([]byte("not-default")))
// 	// assert.True(t, strings.Contains(err.Error(), "TPM_RC_NV_DEFINED"))
// }
