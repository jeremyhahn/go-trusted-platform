package tpm2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func TestSignerRSA_PSS(t *testing.T) {

	soPIN := []byte("so-pin")
	userPIN := []byte("testme")

	hierarchyAuth := keystore.NewClearPassword(soPIN)
	userSecret := keystore.NewClearPassword(userPIN)

	_, tpmks, tpm, err := createKeyStore(true, soPIN, userPIN, true)
	defer tpmks.Close()

	// Ensure the key store is not initialied
	assert.NotNil(t, tpm)
	assert.NotNil(t, tpmks)
	assert.Equal(t, keystore.ErrNotInitalized, err)

	// Initialize the key store
	err = tpmks.Initialize(hierarchyAuth, userSecret)
	assert.Nil(t, err)

	// Generate RSA key attributes template
	caKey, _ := keystore.Templates[x509.RSA]
	caKey.CN = "test1"
	caKey.KeyType = keystore.KEY_TYPE_CA
	caKey.PlatformPolicy = true
	caKey.SignatureAlgorithm = x509.SHA256WithRSAPSS

	// Generate RSA key from attributes template
	opaqueKey, err := tpmks.GenerateRSA(caKey)
	assert.Nil(t, err)
	assert.NotNil(t, opaqueKey)
	assert.NotNil(t, opaqueKey.Public())

	// Define data and create digest
	data := []byte("some data")
	digest, err := opaqueKey.Digest(data)
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	// Define RSA PSS opts
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       caKey.Hash,
	}

	// Generate signer opts
	signerOpts := keystore.NewSignerOpts(caKey, data)
	assert.Nil(t, err)

	// Generate blob CN to store signed data
	blobCN := []byte("example.com/data.bin")
	signerOpts.BlobCN = blobCN

	// Attach RSS PSS opts
	signerOpts.PSSOptions = pssOpts

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// Get the public key
	rsaPub, ok := opaqueKey.Public().(*rsa.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, rsaPub)

	// Verify the signature
	err = rsa.VerifyPSS(rsaPub, caKey.Hash, digest, sig, pssOpts)
	assert.Nil(t, err)
}

func TestSignerRSA_PKCS1v15(t *testing.T) {

	soPIN := []byte("so-pin")
	userPIN := []byte("testme")

	hierarchyAuth := keystore.NewClearPassword(soPIN)
	userSecret := keystore.NewClearPassword(userPIN)

	_, tpmks, tpm, err := createKeyStore(true, soPIN, userPIN, true)
	defer tpmks.Close()

	assert.NotNil(t, tpm)
	assert.NotNil(t, tpmks)
	assert.Equal(t, keystore.ErrNotInitalized, err)

	// Initialize the key store
	err = tpmks.Initialize(hierarchyAuth, userSecret)
	assert.Nil(t, err)

	// Generate RSA key attributes template
	caKey, _ := keystore.Templates[x509.RSA]
	caKey.CN = "test2"
	caKey.KeyType = keystore.KEY_TYPE_CA
	caKey.SignatureAlgorithm = x509.SHA256WithRSA
	caKey.PlatformPolicy = true

	// Generate RSA key from attributes template
	opaqueKey, err := tpmks.GenerateRSA(caKey)
	assert.Nil(t, err)
	assert.NotNil(t, opaqueKey)
	assert.NotNil(t, opaqueKey.Public())

	// Define data and create digest
	data := []byte("some data")
	digest, err := opaqueKey.Digest(data)
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	// Generate signer opts
	signerOpts := keystore.NewSignerOpts(caKey, data)
	assert.Nil(t, err)

	// Generate blob CN to store signed data
	blobCN := []byte("example2.com/data.bin")
	signerOpts.BlobCN = blobCN

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// Get the public key
	rsaPub, ok := opaqueKey.Public().(*rsa.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, rsaPub)

	// Verify the signature
	err = rsa.VerifyPKCS1v15(rsaPub, caKey.Hash, digest, sig)
	assert.Nil(t, err)
}
