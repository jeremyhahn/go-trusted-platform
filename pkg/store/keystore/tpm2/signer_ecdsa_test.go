package tpm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func TestSignerECDSA(t *testing.T) {

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

	caKey, _ := keystore.Templates[x509.ECDSA]
	caKey.KeyType = keystore.KEY_TYPE_CA
	caKey.PlatformPolicy = true
	caKey.SignatureAlgorithm = x509.ECDSAWithSHA256
	caKey.StoreType = keystore.STORE_TPM2

	opaqueKey, err := tpmks.GenerateECDSA(caKey)
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
	blobCN := []byte("example.com/data.bin")
	signerOpts.BlobCN = blobCN

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// Get the public key
	ecdsaPub, ok := opaqueKey.Public().(*ecdsa.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, ecdsaPub)

	// Verify the signature
	ok = ecdsa.VerifyASN1(ecdsaPub, digest, sig)
	assert.True(t, ok)
}
