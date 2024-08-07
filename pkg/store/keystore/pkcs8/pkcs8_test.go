package pkcs8

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/op/go-logging"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var (
	TEST_DATA_DIR = "./testdata"
)

func TestSignPKCS1v15_WithoutFileIntegrityCheck(t *testing.T) {

	_, ks, _, _ := createKeystore()

	// Create new key attributes using the pre-defined
	// key store RSA template
	testKeyAttrs := keystore.TemplateRSA

	// Create a new RSA test key
	opaqueKey, err := ks.CreateKey(testKeyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaqueKey)
	assert.NotNil(t, opaqueKey.Public())

	// Define data and create digest
	data := []byte("some data")
	digest, err := opaqueKey.Digest(data)
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, nil)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// Get the public key
	rsaPub, ok := opaqueKey.Public().(*rsa.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, rsaPub)

	// Verify the signature
	err = rsa.VerifyPKCS1v15(rsaPub, testKeyAttrs.Hash, digest, sig)
	assert.Nil(t, err)

	// Verify using the key store verifier
	verifier := ks.Verifier(testKeyAttrs, nil)
	verifier.Verify(rsaPub, testKeyAttrs.Hash, digest, sig, nil)

	// Verify using the key store verifier with a file intergrity
	// check using the stored checksum - should fail; no blob options
	// passed during signing.
	opts := keystore.VerifyOpts{
		KeyAttributes:  testKeyAttrs,
		IntegrityCheck: true,
	}
	err = verifier.Verify(rsaPub, testKeyAttrs.Hash, digest, sig, &opts)
	assert.Equal(t, keystore.ErrInvalidBlobName, err)
}

func TestSignPKCS1v15_WithFileIntegrityCheck(t *testing.T) {

	_, ks, _, _ := createKeystore()

	// Create new key attributes using the pre-defined
	// key store RSA template
	testKeyAttrs := keystore.TemplateRSA

	// Create a new RSA test key
	opaqueKey, err := ks.CreateKey(testKeyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaqueKey)
	assert.NotNil(t, opaqueKey.Public())

	// Define data and create digest
	data := []byte("some data")
	digest, err := opaqueKey.Digest(data)
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	signerOpts, err := keystore.NewSignerOpts(testKeyAttrs, data)
	assert.Nil(t, err)

	blobCN := "example.com/data.bin"
	signerOpts.KeyAttributes = testKeyAttrs
	signerOpts.BlobCN = &blobCN

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// Get the public key
	rsaPub, ok := opaqueKey.Public().(*rsa.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, rsaPub)

	// Verify the signature
	err = rsa.VerifyPKCS1v15(rsaPub, testKeyAttrs.Hash, digest, sig)
	assert.Nil(t, err)

	// Verify using the key store verifier
	verifier := ks.Verifier(testKeyAttrs, nil)
	verifier.Verify(rsaPub, testKeyAttrs.Hash, digest, sig, nil)

	// Verify using the key store verifier with a file intergrity
	// check using the stored checksum - should fail; no blob options
	// passed during signing.
	opts := keystore.VerifyOpts{
		KeyAttributes:  testKeyAttrs,
		BlobCN:         blobCN,
		IntegrityCheck: true,
	}
	err = verifier.Verify(rsaPub, testKeyAttrs.Hash, digest, sig, &opts)
	assert.Equal(t, nil, err)
}

func TestSignRSAPSS(t *testing.T) {

	_, ks, _, _ := createKeystore()

	// Create new key attributes using the pre-defined
	// key store RSA template
	testKeyAttrs := keystore.TemplateRSA

	// Create a new RSA test key
	opaqueKey, err := ks.CreateKey(testKeyAttrs)
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
		Hash:       testKeyAttrs.Hash,
	}

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, pssOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// Get the public key
	rsaPub, ok := opaqueKey.Public().(*rsa.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, rsaPub)

	// Verify the signature
	err = rsa.VerifyPSS(rsaPub, testKeyAttrs.Hash, digest, sig, pssOpts)
	assert.Nil(t, err)
}

func TestSignECDSA(t *testing.T) {

	_, ks, _, _ := createKeystore()

	// Create new key attributes using the pre-defined
	// key store RSA template
	testKeyAttrs := keystore.TemplateECDSA

	// Create a new RSA test key
	opaqueKey, err := ks.CreateKey(testKeyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaqueKey)
	assert.NotNil(t, opaqueKey.Public())

	// Define data and create digest
	data := []byte("some data")
	digest, err := opaqueKey.Digest(data)
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, nil)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// Get the public key
	ecdsaPub, ok := opaqueKey.Public().(*ecdsa.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, ecdsaPub)

	// Verify the signature
	valid := ecdsa.VerifyASN1(ecdsaPub, digest, sig)
	assert.Equal(t, true, valid)
}

func TestSignED25519(t *testing.T) {

	_, ks, _, _ := createKeystore()

	// Create new key attributes using the pre-defined
	// key store RSA template
	testKeyAttrs := keystore.TemplateEd25519

	// Create a new RSA test key
	opaqueKey, err := ks.CreateKey(testKeyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaqueKey)
	assert.NotNil(t, opaqueKey.Public())

	// Define data and create digest
	data := []byte("some data")
	digest, err := opaqueKey.Digest(data)
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, nil)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// Get the public key
	ed25519Pub, ok := opaqueKey.Public().(ed25519.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, ed25519Pub)

	// Verify the signature
	valid := ed25519.Verify(ed25519Pub, digest, sig)
	assert.Equal(t, true, valid)
}

func createKeystore() (*logging.Logger,
	keystore.KeyStorer, keystore.KeyAttributes, blobstore.BlobStorer) {

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("keystore-pkcs8")

	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logFormatter := logging.NewBackendFormatter(stdout, logFormat)
	backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(backends)

	// Create a temp directory for each instantiation
	// so parallel tests don't corrupt each other.
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		logger.Fatal(err)
	}
	tmpDir := hex.EncodeToString(buf)

	rootDir := fmt.Sprintf("%s/%s", TEST_DATA_DIR, tmpDir)
	blobStore, err := blobstore.NewFSBlobStore(logger, rootDir)
	if err != nil {
		logger.Fatal(err)
	}

	signerStore := store.NewSignerStore(blobStore)
	backend := store.NewFileBackend(logger, rootDir)
	caTemplate := keystore.TemplateRSA

	params := Params{
		KeyDir:         rootDir,
		DefaultKeySize: caTemplate.RSAAttributes.KeySize,
		Random:         rand.Reader,
		Backend:        backend,
		SignerStore:    signerStore,
		BlobStore:      blobStore,
		Logger:         logger,
	}
	return logger, NewKeyStorePKCS8(params), caTemplate, blobStore
}
