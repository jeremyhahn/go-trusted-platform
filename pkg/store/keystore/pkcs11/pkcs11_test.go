package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	tpm2ks "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/tpm2"
)

func TestConnection(t *testing.T) {

	_, ks, _, _, tmp, err := createKeystore()
	assert.Nil(t, err)
	defer func() {
		ks.Close()
		cleanTempDir(tmp)

	}()

	// uses cached TPM instance
	_, ks, _, _, tmp, err = createKeystore()
	defer cleanTempDir(tmp)
	assert.NotNil(t, ks)
	assert.NotNil(t, err)
	assert.Equal(t, err, keystore.ErrAlreadyInitialized)
}

func TestSignEd25519_WithoutFileIntegrityCheck(t *testing.T) {

	_, ks, _, _, tmp, err := createKeystore()
	assert.Nil(t, err)
	defer func() {
		ks.Close()
		cleanTempDir(tmp)
	}()

	// Generate new key attributes using the pre-defined
	// key store RSA template
	testKeyAttrs := keystore.TemplateEd25519

	// Generate a new RSA test key
	_, err = ks.GenerateKey(testKeyAttrs)
	assert.Equal(t, ErrUnsupportedOperation, err)
}

func TestSignECDSA_WithoutFileIntegrityCheck(t *testing.T) {

	_, ks, _, _, tmp, err := createKeystore()
	assert.Nil(t, err)
	defer func() {
		ks.Close()
		cleanTempDir(tmp)

	}()

	// Generate new key attributes using the pre-defined
	// key store RSA template
	testKeyAttrs := keystore.TemplateECDSA

	// Generate a new RSA test key
	opaqueKey, err := ks.GenerateKey(testKeyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaqueKey)
	assert.NotNil(t, opaqueKey.Public())

	// Define data and create digest
	data := []byte("some data")
	digest, err := opaqueKey.Digest(data)
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, opaqueKey.KeyAttributes().Hash)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// Get the public key
	ecdsaPub, ok := opaqueKey.Public().(*ecdsa.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, ecdsaPub)

	// Verify the signature
	valid := ecdsa.VerifyASN1(ecdsaPub, digest, sig)
	assert.Equal(t, true, valid)

	// Verify using the key store verifier
	verifier := ks.Verifier(testKeyAttrs, nil)
	err = verifier.Verify(ecdsaPub, testKeyAttrs.Hash, digest, sig, nil)
	assert.Nil(t, err)
}

func TestSignRSASSA_WithoutFileIntegrityCheck(t *testing.T) {

	_, ks, _, _, tmp, err := createKeystore()
	assert.Nil(t, err)
	defer func() {
		ks.Close()
		cleanTempDir(tmp)

	}()

	// Generate new key attributes using the pre-defined
	// key store RSA template
	testKeyAttrs := keystore.TemplateRSA

	// Generate a new RSA test key
	opaqueKey, err := ks.GenerateKey(testKeyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaqueKey)
	assert.NotNil(t, opaqueKey.Public())

	// Define data and create digest
	data := []byte("some data")
	digest, err := opaqueKey.Digest(data)
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, opaqueKey.KeyAttributes().Hash)
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
	err = verifier.Verify(rsaPub, testKeyAttrs.Hash, digest, sig, nil)
	assert.Nil(t, err)
}

func TestSignRSAPSS_WithoutFileIntegrityCheck(t *testing.T) {

	_, ks, _, _, tmp, err := createKeystore()
	assert.Nil(t, err)
	defer func() {
		ks.Close()
		cleanTempDir(tmp)

	}()

	// Generate new key attributes using the pre-defined
	// key store RSA template
	testKeyAttrs := keystore.TemplateRSA

	// Generate a new RSA test key
	opaqueKey, err := ks.GenerateKey(testKeyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaqueKey)
	assert.NotNil(t, opaqueKey.Public())

	// Define data and create digest
	data := []byte("some data")
	digest, err := opaqueKey.Digest(data)
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	pssOpts := &rsa.PSSOptions{
		// Note that (at present) the crypto.rsa.PSSSaltLengthEqualsHash option is
		// not supported. The caller must either use
		// crypto.rsa.PSSSaltLengthEqualsHash (recommended) or pass an
		// explicit salt length. Moreover the underlying PKCS#11
		// implementation may impose further restrictions.
		// https://github.com/ThalesGroup/crypto11/blob/master/rsa.go#L309
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       opaqueKey.KeyAttributes().Hash,
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

	// Verify using the key store verifier, without file integrity
	verifierOpts := &keystore.VerifyOpts{
		KeyAttributes: testKeyAttrs,
		PSSOptions:    pssOpts,
	}
	verifier := ks.Verifier(testKeyAttrs, nil)
	err = verifier.Verify(rsaPub, testKeyAttrs.Hash, digest, sig, verifierOpts)
	assert.Nil(t, err)

	// Verify using the key store verifier with a file intergrity
	// check using the stored checksum - should fail; no blob CN
	verifierOpts.IntegrityCheck = true
	err = verifier.Verify(rsaPub, testKeyAttrs.Hash, digest, sig, verifierOpts)
	assert.Equal(t, keystore.ErrInvalidBlobName, err)
}

func TestSignRSAPSS_WithFileIntegrityCheck(t *testing.T) {

	_, ks, _, _, tmp, err := createKeystore()
	assert.Nil(t, err)
	defer func() {
		ks.Close()
		cleanTempDir(tmp)

	}()

	// Generate new key attributes using the pre-defined
	// key store RSA template
	testKeyAttrs := keystore.TemplateRSA

	// Generate a new RSA test key
	opaqueKey, err := ks.GenerateKey(testKeyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaqueKey)
	assert.NotNil(t, opaqueKey.Public())

	// Define data and create digest
	data := []byte("some data")
	digest, err := opaqueKey.Digest(data)
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	pssOpts := &rsa.PSSOptions{
		// Note that (at present) the crypto.rsa.PSSSaltLengthEqualsHash option is
		// not supported. The caller must either use
		// crypto.rsa.PSSSaltLengthEqualsHash (recommended) or pass an
		// explicit salt length. Moreover the underlying PKCS#11
		// implementation may impose further restrictions.
		// https://github.com/ThalesGroup/crypto11/blob/master/rsa.go#L309
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       opaqueKey.KeyAttributes().Hash,
	}

	blobCN := []byte("test-blob")

	sigOpts := keystore.NewSignerOpts(testKeyAttrs, data)
	sigOpts.PSSOptions = pssOpts
	sigOpts.BlobCN = blobCN
	sigOpts.BlobData = data

	// Sign the digest
	sig, err := opaqueKey.Sign(rand.Reader, digest, sigOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// Get the public key
	rsaPub, ok := opaqueKey.Public().(*rsa.PublicKey)
	assert.True(t, ok)
	assert.NotNil(t, rsaPub)

	// Verify the signature
	err = rsa.VerifyPSS(rsaPub, testKeyAttrs.Hash, digest, sig, pssOpts)
	assert.Nil(t, err)

	// Verify using the key store verifier, without file integrity
	verifierOpts := &keystore.VerifyOpts{
		KeyAttributes:  testKeyAttrs,
		PSSOptions:     pssOpts,
		BlobCN:         blobCN,
		IntegrityCheck: true,
	}
	verifier := ks.Verifier(testKeyAttrs, nil)
	err = verifier.Verify(rsaPub, testKeyAttrs.Hash, digest, sig, verifierOpts)
	assert.Nil(t, err)

	// Verify using the key store verifier with a file intergrity
	// check using the stored checksum - should fail; no blob options
	// passed during signing.
	verifierOpts.IntegrityCheck = true
	err = verifier.Verify(rsaPub, testKeyAttrs.Hash, digest, sig, verifierOpts)
	assert.Nil(t, err)
}

func createKeystore() (
	*logging.Logger,
	keystore.KeyStorer,
	tpm2.TrustedPlatformModule,
	keystore.SignerStorer,
	string,
	error) {

	soPIN := []byte("so-pin")
	userPIN := []byte("testme")

	sopin := keystore.NewClearPassword(soPIN)
	userpin := keystore.NewClearPassword(userPIN)

	logger, tpm, temp, err := createTPM(true, true, true, soPIN, userPIN, true)
	if err != nil {
		if err == keystore.ErrNotInitalized {
			if err := tpm.Provision(sopin); err != nil {
				return nil, nil, nil, nil, "", err
			}
		} else {
			return nil, nil, nil, nil, "", err
		}
	}

	rootDir := fmt.Sprintf("%s/%s", TEST_DATA_DIR, temp)

	fs := afero.NewOsFs()

	fs.MkdirAll(rootDir, os.ModePerm)

	blobStore, err := blobstore.NewFSBlobStore(logger, fs, rootDir, nil)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}

	softhsm_conf := fmt.Sprintf("%s/softhsm.conf", temp)
	conf := strings.ReplaceAll(string(TEST_SOFTHSM_CONF), "testdata/", temp)
	err = os.WriteFile(softhsm_conf, []byte(conf), os.ModePerm)
	if err != nil {
		return nil, nil, nil, nil, "", err
	}

	var slot int = 0
	signerStore := keystore.NewSignerStore(blobStore)
	config := &Config{
		Library:       "/usr/local/lib/softhsm/libsofthsm2.so",
		LibraryConfig: softhsm_conf,
		Slot:          &slot,
		SOPin:         string(soPIN),
		Pin:           string(userPIN),
		TokenLabel:    "Trusted Platform",
	}
	if err != nil {
		return nil, nil, nil, nil, "", err
	}

	keyBackend := keystore.NewFileBackend(logger, afero.NewMemMapFs(), temp)

	// Generate new platform key store to seal the PKCS11 pin
	tpmksParams := &tpm2ks.Params{
		Config: &tpm2.KeyStoreConfig{
			CN:             "testks",
			SRKAuth:        string(userPIN),
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
		DebugSecrets: true,
		Logger:       logger,
		SignerStore:  signerStore,
		TPM:          tpm,
		Backend:      keyBackend,
	}
	tpmks, err := tpm2ks.NewKeyStore(tpmksParams)
	if err != nil {
		if err == keystore.ErrNotInitalized {
			if err := tpmks.Initialize(sopin, userpin); err != nil {
				return nil, nil, nil, nil, "", err
			}
		} else {
			return nil, nil, nil, nil, "", err
		}
	}

	pkcs11Params := &Params{
		Backend:      keyBackend,
		Config:       config,
		DebugSecrets: true,
		Fs:           fs,
		Logger:       logger,
		Random:       rand.Reader,
		SignerStore:  signerStore,
		TPMKS:        tpmks,
	}

	pkcs11store, err := NewKeyStore(pkcs11Params)
	if err == keystore.ErrNotInitalized {
		if err = pkcs11store.Initialize(sopin, userpin); err != nil {
			return nil, nil, nil, nil, "", err
		}
	} else {
		return nil, pkcs11store, nil, nil, "", err
	}

	return logger, pkcs11store, tpm, signerStore, temp, nil
}

func createTPM(
	encrypt, entropy bool,
	provision bool,
	soPIN, userPIN []byte,
	platformPolicy bool) (*logging.Logger, tpm2.TrustedPlatformModule, string, error) {

	logger := logging.DefaultLogger()

	if CACHED_TPM != nil {
		return logger, CACHED_TPM, CACHED_DIR, nil
	}

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		return nil, nil, "", err
	}
	hexVal := hex.EncodeToString(buf)
	tmp := fmt.Sprintf("%s/%s", TEST_DATA_DIR, hexVal)

	// Return cached TPM instance if already instantiated
	// by concurrent test. The simulator will hang if a
	// 2nd connection is opened.
	// if TPM != nil {
	// 	return logger, TPM, tmp, nil
	// }

	// fs := afero.NewMemMapFs()
	fs := afero.NewOsFs()
	fs.MkdirAll(tmp, os.ModePerm)

	blobStore, err := blob.NewFSBlobStore(logger, fs, tmp, nil)
	if err != nil {
		return nil, nil, "", err
	}

	fileBackend := keystore.NewFileBackend(logger, fs, tmp)

	signerStore := keystore.NewSignerStore(blobStore)

	config := &tpm2.Config{
		EncryptSession: true,
		UseEntropy:     true,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		EK: &tpm2.EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: keystore.DEFAULT_PASSWORD,
			RSAConfig: &keystore.RSAConfig{
				KeySize: 2048,
			},
		},
		IAK: &tpm2.IAKConfig{
			CN:           "device-id-001",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       uint32(0x81010002),
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &keystore.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		PlatformPCR: 16,
		SSRK: &tpm2.SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: keystore.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &keystore.RSAConfig{
				KeySize: 2048,
			},
		},
		FileIntegrity: []string{
			"./",
		},
	}

	params := &tpm2.Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "node1.example.com",
		SignerStore:  signerStore,
	}

	sopin := keystore.NewClearPassword(soPIN)

	tpm, err := tpm2.NewTPM2(params)
	if err != nil {
		if err == tpm2.ErrNotInitialized {
			if err = tpm.Provision(sopin); err != nil {
				return nil, nil, "", err
			}
		} else {
			return nil, nil, "", err
		}
	}

	// Cache the tpm instance
	CACHED_TPM = tpm
	CACHED_DIR = tmp

	return logger, tpm, tmp, nil
}
