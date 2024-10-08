package platform

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs11"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs8"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/tpm2"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	tptpm2 "github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

const (
	TESTDATA_DIR = "./testdata"
)

var (
	// General TPM handles
	ekCertHandle uint32 = 0x01C00002
	ekHandle     uint32 = 0x81010001
	srkHandle    uint32 = 0x81000001

	// Key Store TPM Handles
	pkcs8PasswordHandle uint32 = 0x81000010
	pkcs11PinHandle     uint32 = 0x81000011
	tpmksSRKHandle      uint32 = 0x81000002
	tpmksKeyHandle      uint32 = 0x81000012

	platformPCR uint = 16
)

var TEST_SOFTHSM_CONF = []byte(`
# SoftHSM v2 configuration file

directories.tokendir = testdata/
objectstore.backend = file
objectstore.umask = 0077

# ERROR, WARNING, INFO, DEBUG
log.level = DEBUG

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false

# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL

# If the library should reset the state on fork
library.reset_on_fork = false
`)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
	// os.RemoveAll(TEST_DATA_DIR)
}

func setup() {
	os.RemoveAll(TESTDATA_DIR)
}

func TestKeyring_ECDSA(t *testing.T) {

	keyring := createKeyring()

	keyAttrs := &keystore.KeyAttributes{
		CN:             "test",
		Debug:          true,
		Hash:           crypto.SHA256,
		KeyAlgorithm:   x509.ECDSA,
		KeyType:        keystore.KEY_TYPE_TLS,
		PlatformPolicy: true,
		ECCAttributes: &keystore.ECCAttributes{
			Curve: elliptic.P256(),
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		StoreType:          keystore.STORE_PKCS8,
	}

	// PKCS #8: Create key
	opaque, err := keyring.GenerateKey(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaque.Public())

	// PKCS #8: Sign ECDSA
	data := []byte("test")
	signerOpts := keystore.NewSignerOpts(keyAttrs, data)

	digest, err := signerOpts.Digest()
	assert.Nil(t, err)

	sig, err := opaque.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// PKCS #8: Verify ECDSA
	ok := ecdsa.VerifyASN1(opaque.Public().(*ecdsa.PublicKey), digest, sig)
	assert.True(t, ok)

	// PKCS #11: Create key
	keyAttrs.StoreType = keystore.STORE_PKCS11
	opaque, err = keyring.GenerateKey(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaque.Public())

	// PKCS #11: Sign ECDSA
	sig, err = opaque.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// PKCS #11: Verify PKCS1v15
	ok = ecdsa.VerifyASN1(opaque.Public().(*ecdsa.PublicKey), digest, sig)
	assert.True(t, ok)

	// TPM: Create key
	keyAttrs.StoreType = keystore.STORE_TPM2
	keyAttrs.PlatformPolicy = true
	opaque, err = keyring.GenerateKey(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaque.Public())

	// TPM: Sign ECDSA
	sig, err = opaque.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// TPM: Verify ECDSA
	ok = ecdsa.VerifyASN1(
		opaque.Public().(*ecdsa.PublicKey), digest, sig)
	assert.True(t, ok)
}

func TestKeyring_RSSPSS(t *testing.T) {

	keyring := createKeyring()

	keyAttrs := &keystore.KeyAttributes{
		CN:             "test",
		Debug:          true,
		Hash:           crypto.SHA256,
		KeyAlgorithm:   x509.RSA,
		KeyType:        keystore.KEY_TYPE_TLS,
		PlatformPolicy: true,
		RSAAttributes: &keystore.RSAAttributes{
			KeySize: 2048,
		},
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		StoreType:          keystore.STORE_PKCS8,
	}

	// PKCS #8: Create key
	opaque, err := keyring.GenerateKey(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaque.Public())

	// PKCS #8: Sign RSAPSS
	data := []byte("test")
	signerOpts := keystore.NewSignerOpts(keyAttrs, data)
	signerOpts.PSSOptions = &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}

	digest, err := signerOpts.Digest()
	assert.Nil(t, err)

	sig, err := opaque.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// PKCS #8: Verify RSAPSS
	err = rsa.VerifyPSS(
		opaque.Public().(*rsa.PublicKey),
		crypto.SHA256,
		digest,
		sig,
		signerOpts.PSSOptions)

	// PKCS #11: Create key
	keyAttrs.StoreType = keystore.STORE_PKCS11

	opaque, err = keyring.GenerateKey(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaque.Public())

	// PKCS #11: Sign PKCS1v15
	sig, err = opaque.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// PKCS #11: Verify PKCS1v15
	err = rsa.VerifyPSS(
		opaque.Public().(*rsa.PublicKey),
		crypto.SHA256,
		digest,
		sig,
		signerOpts.PSSOptions)

	// TPM: Create key
	keyAttrs.StoreType = keystore.STORE_TPM2
	keyAttrs.PlatformPolicy = true
	opaque, err = keyring.GenerateKey(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaque.Public())

	// TPM: Sign RSAPSS
	sig, err = opaque.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// TPM: Verify RSAPSS
	err = rsa.VerifyPSS(
		opaque.Public().(*rsa.PublicKey),
		crypto.SHA256,
		digest,
		sig,
		signerOpts.PSSOptions)

	assert.Nil(t, err)
}

func TestKeyring_PKCS1v15(t *testing.T) {

	keyring := createKeyring()

	keyAttrs := &keystore.KeyAttributes{
		CN:             "test",
		Debug:          true,
		Hash:           crypto.SHA256,
		KeyAlgorithm:   x509.RSA,
		KeyType:        keystore.KEY_TYPE_TLS,
		PlatformPolicy: true,
		RSAAttributes: &keystore.RSAAttributes{
			KeySize: 2048,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		StoreType:          keystore.STORE_PKCS8,
	}

	// PKCS #8: Create key
	opaque, err := keyring.GenerateKey(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaque.Public())

	// PKCS #8: Sign PKCS1v15
	data := []byte("test")
	signerOpts := keystore.NewSignerOpts(keyAttrs, data)

	digest, err := signerOpts.Digest()
	assert.Nil(t, err)

	sig, err := opaque.Sign(rand.Reader, digest, nil)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// PKCS #8: Verify PKCS1v15
	err = rsa.VerifyPKCS1v15(
		opaque.Public().(*rsa.PublicKey),
		crypto.SHA256,
		digest,
		sig)

	// PKCS #11: Create key
	keyAttrs.StoreType = keystore.STORE_PKCS11

	opaque, err = keyring.GenerateKey(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaque.Public())

	// PKCS #11: Sign PKCS1v15
	sig, err = opaque.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// PKCS #11: Verify PKCS1v15
	err = rsa.VerifyPKCS1v15(
		opaque.Public().(*rsa.PublicKey),
		crypto.SHA256,
		digest,
		sig)

	// TPM: Create key
	keyAttrs.StoreType = keystore.STORE_TPM2
	keyAttrs.PlatformPolicy = true
	opaque, err = keyring.GenerateKey(keyAttrs)
	assert.Nil(t, err)
	assert.NotNil(t, opaque.Public())

	// TPM: Sign PKCS1v15
	sig, err = opaque.Sign(rand.Reader, digest, signerOpts)
	assert.Nil(t, err)
	assert.NotNil(t, sig)

	// TPM: Verify PKCS1v15
	err = rsa.VerifyPKCS1v15(
		opaque.Public().(*rsa.PublicKey),
		crypto.SHA256,
		digest,
		sig)

	assert.Nil(t, err)
}

func pkcs8Config() *pkcs8.Config {
	// return &pkcs8.Config{
	// 	Password:       keystore.DEFAULT_PASSWORD,
	// 	PasswordHandle: pkcs8PasswordHandle,
	// }
	return &pkcs8.Config{
		CN: "test",
		// Home: TESTDATA_DIR,
	}
}

func pkcs11Config() *pkcs11.Config {
	logger := logging.DefaultLogger()

	if err := os.MkdirAll(TESTDATA_DIR, fs.ModePerm); err != nil {
		logger.FatalError(err)
	}

	softhsm_conf := fmt.Sprintf("%s/softhsm.conf", TESTDATA_DIR)
	err := os.WriteFile(softhsm_conf, TEST_SOFTHSM_CONF, fs.ModePerm)
	if err != nil {
		logger.FatalError(err)
	}

	var slot int = 0
	config := &pkcs11.Config{
		Library:       "/usr/local/lib/softhsm/libsofthsm2.so",
		LibraryConfig: softhsm_conf,
		Slot:          &slot,
		SOPin:         "12345678",
		Pin:           keystore.DEFAULT_PASSWORD,
		TokenLabel:    "Trusted Platform",
	}

	return config
}

func tpmKeyStoreConfig() *tptpm2.KeyStoreConfig {
	return &tptpm2.KeyStoreConfig{
		CN:             "test",
		SRKAuth:        keystore.DEFAULT_PASSWORD,
		SRKHandle:      tpmksSRKHandle,
		PlatformPolicy: true,
	}
}

func createKeyring() *Keyring {

	logger := logging.DefaultLogger()

	soPIN := keystore.NewClearPassword([]byte("test"))
	userPIN := keystore.NewClearPassword([]byte("test"))

	// Create a temp directory (only necessary for NewOsFs()
	// when testing PKCS #11 w/ SoftHSM)
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		logger.FatalError(err)
	}
	hexVal := hex.EncodeToString(buf)
	tmp := fmt.Sprintf("%s/%s", TESTDATA_DIR, hexVal)

	// Create memory file system abstraction
	fs := afero.NewMemMapFs()

	// Create blob store
	blobStore, err := blob.NewFSBlobStore(logger, fs, tmp, nil)
	if err != nil {
		logger.FatalError(err)
	}

	// Create a key store backend
	keyBackend := keystore.NewFileBackend(logger, afero.NewMemMapFs(), tmp)

	// Create a signer store
	signerStore := keystore.NewSignerStore(blobStore)

	// Create TPM config
	config := &tptpm2.Config{
		EncryptSession: true,
		UseEntropy:     true,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		EK: &tptpm2.EKConfig{
			CertHandle:    ekCertHandle,
			Handle:        ekHandle,
			HierarchyAuth: keystore.DEFAULT_PASSWORD,
			RSAConfig: &keystore.RSAConfig{
				KeySize: 2048,
			},
		},
		IAK: &tptpm2.IAKConfig{
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
		SSRK: &tptpm2.SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: keystore.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &keystore.RSAConfig{
				KeySize: 2048,
			},
		},
		PlatformPCR: platformPCR,
		FileIntegrity: []string{
			"./",
		},
	}

	// Create TPM constructor params
	params := &tptpm2.Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      keyBackend,
		SignerStore:  signerStore,
		FQDN:         "node1.example.com",
	}

	// Create TPM 2.0 service
	tpm, err := tptpm2.NewTPM2(params)
	if err != nil {
		if err == tptpm2.ErrNotInitialized {
			if err = tpm.Provision(soPIN); err != nil {
				logger.FatalError(err)
			}
		} else {
			logger.FatalError(err)
		}
	}

	// Create keyring config
	keyringConfig := &KeyringConfig{
		CN:           "test",
		PKCS8Config:  pkcs8Config(),
		PKCS11Config: pkcs11Config(),
		TPMConfig:    tpmKeyStoreConfig(),
	}

	// Create TPM 2.0 key store
	ksparams := &tpm2.Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       tpmKeyStoreConfig(),
		SignerStore:  signerStore,
		TPM:          tpm,
	}
	tpmks, err := tpm2.NewKeyStore(ksparams)
	if err != nil {
		if err == keystore.ErrNotInitalized {
			if err := tpmks.Initialize(soPIN, userPIN); err != nil {
				logger.FatalError(err)
			}
		} else {
			logger.FatalError(err)
		}
	}

	// Create a new keyring with PKCS #8, PKCS #11,
	// and TPM 2.0 key stores
	keyring, err := NewKeyring(
		logging.DefaultLogger(),
		true,
		fs,
		TESTDATA_DIR,
		rand.Reader,
		keyringConfig,
		keyBackend,
		blobStore,
		signerStore,
		tpm,
		tpmks,
		soPIN,
		userPIN)
	if err != nil {
		logger.FatalError(err)
	}

	return keyring
}
