package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs11"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs8"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/spf13/afero"

	tpmks "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/tpm2"
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
	os.RemoveAll(TESTDATA_DIR)
}

func setup() {
	os.RemoveAll(TESTDATA_DIR)
}

// func testConfig() *webservice.WebServerConfig {
// return &webservice.WebServerConfig{
// 	Home: "public_html",
// 	Port: 8080,
// 	JWT: webservice.JWT{
// 		Expiration: 525960, // 1 year
// 	},
// 	Key: &keystore.KeyConfig{
// 		CN:                 "test",
// 		Debug:              true,
// 		Hash:               crypto.SHA256.String(),
// 		KeyAlgorithm:       x509.RSA.String(),
// 		SignatureAlgorithm: x509.SHA256WithRSA.String(),
// 		StoreType:          keystore.STORE_PKCS8.String(),
// 	},
// 	TLSPort: 8443,
// 	Certificate: webservice.Identity{
// 		Valid: 365, // days
// 		Subject: ca.Subject{
// 			CommonName:         "www.example.com",
// 			Organization:       "Trusted Platform",
// 			OrganizationalUnit: "IoT",
// 			Country:            "USA",
// 			Province:           "Kernel",
// 			Locality:           "Hypervisor",
// 			Address:            "123 Example Street",
// 			PostalCode:         "12345",
// 		},
// 		SANS: &ca.SubjectAlternativeNames{
// 			DNS: []string{
// 				"www.example.com",
// 				"localhost",
// 				"localhost.localdomain",
// 			},
// 			IPs: []string{
// 				"127.0.0.1",
// 			},
// 			Email: []string{
// 				"root@localhost",
// 				"root@localhost.localdomain",
// 			},
// 		},
// 	},
// }
// }

func testKeyConfig() *keystore.KeyConfig {
	return &keystore.KeyConfig{
		CN:                 "test",
		Debug:              true,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.RSA.String(),
		SignatureAlgorithm: x509.SHA256WithRSA.String(),
		StoreType:          keystore.STORE_PKCS8.String(),
	}
}

func testServiceParams() ServiceParams {
	keyAttrs, err := keystore.KeyAttributesFromConfig(testKeyConfig())
	if err != nil {
		panic(err)
	}
	return ServiceParams{
		Audience:   "localhost",
		Issuer:     "localhost",
		Expiration: 3600,
		KeyAttrs:   keyAttrs,
		Keyring:    createKeyring(),
	}
}

func pkcs8Config() *pkcs8.Config {
	return &pkcs8.Config{
		CN: "test",
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

func tpmKeyStoreConfig() *tpm2.KeyStoreConfig {
	return &tpm2.KeyStoreConfig{
		CN:             "test",
		SRKAuth:        keystore.DEFAULT_PASSWORD,
		SRKHandle:      tpmksSRKHandle,
		PlatformPolicy: true,
	}
}

func createKeyring() *platform.Keyring {

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
	fs := afero.NewOsFs()

	// Create blob store
	blobStore, err := blob.NewFSBlobStore(logger, fs, tmp, nil)
	if err != nil {
		logger.FatalError(err)
	}

	// Create a key store backend
	keyBackend := keystore.NewFileBackend(logger, fs, tmp)

	// Create a signer store
	signerStore := keystore.NewSignerStore(blobStore)

	// Create TPM config
	config := &tpm2.Config{
		EncryptSession: true,
		UseEntropy:     true,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		EK: &tpm2.EKConfig{
			CertHandle:    ekCertHandle,
			Handle:        ekHandle,
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
		SSRK: &tpm2.SRKConfig{
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
	params := &tpm2.Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      keyBackend,
		SignerStore:  signerStore,
		FQDN:         "node1.example.com",
	}

	// Create TPM 2.0 service
	tpm, err := tpm2.NewTPM2(params)
	if err != nil {
		if err == tpm2.ErrNotInitialized {
			if err = tpm.Provision(soPIN); err != nil {
				logger.FatalError(err)
			}
		} else {
			logger.FatalError(err)
		}
	}

	// Create keyring config
	keyringConfig := &platform.KeyringConfig{
		CN:           "test",
		PKCS8Config:  pkcs8Config(),
		PKCS11Config: pkcs11Config(),
		TPMConfig:    tpmKeyStoreConfig(),
	}

	// Create TPM 2.0 key store
	ksparams := &tpmks.Params{
		Logger:       logger,
		DebugSecrets: true,
		Config:       tpmKeyStoreConfig(),
		SignerStore:  signerStore,
		TPM:          tpm,
	}
	tpmks, err := tpmks.NewKeyStore(ksparams)
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
	keyring, err := platform.NewKeyring(
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
