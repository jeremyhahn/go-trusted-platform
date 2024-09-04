package tpm2

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/op/go-logging"
)

var currentWorkingDirectory, _ = os.Getwd()
var TEST_DIR = fmt.Sprintf("%s/testdata", currentWorkingDirectory)
var CLEAN_TMP = false
var REAL_TPM_TESTS = false

var (
	ekHandle     uint32 = 0x81010001
	srkHandle    uint32 = 0x81000001
	ekCertHandle uint32 = 0x01C00002
	platformPCR  uint   = 16

	ksSRKHandle uint32 = 0x81000003
)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {

}

func setup() {
	os.RemoveAll(TEST_DIR)
}

func createKeyStore(
	provision bool,
	soPIN, userPIN []byte,
	platformPolicy bool) (*logging.Logger, PlatformKeyStorer, tpm2.TrustedPlatformModule, error) {

	logger := util.Logger()

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		logger.Fatal(err)
	}
	hexVal := hex.EncodeToString(buf)
	tmp := fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	blobStore, err := blob.NewFSBlobStore(logger, tmp, nil)
	if err != nil {
		logger.Fatal(err)
	}

	certStore, err := certstore.NewCertificateStore(logger, blobStore)
	if err != nil {
		logger.Fatal(err)
	}

	keyBackend := keystore.NewFileBackend(logger, tmp)

	signerStore := keystore.NewSignerStore(blobStore)

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
		PlatformPCR: platformPCR,
		SSRK: &tpm2.SRKConfig{
			Handle:        srkHandle,
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
		CertStore:    certStore,
		Logger:       logger,
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      keyBackend,
		SignerStore:  signerStore,
		FQDN:         "node1.example.com",
	}

	sopin := keystore.NewClearPassword(soPIN)

	tpm, err := tpm2.NewTPM2(params)
	if err != nil {
		if err == tpm2.ErrNotInitialized && provision {
			err = tpm.Provision(sopin)
			if err != nil {
				logger.Error(err)
				return nil, nil, nil, err
			}
		} else if provision {
			logger.Error(err)
			return logger, nil, tpm, err
		}
	}

	ksparams := &Params{
		Backend: keyBackend,
		Config: &tpm2.KeyStoreConfig{
			CN:             "test",
			SRKAuth:        string(userPIN),
			SRKHandle:      ksSRKHandle,
			PlatformPolicy: platformPolicy,
		},
		DebugSecrets: true,
		Logger:       logger,
		SignerStore:  signerStore,
		TPM:          tpm,
	}

	ks, err := NewKeyStore(ksparams)

	return logger, ks, tpm, err
}
