package tpm2

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/op/go-logging"
	"github.com/spf13/afero"
)

var (
	// TPM_RC_AUTH_FAIL (session 1): the authorization HMAC check failed and DA counter incremented
	ErrAuthFailWithDA = tpm2.TPMRC(0x98e)

	// TPM_RC_ATTRIBUTES (session 1): inconsistent attributes
	ErrInconsistentAttributes = tpm2.TPMRC(0x982)

	// TPM_RC_AUTH_FAIL (session 1): the authorization HMAC check failed and DA counter incremented
	ErrAuthFailHMACWithDA = tpm2.TPMRC(0x99d)

	// TPM_RC_POLICY_FAIL (session 1): a policy check failed
	ErrPolicyCheckFailed = tpm2.TPMRC(0x99d)

	currentWorkingDirectory, _ = os.Getwd()
	TEST_DIR                   = fmt.Sprintf("%s/testdata", currentWorkingDirectory)
	CLEAN_TMP                  = false

	keyStoreHandle = tpm2.TPMHandle(0x81000003)
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

func TestOpenAndCloseTPM(t *testing.T) {

	_, tpm := createSim(false, false)
	tpm.Close()

	_, tpm = createSim(false, false)
	tpm.Close()

	_, tpm = createSim(false, false)
	defer tpm.Close()
}

// Extends the debug PCR with random bytes
func extendRandomBytes(transport transport.TPM) {

	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)

	fmt.Printf(
		"tpm: extending %s measurement to platform PCR %d\n",
		string(bytes), debugPCR)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(debugPCR),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  bytes,
				},
			},
		},
	}.Execute(transport)
	if err != nil {
		log.Fatal(err)
	}
}

func createKey(
	tpm TrustedPlatformModule,
	platformPolicy bool) *keystore.KeyAttributes {

	srkTemplate := tpm2.RSASRKTemplate
	srkTemplate.ObjectAttributes.NoDA = false

	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		log.Fatal(err)
	}

	srkAttrs := &keystore.KeyAttributes{
		CN:             "srk",
		KeyAlgorithm:   x509.RSA,
		KeyType:        keystore.KEY_TYPE_TPM,
		Parent:         ekAttrs,
		Password:       keystore.NewClearPassword([]byte("srk-pass")),
		PlatformPolicy: platformPolicy,
		StoreType:      keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Handle:        keyStoreHandle,
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      srkTemplate,
		}}
	err = tpm.CreateSRK(srkAttrs)
	if err != nil {
		log.Fatal(err)
	}

	return &keystore.KeyAttributes{
		CN:             "key",
		KeyAlgorithm:   x509.RSA,
		KeyType:        keystore.KEY_TYPE_CA,
		Parent:         srkAttrs,
		PlatformPolicy: platformPolicy,
		Password:       keystore.NewClearPassword([]byte("key-pass")),
		StoreType:      keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		}}
}

// Creates a connection a simulated TPM (without creating a CA)
func createSim(encrypt, entropy bool) (*logging.Logger, TrustedPlatformModule) {

	logger := util.Logger()

	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		logger.Fatal(err)
	}
	hexVal := hex.EncodeToString(buf)
	tmp := fmt.Sprintf("%s/%s", TEST_DIR, hexVal)

	fs := afero.NewMemMapFs()
	blobStore, err := blob.NewFSBlobStore(logger, fs, tmp, nil)
	if err != nil {
		logger.Fatal(err)
	}

	fileBackend := keystore.NewFileBackend(logger, afero.NewMemMapFs(), tmp)

	config := &Config{
		EncryptSession: encrypt,
		UseEntropy:     entropy,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: keystore.DEFAULT_PASSWORD,
			RSAConfig: &keystore.RSAConfig{
				KeySize: 2048,
			},
		},
		FileIntegrity: []string{
			"./",
		},
		IAK: &IAKConfig{
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
		PlatformPCR: debugPCR,
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: keystore.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig: &keystore.RSAConfig{
				KeySize: 2048,
			},
		},
		KeyStore: &KeyStoreConfig{
			// SRKAuth:        keystore.DEFAULT_PASSWORD,
			SRKAuth:        "testme",
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
	}

	params := &Params{
		Logger:       util.Logger(),
		DebugSecrets: true,
		Config:       config,
		BlobStore:    blobStore,
		Backend:      fileBackend,
		FQDN:         "node1.example.com",
	}

	tpm, err := NewTPM2(params)
	if err != nil {
		if err == ErrNotInitialized {
			if err = tpm.Provision(nil); err != nil {
				logger.Fatal(err)
			}
		} else {
			logger.Fatal(err)
		}
	}

	return logger, tpm
}

func cleanTempDir(dir string) {
	if CLEAN_TMP {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Errorf("%S", err)
		}
	}
}
