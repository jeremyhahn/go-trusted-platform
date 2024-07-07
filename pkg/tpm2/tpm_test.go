package tpm2

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/logger"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
)

// Create a fake TPM cert
// https://gist.github.com/op-ct/e202fc911de22c018effdb3371e8335f
// https://github.com/osresearch/safeboot/pull/85

var currentWorkingDirectory, _ = os.Getwd()
var CERTS_DIR = fmt.Sprintf("%s/certs", currentWorkingDirectory)
var CLEAN_TMP = false
var REAL_TPM_TESTS = false

const (
	EK_CERT_PATH = "./ECcert.bin"
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
	os.RemoveAll(CERTS_DIR)
}

func TestReadPCRs_TPM(t *testing.T) {

	if !REAL_TPM_TESTS {
		return
	}

	_, tpm := createTPM(false, false)
	defer tpm.Close()

	pcrs := []uint{0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}

	banks, err := tpm.ReadPCRs(pcrs)
	assert.Nil(t, err)
	assert.NotNil(t, banks)

	for _, bank := range banks {
		for _, pcr := range bank.PCRs {
			logger.Infof("%s %d: 0x%s",
				bank.Algorithm, pcr.ID, string(pcr.Value))
		}
	}

	assert.True(t, len(banks) >= 2)
	assert.Equal(t, 23, len(banks[0].PCRs)) // SHA1
	assert.Equal(t, 23, len(banks[1].PCRs)) // SHA256
}

// NOTE: The user account running the test requires read permissions
// to binary_bios_measurements:
// sudo chown root.myuser /sys/kernel/security/tpm0/binary_bios_measurements
func TestParseEventLog(t *testing.T) {

	if !REAL_TPM_TESTS {
		return
	}

	logger, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	eventLog, err := tpm.EventLog()
	assert.Nil(t, err)
	assert.NotNil(t, eventLog)

	logger.Debugf("%d", eventLog)
}

func TestEKCert(t *testing.T) {

	logger, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	intermediatePass := []byte("intermediate-password")
	cert, err := tpm.EKCert(nil, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	logger.Debugf("cert: %+v", cert)
}

func TestImportTSS(t *testing.T) {

	expectedSN := "455850945431947993541652326598156649892946412448"

	logger, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	assert.NotNil(t, logger)
	assert.NotNil(t, tpm)

	intermediatePass := []byte("intermediate-password")
	cert, err := tpm.ImportTSSFile(EK_CERT_PATH, true, intermediatePass)
	assert.Nil(t, err)
	assert.Equal(t, expectedSN, cert.SerialNumber.String())

	logger.Debugf("%+v", cert)
}

func TestQuote(t *testing.T) {

	_, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	nonce := []byte("nonce")

	// Quote with a nonce
	pcrs := []uint{0, 1, 2, 3}
	quote, err := tpm.Quote(pcrs, nonce)
	assert.Nil(t, err)
	assert.NotNil(t, quote.Quoted)

	// Quote without a nonce
	quote, err = tpm.Quote(pcrs, nil)
	assert.Nil(t, err)
	assert.NotNil(t, quote.Quoted)

	pcrs = []uint{0, 1, 2, 3, 5, 6, 7, 8, 9}
	quote, err = tpm.Quote(pcrs, nonce)
	// The simulator doesn't seem to support quoting more than 4 pcrs ??
	// TPM_RC_SIZE (parameter 3): structure is the wrong size
	errStructureWrongSize := tpm2.TPMRC(0x3d5)
	assert.Equal(t, errStructureWrongSize, err)
}

func TestEncodeDecodeQuote(t *testing.T) {

	_, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	nonce := []byte("nonce")

	pcrs := []uint{0, 1, 2, 3}
	quote, err := tpm.Quote(pcrs, nonce)
	assert.Nil(t, err)
	assert.NotNil(t, quote.Quoted)

	encoded, err := tpm.EncodeQuote(quote)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)

	decoded, err := tpm.DecodeQuote(encoded)
	assert.Nil(t, err)
	assert.NotNil(t, decoded)

	assert.Equal(t, quote, decoded)
}

func TestEncodeDecodePCRBanks(t *testing.T) {

	_, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	pcrs := []uint{0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
	banks, err := tpm.ReadPCRs(pcrs)
	assert.Nil(t, err)
	assert.NotNil(t, banks)

	encoded, err := tpm.EncodePCRs(banks)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)

	decoded, err := tpm.DecodePCRs(encoded)
	assert.Nil(t, err)
	assert.NotNil(t, decoded)

	assert.Equal(t, banks, decoded)
}

func TestReadPCRs_SIM(t *testing.T) {

	_, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	pcrs := []uint{0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
	banks, err := tpm.ReadPCRs(pcrs)
	assert.Nil(t, err)
	assert.NotNil(t, banks)

	for _, bank := range banks {
		for _, pcr := range bank.PCRs {
			logger.Infof("%s %d: 0x%s",
				bank.Algorithm, pcr.ID, string(pcr.Value))
		}
	}

	assert.Equal(t, 4, len(banks))
	assert.Equal(t, 23, len(banks[0].PCRs)) // SHA1
	assert.Equal(t, 23, len(banks[1].PCRs)) // SHA256
	assert.Equal(t, 23, len(banks[2].PCRs)) // SHA386
	assert.Equal(t, 23, len(banks[3].PCRs)) // SHA512
}

func TestMakeActivateCredentialWithGeneratedSecret(t *testing.T) {

	_, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	ek, ak, err := tpm.RSAAK()
	assert.Nil(t, err)
	assert.NotNil(t, ek)
	assert.NotNil(t, ak)

	makeCredentialResponse, secret, err := tpm.MakeCredential(ek, ak, nil)
	assert.Nil(t, err)
	assert.NotNil(t, makeCredentialResponse)

	// Make sure valid credential passes
	digest, err := tpm.ActivateCredential(ak, Credential{
		CredentialBlob:  makeCredentialResponse.CredentialBlob.Buffer,
		EncryptedSecret: makeCredentialResponse.Secret.Buffer,
	})
	assert.Nil(t, err)
	assert.NotNil(t, digest)

	// ... and invalid credential secret fails
	digest, err = tpm.ActivateCredential(ak, Credential{
		CredentialBlob:  makeCredentialResponse.CredentialBlob.Buffer,
		EncryptedSecret: []byte("invalid-secret")})
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidActivationCredential, err)
	assert.NotEqual(t, secret, digest)
}

func TestMakeActivateCredential(t *testing.T) {

	_, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	ek, ak, err := tpm.RSAAK()
	assert.Nil(t, err)
	assert.NotNil(t, ek)
	assert.NotNil(t, ak)

	secret := []byte("tpms-are-fun")

	makeCredentialResponse, digest, err := tpm.MakeCredential(ek, ak, secret)
	assert.Nil(t, err)
	assert.NotNil(t, makeCredentialResponse)

	// Make sure valid credential passes
	digest, err = tpm.ActivateCredential(ak, Credential{
		CredentialBlob:  makeCredentialResponse.CredentialBlob.Buffer,
		EncryptedSecret: makeCredentialResponse.Secret.Buffer,
	})
	assert.Nil(t, err)

	if secret != nil {
		assert.Equal(t, secret, digest)
	}

	// ... and invalid credential secret fails
	digest, err = tpm.ActivateCredential(ak, Credential{
		CredentialBlob:  makeCredentialResponse.CredentialBlob.Buffer,
		EncryptedSecret: []byte("invalid-secret")})
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidActivationCredential, err)
	assert.NotEqual(t, secret, digest)
}

func TestCapabilities(t *testing.T) {

	logger, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	caps, err := tpm.Capabilities()
	assert.Nil(t, err)
	assert.NotNil(t, caps)

	logger.Debugf("Vendor: %s", caps.vendor)
	logger.Debugf("Manufacturer: %s", caps.manufacturer.String())
	logger.Debugf("Firmware: %d.%d", caps.fwMajor, caps.fwMinor)
}

func TestRSAEK(t *testing.T) {

	logger, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	ek, err := tpm.RSAEK()
	assert.Nil(t, err)
	assert.NotNil(t, ek.Handle)
	assert.NotNil(t, ek.Name)
	assert.NotNil(t, ek.Public)

	logger.Debugf("ekPub: %+v", ek.Public)
}

func TestRSASRK(t *testing.T) {

	logger, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	ek, err := tpm.RSAEK()
	assert.Nil(t, err)
	assert.NotNil(t, ek.Handle)
	assert.NotNil(t, ek.Name)
	assert.NotNil(t, ek.Public)

	logger.Debugf("ekPub: %+v", ek.Public)

	srkAuth := []byte("my-password")
	srk, err := tpm.RSASRK(ek, srkAuth)
	defer tpm.Flush(srk.Handle)

	assert.Nil(t, err)
	assert.NotNil(t, srk.Handle)
	assert.NotNil(t, srk.Name)
	assert.NotNil(t, srk.Public)

	logger.Debugf("srk.Public: %+v", srk.Public)
}

func TestSealUnseal(t *testing.T) {

	logger, tpm, tmpDir := createSim(false, false)
	defer tpm.Close()
	defer cleanTempDir(tmpDir)

	ek, err := tpm.RSAEK()
	assert.Nil(t, err)
	assert.NotNil(t, ek.Handle)
	assert.NotNil(t, ek.Name)
	assert.NotNil(t, ek.Public)

	logger.Debugf("ek.Public: %+v", ek.Public)

	srkAuth := []byte("my-password")
	srk, err := tpm.RSASRK(ek, srkAuth)
	defer tpm.Flush(srk.Handle)

	assert.Nil(t, err)
	assert.NotNil(t, srk.Handle)
	assert.NotNil(t, srk.Public)

	logger.Debugf("srkPub: %+v", srk.Public)

	sealAuth := []byte("my-seal-password")
	sealName := []byte("my-seal")
	sealData := []byte("my-secret")
	createResponse, err := tpm.Seal(srk, sealAuth, sealName, sealData)
	assert.Nil(t, err)
	assert.NotNil(t, createResponse)

	unsealed, err := tpm.Unseal(srk, createResponse, sealName, sealAuth)
	assert.Nil(t, err)
	assert.NotNil(t, unsealed)

	logger.Debugf("original: %+v", sealData)
	logger.Debugf("sealed: %+v", createResponse.OutPublic.Bytes())
	logger.Debugf("unsealed: %+v", unsealed)
	logger.Debugf("create-response: %+v", createResponse)
	logger.Debugf("creation-hash: %+v", createResponse.CreationHash)
	logger.Debugf("creation-data: %+v", createResponse.CreationData.Bytes())
	logger.Debugf("creation-ticket-digest: %+v", createResponse.CreationTicket.Digest.Buffer)
}

func TestRandom(t *testing.T) {

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("tpm")

	debugSecrets := true
	domain := "test.com"

	// Create TPM instance
	tpm, err := NewTPM2(logger, debugSecrets, &Config{
		Device:         "/dev/tpmrm0",
		EncryptSession: false,
		UseEntropy:     true,
	}, domain)
	if err != nil {
		log.Fatal(err)
	}
	defer tpm.Close()

	assert.Nil(t, err)

	random, err := tpm.Random()
	assert.Nil(t, err)
	assert.NotNil(t, random)
	assert.Equal(t, 32, len(random))

	encoded := hex.EncodeToString(random)

	logger.Debugf("%+s", encoded)
}

// Creates a basic connection the TPM (without creating a CA)
func createTPM(encrypt, entropy bool) (*logging.Logger, TrustedPlatformModule2) {

	debugSecrets := true
	domain := "test.com"

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("tpm")

	tpm, err := NewTPM2(logger, debugSecrets, &Config{
		Device:         "/dev/tpmrm0",
		EncryptSession: encrypt,
		UseEntropy:     entropy,
	}, domain)
	if err != nil {
		logger.Fatal(err)
	}

	return logger, tpm
}

// Creates a connection a simulated TPM (without creating a CA)
func createSim(encrypt, entropy bool) (*logging.Logger, TrustedPlatformModule2, string) {

	debugSecrets := true
	domain := "test.com"

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("tpm")

	tpm, err := NewSimulation(logger, debugSecrets, &Config{
		EncryptSession: encrypt,
		UseEntropy:     entropy,
		EKCert:         "ECcert.bin",
		Device:         "/dev/tpm0",
		UseSimulator:   true,
	}, domain)
	if err != nil {
		logger.Fatal(err)
	}

	config, err := defaultConfig()
	if err != nil {
		logger.Fatal(err)
	}

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	ca := createCA(config, rootPass, intermediatePass, true)

	tpm.SetCertificateAuthority(ca)

	return logger, tpm, config.Home
}

func cleanTempDir(dir string) {
	if CLEAN_TMP {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Errorf("%S", err)
		}
	}
}

func createCA(
	config *ca.Config,
	rootPass, intermediatePass []byte,
	performInit bool) ca.CertificateAuthority {

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("tpm")

	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logFormatter := logging.NewBackendFormatter(stdout, logFormat)
	backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(backends)

	var err error
	if config == nil {
		config, err = defaultConfig()
		if err != nil {
			logger.Fatal(err)
		}
	}

	// CA constructor params
	params := ca.CAParams{
		Logger:               logger,
		Config:               config,
		Password:             intermediatePass,
		SelectedIntermediate: 1,
		Random:               rand.Reader,
	}

	rootCA, intermediateCA, err := ca.NewCA(params)
	if err != nil {
		if err == ca.ErrNotInitialized && performInit {
			privKey, cert, initErr := rootCA.Init(nil, nil, rootPass, rand.Reader)
			if initErr != nil {
				logger.Fatal(err)
			}
			_, _, initErr = intermediateCA.Init(privKey, cert, intermediatePass, rand.Reader)
			if initErr != nil {
				logger.Fatal(err)
			}
			err = nil
		} else if performInit {
			logger.Fatal(err)
		}
	} else {
		logger.Warning("CA has already been initialized")
	}

	return intermediateCA
}

// Creates a default CA configuration
func defaultConfig() (*ca.Config, error) {
	rootIdentity := ca.Identity{
		KeySize: 1024, // bits
		Valid:   10,   // years
		Subject: ca.Subject{
			CommonName:   "root-ca",
			Organization: "Example Corporation",
			Country:      "US",
			Locality:     "Miami",
			Address:      "123 acme street",
			PostalCode:   "12345"},
		SANS: &ca.SubjectAlternativeNames{
			DNS: []string{
				"root-ca",
				"root-ca.localhost",
				"root-ca.localhost.localdomain",
			},
			IPs: []string{
				"127.0.0.1",
			},
			Email: []string{
				"root@localhost",
				"root@test.com",
			},
		},
	}

	intermediateIdentity := ca.Identity{
		KeySize: 1024, // bits
		Valid:   10,   // years

		Subject: ca.Subject{
			CommonName:   "intermediate-ca",
			Organization: "Example Corporation",
			Country:      "US",
			Locality:     "Miami",
			Address:      "123 acme street",
			PostalCode:   "12345"},
		SANS: &ca.SubjectAlternativeNames{
			DNS: []string{
				"intermediate-ca",
				"intermediate-ca.localhost",
				"intermediate-ca.localhost.localdomain",
			},
			IPs: []string{
				"127.0.0.1",
			},
			Email: []string{
				"root@localhost",
				"root@test.com",
			},
		},
	}

	// Create a temp directory so parallel tests don't
	// corrupt each other.
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		return nil, err
	}
	tmpDir := hex.EncodeToString(buf)

	return &ca.Config{
		Home:                      fmt.Sprintf("%s/%s", CERTS_DIR, tmpDir),
		AutoImportIssuingCA:       true,
		KeyAlgorithm:              ca.KEY_ALGO_RSA,
		KeyStore:                  ca.KEY_STORE_PKCS8,
		SignatureAlgorithm:        "SHA256WithRSA",
		RSAScheme:                 ca.RSA_SCHEME_RSAPSS,
		Hash:                      "SHA256",
		EllipticalCurve:           ca.CURVE_P256,
		RetainRevokedCertificates: false,
		//PasswordPolicy:            "^[a-zA-Z0-9-_]+$",
		PasswordPolicy:            "^*$",
		RequirePrivateKeyPassword: true,
		Identity: []ca.Identity{
			rootIdentity,
			intermediateIdentity},
	}, nil
}

/*
// Verify CA chain:

	openssl verify \
	  -CAfile db/certs/root-ca/root-ca.crt \
	  db/certs/intermediate-ca/intermediate-ca.crt

// Verify CA chain & server certificate:

	openssl verify \
	 -CAfile db/certs/intermediate-ca/trusted-root/root-ca.crt \
	 -untrusted db/certs/intermediate-ca/intermediate-ca.crt \
	 db/certs/intermediate-ca/issued/localhost/localhost.crt

// Verify EK chain & certificate:

	openssl verify \
	 -CAfile db/certs/intermediate-ca/trusted-root/www.intel.com.crt \
	 -untrusted db/certs/intermediate-ca/trusted-intermediate/CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.crt \
	 db/certs/intermediate-ca/issued/tpm-ek/tpm-ek.crt
*/
// func TestTPM(t *testing.T) {

// 	logger, tp, _, err := createTP(false) // tp, CA, err
// 	defer tp.Close()

// 	assert.Nil(t, err)

// 	// openssl rsa -in certs/ca.key -text (-check)
// 	// openssl x509 -in certs/ca.crt -text -noout
// 	//
// 	// openssl rsa -pubin -in certs/tpm-ek.key.pub -text
// 	// openssl rsa -pubin -in certs/tpm-ek.key.pub.der -inform DER -text
// 	// openssl x509 -in certs/tpm-ek.der -inform DER -noout -text
// 	// openssl x509 -in certs/tpm-ek.crt -noout -text
// 	err = tp.Init()
// 	assert.Nil(t, err)

// 	//log.Printf("%+v", tp.EK())

// 	tpm := tp.AttestTPM()

// 	akConfig := &attest.AKConfig{}
// 	ak, err := tpm.NewAK(akConfig)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	nonce, err := tp.Random()
// 	assert.Nil(t, err)

// 	_, err = tpm.AttestPlatform(ak, nonce, nil)
// 	assert.Nil(t, err)
// 	// for _, e := range platformParameters.EventLog {
// 	// 	fmt.Printf("%x", e)
// 	// }

// 	attestParams := ak.AttestationParameters()
// 	logger.Infof("%+v", attestParams)

// 	akBytes, err := ak.Marshal()
// 	if err != nil {
// 		logger.Fatal(err)
// 	}

// 	if err := os.WriteFile("encrypted_aik.json", akBytes, 0600); err != nil {
// 		logger.Fatal(err)
// 	}
// }

// func TestCreateAK(t *testing.T) {

// 	logger, tpm := createSim(false, false)
// 	defer tpm.Close()

// 	ek, err := tpm.RSAEK()
// 	assert.Nil(t, err)
// 	assert.NotNil(t, ek.Handle)
// 	assert.NotNil(t, ek.Name)
// 	assert.NotNil(t, ek.Public)

// 	logger.Debugf("ek.Public: %+v", ek.Public)

// 	// Set a password for the SRK
// 	srkAuth := []byte("my-password")

// 	srk, err := tpm.RSASRK(ek, srkAuth)
// 	defer tpm.Flush(srk.Handle)

// 	// Supply the password to CreateAK
// 	srk.Auth = srkAuth

// 	assert.Nil(t, err)
// 	assert.NotNil(t, srk.Handle)
// 	assert.NotNil(t, srk.Name)
// 	assert.NotNil(t, srk.Public)

// 	logger.Debugf("srkPub: %+v", srk.Public)

// 	createResponse, err := tpm.CreateAK(srk)
// 	assert.Nil(t, err)
// 	assert.NotNil(t, createResponse)

// 	logger.Debugf("CreationHash: %+v", createResponse.CreationHash)
// 	logger.Debugf("CreationData: %+v", createResponse.CreationData)
// 	logger.Debugf("CreationText: %+v", createResponse.CreationTicket)

// 	outPub, err := createResponse.OutPublic.Contents()
// 	assert.Nil(t, err)
// 	assert.NotNil(t, outPub)

// 	logger.Debugf("outPub: %+v", outPub)

// 	assert.NotNil(t, tpm.EKRSAPubKey())
// 	logger.Debugf("tpm.EKRSAPubKey: %+v", tpm.EKRSAPubKey())
// }

// func TestMap(t *testing.T) {

// 	logger, tpm := createSim(false, false)
// 	defer tpm.Close()

// 	m := []int{
// 		0, 1, 2, 3, 4, 5,
// 	}
// 	val := m[:2]

// 	logger.Infof("value = %+v", val)
// }

// Creates a new TPM for testing
// func createTP(encrypt bool) (*logging.Logger, TrustedPlatformModule2, ca.CertificateAuthority, error) {

// 	debugSecrets := true
// 	domain := "test.com"

// 	stdout := logging.NewLogBackend(os.Stdout, "", 0)
// 	logging.SetBackend(stdout)
// 	logger := logging.MustGetLogger("tpm")

// 	// Create TPM instance
// 	tpm, err := NewTPM2(logger, debugSecrets, &Config{
// 		Device: "/dev/tpmrm0",
// 		//EnableEncryption: encrypt,
// 		UseEntropy: false,
// 	}, domain)
// 	if err != nil {
// 		logger.Fatal(err)
// 	}

// 	intermediateCA := createCA()
// 	tpm.SetCertificateAuthority(intermediateCA)

// 	// Generate server certificate
// 	certReq := ca.CertificateRequest{
// 		Valid: 365, // days
// 		Subject: ca.Subject{
// 			CommonName:   "localhost",
// 			Organization: "ACME Corporation",
// 			Country:      "US",
// 			Locality:     "Miami",
// 			Address:      "123 acme street",
// 			PostalCode:   "12345"},
// 		SANS: &ca.SubjectAlternativeNames{
// 			DNS: []string{
// 				"localhost",
// 				"localhost.localdomain",
// 			},
// 			IPs: []string{
// 				"127.0.0.1",
// 			},
// 			Email: []string{
// 				"root@localhost",
// 				"root@test.com",
// 			},
// 		},
// 	}

// 	// Issue a new test certificate using random number generator
// 	_, err = intermediateCA.IssueCertificate(certReq)
// 	if err != nil {
// 		logger.Fatal(err)
// 	}

// 	return logger, tpm, intermediateCA, nil
// }
