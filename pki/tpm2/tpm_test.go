package tpm2

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pki/ca"
	"github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
)

// Create a fake TPM cert
// https://gist.github.com/op-ct/e202fc911de22c018effdb3371e8335f
// https://github.com/osresearch/safeboot/pull/85

var currentWorkingDirectory, _ = os.Getwd()
var CERTS_DIR = fmt.Sprintf("%s/certs", currentWorkingDirectory)

const (
	EK_CERT_PATH = "./ECcert.bin"
)

//var CERTS_DIR = "./certs"

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
	// os.RemoveAll(CERTS_DIR)
}

func setup() {
	os.RemoveAll(CERTS_DIR)
}

func TestParseEventLog(t *testing.T) {

	logger, tpm := createSim(false, false)

	eventLog, err := tpm.Measurements(nil)
	assert.Nil(t, err)
	assert.NotNil(t, eventLog)

	logger.Debug("%+v", eventLog)
}

func TestMakeActivateCredential(t *testing.T) {

	logger, tpm := createSim(false, false)

	srkAuth := []byte("my-password")

	secret := []byte("my-secret")
	ekHandle, ekName, srkHandle, srkName, srkPub, makeCredentialResponse, err := tpm.MakeCredential(srkAuth, secret)
	assert.Nil(t, err)

	defer tpm.Flush(ekHandle)
	defer tpm.Flush(srkHandle)

	logger.Debugf("MakeCredential: encrypted-secret: %+v", makeCredentialResponse.CredentialBlob.Buffer)

	activateCredentialResponse, err := tpm.ActivateCredential(
		ekHandle,
		ekName,
		srkHandle,
		srkName,
		srkPub,
		srkAuth,
		makeCredentialResponse.CredentialBlob,
		makeCredentialResponse.Secret)
	assert.Nil(t, err)
	assert.NotNil(t, activateCredentialResponse)

	decrypted := activateCredentialResponse.CertInfo.Buffer

	logger.Debugf("ActivateCredential: secret: %s", decrypted)

	assert.Equal(t, secret, decrypted)
}

func TestCreateAK(t *testing.T) {

	logger, tpm := createSim(false, false)

	ekHandle, ekName, ekPub, err := tpm.RSAEK()
	assert.Nil(t, err)
	assert.NotNil(t, ekHandle)
	assert.NotNil(t, ekName)
	assert.NotNil(t, ekPub)

	logger.Debugf("ekPub: %+v", ekPub)

	srkAuth := []byte("my-password")
	srkHandle, srkName, srkPub, err := tpm.CreateSRK(nil, ekPub, srkAuth)
	defer tpm.Flush(srkHandle)

	assert.Nil(t, err)
	assert.NotNil(t, srkHandle)
	assert.NotNil(t, srkName)
	assert.NotNil(t, srkPub)

	logger.Debugf("srkPub: %+v", srkPub)

	createResponse, err := tpm.CreateAK(
		srkHandle,
		srkName,
		srkPub,
		srkAuth)
	assert.Nil(t, err)
	assert.NotNil(t, createResponse)

	logger.Debugf("CreationHash: %+v", createResponse.CreationHash)
	logger.Debugf("CreationData: %+v", createResponse.CreationData)
	logger.Debugf("CreationText: %+v", createResponse.CreationTicket)

	outPub, err := createResponse.OutPublic.Contents()
	assert.Nil(t, err)
	assert.NotNil(t, outPub)

	logger.Debugf("outPub: %+v", outPub)

	assert.NotNil(t, tpm.EKRSAPubKey())
	logger.Debugf("tpm.EKRSAPubKey: %+v", tpm.EKRSAPubKey())

}

func TestImportTSS(t *testing.T) {

	expectedSN := "455850945431947993541652326598156649892946412448"

	logger, tpm, ca, err := createTP(false)
	assert.Nil(t, err)
	assert.NotNil(t, logger)
	assert.NotNil(t, tpm)
	assert.NotNil(t, ca)

	cert, err := tpm.ImportTSSFile(EK_CERT_PATH, true)
	assert.Nil(t, err)
	assert.Equal(t, expectedSN, cert.SerialNumber.String())

	logger.Debugf("%+v", cert)
}

func TestReadPCRs(t *testing.T) {

	logger, tpm := createSim(false, false)

	algos, err := tpm.ReadPCRs()
	assert.Nil(t, err)
	assert.NotNil(t, algos)

	for algoK, algoV := range algos {

		logger.Infof("%s", algoK)

		for pcrK, pcrV := range algoV {
			logger.Infof("%d: 0x%s", pcrK, pcrV)
		}
	}
}

func TestCapabilities(t *testing.T) {

	logger, tpm := createSim(false, false)

	caps, err := tpm.Capabilities()
	assert.Nil(t, err)
	assert.NotNil(t, caps)

	logger.Debugf("Vendor: %s", caps.vendor)
	logger.Debugf("Manufacturer: %s", caps.manufacturer.String())
	logger.Debugf("Firmware: %d.%d", caps.fwMajor, caps.fwMinor)
}

func TestEKCert(t *testing.T) {

	logger, tpm := createSim(true, false)

	ca := createCA()

	tpm.SetCertificateAuthority(ca)

	cert, err := tpm.EKCert(nil, nil)
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	logger.Debugf("cert: %+v", cert)
}

func TestEK(t *testing.T) {

	logger, tpm := createSim(false, false)

	ekHandle, ekName, ekPub, err := tpm.RSAEK()
	assert.Nil(t, err)
	assert.NotNil(t, ekHandle)
	assert.NotNil(t, ekName)
	assert.NotNil(t, ekPub)

	logger.Debugf("ekPub: %+v", ekPub)
}

func TestCreateSRK(t *testing.T) {

	logger, tpm := createSim(false, false)

	ekHandle, ekName, ekPub, err := tpm.RSAEK()
	assert.Nil(t, err)
	assert.NotNil(t, ekHandle)
	assert.NotNil(t, ekName)
	assert.NotNil(t, ekPub)

	logger.Debugf("ekPub: %+v", ekPub)

	srkAuth := []byte("my-password")
	srkHandle, srkName, srkPub, err := tpm.CreateSRK(nil, ekPub, srkAuth)
	defer tpm.Flush(srkHandle)

	assert.Nil(t, err)
	assert.NotNil(t, srkHandle)
	assert.NotNil(t, srkName)
	assert.NotNil(t, srkPub)

	logger.Debugf("srkPub: %+v", srkPub)
}

func TestSealUnseal(t *testing.T) {

	logger, tpm := createSim(false, false)

	ekHandle, ekName, ekPub, err := tpm.RSAEK()
	assert.Nil(t, err)
	assert.NotNil(t, ekHandle)
	assert.NotNil(t, ekName)
	assert.NotNil(t, ekPub)

	logger.Debugf("ekPub: %+v", ekPub)

	srkAuth := []byte("my-password")
	srkHandle, srkName, srkPub, err := tpm.CreateSRK(nil, ekPub, srkAuth)
	defer tpm.Flush(srkHandle)

	assert.Nil(t, err)
	assert.NotNil(t, srkHandle)
	assert.NotNil(t, srkPub)

	logger.Debugf("srkPub: %+v", srkPub)

	sealAuth := []byte("my-seal-password")
	sealName := []byte("my-seal")
	sealData := []byte("my-secret")
	createResponse, err := tpm.Seal(srkHandle, srkName, srkPub, srkAuth, sealAuth, sealName, sealData)
	assert.Nil(t, err)
	assert.NotNil(t, createResponse)

	unsealed, err := tpm.Unseal(srkHandle, srkName, srkPub, srkAuth, createResponse, sealName, sealAuth)
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

func TestRandom(t *testing.T) {

	//logger, tpm, _, err := createTP(true) // tp, CA, err
	//	defer tpm.Close()

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("tpm")

	domain := "test.com"

	// Create TPM instance
	tpm, err := NewTPM2(logger, &Config{
		Device:         "/dev/tpmrm0",
		EncryptSession: false,
		UseEntropy:     true,
	}, domain)
	if err != nil {
		log.Fatal(err)
	}

	assert.Nil(t, err)

	random, err := tpm.Random()
	assert.Nil(t, err)
	assert.NotNil(t, random)
	assert.Equal(t, 32, len(random))

	encoded := hex.EncodeToString(random)

	logger.Debugf("%+s", encoded)
}

// Creates a connection a simulated TPM (without creating a CA)
func createSim(encrypt, entropy bool) (*logging.Logger, TrustedPlatformModule2) {

	domain := "test.com"

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("tpm")

	tpm, err := NewSimulation(logger, &Config{
		EncryptSession: encrypt,
		UseEntropy:     entropy,
	}, domain)
	if err != nil {
		logger.Fatal(err)
	}

	return logger, tpm
}

// Creates a basic connection the TPM (without creating a CA)
func createTPM(encrypt, entropy bool) (*logging.Logger, TrustedPlatformModule2) {

	domain := "test.com"

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("tpm")

	tpm, err := NewTPM2(logger, &Config{
		Device:         "/dev/tpmrm0",
		EncryptSession: encrypt,
		UseEntropy:     entropy,
	}, domain)
	if err != nil {
		logger.Fatal(err)
	}

	return logger, tpm
}

// Creates a new TPM for testing
func createTP(encrypt bool) (*logging.Logger, TrustedPlatformModule2, ca.CertificateAuthority, error) {

	domain := "test.com"

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("tpm")

	// Create TPM instance
	tpm, err := NewTPM2(logger, &Config{
		Device: "/dev/tpmrm0",
		//EnableEncryption: encrypt,
		UseEntropy: false,
	}, domain)
	if err != nil {
		logger.Fatal(err)
	}

	intermediateCA := createCA()
	tpm.SetCertificateAuthority(intermediateCA)

	// Generate server certificate
	certReq := ca.CertificateRequest{
		Valid: 365, // days
		Subject: ca.Subject{
			CommonName:   "localhost",
			Organization: "ACME Corporation",
			Country:      "US",
			Locality:     "Miami",
			Address:      "123 acme street",
			PostalCode:   "12345"},
		SANS: &ca.SubjectAlternativeNames{
			DNS: []string{
				"localhost",
				"localhost.localdomain",
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

	// Create TPM based random character reader
	random, err := tpm.RandomReader()
	if err != nil {
		logger.Fatal(random)
	}

	// Issue a new test certificate using random number generator
	_, err = intermediateCA.IssueCertificate(certReq, random)
	if err != nil {
		logger.Fatal(err)
	}

	return logger, tpm, intermediateCA, nil
}

func createCA() ca.CertificateAuthority {

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("certificate-authority")

	// Create Root and Intermediate Certificate Authorities
	rootIdentity := ca.Identity{
		KeySize: 1024, // bits
		Valid:   10,   // years
		Subject: ca.Subject{
			CommonName:   "root-ca",
			Organization: "ACME Corporation",
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
			Organization: "ACME Corporation",
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

	// Initialize CA config
	config := &ca.Config{
		AutoImportIssuingCA: true,
		Identity: []ca.Identity{
			rootIdentity,
			intermediateIdentity},
	}

	// Create the CAs
	_, intermediateCAs, err := ca.NewCA(logger, CERTS_DIR, config, rand.Reader)
	if err != nil {
		logger.Fatal(err)
	}
	intermediateCA := intermediateCAs["intermediate-ca"]

	return intermediateCA
}
