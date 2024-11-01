package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs11"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs8"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	tpm2ks "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/tpm2"
)

/*
// Verify CA chain:

	openssl verify \
	  -CAfile testdata/root-ca/root-ca.crt \
	  testdata/intermediate-ca/intermediate-ca.crt

// Verify CA chain & server certificate:

	openssl verify \
	 -CAfile testdata/intermediate-ca/trusted-root/root-ca.crt \
	 -untrusted testdata/intermediate-ca/intermediate-ca.crt \
	 testdata/intermediate-ca/issued/localhost/localhost.crt

// Verify EK chain & certificate:

	openssl verify \
	 -CAfile testdata/intermediate-ca/trusted-root/www.intel.com.crt \
	 -untrusted testdata/intermediate-ca/trusted-intermediate/CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.crt \
	 testdata/intermediate-ca/issued/tpm-ek/tpm-ek.crt
*/

var TEST_DATA_DIR = "./testdata"
var SOFTHSM_DATA_DIR = "./trusted-data"
var INTEL_CERT_URL = "https://trustedservices.intel.com/content/CRL/ekcert/CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.cer"
var CLEAN_TMP = false
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

	os.RemoveAll(TEST_DATA_DIR)
	os.RemoveAll(SOFTHSM_DATA_DIR)

	if err := os.MkdirAll(TEST_DATA_DIR+"/trusted-data/etc", os.ModePerm); err != nil {
		fmt.Println(err)
		return
	}
}

func TestInit(t *testing.T) {

	performInit := true
	encrypt := false
	entropy := false

	config := &DefaultConfig
	assert.NotNil(t, config)

	rootCA, intermediateCA, tpm, tmp, err := createService(
		config, performInit, encrypt, entropy)
	assert.Nil(t, err)
	defer tpm.Close()
	defer cleanTempDir(tmp)

	assert.Nil(t, err)
	assert.NotNil(t, rootCA)
	assert.NotNil(t, intermediateCA)

	caKeyAttrs, err := rootCA.CAKeyAttributes(
		keystore.STORE_TPM2, x509.RSA)
	assert.Nil(t, err)
	bundle, err := intermediateCA.CABundle(
		&caKeyAttrs.StoreType, &caKeyAttrs.KeyAlgorithm)
	assert.NotNil(t, bundle)
	fmt.Println(string(bundle))
}

func TestPasswordComplexity(t *testing.T) {

	pattern := "^[a-zA-Z0-9-_!@#$%^&*() /\\\\+]{10,20}$"

	var err error
	var matcher *regexp.Regexp
	matcher, err = regexp.Compile(pattern)
	assert.Nil(t, err)
	assert.NotNil(t, matcher)

	matches := matcher.MatchString("password")
	assert.False(t, matches)

	matches = matcher.MatchString("p\\s!@#$%^&*()-+swo ")
	assert.True(t, matches)
}

func TestImportIssuingCAs(t *testing.T) {

	performInit := true
	encrypt := false
	entropy := false

	config := &DefaultConfig
	assert.NotNil(t, config)

	_, intermediateCA, tpm, _, err := createService(
		config, performInit, encrypt, entropy)
	defer tpm.Close()

	// Download the certificate
	resp, err := http.Get(INTEL_CERT_URL)
	assert.Nil(t, err)

	// Read the certificate into a memory buffer
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, resp.Body)
	assert.Nil(t, err)

	bufBytes := buf.Bytes()

	// Parse the cert to make sure its valid
	cert, err := x509.ParseCertificate(bufBytes)
	assert.Nil(t, err)

	err = intermediateCA.ImportIssuingCAs(cert)
	assert.Nil(t, err)

	err = intermediateCA.ImportIssuingCAs(cert)
	assert.Equal(t, certstore.ErrTrustExists, err)
}

func TestDownloadDistribuitionCRLs(t *testing.T) {

	performInit := true
	encrypt := false
	entropy := false

	config := &DefaultConfig
	assert.NotNil(t, config)

	rootCA, _, tpm, _, err := createService(
		config, performInit, encrypt, entropy)
	defer tpm.Close()

	// Download the certificate
	resp, err := http.Get(INTEL_CERT_URL)
	assert.Nil(t, err)

	// Read the certificate into a memory buffer
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, resp.Body)
	assert.Nil(t, err)

	bufBytes := buf.Bytes()

	// Parse the cert to make sure its valid
	cert, err := x509.ParseCertificate(bufBytes)
	assert.Nil(t, err)

	// Import it
	err = rootCA.ImportDistrbutionCRLs(cert)
	assert.Nil(t, err)

	// Import it again and make sure it fails with already exists
	err2 := rootCA.ImportDistrbutionCRLs(cert)
	assert.Equal(t, ErrCRLAlreadyExists, err2)
}

func TestIssueCertificateWithPassword(t *testing.T) {

	performInit := true
	encrypt := false
	entropy := false

	config := &DefaultConfig
	assert.NotNil(t, config)

	rootCA, _, tpm, _, err := createService(
		config, performInit, encrypt, entropy)
	defer tpm.Close()

	caKeyAttrs, err := rootCA.CAKeyAttributes(
		keystore.STORE_TPM2, x509.RSA)
	assert.Nil(t, err)

	attrs, err := keystore.Template(caKeyAttrs.KeyAlgorithm)
	attrs.KeyType = keystore.KEY_TYPE_TLS
	attrs.CN = "www.example.com"
	attrs.Password = keystore.NewClearPassword([]byte("server-password"))

	certReq := CertificateRequest{
		KeyAttributes: attrs,
		Valid:         365, // days
		Subject: Subject{
			CommonName:   attrs.CN,
			Organization: "Test Corporation",
			Country:      "US",
			Locality:     "Miami",
			Address:      "123 acme street",
			PostalCode:   "12345"},
		SANS: &SubjectAlternativeNames{
			DNS: []string{
				attrs.CN,
				"localhost",
				"localhost.localdomain",
			},
			IPs: []string{
				"127.0.0.1",
				"127.0.0.2",
			},
			Email: []string{
				"root@localhost",
				"root@test.com",
			},
		},
	}
	// Issue certificate using golang runtime random number
	// generator when creating the private key
	der, err := rootCA.IssueCertificate(certReq)
	assert.Nil(t, err)
	assert.NotNil(t, der)

	cert, err := x509.ParseCertificate(der)
	assert.Nil(t, err)
	assert.Equal(t, attrs.CN, cert.Subject.CommonName)
}

func TestIssueCertificate_CA_RSA_WITH_LEAF_ECDSA(t *testing.T) {

	performInit := true
	encrypt := false
	entropy := false

	config := &DefaultConfig
	assert.NotNil(t, config)

	rootCA, _, tpm, _, err := createService(
		config, performInit, encrypt, entropy)
	defer tpm.Close()

	logger := logging.DefaultLogger()
	DebugCipherSuites(logger)
	DebugInsecureCipherSuites(logger)

	attrs, err := keystore.Template(x509.ECDSA)
	attrs.KeyType = keystore.KEY_TYPE_TLS
	attrs.CN = "www.example.com"
	attrs.Password = keystore.NewClearPassword([]byte("server-password"))

	certReq := CertificateRequest{
		KeyAttributes: attrs,
		Valid:         365, // days
		Subject: Subject{
			CommonName:   attrs.CN,
			Organization: "ACME Corporation",
			Country:      "US",
			Locality:     "Miami",
			Address:      "123 acme street",
			PostalCode:   "12345"},
		SANS: &SubjectAlternativeNames{
			DNS: []string{
				attrs.CN,
				"localhost",
				"localhost.localdomain",
			},
			IPs: []string{
				"127.0.0.1",
				"127.0.0.2",
			},
			Email: []string{
				"root@localhost",
				"root@test.com",
			},
		},
	}
	// Issue certificate using golang runtime random number
	// generator when creating the private key
	der, err := rootCA.IssueCertificate(certReq)
	assert.Nil(t, err)
	assert.NotNil(t, der)

	cert, err := x509.ParseCertificate(der)
	assert.Nil(t, err)
	assert.Equal(t, attrs.CN, cert.Subject.CommonName)
}

func TestIssueCertificateWithoutPassword(t *testing.T) {

	performInit := true
	encrypt := false
	entropy := false

	config := &DefaultConfig
	assert.NotNil(t, config)

	rootCA, _, tpm, _, err := createService(
		config, performInit, encrypt, entropy)
	defer tpm.Close()

	caKeyAttrs, err := rootCA.CAKeyAttributes(
		keystore.STORE_TPM2, x509.RSA)
	assert.Nil(t, err)

	attrs, err := keystore.Template(caKeyAttrs.KeyAlgorithm)
	attrs.KeyType = keystore.KEY_TYPE_TLS
	attrs.CN = "www.example.com"
	attrs.Password = keystore.NewClearPassword([]byte("server-password"))

	certReq := CertificateRequest{
		KeyAttributes: attrs,
		Valid:         365, // days
		Subject: Subject{
			CommonName:   attrs.CN,
			Organization: "Test Corporation",
			Country:      "US",
			Locality:     "Miami",
			Address:      "123 acme street",
			PostalCode:   "12345"},
		SANS: &SubjectAlternativeNames{
			DNS: []string{
				attrs.CN,
				"localhost",
				"localhost.localdomain",
			},
			IPs: []string{
				"127.0.0.1",
				"127.0.0.2",
			},
			Email: []string{
				"root@localhost",
				"root@test.com",
			},
		},
	}
	// Issue certificate using golang runtime random number
	// generator when creating the private key
	der, err := rootCA.IssueCertificate(certReq)
	assert.Nil(t, err)
	assert.NotNil(t, der)

	cert, err := x509.ParseCertificate(der)
	assert.Nil(t, err)
	assert.Equal(t, attrs.CN, cert.Subject.CommonName)
}

func cleanTempDir(dir string) {
	if CLEAN_TMP {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Errorf("%S", err)
		}
	}
}

// Initialize Root and Intermediate Certificate Authorities
// based on configuration
//
// Root CA certificates
// openssl rsa -in testdata/ca/root-ca.key -text (-check)
// openssl x509 -in testdata/ca/root-ca.crt -text -noout
// openssl rsa -pubin -in platform/ca/root-ca.pub -text
//
// Intermediate CA certificates
// openssl rsa -in testdata/ca/intermediate-ca.key -text (-check)
// openssl x509 -in testdata/ca/intermediate-ca.crt -text -noout
// openssl rsa -pubin -in testdata/ca/intermediate-ca.pub -text

func TestRSAGenerateAndSignCSR_Then_VerifyAndRevoke(t *testing.T) {

	performInit := true
	encrypt := false
	entropy := false

	config := &DefaultConfig
	assert.NotNil(t, config)

	_, intermediateCA, tpm, tmp, err := createService(
		config, performInit, encrypt, entropy)
	defer tpm.Close()

	defer cleanTempDir(tmp)

	// publicKey := intermediateCA.Public()
	caKeyAttrs, err := intermediateCA.CAKeyAttributes(
		keystore.STORE_TPM2, x509.RSA)
	assert.Nil(t, err)

	attrs, err := keystore.Template(caKeyAttrs.KeyAlgorithm)
	attrs.KeyType = keystore.KEY_TYPE_TLS
	attrs.CN = "www.test.com"

	// openssl rsa -in www.test.com.key -check
	// openssl x509 -in www.test.com.crt -text -noout
	certReq := CertificateRequest{
		KeyAttributes: attrs,
		Valid:         365, // 1 days
		Subject: Subject{
			CommonName:         attrs.CN,
			Organization:       "Test Organization",
			OrganizationalUnit: "Web Services",
			Country:            "US",
			Locality:           "New York",
			Address:            "123 anywhere street",
			PostalCode:         "54321"},
		SANS: &SubjectAlternativeNames{
			DNS: []string{
				"localhost",
				"localhost.localdomain",
			},
			IPs: []string{
				"127.0.0.1",
			},
			Email: []string{
				"user@testorg.com",
				"root@test.com",
			},
		},
	}

	// openssl req -in testme.example.com.csr -noout -text
	csrBytes, err := intermediateCA.CreateCSR(certReq)
	assert.Nil(t, err)
	assert.NotNil(t, csrBytes)

	// openssl x509 -in testme.example.com.crt -text -noout
	cert, err := intermediateCA.SignCSR(csrBytes, &certReq)
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	// Encode from ASN.1 DER to PEM
	pem, err := EncodePEM(cert.Raw)
	assert.Nil(t, err)
	assert.NotNil(t, pem)

	// Make sure the cert is valid
	err = intermediateCA.Verify(cert)
	assert.Nil(t, err)

	err = intermediateCA.Revoke(cert, true)
	assert.Nil(t, err)

	// Revoke the certificate again to ensure it errors
	err = intermediateCA.Revoke(cert, true)
	assert.Equal(t, certstore.ErrCertRevoked, err)

	// Make sure the cert is no longer valid
	err = intermediateCA.Verify(cert)
	assert.NotNil(t, err)
	assert.Equal(t, certstore.ErrCertRevoked, err)

	// Test the web server certificate
	//
	// openssl s_client \
	//   -connect localhost:8443 \
	//   -servername localhost  | openssl x509 -noout -text
}

func createService(
	config *Config,
	performInit bool,
	encrypt, entropy bool) (CertificateAuthority,
	CertificateAuthority, tpm2.TrustedPlatformModule, string, error) {

	logger := logging.DefaultLogger()

	soPinBytes := []byte("so-pin-test")
	pinBytes := []byte("user-pin-test")

	soPIN := keystore.NewClearPassword(soPinBytes)
	userPIN := keystore.NewClearPassword(pinBytes)

	// Create temp directory for each test
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		logger.FatalError(err)
	}
	hexVal := hex.EncodeToString(buf)
	tmp := fmt.Sprintf("%s/%s", TEST_DATA_DIR, hexVal)

	//
	// Setup Global Platform Objects
	//

	// Create global platform blob store
	// fs := afero.NewMemMapFs()
	fs := afero.NewOsFs()
	platformBlobStore, err := blob.NewFSBlobStore(logger, fs, tmp, nil)
	if err != nil {
		logger.FatalError(err)
	}

	// Write SoftHSM config
	softhsm_conf := fmt.Sprintf("%s/softhsm.conf", tmp)
	conf := strings.ReplaceAll(string(TEST_SOFTHSM_CONF), "testdata/", tmp)
	err = os.WriteFile(softhsm_conf, []byte(conf), os.ModePerm)
	if err != nil {
		return nil, nil, nil, "", err
	}

	platformBackend := keystore.NewFileBackend(logger, afero.NewMemMapFs(), tmp+"/platform")

	// Create new TPM simulator
	tpmConfig := &tpm2.Config{
		// HierarchiesAuth: keystore.DEFAULT_PASSWORD,
		EncryptSession: encrypt,
		UseEntropy:     entropy,
		Device:         "/dev/tpmrm0",
		UseSimulator:   true,
		Hash:           "SHA-256",
		EK: &tpm2.EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: keystore.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
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
		PlatformPCR: 16,
		FileIntegrity: []string{
			"./",
		},
		KeyStore: &tpm2.KeyStoreConfig{
			// SRKAuth:        keystore.DEFAULT_PASSWORD,
			SRKAuth:        "testme",
			SRKHandle:      0x81000001,
			PlatformPolicy: true,
		},
	}
	tpmParams := &tpm2.Params{
		Logger:       logging.DefaultLogger(),
		DebugSecrets: true,
		Config:       tpmConfig,
		BlobStore:    platformBlobStore,
		Backend:      platformBackend,
		FQDN:         "node1.example.com",
	}

	// Provision EK and Shared SRK
	tpm, err := tpm2.NewTPM2(tpmParams)
	if err != nil {
		if err == tpm2.ErrNotInitialized {
			if err = tpm.Provision(soPIN); err != nil {
				logger.FatalError(err)
			}
		} else {
			logger.FatalError(err)
		}
	}

	// Create platform signer store
	platformSignerStore := keystore.NewSignerStore(platformBlobStore)

	// Create the platform key store
	platformKSParams := &tpm2ks.Params{
		Backend:      platformBackend,
		Logger:       logger,
		DebugSecrets: true,
		Config: &tpm2.KeyStoreConfig{
			CN:             "keystore",
			SRKHandle:      0x81000002,
			SRKAuth:        string(soPinBytes),
			PlatformPolicy: true,
		},
		PlatformKeyStore: nil,
		SignerStore:      platformSignerStore,
		TPM:              tpm,
	}
	platformKS, err := tpm2ks.NewKeyStore(platformKSParams)
	if err != nil {
		if err == keystore.ErrNotInitalized {
			err = platformKS.Initialize(soPIN, userPIN)
			if err != nil {
				logger.FatalError(err)
			}
		} else {
			logger.FatalError(err)
		}
	}

	//
	// Setup Root CA
	//

	rootHome := tmp + "/ca/root"

	rootKeyBackend := keystore.NewFileBackend(logger, afero.NewMemMapFs(), rootHome)

	// Create root CA blob store
	rootBlobStore, err := blob.NewFSBlobStore(
		logger, fs, rootHome, &config.Identity[0].Subject.CommonName)
	if err != nil {
		logger.FatalError(err)
	}

	rootSignerStore := keystore.NewSignerStore(rootBlobStore)

	// Create x509 certificate store
	rootCertStore, err := certstore.NewCertificateStore(
		logger, rootBlobStore)
	if err != nil {
		logger.FatalError(err)
	}

	// Create root CA key chain
	slot := 0
	rootKeyringConfig := &platform.KeyringConfig{
		CN: "root-ca",
		PKCS8Config: &pkcs8.Config{
			PlatformPolicy: true,
		},
		PKCS11Config: &pkcs11.Config{
			Library:        "/usr/local/lib/softhsm/libsofthsm2.so",
			LibraryConfig:  softhsm_conf,
			Slot:           &slot,
			TokenLabel:     "SoftHSM",
			SOPin:          string(soPinBytes),
			Pin:            string(pinBytes),
			PlatformPolicy: true,
		},
		TPMConfig: &tpm2.KeyStoreConfig{
			// CN:             "Test",
			SRKHandle:      0x81000003,
			SRKAuth:        string(pinBytes),
			PlatformPolicy: true,
		},
	}

	rootKC, err := platform.NewKeyring(
		logger,
		true,
		fs,
		tmp,
		rand.Reader,
		rootKeyringConfig,
		rootKeyBackend,
		rootBlobStore,
		rootSignerStore,
		tpm,
		// rootTPMKS,
		platformKS,
		soPIN,
		userPIN)
	if err != nil {
		logger.FatalError(err)
	}

	rootParams := CAParams{
		Backend:      rootKeyBackend,
		BlobStore:    rootBlobStore,
		CertStore:    rootCertStore,
		Config:       *config,
		Debug:        true,
		DebugSecrets: true,
		Fs:           fs,
		Home:         tmp,
		Identity:     config.Identity[0],
		Keyring:      rootKC,
		Logger:       logger,
		Random:       rand.Reader,
		SelectedCA:   1,
		SignerStore:  rootSignerStore,
		TPM:          tpm,
	}
	rootParams.Identity.KeyringConfig.CN = config.Identity[1].Subject.CommonName

	// Creates a new Parent / Root Certificate Authority
	rootCA, err := NewParentCA(&rootParams)
	if err != nil {
		logger.FatalError(err)
	}

	// Initialize the CA by creating new keys and certificates
	if err := rootCA.Init(nil); err != nil {
		logger.FatalError(err)
	}

	//
	// Setup Intermediate CA
	//

	// Create intermediate key chain
	intermediateHome := tmp + "/ca/intermediate"
	os.MkdirAll(intermediateHome, os.ModePerm)

	intermediateKeyBackend := keystore.NewFileBackend(logger, afero.NewMemMapFs(), intermediateHome)

	intermediateBlobStore, err := blob.NewFSBlobStore(
		logger, fs, intermediateHome, &config.Identity[1].Subject.CommonName)
	if err != nil {
		logger.FatalError(err)
	}

	intermediateSignerStore := keystore.NewSignerStore(intermediateBlobStore)

	// Create x509 certificate store
	intermediateCertStore, err := certstore.NewCertificateStore(
		logger, intermediateBlobStore)
	if err != nil {
		logger.FatalError(err)
	}

	intermediateKeyringConfig := &platform.KeyringConfig{
		CN: "intermediate-ca",
		PKCS8Config: &pkcs8.Config{
			PlatformPolicy: true,
		},
		PKCS11Config: &pkcs11.Config{
			Library:        "/usr/local/lib/softhsm/libsofthsm2.so",
			LibraryConfig:  softhsm_conf,
			Slot:           &slot,
			TokenLabel:     "SoftHSM",
			SOPin:          string(soPinBytes),
			Pin:            string(pinBytes),
			PlatformPolicy: true,
		},
		TPMConfig: &tpm2.KeyStoreConfig{
			SRKHandle:      0x81000004,
			SRKAuth:        string(pinBytes),
			PlatformPolicy: true,
		},
	}

	intermediateKC, err := platform.NewKeyring(
		logger,
		true,
		fs,
		intermediateHome,
		rand.Reader,
		intermediateKeyringConfig,
		intermediateKeyBackend,
		intermediateBlobStore,
		intermediateSignerStore,
		tpm,
		platformKS,
		soPIN,
		userPIN)

	// Create intermediate params
	intermediateParams := CAParams{
		Backend:      intermediateKeyBackend,
		BlobStore:    intermediateBlobStore,
		CertStore:    intermediateCertStore,
		Config:       *config,
		Debug:        true,
		DebugSecrets: true,
		Home:         tmp,
		Identity:     config.Identity[1],
		Keyring:      intermediateKC,
		Logger:       logger,
		Random:       rand.Reader,
		SelectedCA:   1,
		SignerStore:  intermediateSignerStore,
		TPM:          tpm,
	}
	intermediateParams.Identity.KeyringConfig.CN = config.Identity[1].Subject.CommonName

	intermediateCA, err := NewIntermediateCA(&intermediateParams)
	if err != nil {
		logger.FatalError(err)
	}

	// Initialize the CA by creating new keys and certificates, using
	// the parentCA to sign for this new intermediate
	if err := intermediateCA.Init(rootCA); err != nil {
		logger.FatalError(err)
	}

	return rootCA, intermediateCA, tpm, tmp, nil
}
