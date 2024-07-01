package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"testing"

	"github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
)

var CERTS_DIR = "./certs"
var INTEL_CERT_URL = "https://trustedservices.intel.com/content/CRL/ekcert/CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.cer"
var CLEAN_TMP = false

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

func TestLoad(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	logger, _, intermediateCA, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)

	// Instantiate the CA using Init(), it should create a Root
	// and Intermediate CA ready for use
	config, err = defaultConfig() // call again to get new temp dir
	assert.Nil(t, err)
	assert.NotNil(t, config)

	_, _, intermediateCA, err = createService(
		config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Get the CA bundle
	bundle, err := intermediateCA.CABundle()
	assert.Nil(t, err)
	assert.NotNil(t, bundle)

	logger.Info(string(bundle))
}

func TestInit(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	logger, rootCA, intermediateCA, err := createService(config, rootPass, intermediatePass, false)
	defer cleanTempDir(config.Home)

	assert.Equal(t, ErrNotInitialized, err)
	assert.NotNil(t, rootCA)
	assert.NotNil(t, intermediateCA)

	rootPrivKey, rootCert, err := rootCA.Init(nil, nil, rootPass, rand.Reader)
	assert.Nil(t, err)
	assert.NotNil(t, rootPrivKey)

	intermediatePrivKey, intermediateCert, err := intermediateCA.Init(
		rootPrivKey, rootCert, intermediatePass, rand.Reader)
	assert.Nil(t, err)
	assert.NotNil(t, intermediatePrivKey)
	assert.NotNil(t, intermediateCert)

	bundle, err := intermediateCA.CABundle()
	assert.NotNil(t, bundle)

	logger.Info(string(bundle))
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

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

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

	leafCN := "www.intel.com"

	err = rootCA.ImportIssuingCAs(cert, &leafCN, nil)
	assert.Nil(t, err)

	err = rootCA.ImportIssuingCAs(cert, &leafCN, nil)
	assert.Equal(t, ErrTrustExists, err)

	importedCert, err := rootCA.TrustedRootCertificate(cert.Subject.CommonName)
	assert.Nil(t, err)
	assert.Equal(t, cert.Subject.CommonName, importedCert.Subject.CommonName)
}

func TestDownloadDistribuitionCRLs(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

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

	err = rootCA.ImportDistrbutionCRLs(cert)
	assert.Nil(t, err)

	err2 := rootCA.ImportDistrbutionCRLs(cert)
	assert.Equal(t, ErrCRLAlreadyExists, err2)
}

func TestRSAGenerateAndSignCSR_Then_VerifyAndRevoke(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	// Don't require passwords for this test
	config.RequirePrivateKeyPassword = false

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, _, intermediateCA, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)

	// Get the CA public key
	publicKey, err := intermediateCA.CAPubKey()
	assert.Nil(t, err)
	assert.NotNil(t, publicKey)

	// openssl rsa -in testorg.example.com.key -check
	// openssl x509 -in testorg.example.com.crt -text -noout
	certReq := CertificateRequest{
		Valid: 365, // 1 days
		Subject: Subject{
			CommonName:         "testorg.example.com",
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

	// Issue certificate using golang random number genrator
	// go generate the private key
	keypair, err := intermediateCA.IssueCertificate(certReq, intermediatePass, nil)
	assert.Nil(t, err)
	assert.NotNil(t, keypair)

	// openssl req -in testme.example.com.csr -noout -text
	csrBytes, err := intermediateCA.CreateCSR(
		"me@mydomain.com",
		CertificateRequest{
			Valid: 365, // 1 days
			Subject: Subject{
				CommonName:         "testme.example.com",
				Organization:       "Customer Organization",
				OrganizationalUnit: "Farming",
				Country:            "US",
				Locality:           "California",
				Address:            "123 farming street",
				PostalCode:         "01210",
			},
			SANS: &SubjectAlternativeNames{
				DNS: []string{
					"localhost",
					"localhost.localdomain",
					"localhost.testme",
				},
				IPs: []string{
					"127.0.0.1",
					"192.168.1.10",
				},
				Email: []string{
					"user@testme.com",
					"info@testme.com",
				},
			},
		}, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, csrBytes)

	// openssl x509 -in testme.example.com.crt -text -noout
	certBytes, err := intermediateCA.SignCSR(
		csrBytes,
		CertificateRequest{
			Valid: 365, // 1 days
			Subject: Subject{
				CommonName:         "testme.example.com",
				Organization:       "Customer Organization",
				OrganizationalUnit: "Farming",
				Country:            "US",
				Locality:           "California",
				Address:            "123 farming street",
				PostalCode:         "01210",
			},
			SANS: &SubjectAlternativeNames{
				DNS: []string{
					"localhost",
					"localhost.localdomain",
					"localhost.testme",
				},
				IPs: []string{
					"127.0.0.1",
					"192.168.1.10",
				},
				Email: []string{
					"user@testme.com",
					"info@testme.com",
				},
			},
		}, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, certBytes)

	cert, err := intermediateCA.DecodePEM(certBytes)
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	// Make sure the cert is valid
	valid, err := intermediateCA.Verify(cert, nil)
	assert.Nil(t, err)
	assert.True(t, valid)

	// Get the cert *rsa.PublicKey
	publicKey, err = intermediateCA.PubKey("testme.example.com")
	assert.Nil(t, err)
	assert.NotNil(t, publicKey)

	// Removke the cert
	err = intermediateCA.Revoke("testme.example.com", intermediatePass)
	assert.Nil(t, err)

	// Revoke the certificate again to ensure it errors
	err = intermediateCA.Revoke("testme.example.com", intermediatePass)
	assert.Equal(t, ErrCertNotFound, err) // TODO: should return ErrCertRevoked

	// Make sure the cert is no longer valid
	valid, err = intermediateCA.Verify(cert, nil)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCertRevoked, err)
	assert.False(t, valid)

	// Test the web server certificate
	//
	// openssl s_client \
	//   -connect localhost:8443 \
	//   -servername localhost  | openssl x509 -noout -text
}

func TestIssueCertificateWithPassword(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	domain := "www.domain.com"

	certReq := CertificateRequest{
		Valid: 365, // days
		Subject: Subject{
			CommonName:   domain,
			Organization: "ACME Corporation",
			Country:      "US",
			Locality:     "Miami",
			Address:      "123 acme street",
			PostalCode:   "12345"},
		SANS: &SubjectAlternativeNames{
			DNS: []string{
				domain,
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
	certPassword := []byte("server-password")
	der, err := rootCA.IssueCertificate(certReq, rootPass, certPassword)
	assert.Nil(t, err)
	assert.NotNil(t, der)

	cert, err := x509.ParseCertificate(der)
	assert.Nil(t, err)
	assert.Equal(t, domain, cert.Subject.CommonName)
	assert.Equal(t, x509.SHA256WithRSA, cert.SignatureAlgorithm)
}

func cleanTempDir(dir string) {
	if CLEAN_TMP {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Errorf("%S", err)
		}
	}
}

func createService(
	config *Config,
	rootPass, intermediatePass []byte,
	performInit bool) (*logging.Logger, CertificateAuthority, CertificateAuthority, error) {

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("certificate-authority")

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

	// Initialize Root and Intermediate Certificate Authorities
	// based on configuration
	//
	// Root CA certificates
	// openssl rsa -in certs/ca/root-ca.key -text (-check)
	// openssl x509 -in certs/ca/root-ca.crt -text -noout
	// openssl rsa -pubin -in platform/ca/root-ca.pub -text
	//
	// Intermediate CA certificates
	// openssl rsa -in certs/ca/intermediate-ca.key -text (-check)
	// openssl x509 -in certs/ca/intermediate-ca.crt -text -noout
	// openssl rsa -pubin -in certs/ca/intermediate-ca.pub -text
	params := CAParams{
		Logger:               logger,
		Config:               config,
		Password:             intermediatePass,
		SelectedIntermediate: 1,
		Random:               rand.Reader,
	}
	rootCA, intermediateCA, err := NewCA(params)
	if err != nil {
		if err == ErrNotInitialized && performInit {
			privKey, cert, initErr := rootCA.Init(nil, nil, rootPass, rand.Reader)
			if initErr != nil {
				logger.Error(initErr)
				return nil, nil, nil, initErr
			}
			_, _, initErr = intermediateCA.Init(privKey, cert, intermediatePass, rand.Reader)
			if initErr != nil {
				logger.Error(initErr)
				return nil, nil, nil, initErr
			}
			err = nil
		} else if performInit {
			logger.Error(err)
			return nil, nil, nil, err
		}
	} else {
		logger.Warning("CA has already been initialized")
	}

	return logger, rootCA, intermediateCA, err
}

// Creates a default CA configuration
func defaultConfig() (*Config, error) {
	rootIdentity := Identity{
		KeySize: 1024, // bits
		Valid:   10,   // years
		Subject: Subject{
			CommonName:   "root-ca",
			Organization: "ACME Corporation",
			Country:      "US",
			Locality:     "Miami",
			Address:      "123 acme street",
			PostalCode:   "12345"},
		SANS: &SubjectAlternativeNames{
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

	intermediateIdentity := Identity{
		KeySize: 1024, // bits
		Valid:   10,   // years

		Subject: Subject{
			CommonName:   "intermediate-ca",
			Organization: "ACME Corporation",
			Country:      "US",
			Locality:     "Miami",
			Address:      "123 acme street",
			PostalCode:   "12345"},
		SANS: &SubjectAlternativeNames{
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

	return &Config{
		Home:                      fmt.Sprintf("%s/%s", CERTS_DIR, tmpDir),
		AutoImportIssuingCA:       true,
		DefaultKeyAlgorithm:       KEY_ALGO_RSA,
		EllipticalCurve:           CURVE_P256,
		RetainRevokedCertificates: false,
		//PasswordPolicy:            "^[a-zA-Z0-9-_]+$",
		PasswordPolicy:            "^*$",
		RequirePrivateKeyPassword: true,
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}, nil
}
