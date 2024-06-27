package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
)

var CERTS_DIR = "./certs"
var INTEL_CERT_URL = "https://trustedservices.intel.com/content/CRL/ekcert/CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.cer"

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
	os.RemoveAll(CERTS_DIR)
}

func setup() {
	os.RemoveAll(CERTS_DIR)
}

func TestRSAInit(t *testing.T) {

	logger, _, intermediateCAs, err := createService(KEY_ALGO_RSA, true)
	assert.Nil(t, err)

	intermediateCA := intermediateCAs["intermediate-ca"]
	bundle, err := intermediateCA.CABundle()
	assert.Nil(t, err)
	assert.NotNil(t, bundle)

	if err != nil {
		logger.Error(err)
	}

	logger.Info(string(bundle))
}

func TestRSALoad(t *testing.T) {

	logger, _, intermediateCAs, err := createService(KEY_ALGO_RSA, false)
	assert.Nil(t, err)

	logger, _, intermediateCAs, err = createService(KEY_ALGO_RSA, false)
	assert.Nil(t, err)

	intermediateCA := intermediateCAs["intermediate-ca"]
	bundle, err := intermediateCA.CABundle()
	assert.Nil(t, err)
	assert.NotNil(t, bundle)

	if err != nil {
		logger.Error(err)
	}

	logger.Info(string(bundle))
}

func TestNewEncryptionKey(t *testing.T) {

	logger, _, intermediateCAs, err := createService(KEY_ALGO_RSA, false)
	assert.Nil(t, err)

	cn := "localhost"
	keyName := "test"
	secret := []byte("password")

	intermediateCA := intermediateCAs["intermediate-ca"]
	pub, err := intermediateCA.NewEncryptionKey(cn, keyName)
	assert.Nil(t, err)
	assert.NotNil(t, pub)

	ciphertext, err := intermediateCA.RSAEncrypt(cn, keyName, secret)
	assert.Nil(t, err)
	assert.NotEqual(t, secret, ciphertext)

	decrypted, err := intermediateCA.RSADecrypt(cn, keyName, ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)

	logger.Debugf("encryption-key: cn: %s", cn)
	logger.Debugf("encryption-key: keyName: %s", keyName)
	logger.Debugf("encryption-key: secret: %s", secret)
	logger.Debugf("encryption-key: ciphertext: %s", ciphertext)
	logger.Debugf("encryption-key: decrypted: %s", decrypted)

	// Create a 2nd key
	keyName2 := "test2"
	secret2 := []byte("password2")
	pub2, err := intermediateCA.NewEncryptionKey(cn, keyName2)
	assert.Nil(t, err)
	assert.NotNil(t, pub2)

	ciphertext2, err := intermediateCA.RSAEncrypt(cn, keyName2, secret2)
	assert.Nil(t, err)
	assert.NotEqual(t, secret, ciphertext)

	decrypted2, err := intermediateCA.RSADecrypt(cn, keyName2, ciphertext2)
	assert.Nil(t, err)
	assert.Equal(t, secret2, decrypted2)

	// Ensure encryption fails
	decryptFails, err := intermediateCA.RSADecrypt(cn, keyName, ciphertext2)
	assert.NotNil(t, err)
	assert.Nil(t, decryptFails)
}

func TestRSAImportIssuingCAs(t *testing.T) {

	_, rootCA, _, err := createService(KEY_ALGO_RSA, false)
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

func TestRSADownloadDistribuitionCRLs(t *testing.T) {

	_, rootCA, _, err := createService(KEY_ALGO_RSA, false)
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

func TestRSASignAndVerify(t *testing.T) {

	_, rootCA, _, err := createService(KEY_ALGO_RSA, false)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	// Sign it
	signature, err := rootCA.Sign(data)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	assert.Nil(t, rootCA.VerifySignature(data, signature))

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.VerifySignature(newData, signature))
}

func TestRSAPersistentSignAndVerify(t *testing.T) {

	_, rootCA, _, err := createService(KEY_ALGO_RSA, false)
	assert.Nil(t, err)

	// Create test data
	blobKey := "/my/secret/data.dat"
	data := []byte("hello\nworld\n")

	// Sign and store the data and the signature
	err = rootCA.PersistentSign(blobKey, data, true)
	assert.Nil(t, err)

	signature, err := rootCA.Signature(blobKey)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify the data with the stored signature
	assert.Nil(t, rootCA.PersistentVerifySignature(blobKey, data))

	// Modified data to ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.PersistentVerifySignature(blobKey, newData))

	// Ensure the check to see if the signature data exists
	signed, err := rootCA.Signed(blobKey)
	assert.Nil(t, err)
	assert.True(t, signed)

	// Ensure the signed data can be retrieved
	signedData, err := rootCA.SignedData(blobKey)
	assert.Nil(t, err)
	assert.Equal(t, data, signedData)
}

func TestRSAGenerateAndSignCSR_Then_VerifyAndRevoke(t *testing.T) {

	_, rootCA, _, err := createService(KEY_ALGO_RSA, false)
	assert.Nil(t, err)

	// Get the CA public key
	publicKey, err := rootCA.CAPubKey()
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
	keypair, err := rootCA.IssueCertificate(certReq)
	assert.Nil(t, err)
	assert.NotNil(t, keypair)

	// openssl req -in testme.example.com.csr -noout -text
	csrBytes, err := rootCA.CreateCSR(
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
		})
	assert.Nil(t, err)
	assert.NotNil(t, csrBytes)

	// openssl x509 -in testme.example.com.crt -text -noout
	certBytes, err := rootCA.SignCSR(
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
		})
	assert.Nil(t, err)
	assert.NotNil(t, certBytes)

	cert, err := rootCA.DecodePEM(certBytes)
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	// Make sure the cert is valid
	valid, err := rootCA.Verify(cert, nil)
	assert.Nil(t, err)
	assert.True(t, valid)

	// Get the cert *rsa.PublicKey
	publicKey, err = rootCA.PubKey("testme.example.com")
	assert.Nil(t, err)
	assert.NotNil(t, publicKey)

	// Removke the cert
	err = rootCA.Revoke("testme.example.com")
	assert.Nil(t, err)

	// Revoke the certificate again to ensure it errors
	err = rootCA.Revoke("testme.example.com")
	assert.Equal(t, ErrCertNotFound, err)

	// Make sure the cert is no longer valid
	valid, err = rootCA.Verify(cert, nil)
	assert.NotNil(t, err)
	assert.Equal(t, ErrCertRevoked, err)
	assert.False(t, valid)

	// Test the web server certificate
	//
	// openssl s_client \
	//   -connect localhost:8443 \
	//   -servername localhost  | openssl x509 -noout -text
}

func TestRSAIssueCertificateRSA(t *testing.T) {

	_, rootCA, _, err := createService(KEY_ALGO_RSA, false)
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
	der, err := rootCA.IssueCertificate(certReq)
	assert.Nil(t, err)
	assert.NotNil(t, der)

	cert, err := x509.ParseCertificate(der)
	assert.Nil(t, err)
	assert.Equal(t, domain, cert.Subject.CommonName)
	assert.Equal(t, x509.SHA256WithRSA, cert.SignatureAlgorithm)
}

func createService(
	algorithm string,
	issueServerCert bool) (*logging.Logger, CertificateAuthority, map[string]CertificateAuthority, error) {

	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logging.SetBackend(stdout)
	logger := logging.MustGetLogger("certificate-authority")

	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logFormatter := logging.NewBackendFormatter(stdout, logFormat)
	backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(backends)

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

	config := &Config{
		AutoImportIssuingCA: true,
		DefaultKeyAlgorithm: algorithm,
		EllipticalCurve:     CURVE_P256,
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}

	// Initialize Root and Intermediate Certificate Authorities
	// based on configuration
	//
	// Root CA certificates
	// openssl rsa -in certs/ca/root-ca.key -text (-check)
	// openssl x509 -in certs/ca/root-ca.crt -text -noout
	// openssl rsa -pubin -in certs/ca/root-ca.pub -text
	//
	// Intermediate CA certificates
	// openssl rsa -in certs/ca/intermediate-ca.key -text (-check)
	// openssl x509 -in certs/ca/intermediate-ca.crt -text -noout
	// openssl rsa -pubin -in certs/ca/intermediate-ca.pub -text
	rootCA, intermediateCAs, err := NewCA(logger, CERTS_DIR, config, rand.Reader)
	if err != nil {
		logger.Fatal(err)
	}

	// Generate server certificate
	intermediateCA := intermediateCAs["intermediate-ca"]
	certReq := CertificateRequest{
		Valid: 365, // days
		Subject: Subject{
			CommonName:   "localhost",
			Organization: "ACME Corporation",
			Country:      "US",
			Locality:     "Miami",
			Address:      "123 acme street",
			PostalCode:   "12345"},
		SANS: &SubjectAlternativeNames{
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

	if issueServerCert {
		_, err = intermediateCA.IssueCertificate(certReq)
		if err != nil {
			logger.Fatal(err)
		}
	}

	return logger, rootCA, intermediateCAs, nil
}
