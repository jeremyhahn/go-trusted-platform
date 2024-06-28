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

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")

	// Instantiate the CA without calling Init(), it should fail
	// with ErrNotInitialized
	logger, _, intermediateCA, tmpDir, err := createService(
		KEY_ALGO_RSA, rootPass, intermediatePass, false)
	defer cleanTempDir(tmpDir)
	assert.Equal(t, ErrNotInitialized, err)

	// Instantiate the CA using Init(), it should create a Root
	// and Intermediate CA ready for use
	_, _, intermediateCA, tmpDir, err = createService(
		KEY_ALGO_RSA, rootPass, intermediatePass, true)
	defer cleanTempDir(tmpDir)
	assert.Nil(t, err)

	// Get the CA bundle
	bundle, err := intermediateCA.CABundle()
	assert.Nil(t, err)
	assert.NotNil(t, bundle)

	logger.Info(string(bundle))
}

func TestInit(t *testing.T) {

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	logger, rootCA, intermediateCA, tmpDir, err := createService(KEY_ALGO_RSA, rootPass, intermediatePass, false)
	defer cleanTempDir(tmpDir)

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

func TestNewEncryptionWithPassword(t *testing.T) {

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	logger, _, intermediateCA, tmpDir, err := createService(KEY_ALGO_RSA, rootPass, intermediatePass, true)
	defer cleanTempDir(tmpDir)
	assert.Nil(t, err)

	cn := "localhost"
	keyName := "test-with-password"
	secret := []byte("app-secret")
	keyPass := []byte("key-password")

	pub, err := intermediateCA.NewEncryptionKey(cn, keyName, keyPass, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, pub)

	ciphertext, err := intermediateCA.RSAEncrypt(cn, keyName, secret)
	assert.Nil(t, err)
	assert.NotEqual(t, secret, ciphertext)

	decrypted, err := intermediateCA.RSADecrypt(cn, keyName, keyPass, ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)

	logger.Debugf("encryption-key: cn: %s", cn)
	logger.Debugf("encryption-key: keyName: %s", keyName)
	logger.Debugf("encryption-key: secret: %s", secret)
	logger.Debugf("encryption-key: ciphertext: %s", ciphertext)
	logger.Debugf("encryption-key: decrypted: %s", decrypted)

	// Create a 2nd key
	keyName2 := "test2-with-password"
	secret2 := []byte("password2")
	pub2, err := intermediateCA.NewEncryptionKey(cn, keyName2, keyPass, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, pub2)

	ciphertext2, err := intermediateCA.RSAEncrypt(cn, keyName2, secret2)
	assert.Nil(t, err)
	assert.NotEqual(t, secret, ciphertext)

	decrypted2, err := intermediateCA.RSADecrypt(cn, keyName2, keyPass, ciphertext2)
	assert.Nil(t, err)
	assert.Equal(t, secret2, decrypted2)

	// Ensure encryption fails
	_, err = intermediateCA.RSADecrypt(cn, keyName, keyPass, ciphertext2)
	assert.NotNil(t, err)
	assert.Equal(t, "crypto/rsa: decryption error", err.Error())
}

func TestNewEncryptionKeyWihtInvalidPasswordCombinations(t *testing.T) {

	// Create the Root and Intermediate CA
	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	logger, _, intermediateCA, tmpDir, err := createService(KEY_ALGO_RSA, nil, nil, true)
	defer cleanTempDir(tmpDir)
	assert.Equal(t, ErrPrivateKeyPasswordRequired, err)

	cn := "localhost"
	keyName := "test-without-password"
	secret := []byte("app-secret")
	keyPass := []byte("key-password")

	// Create the Root and Intermediate CA
	logger, _, intermediateCA, tmpDir, err = createService(KEY_ALGO_RSA, rootPass, intermediatePass, true)
	defer cleanTempDir(tmpDir)
	assert.Nil(t, err)

	// Create new encryption key
	pub, err := intermediateCA.NewEncryptionKey(cn, keyName, keyPass, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, pub)

	// Encrypt the secret
	ciphertext, err := intermediateCA.RSAEncrypt(cn, keyName, secret)
	assert.Nil(t, err)
	assert.NotEqual(t, secret, ciphertext)

	// Decrypt without a password (should fail with invalid password)
	decrypted, err := intermediateCA.RSADecrypt(cn, keyName, nil, ciphertext)
	assert.Equal(t, ErrInvalidPassword, err)

	// Decrypt with a bad password (should fail with invalid password)
	decrypted, err = intermediateCA.RSADecrypt(cn, keyName, secret, ciphertext)
	assert.Equal(t, ErrInvalidPassword, err)

	// Decrypt with correct password (should work)
	decrypted, err = intermediateCA.RSADecrypt(cn, keyName, keyPass, ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, secret, decrypted)

	logger.Debugf("encryption-key: cn: %s", cn)
	logger.Debugf("encryption-key: keyName: %s", keyName)
	logger.Debugf("encryption-key: secret: %s", secret)
	logger.Debugf("encryption-key: ciphertext: %s", ciphertext)
	logger.Debugf("encryption-key: decrypted: %s", decrypted)

	// Create a 2nd key without a password
	keyName2 := "test2-without-password"
	pub2, err := intermediateCA.NewEncryptionKey(cn, keyName2, nil, intermediatePass)
	assert.Equal(t, ErrPrivateKeyPasswordRequired, err)
	assert.Nil(t, pub2)

	pub3, err := intermediateCA.NewEncryptionKey(cn, keyName2, nil, intermediatePass)
	assert.Equal(t, ErrPrivateKeyPasswordRequired, err)
	assert.Nil(t, pub3)

	// Create a 3rd with a bad password
	keyName3 := "test2-without-password"
	secret3 := []byte("password2")

	// Try to decrypt using a key that doesnt exist
	_, err = intermediateCA.RSAEncrypt(cn, keyName3, secret3)
	assert.Equal(t, ErrFileNotFound, err)

	// Create the missing key
	pub4, err := intermediateCA.NewEncryptionKey(cn, keyName3, keyPass, intermediatePass)
	assert.Nil(t, err)
	assert.NotNil(t, pub4)

	ciphertext3, err := intermediateCA.RSAEncrypt(cn, keyName3, secret3)
	assert.Nil(t, err)
	assert.NotEqual(t, secret3, ciphertext3)

	// It works
	decrypted3, err := intermediateCA.RSADecrypt(cn, keyName3, keyPass, ciphertext3)
	assert.Nil(t, err)
	assert.Equal(t, secret3, decrypted3)
}

func TestImportIssuingCAs(t *testing.T) {

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, tmpDir, err := createService(KEY_ALGO_RSA, rootPass, intermediatePass, true)
	defer cleanTempDir(tmpDir)
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

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, tmpDir, err := createService(KEY_ALGO_RSA, rootPass, intermediatePass, true)
	defer cleanTempDir(tmpDir)
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

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, tmpDir, err := createService(KEY_ALGO_RSA, rootPass, intermediatePass, true)
	defer cleanTempDir(tmpDir)
	assert.Nil(t, err)

	// Create test data
	data := []byte("hello\nworld\n")

	// Sign it
	signature, err := rootCA.Sign(data, rootPass)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	// Verify it
	assert.Nil(t, rootCA.VerifySignature(data, signature))

	// Ensure verification fails
	newData := []byte("injected-malware")
	assert.NotNil(t, rootCA.VerifySignature(newData, signature))
}

func TestRSAPersistentSignAndVerify(t *testing.T) {

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, tmpDir, err := createService(KEY_ALGO_RSA, rootPass, intermediatePass, true)
	defer cleanTempDir(tmpDir)
	assert.Nil(t, err)

	// Create test data
	blobKey := "/my/secret/data.dat"
	data := []byte("hello\nworld\n")

	// Sign and store the data and the signature
	err = rootCA.PersistentSign(blobKey, data, rootPass, true)
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

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, _, intermediateCA, tmpDir, err := createService(KEY_ALGO_RSA, rootPass, intermediatePass, true)
	defer cleanTempDir(tmpDir)
	assert.Nil(t, err)

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
	keypair, err := intermediateCA.IssueCertificate(certReq, intermediatePass)
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

func TestRSAIssueCertificate(t *testing.T) {

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, tmpDir, err := createService(KEY_ALGO_RSA, rootPass, intermediatePass, true)
	defer cleanTempDir(tmpDir)
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
	der, err := rootCA.IssueCertificate(certReq, rootPass)
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
	algorithm string,
	rootPass, intermediatePass []byte,
	performInit bool) (*logging.Logger, CertificateAuthority, CertificateAuthority, string, error) {

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

	// Create a temp directory so parallel tests don't
	// corrupt each other.
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	tmpDir := hex.EncodeToString(buf)

	config := &Config{
		Home:                      fmt.Sprintf("%s/%s", CERTS_DIR, tmpDir),
		AutoImportIssuingCA:       true,
		DefaultKeyAlgorithm:       algorithm,
		EllipticalCurve:           CURVE_P256,
		RetainRevokedCertificates: false,
		//PasswordPolicy:            "^[a-zA-Z0-9-_]+$",
		PasswordPolicy:            "^*$",
		RequirePrivateKeyPassword: false,
		Identity: []Identity{
			rootIdentity,
			intermediateIdentity},
	}

	// Initialize Root and Intermediate Certificate Authorities
	// based on configuration
	//
	// Root CA certificates
	// openssl rsa -in platform/ca/root-ca.key -text (-check)
	// openssl x509 -in platform/ca/root-ca.crt -text -noout
	// openssl rsa -pubin -in platform/ca/root-ca.pub -text
	//
	// Intermediate CA certificates
	// openssl rsa -in platform/ca/intermediate-ca.key -text (-check)
	// openssl x509 -in platform/ca/intermediate-ca.crt -text -noout
	// openssl rsa -pubin -in platform/ca/intermediate-ca.pub -text
	rootCA, intermediateCA, err := NewCA(logger, config, intermediatePass, 1, rand.Reader)
	if err != nil {
		if err == ErrNotInitialized && performInit {
			privKey, cert, initErr := rootCA.Init(nil, nil, rootPass, rand.Reader)
			if initErr != nil {
				logger.Error(initErr)
				return nil, nil, nil, tmpDir, initErr
			}
			_, _, initErr = intermediateCA.Init(privKey, cert, intermediatePass, rand.Reader)
			if initErr != nil {
				logger.Error(initErr)
				return nil, nil, nil, tmpDir, initErr
			}
			err = nil
		} else if performInit {
			logger.Error(err)
			return nil, nil, nil, tmpDir, err
		}
	} else {
		logger.Warning("CA has already been initialized")
	}

	return logger, rootCA, intermediateCA, tmpDir, err
}
