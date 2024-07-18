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

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
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

var CERTS_DIR = "./testdata"
var INTEL_CERT_URL = "https://trustedservices.intel.com/content/CRL/ekcert/CNLEPIDPOSTB1LPPROD2_EK_Platform_Public_Key.cer"
var CLEAN_TMP = false

func TestLoad(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	params, _, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)

	if err != nil {
		params.Logger.Fatal(err)
	}

	// Instantiate the CA using Init(), it should create a Root
	// and Intermediate CA ready for use
	config = defaultConfig() // call again to get new temp dir
	assert.NotNil(t, config)

	_, _, intermediateCA, err = createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	// Get the CA bundle
	bundle, err := intermediateCA.CABundle(nil)
	assert.Nil(t, err)
	assert.NotNil(t, bundle)

	params.Logger.Info(string(bundle))
}

func TestInit(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	params, rootCA, intermediateCA, err := createService(config, false)
	defer cleanTempDir(config.Home)

	assert.Equal(t, ErrNotInitialized, err)
	assert.NotNil(t, rootCA)
	assert.NotNil(t, intermediateCA)

	rootCerts, err := rootCA.Init(nil)
	assert.Nil(t, err)
	assert.NotNil(t, rootCerts)

	intermediateCerts, err := intermediateCA.Init(rootCerts)
	assert.Nil(t, err)
	assert.NotNil(t, intermediateCerts)

	bundle, err := intermediateCA.CABundle(nil)
	assert.NotNil(t, bundle)

	params.Logger.Info(string(bundle))
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

	config := defaultConfig()
	assert.NotNil(t, config)

	_, _, intermediateCA, err := createService(config, true)
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

	err = intermediateCA.ImportIssuingCAs(cert, &leafCN, nil)
	assert.Nil(t, err)

	err = intermediateCA.ImportIssuingCAs(cert, &leafCN, nil)
	assert.Equal(t, ErrTrustExists, err)

	attrs, _ := keystore.Template(intermediateCA.DefaultKeyAlgorithm())
	attrs.Domain = "EKRootPublicKey"
	attrs.KeyType = keystore.KEY_TYPE_NULL
	importedCert, err := intermediateCA.TrustedRootCertificate(attrs, store.FSEXT_DER)

	assert.Nil(t, err)
	assert.Equal(t, cert.Subject.CommonName, importedCert.Subject.CommonName)
}

func TestDownloadDistribuitionCRLs(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	_, rootCA, _, err := createService(config, true)
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

	// Import it
	err = rootCA.ImportDistrbutionCRLs(cert)
	assert.Nil(t, err)

	// Import it again and make sure it fails with already exists
	err2 := rootCA.ImportDistrbutionCRLs(cert)
	assert.Equal(t, ErrCRLAlreadyExists, err2)
}

func TestRSAGenerateAndSignCSR_Then_VerifyAndRevoke(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	// Don't require passwords for this test
	config.RequirePrivateKeyPassword = false

	_, rootCA, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)

	publicKey := intermediateCA.Public()
	caAttrs := intermediateCA.CAKeyAttributes(nil)

	attrs, err := keystore.Template(caAttrs.KeyAlgorithm)
	attrs.KeyType = keystore.KEY_TYPE_TLS
	attrs.Domain = "example.com"
	attrs.CN = "www.example.com"
	attrs.AuthPassword = []byte(rootCA.Identity().KeyPassword)
	attrs.Password = []byte("server-password")

	// openssl rsa -in testorg.example.com.key -check
	// openssl x509 -in testorg.example.com.crt -text -noout
	certReq := CertificateRequest{
		KeyAttributes: &attrs,
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
	certBytes, err := intermediateCA.SignCSR(csrBytes, certReq)
	assert.Nil(t, err)
	assert.NotNil(t, certBytes)

	// Decode from PEM to ASN.1 DER
	cert, err := DecodePEM(certBytes)
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	// Make sure the cert is valid
	valid, err := intermediateCA.Verify(cert, nil)
	assert.Nil(t, err)
	assert.True(t, valid)

	// Get the cert crypto.PublicKey
	publicKey, err = intermediateCA.PubKey(attrs)
	assert.Nil(t, err)
	assert.NotNil(t, publicKey)

	// Removke the cert
	err = intermediateCA.Revoke(attrs)
	assert.Nil(t, err)

	// Revoke the certificate again to ensure it errors
	err = intermediateCA.Revoke(attrs)

	// TODO: should return ErrCertRevoked
	assert.Equal(t, store.ErrFileNotFound, err)

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

	config := defaultConfig()
	assert.NotNil(t, config)

	_, rootCA, _, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	caAttrs := rootCA.CAKeyAttributes(nil)

	attrs, err := keystore.Template(caAttrs.KeyAlgorithm)
	attrs.KeyType = keystore.KEY_TYPE_TLS
	attrs.Domain = "example.com"
	attrs.CN = "www.example.com"
	attrs.AuthPassword = []byte(rootCA.Identity().KeyPassword)
	attrs.Password = []byte("server-password")

	certReq := CertificateRequest{
		KeyAttributes: &attrs,
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

func TestIssueCertificate_CA_RSA_WITH_LEAF_ECDSA(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	config.KeyAlgorithms = []string{
		x509.RSA.String(),
		x509.ECDSA.String(),
		x509.Ed25519.String(),
	}

	params, rootCA, _, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	DebugCipherSuites(params.Logger)
	DebugInsecureCipherSuites(params.Logger)

	attrs, err := keystore.Template(x509.ECDSA)
	attrs.KeyType = keystore.KEY_TYPE_TLS
	attrs.Domain = "example.com"
	attrs.CN = "www.example.com"
	attrs.AuthPassword = []byte(rootCA.Identity().KeyPassword)
	attrs.Password = []byte("server-password")

	certReq := CertificateRequest{
		KeyAttributes: &attrs,
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

	config := defaultConfig()
	assert.NotNil(t, config)

	config.RequirePrivateKeyPassword = false

	_, rootCA, _, err := createService(config, true)
	defer cleanTempDir(config.Home)
	assert.Nil(t, err)

	caAttrs := rootCA.CAKeyAttributes(nil)
	attrs, err := keystore.Template(caAttrs.KeyAlgorithm)
	attrs.KeyType = keystore.KEY_TYPE_TLS
	attrs.Domain = "example.com"
	attrs.CN = "www.example.com"
	attrs.AuthPassword = []byte(rootCA.Identity().KeyPassword)
	attrs.Password = []byte("server-password")

	certReq := CertificateRequest{
		KeyAttributes: &attrs,
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

func cleanTempDir(dir string) {
	if CLEAN_TMP {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Errorf("%S", err)
		}
	}
}

func createService(
	config Config,
	performInit bool) (CAParams, CertificateAuthority, CertificateAuthority, error) {

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

	logger := defaultLogger()
	params := defaultParams(logger, config)

	rootCA, intermediateCA, err := NewCA(params)
	if err != nil {
		if err == ErrNotInitialized && performInit {
			rootCerts, initErr := rootCA.Init(nil)
			if initErr != nil {
				logger.Error(initErr)
				return params, nil, nil, initErr
			}
			_, initErr = intermediateCA.Init(rootCerts)
			if initErr != nil {
				logger.Error(initErr)
				return params, nil, nil, initErr
			}
			params.Identity = intermediateCA.Identity()
			err = nil
		} else if performInit {
			logger.Error(err)
			return params, nil, nil, err
		}
	} else {
		logger.Warning("CA already initialized")
	}

	return params, rootCA, intermediateCA, err
}

func defaultLogger() *logging.Logger {
	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	//logging.SetBackend(stdout)
	logger := logging.MustGetLogger("certificate-authority")
	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logFormatter := logging.NewBackendFormatter(stdout, logFormat)
	// backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(logFormatter)

	keystore.DebugAvailableHashes(logger)
	keystore.DebugAvailableSignatureAkgorithms(logger)

	return logger
}

func defaultParams(
	logger *logging.Logger,
	config Config) CAParams {

	initParams := CAParams{
		Config:       config,
		Logger:       logger,
		Random:       rand.Reader,
		SelectedCA:   1,
		Identity:     config.Identity[0],
		Debug:        true,
		DebugSecrets: true,
	}
	return initStores(initParams)
}

// Creates a default CA configuration
func defaultConfig() Config {

	rootIdentity := Identity{
		KeyPassword: "root-password",
		KeySize:     512, // bits
		Valid:       1,   // year
		Subject: Subject{
			CommonName:   "root-ca",
			Organization: "Example Corporation",
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
		KeyPassword: "intermediate-password",
		KeySize:     512, // bits
		Valid:       1,   // year
		Subject: Subject{
			CommonName:   "intermediate-ca",
			Organization: "Example Corporation",
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

	// Create a temp directory for each instantiation
	// so parallel tests don't corrupt each other.
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		defaultLogger().Fatal(err)
	}
	tmpDir := hex.EncodeToString(buf)

	caDir := fmt.Sprintf("%s/%s", CERTS_DIR, tmpDir)
	//return DefaultConfigECDSA(caDir, rootIdentity, intermediateIdentity)
	return DefaultConfigRSA(caDir, rootIdentity, intermediateIdentity)
}
