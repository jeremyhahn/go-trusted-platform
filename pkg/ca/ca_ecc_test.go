package ca

import (
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/stretchr/testify/assert"
)

func TestECCIssueCertificateWithoutPrivateKeyPassword(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	// Set CA's default key algorithm to ECC
	config.DefaultKeyAlgorithm = x509.ECDSA.String()
	config.SignatureAlgorithm = x509.ECDSAWithSHA256.String()

	// Don't require passwords for these operations
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

	domain := "www.domain.com"
	certReq := CertificateRequest{
		KeyAttributes: &attrs,
		Valid:         365, // days
		Subject: Subject{
			CommonName:   domain,
			Organization: "Example Corporation",
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
	assert.Equal(t, x509.ECDSAWithSHA256, cert.SignatureAlgorithm)
}

func TestECCIssueCertificateWithPrivateKeyPassword(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	// Set CA's default key algorithm to ECC
	config.DefaultKeyAlgorithm = x509.ECDSA.String()
	config.SignatureAlgorithm = x509.ECDSAWithSHA256.String()

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

	domain := "www.domain.com"
	certReq := CertificateRequest{
		KeyAttributes: &attrs,
		Valid:         365, // days
		Subject: Subject{
			CommonName:   domain,
			Organization: "Example Corporation",
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
	assert.Equal(t, x509.ECDSAWithSHA256, cert.SignatureAlgorithm)
}

func TestECCInit(t *testing.T) {

	config := defaultConfig()
	assert.NotNil(t, config)

	params, _, intermediateCA, err := createService(config, true)
	defer cleanTempDir(config.Home)

	bundle, err := intermediateCA.CABundle(nil)
	assert.Nil(t, err)
	assert.NotNil(t, bundle)

	if err != nil {
		params.Logger.Error(err)
	}

	params.Logger.Info(string(bundle))
}
