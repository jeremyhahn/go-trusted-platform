package ca

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECCIssueCertificateWithoutPrivateKeyPassword(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	// Set CA's default key algorithm to ECC
	config.DefaultKeyAlgorithm = KEY_ALGO_ECC

	// Don't require passwords for these operations
	config.RequirePrivateKeyPassword = false

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
	der, err := rootCA.IssueCertificate(certReq, rootPass, nil)
	assert.Nil(t, err)
	assert.NotNil(t, der)

	cert, err := x509.ParseCertificate(der)
	assert.Nil(t, err)
	assert.Equal(t, domain, cert.Subject.CommonName)
	assert.Equal(t, x509.ECDSAWithSHA256, cert.SignatureAlgorithm)
}

func TestECCIssueCertificateWithPrivateKeyPassword(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	// Set CA's default key algorithm to ECC
	config.DefaultKeyAlgorithm = KEY_ALGO_ECC

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	_, rootCA, _, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)

	assert.Nil(t, err)

	domain := "www.domain.com"
	keyPass := []byte("cert-private-key-pass")

	certReq := CertificateRequest{
		Valid: 365, // days
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
	der, err := rootCA.IssueCertificate(certReq, rootPass, keyPass)
	assert.Nil(t, err)
	assert.NotNil(t, der)

	cert, err := x509.ParseCertificate(der)
	assert.Nil(t, err)
	assert.Equal(t, domain, cert.Subject.CommonName)
	assert.Equal(t, x509.ECDSAWithSHA256, cert.SignatureAlgorithm)
}

func TestECCInit(t *testing.T) {

	config, err := defaultConfig()
	assert.Nil(t, err)
	assert.NotNil(t, config)

	rootPass := []byte("root-password")
	intermediatePass := []byte("intermediate-password")
	logger, _, intermediateCA, err := createService(config, rootPass, intermediatePass, true)
	defer cleanTempDir(config.Home)

	bundle, err := intermediateCA.CABundle()
	assert.Nil(t, err)
	assert.NotNil(t, bundle)

	if err != nil {
		logger.Error(err)
	}

	logger.Info(string(bundle))
}
