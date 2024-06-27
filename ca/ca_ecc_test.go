package ca

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECCIssueCertificate(t *testing.T) {

	_, rootCA, _, err := createService(KEY_ALGO_ECC, false)
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
	assert.Equal(t, x509.ECDSAWithSHA256, cert.SignatureAlgorithm)
}

func TestECCInit(t *testing.T) {

	logger, _, intermediateCAs, err := createService(KEY_ALGO_ECC, false)
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
