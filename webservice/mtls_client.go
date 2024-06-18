package webservice

import (
	"crypto/tls"
	"io"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pki/ca"
	"github.com/op/go-logging"
)

type MutualTLSClient struct {
	logger *logging.Logger
	http   http.Client
	ca     ca.CertificateAuthority
}

func NewMutalTLSClient(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	cn string) *MutualTLSClient {

	client := &MutualTLSClient{
		logger: logger,
		ca:     ca}

	client.http = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: func(
					info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return client.certificate(cn)
				},
			},
		},
	}

	return client
}

// Performs an HTTP GET request
func (client *MutualTLSClient) Get(url string) ([]byte, error) {

	response, err := client.http.Get(url)
	if err != nil {
		client.logger.Error(err)
		return nil, err
	}
	defer response.Body.Close()

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		client.logger.Error(err)
		return nil, err
	}

	return bytes, nil
}

// Retrieves the mTLS client certificate from the Certificate Authority
func (client *MutualTLSClient) certificate(cn string) (*tls.Certificate, error) {

	client.logger.Infof("requesting client certificate: %s", cn)

	cert, err := client.ca.Certificate(cn)
	if err != nil {
		return nil, err
	}

	certificate := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  &Signer{cert: cert},
	}
	return &certificate, nil
}
