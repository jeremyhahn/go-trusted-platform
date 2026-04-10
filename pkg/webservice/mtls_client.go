// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package webservice

import (
	"crypto/tls"
	"io"
	"net/http"

	trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

type MutualTLSClient struct {
	logger *logging.Logger
	http   http.Client
	ca     trustedca.CACertificateAuthority
}

func NewMutalTLSClient(
	logger *logging.Logger,
	ca trustedca.CACertificateAuthority,
	attrs *xkmssdk.KeyAttributes) MutualTLSClient {

	client := MutualTLSClient{logger: logger, ca: ca}
	client.http = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: func(
					info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return client.certificate(attrs)
				},
			},
		},
	}

	return client
}

// Performs an HTTP GET request
func (client MutualTLSClient) Get(url string) ([]byte, error) {

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
func (client MutualTLSClient) certificate(attrs *xkmssdk.KeyAttributes) (*tls.Certificate, error) {

	client.logger.Infof("requesting client certificate: %s", attrs.CN)

	cert, err := client.ca.Certificate(attrs)
	if err != nil {
		return nil, err
	}

	certificate := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  &Signer{cert: cert},
	}
	return &certificate, nil
}
