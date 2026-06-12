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
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// MutualTLSClient is an HTTP client that presents a platform CA-issued client
// certificate on every request and optionally pins server verification to a
// provided CA pool.
type MutualTLSClient struct {
	logger *logging.Logger
	http   http.Client
	ca     trustedca.CACertificateAuthority
}

// NewMutalTLSClient constructs a MutualTLSClient. The client certificate is
// obtained from ca at handshake time via attrs. When rootCAs is non-nil the
// transport's TLS configuration uses it as RootCAs so the server certificate
// is verified against the platform internal CA pool; when nil the operating
// system trust store is used.
func NewMutalTLSClient(
	ctx context.Context,
	logger *logging.Logger,
	ca trustedca.CACertificateAuthority,
	attrs *xkmssdk.KeyAttributes,
	rootCAs *x509.CertPool,
) MutualTLSClient {

	client := MutualTLSClient{logger: logger, ca: ca}
	client.http = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs, // nil → system roots
				GetClientCertificate: func(
					info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return client.certificate(info.Context(), attrs)
				},
			},
		},
	}

	return client
}

// Get performs an HTTP GET request.
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

// certificate retrieves the mTLS client certificate from the Certificate Authority.
func (client MutualTLSClient) certificate(ctx context.Context, attrs *xkmssdk.KeyAttributes) (*tls.Certificate, error) {

	client.logger.Infof("requesting client certificate: %s", attrs.CN)

	cert, err := client.ca.Certificate(ctx, attrs)
	if err != nil {
		return nil, err
	}

	certificate := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  &Signer{cert: cert},
	}
	return &certificate, nil
}
