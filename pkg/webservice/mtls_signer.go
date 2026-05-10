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
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

type Signer struct {
	logger   *logging.Logger
	ca       trustedca.CACertificateAuthority
	cert     *x509.Certificate
	cn       string
	password []byte
	crypto.Signer
}

func NewSigner(
	logger *logging.Logger,
	ca trustedca.CACertificateAuthority,
	cert *x509.Certificate,
	cn string,
	password []byte) *Signer {

	return &Signer{
		logger:   logger,
		ca:       ca,
		cert:     cert,
		cn:       cn,
		password: password}
}

func (signer *Signer) Public() crypto.PublicKey {
	return signer.cert.PublicKey
}

func (signer *Signer) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) ([]byte, error) {

	signer.logger.Debug("webservice: signing digest", "digest", fmt.Sprintf("%x", digest))

	// The CA's Signer() method returns the default CA signer
	s, err := signer.ca.Signer()
	if err != nil {
		signer.logger.Error(err)
		return nil, err
	}

	return s.Sign(rand, digest, opts)
}
