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
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Signer wraps a CACertificateAuthority to implement the crypto.Signer
// interface for TLS operations. The ctx field carries the lifecycle context
// of the connection being established; it is captured at construction time
// because the crypto.Signer interface does not propagate context.
type Signer struct {
	logger   *logging.Logger
	ca       trustedca.CACertificateAuthority
	cert     *x509.Certificate
	cn       string
	password []byte
	ctx      context.Context
	crypto.Signer
}

// NewSigner creates a Signer backed by the given CA and certificate.
// ctx is used for CA operations that now require a context; it should be
// the request or connection lifetime context of the caller.
func NewSigner(
	ctx context.Context,
	logger *logging.Logger,
	ca trustedca.CACertificateAuthority,
	cert *x509.Certificate,
	cn string,
	password []byte) *Signer {

	return &Signer{
		ctx:      ctx,
		logger:   logger,
		ca:       ca,
		cert:     cert,
		cn:       cn,
		password: password,
	}
}

// Public returns the certificate's public key.
func (signer *Signer) Public() crypto.PublicKey {
	return signer.cert.PublicKey
}

// Sign delegates to the CA's default signer to produce a signature over
// digest. The CA's Signer() call uses the context captured at construction.
func (signer *Signer) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts) ([]byte, error) {

	signer.logger.Debug("webservice: signing digest", "digest", fmt.Sprintf("%x", digest))

	s, err := signer.ca.Signer(signer.ctx)
	if err != nil {
		signer.logger.Error(err)
		return nil, err
	}

	return s.Sign(rand, digest, opts)
}
