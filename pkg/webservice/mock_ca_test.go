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
	"io"

	trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// mockCAForSigner is a minimal mock that only implements the Signer() method.
// It embeds the real CA interface to satisfy the type constraint,
// but only the Signer() method should be called.
type mockCAForSigner struct {
	trustedca.CACertificateAuthority
	signer    crypto.Signer
	signerErr error
}

func (m *mockCAForSigner) Signer() (crypto.Signer, error) {
	if m.signerErr != nil {
		return nil, m.signerErr
	}
	return m.signer, nil
}

func (m *mockCAForSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (m *mockCAForSigner) Public() crypto.PublicKey {
	return nil
}

// mockCAForCert is a minimal mock that only implements the Certificate() method.
type mockCAForCert struct {
	trustedca.CACertificateAuthority
	cert    *x509.Certificate
	certErr error
}

func (m *mockCAForCert) Certificate(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	if m.certErr != nil {
		return nil, m.certErr
	}
	return m.cert, nil
}

func (m *mockCAForCert) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (m *mockCAForCert) Public() crypto.PublicKey {
	return nil
}
