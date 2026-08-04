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

package commands

import (
	"context"
	"crypto"
	"crypto/x509"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// ErrNilVTPMCA is returned when a vtpmCAAdapter is asked to issue a certificate
// but has no backing certificate authority. Construction via newVTPMCAAdapter
// prevents this in practice (it returns a nil interface for a nil CA), but the
// guard keeps the adapter fail-closed if it is ever built directly.
type ErrNilVTPMCA struct{}

func (ErrNilVTPMCA) Error() string {
	return "vtpm: certificate authority is not configured"
}

// vtpmCAAdapter adapts the platform's TCG certificate authority
// (quicbaasca.CACertificateAuthority, reached through the QuicBaaS SDK) to the
// narrow vtpm.CertificateAuthority seam.
//
// It delegates EK certificate issuance to the same TCG CA method used by the
// physical-TPM endorsement flow (app.CA.IssueEKCertificate in pkg/app/app.go),
// so profile-bound vTPM bundles receive a TCG EK Credential Profile
// conformant certificate — EKU tcg-kp-EKCertificate, indefinite validity,
// TPM manufacturer/model/version SAN — rather than an ad hoc, non-conformant
// template. The TCG template is applied inside the CA; this adapter only
// supplies the subject common name and the EK public key.
type vtpmCAAdapter struct {
	ca quicbaasca.CACertificateAuthority
}

// newVTPMCAAdapter wraps ca in a vtpm.CertificateAuthority. It returns a nil
// interface when ca is nil so callers fail closed: vtpm.NewService accepts a
// nil CertificateAuthority and simply skips EK-cert injection, leaving bundles
// with profile binding but no EK certificate.
func newVTPMCAAdapter(ca quicbaasca.CACertificateAuthority) vtpm.CertificateAuthority {
	if ca == nil {
		return nil
	}
	return &vtpmCAAdapter{ca: ca}
}

// IssueEKCertificate issues a TCG EK certificate for publicKey, using hostname
// as the subject common name. The underlying TCGCA.IssueEKCertificate applies
// the TCG EK Credential Profile (extended key usage, key usage, validity, and
// TPM SANs) internally.
func (a *vtpmCAAdapter) IssueEKCertificate(
	ctx context.Context,
	publicKey crypto.PublicKey,
	hostname string,
) (*x509.Certificate, error) {

	if a.ca == nil {
		return nil, ErrNilVTPMCA{}
	}
	req := &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{
			CommonName: hostname,
		},
	}
	return a.ca.IssueEKCertificate(ctx, req, publicKey)
}
