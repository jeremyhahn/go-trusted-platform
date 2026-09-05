// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vm

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"time"
)

// oidTCGVerifiedTPMRestricted is tcg-cap-verifiedTPMRestricted
// (2.23.133.11.1.3): the certified key is a Restricted signing key, so data
// it signs is genuinely TPM internal data.
//
// Defined locally because the quicbaas SDK does not yet re-export go-xkms's
// TCG OID constants (go-quicbaas#533) and this repository may not import
// go-xkms/pkg directly. It is a TCG-registry constant, not xkms logic; once
// the SDK carries it this definition is deleted in favour of the alias.
var (
	oidTCGVerifiedTPMRestricted     = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 3}
	oidTCGVerifiedTPMRestrictedX509 = mustOIDFromInts(2, 23, 133, 11, 1, 3)
)

// mustOIDFromInts builds an x509.OID for a static arc. A failure is a
// programming error in a literal, so it panics at init rather than being
// silently wrong at verification time.
func mustOIDFromInts(arc ...uint64) x509.OID {
	oid, err := x509.OIDFromInts(arc)
	if err != nil {
		panic("vm: invalid static OID: " + err.Error())
	}
	return oid
}

// VerifyAKCertificate parses an attestation-key certificate, verifies it
// chains to roots through intermediates (when roots is non-nil) as of now,
// and requires that it
// carries tcg-cap-verifiedTPMRestricted. It returns the certified public key,
// which is the trust anchor for verifying quotes from that device.
//
// The attribute check is the whole point. TCG "TPM 2.0 Keys for Device
// Identity and Attestation" v1 r12 §8.2: a relying party evaluating signed
// data purporting to be TPM internal data MUST check for the presence of
// tcg-cap-verifiedTPMRestricted in the IAK/LAK certificate to prevent the
// possibility of spoofing. A certificate without it may certify an
// Unrestricted key — one that can sign anything its holder chooses — and a
// quote-shaped blob signed by such a key is exactly the forgery the attribute
// exists to rule out (#374).
//
// Fails closed: every path that cannot establish the property returns an
// error, and a nil error means the certificate parsed, chained, and carries
// the attribute.
func VerifyAKCertificate(certPEM []byte, roots, intermediates *x509.CertPool, now time.Time) (crypto.PublicKey, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrAKCertificateInvalid{Reason: "not a PEM CERTIFICATE block"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrAKCertificateInvalid{Reason: "parse failed", Cause: err}
	}

	if roots != nil {
		// An AK certificate carries no standard EKU that names attestation,
		// so the chain is verified for any usage; what the key is FOR is
		// established by the TCG policy OID below, not by EKU.
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return nil, ErrAKCertificateInvalid{Reason: "does not chain to a trusted root", Cause: err}
		}
	}

	if !carriesVerifiedTPMRestricted(cert) {
		return nil, ErrAKCertificateNotRestricted{Subject: cert.Subject.String()}
	}
	return cert.PublicKey, nil
}

// carriesVerifiedTPMRestricted reports whether the certificate's
// certificatePolicies extension includes tcg-cap-verifiedTPMRestricted. Both
// the x509.OID form and the legacy asn1.ObjectIdentifier form are consulted:
// Go populates Policies for every policy and PolicyIdentifiers for those
// whose arcs fit, and a certificate produced by an older issuer may carry
// only the latter.
func carriesVerifiedTPMRestricted(cert *x509.Certificate) bool {
	for _, p := range cert.Policies {
		if p.Equal(oidTCGVerifiedTPMRestrictedX509) {
			return true
		}
	}
	for _, p := range cert.PolicyIdentifiers {
		if p.Equal(oidTCGVerifiedTPMRestricted) {
			return true
		}
	}
	return false
}
