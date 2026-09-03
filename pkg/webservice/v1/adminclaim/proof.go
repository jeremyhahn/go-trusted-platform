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

package adminclaim

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"os"
	"strings"
)

// LoadTrustAnchor reads the PEM bundle that the firstboot admin
// certificate must chain to. On a deployed node this is the QuicBaaS CA
// chain the embedded server wrote next to the admin bundle
// (<quicbaas data-dir>/certs/ca-chain.crt).
//
// Per docs/08-bootstrap-auth-contract.md the anchor is deliberately NOT
// the platform CA: the admin certificate is issued by the QuicBaaS CA
// during firstboot, before the platform CA has any relationship with it.
func LoadTrustAnchor(pemPath string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, ErrAnchorUnreadable{Path: pemPath, Cause: err}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, ErrAnchorUnreadable{Path: pemPath}
	}
	return pool, nil
}

// parseCertificatePEM decodes a single PEM CERTIFICATE block.
func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrCertificateInvalid{Reason: "not a PEM certificate"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrCertificateInvalid{Reason: "unparseable", Cause: err}
	}
	return cert, nil
}

// verifyAdminCertificate checks that cert is the firstboot system admin's
// client certificate: it chains to the configured anchor, is inside its
// validity window, carries the TLS client EKU, and names the admin.
//
// Identity is asserted two ways, BOTH mandatory:
//
//   - The subject common name must be the admin username. qrdb's CA always
//     sets it (CN=admin on a deployed node).
//   - The certificate must carry a SPIFFE URI SAN of exactly the shape
//     spiffe://<trust-domain>/tenant/<tenantID>/user/<admin username>, with
//     tenantID the platform's adopted operating tenant. qrdb first-boot
//     cannot issue the admin certificate without a configured SPIFFE trust
//     domain — the whole IAM bootstrap fails without one — so every genuine
//     admin certificate has it.
//
// **The tenant segment is compared.** The same deployment CA also issues
// certificates for tenant users, so accepting any tenant would let a
// tenant whose administrator happens to be named "admin" present
// spiffe://<domain>/tenant/acme/user/admin and claim the SYSTEM admin
// identity. qrdb's system tenant has the fixed id "system" and the
// platform adopts it as its operating tenant, so the id the ceremony is
// scoped to is exactly the name that appears in the SPIFFE path.
func verifyAdminCertificate(
	cert *x509.Certificate,
	anchors *x509.CertPool,
	adminUsername string,
	tenantID string,
) error {

	if tenantID == "" {
		return ErrCertificateInvalid{Reason: "no operating tenant is configured"}
	}

	if anchors == nil {
		return ErrCertificateInvalid{Reason: "no trust anchor is configured"}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     anchors,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return ErrCertificateInvalid{Reason: "does not chain to the admin trust anchor", Cause: err}
	}
	if cert.Subject.CommonName != adminUsername {
		return ErrIdentityMismatch{Presented: cert.Subject.CommonName, Expected: adminUsername}
	}
	for _, uri := range cert.URIs {
		if isAdminSPIFFEID(uri, adminUsername, tenantID) {
			return nil
		}
	}
	presented := "<no URI SAN>"
	if len(cert.URIs) > 0 {
		presented = cert.URIs[0].String()
	}
	return ErrIdentityMismatch{
		Presented: presented,
		Expected:  "spiffe://<trust-domain>/tenant/" + tenantID + "/user/" + adminUsername,
	}
}

// isAdminSPIFFEID reports whether uri is the SPIFFE ID of the system
// admin: exactly the four segments tenant/<tenantID>/user/<adminUsername>.
// The shape is matched segment-wise rather than by a string suffix, so a
// trust domain, tenant or user crafted to end in "user/admin" cannot
// satisfy it.
func isAdminSPIFFEID(uri *url.URL, adminUsername, tenantID string) bool {
	if uri == nil || !strings.EqualFold(uri.Scheme, "spiffe") {
		return false
	}
	segments := strings.Split(strings.Trim(uri.Path, "/"), "/")
	if len(segments) != 4 {
		return false
	}
	return segments[0] == "tenant" &&
		segments[1] == tenantID &&
		segments[2] == "user" &&
		segments[3] == adminUsername
}

// verifyChallengeSignature checks that signature was produced over
// challenge by the private key matching cert's public key. This is the
// proof of possession for an operator who reaches the API over ordinary
// server-authenticated TLS, where no client certificate was presented in
// the handshake.
//
// ECDSA and RSA sign the SHA-256 digest of the challenge (ASN.1 and
// PKCS#1 v1.5 respectively); Ed25519 signs the challenge unhashed, as the
// algorithm requires. An unsupported key type is refused rather than
// waved through.
func verifyChallengeSignature(cert *x509.Certificate, challenge, signature []byte) error {
	if len(signature) == 0 {
		return ErrProofInvalid{Cause: ErrCertificateInvalid{Reason: "empty signature"}}
	}
	digest := sha256.Sum256(challenge)
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], signature) {
			return ErrProofInvalid{Cause: ErrCertificateInvalid{Reason: "ECDSA signature does not verify"}}
		}
		return nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			return ErrProofInvalid{Cause: err}
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, challenge, signature) {
			return ErrProofInvalid{Cause: ErrCertificateInvalid{Reason: "Ed25519 signature does not verify"}}
		}
		return nil
	default:
		return ErrProofInvalid{Cause: ErrCertificateInvalid{Reason: "unsupported admin key algorithm"}}
	}
}
