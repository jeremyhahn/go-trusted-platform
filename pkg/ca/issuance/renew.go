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

package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// RenewOptions is what a renewal changes about the certificate it replaces.
type RenewOptions struct {
	// ValidDays is the renewed certificate's validity.
	ValidDays int
	// PreserveSANs carries the old certificate's subject alternative names.
	PreserveSANs bool
	// NewSANs replaces the subject alternative names; it wins over PreserveSANs.
	NewSANs *quicbaasca.CASubjectAlternativeNames
}

// Renew replaces existing with a certificate on re-keyed material, as
// docs/ca/user.md "Renewing" describes: it revokes the old certificate, rotates
// its key to new material under the same key name, and issues the new
// certificate on that key. The key keeps its name because the SDK KMS keeps a
// deleted key's name reserved: a revoke with DeleteKeys followed by a fresh
// generation under the same CN fails with already_exists. Every transport
// renews through here.
func Renew(ctx context.Context, ca quicbaasca.CACertificateAuthority, existing *x509.Certificate, opts RenewOptions) (*x509.Certificate, error) {
	keyStore := ca.KeyStore()
	certStore := ca.CertStore()
	if keyStore == nil || certStore == nil {
		return nil, &RenewStoresUnavailableError{}
	}

	// Refuse before anything is revoked, rotated or deleted: a refusal from
	// Issue after those steps would leave no usable certificate behind.
	if err := checkRenewableRestrictions(existing); err != nil {
		return nil, &RenewError{Step: "check the certificate's restrictions", Err: err}
	}
	req := renewalRequest(existing, opts)
	if err := preflight(ca, req); err != nil {
		return nil, &RenewError{Step: "check the renewal against the issuer", Err: err}
	}

	if err := ca.RevokeCert(ctx, existing, quicbaasca.RevokeOptions{}); err != nil {
		return nil, &RenewError{Step: "revoke the old certificate", Err: err}
	}

	if _, err := keyStore.RotateKey(ctx, renewalKeyAttributes(existing)); err != nil {
		return nil, &RenewError{Step: "rotate the key", Err: err}
	}

	// IssueCertificate refuses a CN the certificate store still holds.
	if err := certStore.DeleteCertificate(existing.Subject.CommonName); err != nil {
		return nil, &RenewError{Step: "remove the old certificate", Err: err}
	}

	// Issue, not IssueCertificate: a CA certificate must be renewed with the
	// CA profile, or the replacement would be a leaf.
	issued, err := Issue(ctx, ca, req)
	if err != nil {
		return nil, &RenewError{Step: "issue the renewed certificate", Err: err}
	}
	return issued.Certificate, nil
}

// policyRestrictions are the RFC 5280 certificate-policy extensions a CA can
// carry to constrain the paths beneath it. The pinned SDK CA profile (go-xkms
// ca.CertificateRequest) has no field for any of them, so a renewal would
// issue the replacement CA without the restriction.
var policyRestrictions = []struct {
	oid  asn1.ObjectIdentifier
	name string
}{
	{asn1.ObjectIdentifier{2, 5, 29, 32}, "certificate policies (RFC 5280 §4.2.1.4)"},
	{asn1.ObjectIdentifier{2, 5, 29, 33}, "policy mappings (RFC 5280 §4.2.1.5)"},
	{asn1.ObjectIdentifier{2, 5, 29, 36}, "policy constraints (RFC 5280 §4.2.1.11)"},
	{asn1.ObjectIdentifier{2, 5, 29, 54}, "inhibit anyPolicy (RFC 5280 §4.2.1.14)"},
}

// checkRenewableRestrictions refuses the renewal of a CA certificate whose
// name constraints, unrecognized extended key usages or certificate-policy
// extensions renewalRequest cannot copy: the SDK request has no field for
// any of them, so the replacement CA would silently lose them
// (CARestrictionUnsupportedError).
func checkRenewableRestrictions(existing *x509.Certificate) error {
	if existing == nil || !existing.IsCA {
		return nil
	}
	if hasNameConstraints(existing) {
		return &CARestrictionUnsupportedError{Restriction: "name constraints"}
	}
	if len(existing.UnknownExtKeyUsage) > 0 {
		return &CARestrictionUnsupportedError{Restriction: "an unrecognized extended key usage"}
	}
	for _, extension := range existing.Extensions {
		for _, policy := range policyRestrictions {
			if extension.Id.Equal(policy.oid) {
				return &CARestrictionUnsupportedError{Restriction: policy.name}
			}
		}
	}
	return nil
}

// hasNameConstraints reports whether the certificate carries any permitted or
// excluded DNS, IP, email or URI name constraint (RFC 5280 §4.2.1.10).
func hasNameConstraints(cert *x509.Certificate) bool {
	return len(cert.PermittedDNSDomains) > 0 || len(cert.ExcludedDNSDomains) > 0 ||
		len(cert.PermittedIPRanges) > 0 || len(cert.ExcludedIPRanges) > 0 ||
		len(cert.PermittedEmailAddresses) > 0 || len(cert.ExcludedEmailAddresses) > 0 ||
		len(cert.PermittedURIDomains) > 0 || len(cert.ExcludedURIDomains) > 0
}

// renewalRequest is the issue request for existing's renewal: its subject,
// constraints and usages, the validity and names opts selects, on the
// software-store TLS key that carries its common name.
func renewalRequest(existing *x509.Certificate, opts RenewOptions) *quicbaasca.CACertificateRequest {
	req := &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{
			CommonName:         existing.Subject.CommonName,
			Organization:       firstOrEmpty(existing.Subject.Organization),
			OrganizationalUnit: firstOrEmpty(existing.Subject.OrganizationalUnit),
			Country:            firstOrEmpty(existing.Subject.Country),
			Province:           firstOrEmpty(existing.Subject.Province),
			Locality:           firstOrEmpty(existing.Subject.Locality),
			Address:            firstOrEmpty(existing.Subject.StreetAddress),
			PostalCode:         firstOrEmpty(existing.Subject.PostalCode),
		},
		Valid:         opts.ValidDays,
		IsCA:          existing.IsCA,
		MaxPathLen:    existing.MaxPathLen,
		KeyUsage:      existing.KeyUsage,
		ExtKeyUsage:   existing.ExtKeyUsage,
		KeyAttributes: renewalKeyAttributes(existing),
	}

	switch {
	case opts.NewSANs != nil:
		req.SANS = opts.NewSANs
	case opts.PreserveSANs:
		req.SANS = existingSANs(existing)
	}
	return req
}

// renewalKeyAttributes names the key existing is renewed on: the software-store
// TLS key under its common name, of its algorithm and, for an ECDSA key, its
// curve or, for an RSA key, its modulus size. Renew rotates this key and issues
// on it, so both see one key; a real go-xkms backend refuses a key without its
// store type, an ECDSA key without its curve, and an RSA key without its size.
func renewalKeyAttributes(existing *x509.Certificate) *xkmssdk.KeyAttributes {
	attrs := &xkmssdk.KeyAttributes{
		CN:           existing.Subject.CommonName,
		KeyAlgorithm: existing.PublicKeyAlgorithm,
		StoreType:    xkmssdk.StoreSoftware,
		KeyType:      xkmssdk.KeyTypeTLS,
	}
	if pub, ok := existing.PublicKey.(*ecdsa.PublicKey); ok {
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{Curve: pub.Curve}
	}
	if pub, ok := existing.PublicKey.(*rsa.PublicKey); ok {
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: pub.N.BitLen()}
	}
	return attrs
}

// existingSANs is existing's subject alternative names, or nil when it has none.
func existingSANs(existing *x509.Certificate) *quicbaasca.CASubjectAlternativeNames {
	if len(existing.DNSNames) == 0 && len(existing.IPAddresses) == 0 &&
		len(existing.EmailAddresses) == 0 && len(existing.URIs) == 0 {
		return nil
	}
	sans := &quicbaasca.CASubjectAlternativeNames{
		DNS:   existing.DNSNames,
		Email: existing.EmailAddresses,
	}
	for _, ip := range existing.IPAddresses {
		sans.IPs = append(sans.IPs, ip.String())
	}
	for _, uri := range existing.URIs {
		sans.URIs = append(sans.URIs, uri.String())
	}
	return sans
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
