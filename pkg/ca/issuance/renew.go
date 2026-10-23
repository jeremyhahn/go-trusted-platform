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
	"crypto/x509"

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

	if err := ca.RevokeCert(ctx, existing, quicbaasca.RevokeOptions{}); err != nil {
		return nil, &RenewError{Step: "revoke the old certificate", Err: err}
	}

	rotateAttrs := &xkmssdk.KeyAttributes{
		CN:           existing.Subject.CommonName,
		KeyAlgorithm: existing.PublicKeyAlgorithm,
	}
	if _, err := keyStore.RotateKey(ctx, rotateAttrs); err != nil {
		return nil, &RenewError{Step: "rotate the key", Err: err}
	}

	// IssueCertificate refuses a CN the certificate store still holds.
	if err := certStore.DeleteCertificate(existing.Subject.CommonName); err != nil {
		return nil, &RenewError{Step: "remove the old certificate", Err: err}
	}

	issued, err := ca.IssueCertificate(ctx, renewalRequest(existing, opts))
	if err != nil {
		return nil, &RenewError{Step: "issue the renewed certificate", Err: err}
	}
	return issued.Certificate, nil
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
		Valid:       opts.ValidDays,
		IsCA:        existing.IsCA,
		MaxPathLen:  existing.MaxPathLen,
		KeyUsage:    existing.KeyUsage,
		ExtKeyUsage: existing.ExtKeyUsage,
		KeyAttributes: &xkmssdk.KeyAttributes{
			CN:           existing.Subject.CommonName,
			KeyAlgorithm: existing.PublicKeyAlgorithm,
			StoreType:    xkmssdk.StoreSoftware,
			KeyType:      xkmssdk.KeyTypeTLS,
		},
	}

	switch {
	case opts.NewSANs != nil:
		req.SANS = opts.NewSANs
	case opts.PreserveSANs:
		req.SANS = existingSANs(existing)
	}
	return req
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
