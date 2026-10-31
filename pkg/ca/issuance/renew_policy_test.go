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
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// anyPolicyOID is anyPolicy (RFC 5280 §4.2.1.4).
var anyPolicyOID = asn1.ObjectIdentifier{2, 5, 29, 32, 0}

// policyMapping is one PolicyMappings entry (RFC 5280 §4.2.1.5).
type policyMapping struct {
	IssuerDomainPolicy  asn1.ObjectIdentifier
	SubjectDomainPolicy asn1.ObjectIdentifier
}

// policyInformation is one CertificatePolicies entry (RFC 5280 §4.2.1.4).
type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
}

func marshalExtensionValue(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	require.NoError(t, err)
	return der
}

// withCriticalExtension adds a critical extension to the CA template, so the
// signed certificate carries it exactly as a stored CA would.
func withCriticalExtension(oid asn1.ObjectIdentifier, value []byte) func(*x509.Certificate) {
	return func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: oid, Critical: true, Value: value})
	}
}

// IssueCertificateWithProfile records a CA issuance the way IssueCertificate
// records a leaf, so a CA renewal that is not refused reaches the issue step.
func (c *renewCA) IssueCertificateWithProfile(ctx context.Context, req *quicbaasca.CACertificateRequest, _ string) (*quicbaasca.IssuedCertificate, error) {
	return c.IssueCertificate(ctx, req)
}

func policyRenewalCA() *renewIssuerCA {
	return &renewIssuerCA{
		renewCA: newRenewCA(),
		issuer:  &x509.Certificate{Subject: pkix.Name{CommonName: "Root"}, IsCA: true, BasicConstraintsValid: true, MaxPathLen: -1},
	}
}

// A CA under requireExplicitPolicy=0 constrains every path beneath it. The
// SDK CA request has no field for the extension, so a renewal would issue a
// replacement CA that validates chains the original prohibited (Codex 8652
// P1-3). The renewal is refused before anything is revoked.
func TestRenew_APolicyConstrainedCAIsRefusedBeforeRevocation(t *testing.T) {
	ca := policyRenewalCA()
	// PolicyConstraints ::= SEQUENCE { requireExplicitPolicy [0] SkipCerts }
	// with requireExplicitPolicy = 0.
	requireExplicitPolicyZero := []byte{0x30, 0x03, 0x80, 0x01, 0x00}
	existing := encodedCACert(t, withCriticalExtension(asn1.ObjectIdentifier{2, 5, 29, 36}, requireExplicitPolicyZero))

	_, err := Renew(context.Background(), ca, existing, RenewOptions{ValidDays: 30})

	var refusal *CARestrictionUnsupportedError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "policy constraints (RFC 5280 §4.2.1.11)", refusal.Restriction)
	assert.True(t, IsInvalidRequest(err))
	assert.Contains(t, err.Error(), "ca.CertificateRequest", "the refusal names the SDK gap")
	assertRenewalUntouched(t, ca.renewCA)
}

func TestRenew_ACAWithACertificatePolicyExtensionIsRefusedBeforeRevocation(t *testing.T) {
	cases := map[string]struct {
		oid         asn1.ObjectIdentifier
		value       func(t *testing.T) []byte
		restriction string
	}{
		"certificate policies": {
			oid: asn1.ObjectIdentifier{2, 5, 29, 32},
			value: func(t *testing.T) []byte {
				return marshalExtensionValue(t, []policyInformation{{PolicyIdentifier: anyPolicyOID}})
			},
			restriction: "certificate policies (RFC 5280 §4.2.1.4)",
		},
		"policy mappings": {
			oid: asn1.ObjectIdentifier{2, 5, 29, 33},
			value: func(t *testing.T) []byte {
				return marshalExtensionValue(t, []policyMapping{{
					IssuerDomainPolicy:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 1},
					SubjectDomainPolicy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 2},
				}})
			},
			restriction: "policy mappings (RFC 5280 §4.2.1.5)",
		},
		"inhibit anyPolicy": {
			oid:         asn1.ObjectIdentifier{2, 5, 29, 54},
			value:       func(t *testing.T) []byte { return marshalExtensionValue(t, 0) },
			restriction: "inhibit anyPolicy (RFC 5280 §4.2.1.14)",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ca := policyRenewalCA()
			existing := encodedCACert(t, withCriticalExtension(tc.oid, tc.value(t)))

			_, err := Renew(context.Background(), ca, existing, RenewOptions{ValidDays: 30})

			var refusal *CARestrictionUnsupportedError
			require.ErrorAs(t, err, &refusal)
			assert.Equal(t, tc.restriction, refusal.Restriction)
			assert.True(t, IsInvalidRequest(err))
			assertRenewalUntouched(t, ca.renewCA)
		})
	}
}

// A CA carrying none of the policy extensions still renews: the refusal is
// keyed on the extensions, not on the certificate being a CA.
func TestRenew_ACAWithoutPolicyExtensionsRenews(t *testing.T) {
	ca := policyRenewalCA()
	existing := encodedCACert(t, func(*x509.Certificate) {})

	renewed, err := Renew(context.Background(), ca, existing, RenewOptions{ValidDays: 30})

	require.NoError(t, err)
	assert.Same(t, ca.renewedCert, renewed)
	require.Len(t, ca.revokeOpts, 1)
	require.Len(t, ca.keyStore.rotated, 1)
	require.Len(t, ca.issued, 1)
	assert.True(t, ca.issued[0].IsCA, "the replacement is issued as a CA")
}

// A CA carrying a critical extension Go does not process would lose it in the
// renewal request, turning a CA relying parties must reject into an accepted
// one (Codex 8673 P1-2). The renewal is refused before anything is revoked,
// rotated or issued, and the refusal names the OID.
func TestRenew_ACAWithAnUnhandledCriticalExtensionIsRefusedBeforeRevocation(t *testing.T) {
	ca := policyRenewalCA()
	unknownOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 1}
	existing := encodedCACert(t, withCriticalExtension(unknownOID, marshalExtensionValue(t, true)))
	require.Len(t, existing.UnhandledCriticalExtensions, 1, "the test certificate carries the unknown extension")

	_, err := Renew(context.Background(), ca, existing, RenewOptions{ValidDays: 30})

	require.ErrorIs(t, err, ErrUnhandledCriticalExtension{})
	var refusal ErrUnhandledCriticalExtension
	require.ErrorAs(t, err, &refusal)
	require.Len(t, refusal.OIDs, 1)
	assert.True(t, refusal.OIDs[0].Equal(unknownOID))
	assert.Contains(t, err.Error(), unknownOID.String())
	assert.True(t, IsInvalidRequest(err))
	assertRenewalUntouched(t, ca.renewCA)
}
