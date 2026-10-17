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

package quicbaas

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// =============================================================================
// Adapter resolution path tests
//
// These exercise the "no provider" / "provider yields nil" branches without
// requiring a full xkmssdk.TrustedCA implementation. Calls that actually
// reach the underlying CA are covered end-to-end by the barrier-gate
// integration test which boots a real platformd against a real platform CA.
// =============================================================================

// TestCeremonyCAAdapter_NoProviderReturnsTypedError verifies the adapter
// returns ErrCeremonyCANotAvailable on every method when no provider has
// been installed (the pre-LoadCA() startup window).
func TestCeremonyCAAdapter_NoProviderReturnsTypedError(t *testing.T) {
	a := NewCeremonyCAAdapter(nil)

	_, err := a.CACertificate()
	require.Error(t, err)
	var notAvail ErrCeremonyCANotAvailable
	assert.ErrorAs(t, err, &notAvail)

	_, err = a.CABundle()
	require.Error(t, err)

	_, err = a.SignCSR(context.Background(), []byte("dummy"), nil)
	require.Error(t, err)

	_, err = a.IssueCertificate(context.Background(), &quicbaas.QRDBCeremonyIssueCertRequest{CommonName: "x"})
	require.Error(t, err)
}

// TestCeremonyCAAdapter_ProviderYieldsNilReturnsTypedError verifies the
// adapter surfaces ErrCeremonyCANotAvailable when the provider is set but
// returns nil (CA has not been loaded yet).
func TestCeremonyCAAdapter_ProviderYieldsNilReturnsTypedError(t *testing.T) {
	a := NewCeremonyCAAdapter(func() xkmssdk.TrustedCA { return nil })

	_, err := a.CACertificate()
	require.Error(t, err)

	_, err = a.SignCSR(context.Background(), []byte("dummy"), nil)
	require.Error(t, err)

	_, err = a.IssueCertificate(context.Background(), &quicbaas.QRDBCeremonyIssueCertRequest{CommonName: "x"})
	require.Error(t, err)
}

// TestCeremonyCAAdapter_SetProviderNilDisables verifies SetProvider(nil)
// detaches the underlying CA reference so subsequent calls return
// ErrCeremonyCANotAvailable.
func TestCeremonyCAAdapter_SetProviderNilDisables(t *testing.T) {
	a := NewCeremonyCAAdapter(func() xkmssdk.TrustedCA { return nil })
	a.SetProvider(nil)

	_, err := a.CACertificate()
	require.Error(t, err)
}

// TestCeremonyCAAdapter_SetProviderRebinds verifies SetProvider swaps the
// provider atomically. We can't supply a real CA without the heavy go-xkms
// stack, but we can verify the provider FUNCTION is replaced — the second
// provider is the one that gets called by the next resolve attempt.
func TestCeremonyCAAdapter_SetProviderRebinds(t *testing.T) {
	calls := 0
	a := NewCeremonyCAAdapter(func() xkmssdk.TrustedCA {
		calls++
		return nil
	})
	_, _ = a.CACertificate()
	require.Equal(t, 1, calls, "first provider should have been called once")

	second := 0
	a.SetProvider(func() xkmssdk.TrustedCA {
		second++
		return nil
	})
	_, _ = a.CACertificate()
	assert.Equal(t, 1, calls, "first provider must not be invoked after swap")
	assert.Equal(t, 1, second, "second provider must be invoked after swap")
}

// TestCeremonyCAAdapter_NilReceiverSafe verifies the adapter tolerates a
// nil receiver (defensive: if a higher-level wiring step accidentally
// passes nil the adapter must not panic).
func TestCeremonyCAAdapter_NilReceiverSafe(t *testing.T) {
	var a *CeremonyCAAdapter
	_, err := a.CACertificate()
	require.Error(t, err)

	// SetProvider on a nil receiver is a no-op (no panic).
	a.SetProvider(func() xkmssdk.TrustedCA { return nil })
}

// =============================================================================
// Option translation tests
// =============================================================================

// TestTranslateSignCSROptions_NilIsNil verifies the helper short-circuits
// on nil input so the underlying CA falls back to its profile defaults.
func TestTranslateSignCSROptions_NilIsNil(t *testing.T) {
	assert.Nil(t, translateSignCSROptions(nil))
}

// TestTranslateSignCSROptions_CopiesAllFields verifies every field of the
// qrdb options struct is copied into the xkms struct without loss.
func TestTranslateSignCSROptions_CopiesAllFields(t *testing.T) {
	in := &quicbaas.QRDBCeremonySignCSROptions{
		Profile:      "security-officer",
		ValidityDays: 30,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	out := translateSignCSROptions(in)
	require.NotNil(t, out)
	assert.Equal(t, in.ValidityDays, out.ValidityDays)
	assert.Equal(t, in.KeyUsage, out.KeyUsage)
	assert.Equal(t, in.ExtKeyUsage, out.ExtKeyUsage)
}

// TestTranslateSignCSROptions_DropsRoleProfile verifies the ceremony's officer
// role name never reaches the CA as a profile: the platform CA's registry has
// no "security-officer" or "administrator" profile and refuses the CSR when
// one is named (#949, ceremony SignCSR answered 500).
func TestTranslateSignCSROptions_DropsRoleProfile(t *testing.T) {
	for _, role := range []string{"security-officer", "administrator", "operator", "user", "auditor", "custodian"} {
		out := translateSignCSROptions(&quicbaas.QRDBCeremonySignCSROptions{Profile: role})
		require.NotNil(t, out, role)
		assert.Empty(t, out.Profile, role)
	}
}

// TestTranslateIssueCertRequest_NilIsNil verifies the helper short-circuits
// on nil input.
func TestTranslateIssueCertRequest_NilIsNil(t *testing.T) {
	assert.Nil(t, translateIssueCertRequest(nil))
}

// TestTranslateIssueCertRequest_PartitionsSANs verifies the helper splits
// the qrdb-side flat SAN slice into DNS, IP and email buckets the way
// the go-xkms CertificateRequest expects.
func TestTranslateIssueCertRequest_PartitionsSANs(t *testing.T) {
	in := &quicbaas.QRDBCeremonyIssueCertRequest{
		CommonName:   "cp.test",
		SANs:         []string{"cp.test", "127.0.0.1", "::1", "admin@cp.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ValidityDays: 365,
	}
	out := translateIssueCertRequest(in)
	require.NotNil(t, out)
	assert.Equal(t, "cp.test", out.Subject.CommonName)
	assert.Equal(t, 365, out.Valid)
	assert.Equal(t, in.KeyUsage, out.KeyUsage)
	assert.Equal(t, in.ExtKeyUsage, out.ExtKeyUsage)

	require.NotNil(t, out.SANS)
	assert.Equal(t, []string{"cp.test"}, out.SANS.DNS)
	assert.Equal(t, []string{"127.0.0.1", "::1"}, out.SANS.IPs)
	assert.Equal(t, []string{"admin@cp.test"}, out.SANS.Email)
}

// TestTranslateIssueCertRequest_NoSANsKeepsSANSNil verifies the helper does
// not allocate an empty SANS struct when the input has no SANs (matches
// the upstream CA behaviour of "no SANs means no SAN extension").
func TestTranslateIssueCertRequest_NoSANsKeepsSANSNil(t *testing.T) {
	in := &quicbaas.QRDBCeremonyIssueCertRequest{
		CommonName:   "cp.test",
		ValidityDays: 30,
	}
	out := translateIssueCertRequest(in)
	require.NotNil(t, out)
	assert.Nil(t, out.SANS)
}

// =============================================================================
// SAN classification predicate
// =============================================================================

// TestIsEmailSAN covers the corner cases the ceremony's SAN translation
// can hit when the operator submits an arbitrary SAN set.
func TestIsEmailSAN(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"plain dns", "cp.test", false},
		{"email", "admin@cp.test", true},
		{"leading at", "@cp.test", false},
		{"trailing at", "admin@", false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isEmailSAN(tc.in))
		})
	}
}

// =============================================================================
// Error type assertions
// =============================================================================

// TestErrCeremonyCANotAvailable_HasMessage verifies the typed error renders
// a non-empty diagnostic string suitable for log scraping.
func TestErrCeremonyCANotAvailable_HasMessage(t *testing.T) {
	e := ErrCeremonyCANotAvailable{}
	assert.NotEmpty(t, e.Error())
	assert.Contains(t, e.Error(), "ceremony CA")
}
