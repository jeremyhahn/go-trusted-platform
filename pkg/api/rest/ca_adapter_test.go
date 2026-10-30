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

package rest

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock production CA implementing xkmsca.TCGCA surface
// =============================================================================
//
// We only implement the methods exercised by CAAuthorityAdapter; the rest are
// stubbed out to satisfy the interface surface used by NewCAAuthorityAdapter.
// =============================================================================

type fakeProdCA struct {
	xkmsca.TCGCA // embed for any unimplemented methods (will panic if called)

	// issuedProfile is the profile the last IssueCertificateWithProfile got.
	issuedProfile string

	identity        string
	initialized     bool
	defaultKeyAlg   x509.PublicKeyAlgorithm
	defaultValidity int
	rootCert        *x509.Certificate
	intermediate    *x509.Certificate
	issued          *xkmsca.IssuedCertificate
	issueErr        error
	revokeErr       error
	revokeOpts      xkmsca.RevokeOptions
	revokeCert      *x509.Certificate
	bundle          []byte
	bundleErr       error
	bundleFiltered  []byte
	bundleFilterErr error
	parseBundle     []*x509.Certificate
	parseBundleErr  error
	certStore       xkmssdk.CertStore
	signed          *x509.Certificate
	signErr         error
	signedCSR       []byte
	signOpts        *xkmsca.SignOptions
}

func (f *fakeProdCA) Identity() string                                { return f.identity }
func (f *fakeProdCA) IsInitialized() bool                             { return f.initialized }
func (f *fakeProdCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm    { return f.defaultKeyAlg }
func (f *fakeProdCA) DefaultValidityPeriod() int                      { return f.defaultValidity }
func (f *fakeProdCA) TrustedRoot() (*x509.Certificate, error)         { return f.rootCert, nil }
func (f *fakeProdCA) TrustedIntermediate() (*x509.Certificate, error) { return f.intermediate, nil }
func (f *fakeProdCA) IssueCertificate(_ context.Context, req *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
	return f.issued, f.issueErr
}

// IssueCertificateWithProfile records the profile and issues as IssueCertificate.
func (f *fakeProdCA) IssueCertificateWithProfile(ctx context.Context, req *xkmsca.CACertificateRequest, profile string) (*xkmsca.IssuedCertificate, error) {
	f.issuedProfile = profile
	return f.IssueCertificate(ctx, req)
}
func (f *fakeProdCA) SignCSR(_ context.Context, csrPEM []byte, opts *xkmsca.SignOptions) (*x509.Certificate, error) {
	f.signedCSR = csrPEM
	f.signOpts = opts
	return f.signed, f.signErr
}
func (f *fakeProdCA) RevokeCert(_ context.Context, cert *x509.Certificate, opts xkmsca.RevokeOptions) error {
	f.revokeCert = cert
	f.revokeOpts = opts
	return f.revokeErr
}
func (f *fakeProdCA) CABundle() ([]byte, error) { return f.bundle, f.bundleErr }
func (f *fakeProdCA) CABundleFiltered(storeType xkmssdk.StoreType, keyAlg x509.PublicKeyAlgorithm) ([]byte, error) {
	return f.bundleFiltered, f.bundleFilterErr
}
func (f *fakeProdCA) ParseBundle(data []byte) ([]*x509.Certificate, error) {
	return f.parseBundle, f.parseBundleErr
}
func (f *fakeProdCA) CertStore() xkmssdk.CertStore { return f.certStore }

// =============================================================================
// Tests
// =============================================================================

func TestNewCAAuthorityAdapter_NilReturnsNil(t *testing.T) {
	adapter := NewCAAuthorityAdapter(nil)
	assert.Nil(t, adapter, "nil CA should return nil adapter")
}

func TestNewCAAuthorityAdapter_NonNilReturnsAdapter(t *testing.T) {
	prod := &fakeProdCA{identity: "Test CA"}
	adapter := NewCAAuthorityAdapter(prod)
	require.NotNil(t, adapter)
	assert.Equal(t, "Test CA", adapter.Identity())
}

func TestCAAuthorityAdapter_PassthroughGetters(t *testing.T) {
	rootCert := &x509.Certificate{Subject: x509.Certificate{}.Subject}
	intermediateCert := &x509.Certificate{Subject: x509.Certificate{}.Subject}
	prod := &fakeProdCA{
		identity:        "Trusted Root CA",
		initialized:     true,
		defaultKeyAlg:   x509.ECDSA,
		defaultValidity: 365,
		rootCert:        rootCert,
		intermediate:    intermediateCert,
	}
	a := NewCAAuthorityAdapter(prod)

	assert.Equal(t, "Trusted Root CA", a.Identity())
	assert.True(t, a.IsInitialized())
	assert.Equal(t, x509.ECDSA, a.DefaultKeyAlgorithm())
	assert.Equal(t, 365*24*time.Hour, a.DefaultValidityPeriod())

	root, err := a.TrustedRoot()
	require.NoError(t, err)
	assert.Same(t, rootCert, root)

	inter, err := a.TrustedIntermediate()
	require.NoError(t, err)
	assert.Same(t, intermediateCert, inter)
}

func TestCAAuthorityAdapter_IssueCertificate_Success(t *testing.T) {
	cert := &x509.Certificate{}
	prod := &fakeProdCA{issued: &xkmsca.IssuedCertificate{Certificate: cert}}
	a := NewCAAuthorityAdapter(prod)

	got, err := a.IssueCertificate(context.Background(), &quicbaasca.CACertificateRequest{})
	require.NoError(t, err)
	assert.Same(t, cert, got)
}

// TestCAAuthorityAdapter_IssueCertificate_CARequestUsesCAProfile checks the
// REST adapter signs an isCA request with the go-xkms CA profile and a leaf
// request with the default profile.
func TestCAAuthorityAdapter_IssueCertificate_CARequestUsesCAProfile(t *testing.T) {
	cert := &x509.Certificate{}
	prod := &fakeProdCA{issued: &xkmsca.IssuedCertificate{Certificate: cert}}
	a := NewCAAuthorityAdapter(prod)

	got, err := a.IssueCertificate(context.Background(), &quicbaasca.CACertificateRequest{IsCA: true, MaxPathLen: 1})
	require.NoError(t, err)
	assert.Same(t, cert, got)
	assert.Equal(t, "ca", prod.issuedProfile)

	leafProd := &fakeProdCA{issued: &xkmsca.IssuedCertificate{Certificate: cert}}
	_, err = NewCAAuthorityAdapter(leafProd).IssueCertificate(context.Background(), &quicbaasca.CACertificateRequest{})
	require.NoError(t, err)
	assert.Empty(t, leafProd.issuedProfile, "a leaf request keeps the default profile")
}

func TestCAAuthorityAdapter_IssueCertificate_PropagatesError(t *testing.T) {
	prodErr := errors.New("backend offline")
	prod := &fakeProdCA{issueErr: prodErr}
	a := NewCAAuthorityAdapter(prod)

	got, err := a.IssueCertificate(context.Background(), &quicbaasca.CACertificateRequest{})
	assert.Nil(t, got)
	require.Error(t, err)
	assert.ErrorIs(t, err, prodErr)
}

func TestCAAuthorityAdapter_IssueCertificate_NilFromCAReturnsErr(t *testing.T) {
	prod := &fakeProdCA{issued: nil}
	a := NewCAAuthorityAdapter(prod)

	got, err := a.IssueCertificate(context.Background(), &quicbaasca.CACertificateRequest{})
	assert.Nil(t, got)
	require.Error(t, err)
	var issueErr ErrCertificateIssueFailed
	assert.ErrorAs(t, err, &issueErr)
}

func TestCAAuthorityAdapter_IssueCertificate_NilCertReturnsErr(t *testing.T) {
	prod := &fakeProdCA{issued: &xkmsca.IssuedCertificate{Certificate: nil}}
	a := NewCAAuthorityAdapter(prod)

	got, err := a.IssueCertificate(context.Background(), &quicbaasca.CACertificateRequest{})
	assert.Nil(t, got)
	require.Error(t, err)
}

func TestCAAuthorityAdapter_SignCSR_Success(t *testing.T) {
	cert := &x509.Certificate{}
	prod := &fakeProdCA{signed: cert}
	a := NewCAAuthorityAdapter(prod)
	opts := &quicbaasca.SignOptions{ValidityDays: 30}

	got, err := a.SignCSR(context.Background(), []byte("csr"), opts)
	require.NoError(t, err)
	assert.Same(t, cert, got)
	assert.Equal(t, []byte("csr"), prod.signedCSR)
	assert.Same(t, opts, prod.signOpts)
}

func TestCAAuthorityAdapter_SignCSR_PropagatesError(t *testing.T) {
	prodErr := errors.New("backend offline")
	a := NewCAAuthorityAdapter(&fakeProdCA{signErr: prodErr})

	got, err := a.SignCSR(context.Background(), []byte("csr"), &quicbaasca.SignOptions{})
	assert.Nil(t, got)
	assert.ErrorIs(t, err, prodErr)
}

func TestCAAuthorityAdapter_Revoke_DeleteKeysTrue(t *testing.T) {
	prod := &fakeProdCA{}
	a := NewCAAuthorityAdapter(prod)
	cert := &x509.Certificate{}

	err := a.Revoke(context.Background(), cert, CARevokeOptions{KeyAttrs: &xkmssdk.KeyAttributes{CN: "test"}})
	require.NoError(t, err)
	assert.Same(t, cert, prod.revokeCert)
	assert.True(t, prod.revokeOpts.DeleteKeys, "DeleteKeys should be true when keyAttrs is non-nil")
}

func TestCAAuthorityAdapter_Revoke_DeleteKeysFalse(t *testing.T) {
	prod := &fakeProdCA{}
	a := NewCAAuthorityAdapter(prod)
	cert := &x509.Certificate{}

	err := a.Revoke(context.Background(), cert, CARevokeOptions{})
	require.NoError(t, err)
	assert.False(t, prod.revokeOpts.DeleteKeys, "DeleteKeys should be false when keyAttrs is nil")
}

func TestCAAuthorityAdapter_Revoke_CarriesReason(t *testing.T) {
	prod := &fakeProdCA{}
	a := NewCAAuthorityAdapter(prod)

	err := a.Revoke(context.Background(), &x509.Certificate{}, CARevokeOptions{
		Reason: platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED,
	})
	require.NoError(t, err)
	// RFC 5280 §5.3.1: superseded is CRLReason 4.
	assert.Equal(t, 4, prod.revokeOpts.Reason, "the reason must reach RevokeOptions.Reason as its RFC 5280 code")
}

func TestCAAuthorityAdapter_Revoke_UnspecifiedReason(t *testing.T) {
	prod := &fakeProdCA{revokeOpts: xkmsca.RevokeOptions{Reason: -1}}
	a := NewCAAuthorityAdapter(prod)

	err := a.Revoke(context.Background(), &x509.Certificate{}, CARevokeOptions{})
	require.NoError(t, err)
	// RFC 5280 §5.3.1: unspecified is CRLReason 0.
	assert.Equal(t, 0, prod.revokeOpts.Reason)
}

func TestCAAuthorityAdapter_Revoke_PropagatesError(t *testing.T) {
	prodErr := errors.New("revoke failed")
	prod := &fakeProdCA{revokeErr: prodErr}
	a := NewCAAuthorityAdapter(prod)

	err := a.Revoke(context.Background(), &x509.Certificate{}, CARevokeOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, prodErr)
}

func TestCAAuthorityAdapter_CABundle_NoFilters_UsesUnfiltered(t *testing.T) {
	prod := &fakeProdCA{
		bundle:         []byte("unfiltered"),
		bundleFiltered: []byte("filtered"),
	}
	a := NewCAAuthorityAdapter(prod)

	// No filters supplied — should use CABundle()
	got, err := a.CABundle("", x509.UnknownPublicKeyAlgorithm)
	require.NoError(t, err)
	assert.Equal(t, []byte("unfiltered"), got, "should use unfiltered bundle when no filters")
}

func TestCAAuthorityAdapter_CABundle_StoreUnknown_UsesUnfiltered(t *testing.T) {
	prod := &fakeProdCA{
		bundle:         []byte("unfiltered"),
		bundleFiltered: []byte("filtered"),
	}
	a := NewCAAuthorityAdapter(prod)

	// StoreUnknown is the zero value when nothing is specified — use unfiltered
	got, err := a.CABundle(xkmssdk.StoreUnknown, x509.UnknownPublicKeyAlgorithm)
	require.NoError(t, err)
	assert.Equal(t, []byte("unfiltered"), got)
}

func TestCAAuthorityAdapter_CABundle_WithStoreFilter_UsesFiltered(t *testing.T) {
	prod := &fakeProdCA{
		bundle:         []byte("unfiltered"),
		bundleFiltered: []byte("filtered"),
	}
	a := NewCAAuthorityAdapter(prod)

	got, err := a.CABundle(xkmssdk.StoreSoftware, x509.UnknownPublicKeyAlgorithm)
	require.NoError(t, err)
	assert.Equal(t, []byte("filtered"), got, "should use filtered bundle when store filter present")
}

func TestCAAuthorityAdapter_CABundle_WithKeyAlgFilter_UsesFiltered(t *testing.T) {
	prod := &fakeProdCA{
		bundle:         []byte("unfiltered"),
		bundleFiltered: []byte("filtered"),
	}
	a := NewCAAuthorityAdapter(prod)

	got, err := a.CABundle("", x509.RSA)
	require.NoError(t, err)
	assert.Equal(t, []byte("filtered"), got, "should use filtered bundle when key alg filter present")
}

func TestCAAuthorityAdapter_CABundle_PropagatesUnfilteredError(t *testing.T) {
	prodErr := errors.New("bundle fail")
	prod := &fakeProdCA{bundleErr: prodErr}
	a := NewCAAuthorityAdapter(prod)

	_, err := a.CABundle("", x509.UnknownPublicKeyAlgorithm)
	require.Error(t, err)
	assert.ErrorIs(t, err, prodErr)
}

func TestCAAuthorityAdapter_CABundle_PropagatesFilteredError(t *testing.T) {
	prodErr := errors.New("filtered bundle fail")
	prod := &fakeProdCA{bundleFilterErr: prodErr}
	a := NewCAAuthorityAdapter(prod)

	_, err := a.CABundle(xkmssdk.StoreSoftware, x509.RSA)
	require.Error(t, err)
	assert.ErrorIs(t, err, prodErr)
}

func TestCAAuthorityAdapter_ParseBundle(t *testing.T) {
	certs := []*x509.Certificate{{}, {}}
	prod := &fakeProdCA{parseBundle: certs}
	a := NewCAAuthorityAdapter(prod)

	got, err := a.ParseBundle([]byte("bundle"))
	require.NoError(t, err)
	assert.Equal(t, certs, got)
}

func TestCAAuthorityAdapter_ParseBundle_PropagatesError(t *testing.T) {
	prodErr := errors.New("parse fail")
	prod := &fakeProdCA{parseBundleErr: prodErr}
	a := NewCAAuthorityAdapter(prod)

	_, err := a.ParseBundle([]byte("bundle"))
	require.Error(t, err)
	assert.ErrorIs(t, err, prodErr)
}

func TestCAAuthorityAdapter_CertificateStore(t *testing.T) {
	store := newMockCertStore()
	prod := &fakeProdCA{certStore: store}
	a := NewCAAuthorityAdapter(prod)

	got := a.CertificateStore()
	assert.Same(t, store, got)
}

func TestErrIssueReturnedNil_Error(t *testing.T) {
	err := ErrIssueReturnedNil{}
	assert.Equal(t, "ca returned nil certificate", err.Error())
}
