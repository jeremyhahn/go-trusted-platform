package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// x509Issuer is an in-memory Issuer: it signs with crypto/x509 beneath its own
// certificate, copying the request's basic constraints, and counts the
// certificates it signs so a refused request can be shown never to reach it.
type x509Issuer struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certErr error
	signed  int
	// bundle is the PEM chain CABundle returns, the issuing certificate
	// first and the root last, as a real CA gives it.
	bundle    []byte
	bundleErr error
}

func (f *x509Issuer) CACertificate() (*x509.Certificate, error) {
	return f.cert, f.certErr
}

func (f *x509Issuer) CABundle() ([]byte, error) {
	return f.bundle, f.bundleErr
}

func (f *x509Issuer) IssueCertificate(_ context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error) {
	return f.sign(req, false)
}

func (f *x509Issuer) IssueCertificateWithProfile(_ context.Context, req *quicbaasca.CACertificateRequest, _ string) (*quicbaasca.IssuedCertificate, error) {
	return f.sign(req, true)
}

func (f *x509Issuer) sign(req *quicbaasca.CACertificateRequest, isCA bool) (*quicbaasca.IssuedCertificate, error) {
	f.signed++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(100 + f.signed)),
		Subject:               pkix.Name{CommonName: req.Subject.CommonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		MaxPathLen:            req.MaxPathLen,
		MaxPathLenZero:        req.MaxPathLenZero,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.cert, req.Signer.Public(), f.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &quicbaasca.IssuedCertificate{Certificate: cert}, nil
}

// testChain is a root without a path length and an intermediate beneath it.
type testChain struct {
	root         *x509.Certificate
	rootKey      *ecdsa.PrivateKey
	intermediate *x509.Certificate
	interKey     *ecdsa.PrivateKey
}

// newCACert signs a CA certificate for key beneath parent (self-signed when
// parent is nil). pathLen below zero leaves the pathLenConstraint out.
func newCACert(t *testing.T, cn string, pathLen int, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(len(cn))),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test Org"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func newTestChain(t *testing.T, interPathLen int) testChain {
	t.Helper()
	rootKey, interKey := newECKey(t), newECKey(t)
	root := newCACert(t, "pathlen-root", -1, rootKey, nil, nil)
	inter := newCACert(t, "pathlen-intermediate", interPathLen, interKey, root, rootKey)
	return testChain{root: root, rootKey: rootKey, intermediate: inter, interKey: interKey}
}

// pemBundle encodes certs as a CA bundle, in the order given.
func pemBundle(certs ...*x509.Certificate) []byte {
	var bundle []byte
	for _, cert := range certs {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return bundle
}

// intermediateIssuer issues from the chain's intermediate and carries the
// bundle a real CA gives: the intermediate, then the root.
func (c testChain) intermediateIssuer() *x509Issuer {
	return &x509Issuer{cert: c.intermediate, key: c.interKey, bundle: pemBundle(c.intermediate, c.root)}
}

// newCAChain builds a chain of CA certificates, root first, one for each
// entry of pathLens (below zero: no pathLenConstraint), named inherit-ca-0
// (the root), inherit-ca-1 and so on. It returns the certificates and the
// key of the last one.
func newCAChain(t *testing.T, pathLens ...int) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	var (
		certs     []*x509.Certificate
		parent    *x509.Certificate
		parentKey *ecdsa.PrivateKey
	)
	for i, pathLen := range pathLens {
		key := newECKey(t)
		cert := newCACert(t, "inherit-ca-"+strconv.Itoa(i), pathLen, key, parent, parentKey)
		certs = append(certs, cert)
		parent, parentKey = cert, key
	}
	return certs, parentKey
}

// chainIssuer issues from the last certificate of a newCAChain chain and
// carries the whole chain as its bundle, the issuing certificate first.
func chainIssuer(certs []*x509.Certificate, key *ecdsa.PrivateKey) *x509Issuer {
	ordered := make([]*x509.Certificate, 0, len(certs))
	for i := len(certs) - 1; i >= 0; i-- {
		ordered = append(ordered, certs[i])
	}
	return &x509Issuer{cert: certs[len(certs)-1], key: key, bundle: pemBundle(ordered...)}
}

// TestIssue_SubordinatePathLen issues beneath issuers of each path length and
// checks the refusals and the issued basic constraints (RFC 5280 §4.2.1.9).
func TestIssue_SubordinatePathLen(t *testing.T) {
	tests := []struct {
		name         string
		interPathLen int
		// unconstrained issues from the root, which has no path length.
		unconstrained bool
		isCA          bool
		requested     int
		wantExhausted bool
		wantExceeded  bool
		wantPathLen   int
	}{
		{name: "ca-beneath-pathlen-0-is-refused", interPathLen: 0, isCA: true, requested: 0, wantExhausted: true},
		{name: "ca-beneath-pathlen-1-gets-pathlen-0", interPathLen: 1, isCA: true, requested: 0, wantPathLen: 0},
		{name: "pathlen-2-beneath-pathlen-1-is-refused", interPathLen: 1, isCA: true, requested: 2, wantExceeded: true},
		{name: "pathlen-1-beneath-pathlen-1-is-refused", interPathLen: 1, isCA: true, requested: 1, wantExceeded: true},
		{name: "unlimited-beneath-pathlen-1-is-refused", interPathLen: 1, isCA: true, requested: -1, wantExceeded: true},
		{name: "pathlen-1-beneath-pathlen-2", interPathLen: 2, isCA: true, requested: 1, wantPathLen: 1},
		{name: "leaf-beneath-pathlen-0-is-issued", interPathLen: 0, isCA: false, requested: 0},
		{name: "unconstrained-issuer-pathlen-3", unconstrained: true, isCA: true, requested: 3, wantPathLen: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := newTestChain(t, tt.interPathLen)
			issuer := chain.intermediateIssuer()
			if tt.unconstrained {
				issuer = &x509Issuer{cert: chain.root, key: chain.rootKey}
			}
			key := newECKey(t)
			issued, err := Issue(context.Background(), issuer, &quicbaasca.CACertificateRequest{
				Subject:    quicbaasca.CASubject{CommonName: tt.name, Organization: "Test Org", Country: "US"},
				Valid:      1,
				IsCA:       tt.isCA,
				MaxPathLen: tt.requested,
				Signer:     key,
			})

			if tt.wantExhausted || tt.wantExceeded {
				require.Error(t, err)
				assert.Nil(t, issued)
				assert.Zero(t, issuer.signed, "a refused request must not be signed")
				assert.True(t, IsInvalidRequest(err), "a path-length refusal is the caller's to fix")
				if tt.wantExhausted {
					var exhausted *IssuerPathLenExhaustedError
					require.ErrorAs(t, err, &exhausted)
					assert.Equal(t, chain.intermediate.Subject.String(), exhausted.Issuer)
					return
				}
				var exceeded *SubordinatePathLenError
				require.ErrorAs(t, err, &exceeded)
				assert.Equal(t, chain.intermediate.Subject.String(), exceeded.Issuer)
				assert.Equal(t, tt.requested, exceeded.Requested)
				assert.Equal(t, tt.interPathLen-1, exceeded.Allowed)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, issued)
			cert := issued.Certificate
			assert.True(t, cert.BasicConstraintsValid)
			assert.Equal(t, tt.isCA, cert.IsCA)
			if !tt.isCA {
				return
			}
			assert.Equal(t, tt.wantPathLen, cert.MaxPathLen)
			assert.Equal(t, tt.wantPathLen == 0, cert.MaxPathLenZero)

			// The issued CA must sign a leaf the standard chain verifier,
			// which enforces every pathLenConstraint on the way, accepts.
			roots := x509.NewCertPool()
			roots.AddCert(chain.root)
			intermediates := x509.NewCertPool()
			intermediates.AddCert(chain.intermediate)
			intermediates.AddCert(cert)
			_, err = signLeafWith(t, cert, key).Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			require.NoError(t, err)
		})
	}
}

// Every pathLenConstraint above the issuing CA bounds a subordinate CA, not
// only the issuing CA's own (RFC 5280 §6.1.4; Codex round 3 on #1544).
func TestIssue_InheritedPathLen(t *testing.T) {
	tests := []struct {
		name string
		// pathLens is the chain, root first; the last one is the issuing CA.
		pathLens  []int
		requested int
		// wantAncestor is the common name of the certificate that refuses;
		// empty when the request is issued.
		wantAncestor string
		wantText     string
		wantPathLen  int
	}{
		{
			name:     "root-pathlen-1-leaves-an-unlimited-intermediate-no-ca",
			pathLens: []int{1, -1}, requested: 0,
			wantAncestor: "inherit-ca-0", wantText: "may issue no subordinate CA",
		},
		{
			name:     "root-pathlen-1-bounds-an-intermediate-that-claims-1",
			pathLens: []int{1, 1}, requested: 0,
			wantAncestor: "inherit-ca-0", wantText: "may issue no subordinate CA",
		},
		{
			name:     "root-pathlen-2-allows-pathlen-0",
			pathLens: []int{2, -1}, requested: 0,
			wantPathLen: 0,
		},
		{
			name:     "root-pathlen-2-refuses-pathlen-1",
			pathLens: []int{2, -1}, requested: 1,
			wantAncestor: "inherit-ca-0", wantText: "at most 0",
		},
		{
			name:     "root-pathlen-2-refuses-unlimited",
			pathLens: []int{2, -1}, requested: -1,
			wantAncestor: "inherit-ca-0", wantText: "not unlimited",
		},
		{
			name:     "root-pathlen-2-is-used-up-two-levels-down",
			pathLens: []int{2, -1, -1}, requested: 0,
			wantAncestor: "inherit-ca-0", wantText: "may issue no subordinate CA",
		},
		{
			name:     "root-pathlen-3-allows-pathlen-0-two-levels-down",
			pathLens: []int{3, -1, -1}, requested: 0,
			wantPathLen: 0,
		},
		{
			name:     "a-middle-pathlen-1-bounds-the-ca-beneath-it",
			pathLens: []int{-1, 1, -1}, requested: 0,
			wantAncestor: "inherit-ca-1", wantText: "may issue no subordinate CA",
		},
		{
			name:     "an-unlimited-chain-issues-as-requested",
			pathLens: []int{-1, -1, -1}, requested: 2,
			wantPathLen: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, issuerKey := newCAChain(t, tt.pathLens...)
			issuer := chainIssuer(certs, issuerKey)
			key := newECKey(t)
			issued, err := Issue(context.Background(), issuer, &quicbaasca.CACertificateRequest{
				Subject:    quicbaasca.CASubject{CommonName: tt.name, Organization: "Test Org", Country: "US"},
				Valid:      1,
				IsCA:       true,
				MaxPathLen: tt.requested,
				Signer:     key,
			})

			if tt.wantAncestor != "" {
				require.Error(t, err, "a path length above the issuing CA must refuse the request")
				assert.Nil(t, issued)
				assert.Zero(t, issuer.signed, "a refused request must not be signed")
				assert.True(t, IsInvalidRequest(err), "a path-length refusal is the caller's to fix")
				assert.ErrorContains(t, err, tt.wantAncestor)
				assert.ErrorContains(t, err, tt.wantText)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, issued)
			cert := issued.Certificate
			assert.True(t, cert.IsCA)
			assert.Equal(t, tt.wantPathLen, cert.MaxPathLen)
			assert.Equal(t, tt.wantPathLen == 0, cert.MaxPathLenZero)

			// The issued CA must sign a leaf the standard chain verifier, which
			// enforces every pathLenConstraint on the way, accepts.
			roots := x509.NewCertPool()
			roots.AddCert(certs[0])
			intermediates := x509.NewCertPool()
			for _, ancestor := range certs[1:] {
				intermediates.AddCert(ancestor)
			}
			intermediates.AddCert(cert)
			_, err = signLeafWith(t, cert, key).Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			require.NoError(t, err)
		})
	}
}

// TestIssue_RolloverSelfIssuedIssuer: a key-rollover CA has the same name as
// the root that signed it (self-issued) but is not self-signed, so it is not a
// trust anchor and the root's pathLenConstraint still binds. A self-issued
// certificate does not count toward that limit (RFC 5280 §6.1.4 (l)).
func TestIssue_RolloverSelfIssuedIssuer(t *testing.T) {
	rootKey := newECKey(t)
	root := newCACert(t, "rollover-ca", 1, rootKey, nil, nil)
	rolloverKey := newECKey(t)
	rollover := newCACert(t, "rollover-ca", -1, rolloverKey, root, rootKey)

	tests := []struct {
		name        string
		issuer      *x509Issuer
		requested   int
		wantRefused bool
	}{
		{
			name:      "requested 2",
			issuer:    &x509Issuer{cert: rollover, key: rolloverKey, bundle: pemBundle(rollover, root)},
			requested: 2, wantRefused: true,
		},
		{
			name:      "requested 1",
			issuer:    &x509Issuer{cert: rollover, key: rolloverKey, bundle: pemBundle(rollover, root)},
			requested: 1, wantRefused: true,
		},
		{
			name:      "requested 0",
			issuer:    &x509Issuer{cert: rollover, key: rolloverKey, bundle: pemBundle(rollover, root)},
			requested: 0,
		},
		{
			name:      "self-signed root issuer still needs no bundle",
			issuer:    &x509Issuer{cert: root, key: rootKey, bundle: pemBundle(root)},
			requested: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issued, err := Issue(context.Background(), tt.issuer, &quicbaasca.CACertificateRequest{
				Subject:    quicbaasca.CASubject{CommonName: "rollover-sub", Organization: "Test Org", Country: "US"},
				Valid:      1,
				IsCA:       true,
				MaxPathLen: tt.requested,
				Signer:     newECKey(t),
			})

			if tt.wantRefused {
				require.Error(t, err, "the root's pathLenConstraint must bind beneath a self-issued rollover")
				assert.Nil(t, issued)
				assert.Zero(t, tt.issuer.signed, "a refused request must not be signed")
				var pathErr *AncestorPathLenError
				require.ErrorAs(t, err, &pathErr)
				assert.Equal(t, root.Subject.String(), pathErr.Ancestor)
				assert.Equal(t, 0, pathErr.Allowed)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, issued)
			assert.True(t, issued.Certificate.IsCA)
			assert.Equal(t, 0, issued.Certificate.MaxPathLen)
			assert.True(t, issued.Certificate.MaxPathLenZero)
		})
	}
}

// TestIssue_IssuerZeroPathLenWithoutZeroFlagIsUnconstrained checks that an
// issuer whose MaxPathLen is 0 without MaxPathLenZero, which crypto/x509 reads
// as no pathLenConstraint, does not bound the subordinate.
func TestIssue_IssuerZeroPathLenWithoutZeroFlagIsUnconstrained(t *testing.T) {
	chain := newTestChain(t, 1)
	unconstrained := *chain.root
	unconstrained.MaxPathLen = 0
	unconstrained.MaxPathLenZero = false
	issuer := &x509Issuer{cert: &unconstrained, key: chain.rootKey}

	issued, err := Issue(context.Background(), issuer, &quicbaasca.CACertificateRequest{
		Subject:    quicbaasca.CASubject{CommonName: "sub-of-unflagged", Organization: "Test Org", Country: "US"},
		Valid:      1,
		IsCA:       true,
		MaxPathLen: 2,
		Signer:     newECKey(t),
	})
	require.NoError(t, err)
	assert.True(t, issued.Certificate.IsCA)
	assert.Equal(t, 2, issued.Certificate.MaxPathLen)
}

// TestIssue_IssuerCertificateUnavailable checks that an isCA request is refused,
// unsigned, when the issuer's certificate cannot be read to check its path length.
func TestIssue_IssuerCertificateUnavailable(t *testing.T) {
	readErr := errors.New("certificate store offline")
	chain := newTestChain(t, 1)
	tests := []struct {
		name    string
		cert    *x509.Certificate
		certErr error
	}{
		{name: "read-error", certErr: readErr},
		{name: "no-certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := &x509Issuer{cert: tt.cert, key: chain.interKey, certErr: tt.certErr}
			issued, err := Issue(context.Background(), issuer, &quicbaasca.CACertificateRequest{
				Subject: quicbaasca.CASubject{CommonName: "sub-ca", Organization: "Test Org", Country: "US"},
				Valid:   1,
				IsCA:    true,
				Signer:  newECKey(t),
			})
			assert.Nil(t, issued)
			var certErr *IssuerCertificateError
			require.ErrorAs(t, err, &certErr)
			assert.Zero(t, issuer.signed)
			assert.False(t, IsInvalidRequest(err), "an unreadable issuer is a server failure")
			if tt.certErr != nil {
				assert.ErrorIs(t, err, readErr)
			}
		})
	}
}

// An isCA request is refused, unsigned, when the chain above the issuing CA
// cannot be read, so the path lengths above it cannot be checked. A
// self-issued issuing certificate has no chain above it and its bundle is not
// read.
func TestIssue_IssuerChainUnavailable(t *testing.T) {
	readErr := errors.New("bundle store offline")
	chain := newTestChain(t, -1)
	request := func(t *testing.T) *quicbaasca.CACertificateRequest {
		t.Helper()
		return &quicbaasca.CACertificateRequest{
			Subject:    quicbaasca.CASubject{CommonName: "sub-ca", Organization: "Test Org", Country: "US"},
			Valid:      1,
			IsCA:       true,
			MaxPathLen: 0,
			Signer:     newECKey(t),
		}
	}
	tests := []struct {
		name      string
		bundle    []byte
		bundleErr error
	}{
		{name: "read-error", bundleErr: readErr},
		{name: "empty-bundle"},
		{name: "bundle-without-the-root", bundle: pemBundle(chain.intermediate)},
		{
			name:   "unparsable-certificate",
			bundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := &x509Issuer{cert: chain.intermediate, key: chain.interKey, bundle: tt.bundle, bundleErr: tt.bundleErr}
			issued, err := Issue(context.Background(), issuer, request(t))
			require.Error(t, err, "an unreadable chain must refuse the request")
			assert.Nil(t, issued)
			assert.Zero(t, issuer.signed, "a refused request must not be signed")
			assert.False(t, IsInvalidRequest(err), "an unreadable chain is a server failure")
			assert.ErrorContains(t, err, "pathlen-intermediate")
			if tt.bundleErr != nil {
				assert.ErrorIs(t, err, readErr)
			}
		})
	}

	t.Run("a-self-issued-issuer-reads-no-bundle", func(t *testing.T) {
		issuer := &x509Issuer{cert: chain.root, key: chain.rootKey, bundleErr: readErr}
		issued, err := Issue(context.Background(), issuer, request(t))
		require.NoError(t, err)
		assert.True(t, issued.Certificate.IsCA)
	})
}

// The SDK's CA profile drops ExtKeyUsage (Codex 8615 P1): a CA restricted to
// serverAuth must be refused, never issued unrestricted, while a restricted
// leaf and an unrestricted CA are still issued.
func TestIssue_CAExtKeyUsageRestriction(t *testing.T) {
	chain := newTestChain(t, 2)

	issuer := chain.intermediateIssuer()
	issued, err := Issue(context.Background(), issuer, &quicbaasca.CACertificateRequest{
		Subject:     quicbaasca.CASubject{CommonName: "eku-restricted-ca", Organization: "Test Org", Country: "US"},
		Valid:       1,
		IsCA:        true,
		MaxPathLen:  0,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Signer:      newECKey(t),
	})
	require.Error(t, err)
	assert.Nil(t, issued)
	assert.ErrorIs(t, err, ErrCAExtKeyUsageUnsupported{})
	assert.True(t, IsInvalidRequest(err), "an EKU-restricted CA request is the caller's to fix")
	assert.Zero(t, issuer.signed, "a refused request must not be signed")
	assert.Contains(t, err.Error(), "ca.NewCAProfile", "the refusal names the upstream gap")

	leafIssuer := chain.intermediateIssuer()
	leaf, err := Issue(context.Background(), leafIssuer, &quicbaasca.CACertificateRequest{
		Subject:     quicbaasca.CASubject{CommonName: "eku-leaf", Organization: "Test Org", Country: "US"},
		Valid:       1,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Signer:      newECKey(t),
	})
	require.NoError(t, err)
	require.NotNil(t, leaf)
	assert.Equal(t, 1, leafIssuer.signed, "a leaf's EKU restriction is not refused")

	caIssuer := chain.intermediateIssuer()
	ca, err := Issue(context.Background(), caIssuer, &quicbaasca.CACertificateRequest{
		Subject:    quicbaasca.CASubject{CommonName: "eku-free-ca", Organization: "Test Org", Country: "US"},
		Valid:      1,
		IsCA:       true,
		MaxPathLen: 0,
		Signer:     newECKey(t),
	})
	require.NoError(t, err)
	assert.True(t, ca.Certificate.IsCA)
	assert.Empty(t, ca.Certificate.ExtKeyUsage)
}

// TestPathLenErrors_Messages checks the refusals name the issuer and the limit.
func TestPathLenErrors_Messages(t *testing.T) {
	exhausted := &IssuerPathLenExhaustedError{Issuer: "CN=inter"}
	assert.Contains(t, exhausted.Error(), `"CN=inter"`)
	assert.Contains(t, exhausted.Error(), "path length 0")

	exceeded := &SubordinatePathLenError{Issuer: "CN=inter", Requested: 2, Allowed: 0}
	assert.Contains(t, exceeded.Error(), "at most 0, not 2")
	unlimited := &SubordinatePathLenError{Issuer: "CN=inter", Requested: -1, Allowed: 1}
	assert.Contains(t, unlimited.Error(), "at most 1, not unlimited")

	assert.Contains(t, (&IssuerCertificateError{}).Error(), "has no certificate")
	assert.Contains(t, (&IssuerCertificateError{Err: errors.New("boom")}).Error(), "boom")
}
