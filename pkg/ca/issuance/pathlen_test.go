package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
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
}

func (f *x509Issuer) CACertificate() (*x509.Certificate, error) {
	return f.cert, f.certErr
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
		{name: "unconstrained-issuer-unlimited", unconstrained: true, isCA: true, requested: -1, wantPathLen: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := newTestChain(t, tt.interPathLen)
			issuer := &x509Issuer{cert: chain.intermediate, key: chain.interKey}
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
