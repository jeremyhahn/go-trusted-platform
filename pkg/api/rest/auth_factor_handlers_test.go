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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// =============================================================================
// Minimal authCA stub for auth factor handler tests.
//
// authTestCA satisfies the authCA interface:
//
//	SignCSR(ctx context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error)
//	TrustedRootCertPool(cert *x509.Certificate) (*x509.CertPool, error)
//	CABundle() ([]byte, error)
// =============================================================================

type authTestCA struct {
	signErr     error
	signedCert  *x509.Certificate
	rootPool    *x509.CertPool
	rootPoolErr error

	// signCalls and signOpts record what SignCSR was asked to do.
	signCalls int
	signOpts  *quicbaasca.SignOptions
}

// Compile-time interface check.
var _ authCA = (*authTestCA)(nil)

// newAuthTestCA builds a test CA that returns a pre-built signed leaf from SignCSR.
func newAuthTestCA(t *testing.T) *authTestCA {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	// Build the leaf cert that SignCSR returns.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return &authTestCA{
		signedCert: leafCert,
		rootPool:   pool,
	}
}

func (a *authTestCA) SignCSR(_ context.Context, _ []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error) {
	a.signCalls++
	a.signOpts = opts
	if a.signErr != nil {
		return nil, a.signErr
	}
	return a.signedCert, nil
}

func (a *authTestCA) TrustedRootCertPool(_ *x509.Certificate) (*x509.CertPool, error) {
	return a.rootPool, a.rootPoolErr
}

func (a *authTestCA) CABundle() ([]byte, error) {
	return []byte("-----BEGIN CERTIFICATE-----\nY2hhaW4K\n-----END CERTIFICATE-----\n"), nil
}

// =============================================================================
// Test helpers
// =============================================================================

// newHandlerWithCA builds an AuthFactorHandlers with the given authCA stub.
func newHandlerWithCA(ca authCA) *AuthFactorHandlers {
	return &AuthFactorHandlers{
		ca:       ca,
		logger:   slog.Default(),
		cache:    make(map[string]aaguidEntry),
		policies: make(map[string]mfaPolicy),
	}
}

// generateAuthTestCSR signs tmpl with a fresh P-256 key and parses it back.
func generateAuthTestCSR(t *testing.T, tmpl *x509.CertificateRequest) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	return csr
}

// selfSignedClientCert creates a self-signed cert with the given CN.
func selfSignedClientCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	return selfSignedClientCertWithSubject(t, pkix.Name{CommonName: cn})
}

// selfSignedClientCertWithSubject creates a self-signed cert with subject.
func selfSignedClientCertWithSubject(t *testing.T, subject pkix.Name) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func registerRoutes(h *AuthFactorHandlers) *mux.Router {
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	return router
}

// =============================================================================
// Gap 1 — AAGUID lookup tests
// =============================================================================

func TestAAGUIDLookup_KnownAAGUID(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/factors/aaguid-lookup?aaguid=ee882879-721c-4913-9775-3dfcce97072a", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp AAGUIDLookupResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "ee882879-721c-4913-9775-3dfcce97072a", resp.AAGUID)
	assert.Equal(t, "YubiKey 5 Series", resp.Name)
	assert.Equal(t, "Yubico", resp.Vendor)
	assert.Equal(t, "FIDO_CERTIFIED_L1", resp.MetadataStatus)
}

func TestAAGUIDLookup_UnknownAAGUID_Returns404(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/factors/aaguid-lookup?aaguid=00000000-0000-0000-0000-000000000000", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAAGUIDLookup_MissingParam_Returns400(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/factors/aaguid-lookup", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAAGUIDLookup_CaseInsensitive(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	// Uppercase variant of a known AAGUID — handler normalises to lowercase.
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/factors/aaguid-lookup?aaguid=EE882879-721C-4913-9775-3DFCCE97072A", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestAAGUIDLookup_CacheHit(t *testing.T) {
	h := NewAuthFactorHandlers(nil, nil)
	router := registerRoutes(h)

	const known = "ee882879-721c-4913-9775-3dfcce97072a"
	custom := AAGUIDLookupResponse{AAGUID: known, Name: "Cached Entry", Vendor: "Test"}
	h.storeCache(known, custom)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/factors/aaguid-lookup?aaguid="+known, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp AAGUIDLookupResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "Cached Entry", resp.Name)
}

// =============================================================================
// Gap 2 — mTLS probe tests
// =============================================================================

func TestMTLSProbe_NoCert_Returns401(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	req := httptest.NewRequest(http.MethodHead, "/api/v1/auth/mtls/probe", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestMTLSProbe_NoTLSField_Returns401(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	req := httptest.NewRequest(http.MethodHead, "/api/v1/auth/mtls/probe", nil)
	// req.TLS remains nil
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestMTLSProbe_WithCert_NoCA_Returns204(t *testing.T) {
	// nil CA: presence of cert is sufficient when no CA is wired.
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	leafCert := selfSignedClientCert(t, "test-user")
	req := httptest.NewRequest(http.MethodHead, "/api/v1/auth/mtls/probe", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leafCert}}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
}

// A clientAuth leaf issued by an intermediate verifies against a root-only
// pool when the client presents the intermediate after the leaf.
func TestMTLSProbe_IntermediateIssuedCert(t *testing.T) {
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	require.NoError(t, err)
	intCert, err := x509.ParseCertificate(intDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf-client"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	rootOnly := x509.NewCertPool()
	rootOnly.AddCert(rootCert)
	router := registerRoutes(newHandlerWithCA(&authTestCA{rootPool: rootOnly}))

	probe := func(peers ...*x509.Certificate) int {
		req := httptest.NewRequest(http.MethodHead, "/api/v1/auth/mtls/probe", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: peers}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr.Code
	}

	t.Run("leaf with its intermediate", func(t *testing.T) {
		assert.Equal(t, http.StatusNoContent, probe(leafCert, intCert))
	})

	t.Run("leaf without its intermediate", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, probe(leafCert))
	})
}

// =============================================================================
// Gap 3 — cert issuance from CSR tests
// =============================================================================

// certPrincipals authenticates a verified client certificate as the principal
// its CN names, holding the roles mapped to that CN: the role comes from the
// principal store, never from the certificate's subject.
type certPrincipals map[string][]string

// authTestTenant is the tenant every certPrincipals caller belongs to.
const authTestTenant = "tenant-a"

func (p certPrincipals) AuthenticatePeer(_ context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error) {
	cn := chain[0].Subject.CommonName
	return &platformtoken.AuthorizedContext{Subject: cn, Username: cn, TenantID: authTestTenant, Roles: p[cn]}, nil
}

// guardedHandlerWithCA is newHandlerWithCA with a guard that authenticates
// verified client certificates through principals.
func guardedHandlerWithCA(ca authCA, principals certPrincipals) *AuthFactorHandlers {
	return newHandlerWithCA(ca).WithScopeGuard(NewScopeGuard(nil, principals, nil))
}

// issueCertRequest builds an issue-cert request for userID carrying a CSR
// whose CN is csrCN, presented over a verified client certificate when
// caller is not nil.
func issueCertRequest(t *testing.T, userID, csrCN string, caller *x509.Certificate) *http.Request {
	t.Helper()
	return issueCertRequestForSubject(t, userID, pkix.Name{CommonName: csrCN}, caller)
}

// issueCertRequestForSubject is issueCertRequest for a CSR with the given
// subject.
func issueCertRequestForSubject(t *testing.T, userID string, subject pkix.Name, caller *x509.Certificate) *http.Request {
	t.Helper()
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: generateAuthTestCSR(t, &x509.CertificateRequest{Subject: subject}).Raw,
	})
	body, err := json.Marshal(IssueMTLSCertRequest{CSRPEM: string(csrPEM)})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+userID+"/factors/mtls/issue-cert", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	withCallerCert(req, caller)
	return req
}

// withCallerCert presents caller as the request's verified mTLS client
// certificate; a nil caller leaves the request unauthenticated.
func withCallerCert(req *http.Request, caller *x509.Certificate) {
	if caller == nil {
		return
	}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{caller},
		VerifiedChains:   [][]*x509.Certificate{{caller}},
	}
}

func serveIssueCert(h *AuthFactorHandlers, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	registerRoutes(h).ServeHTTP(rr, req)
	return rr
}

func TestIssueCert_ValidCSR_ReturnsCert(t *testing.T) {
	h := guardedHandlerWithCA(newAuthTestCA(t), nil)
	rr := serveIssueCert(h, issueCertRequest(t, "user-abc", "user-abc", selfSignedClientCert(t, "user-abc")))

	assert.Equal(t, http.StatusCreated, rr.Code)
	var resp IssueMTLSCertResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.NotEmpty(t, resp.CertPEM)
	assert.True(t, strings.Contains(resp.CertPEM, "BEGIN CERTIFICATE"))
}

func TestIssueCert_InvalidCSR_Returns400(t *testing.T) {
	req := issueCertRequest(t, "user-abc", "user-abc", selfSignedClientCert(t, "user-abc"))
	body, err := json.Marshal(IssueMTLSCertRequest{CSRPEM: "not-a-valid-pem"})
	require.NoError(t, err)
	req.Body = io.NopCloser(bytes.NewReader(body))
	rr := serveIssueCert(guardedHandlerWithCA(newAuthTestCA(t), nil), req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIssueCert_MissingCSRPEM_Returns400(t *testing.T) {
	req := issueCertRequest(t, "user-abc", "user-abc", selfSignedClientCert(t, "user-abc"))
	body, err := json.Marshal(IssueMTLSCertRequest{CSRPEM: ""})
	require.NoError(t, err)
	req.Body = io.NopCloser(bytes.NewReader(body))
	rr := serveIssueCert(guardedHandlerWithCA(newAuthTestCA(t), nil), req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIssueCert_NoCAService_Returns503(t *testing.T) {
	rr := serveIssueCert(NewAuthFactorHandlers(nil, nil), issueCertRequest(t, "user-abc", "user-abc", nil))

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// Without a guard the handler cannot tell a user from an admin, so it issues
// nothing, not even the caller's own certificate.
func TestIssueCert_NoGuard_Refuses(t *testing.T) {
	rr := serveIssueCert(newHandlerWithCA(newAuthTestCA(t)), issueCertRequest(t, "alice", "alice", selfSignedClientCert(t, "alice")))

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), ErrCallerGuardNotConfigured{}.Error())
}

// A request the guard cannot authenticate is refused before the CSR is read.
func TestIssueCert_UnauthenticatedCaller_Returns401(t *testing.T) {
	rr := serveIssueCert(guardedHandlerWithCA(newAuthTestCA(t), nil), issueCertRequest(t, "alice", "alice", nil))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestIssueCert_NonAdminOtherUser_Returns403(t *testing.T) {
	h := guardedHandlerWithCA(newAuthTestCA(t), nil)
	rr := serveIssueCert(h, issueCertRequest(t, "other-user", "other-user", selfSignedClientCert(t, "regular-user")))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), ErrForbiddenUserID{}.Error())
}

// A certificate whose CN starts with "admin", or whose OU is admin, makes its
// holder nobody's admin: the platform anchor issues users' certificates, and
// only the principal's role grants admin.
func TestIssueCert_AdminNamedCertWithoutRole_Returns403(t *testing.T) {
	h := guardedHandlerWithCA(newAuthTestCA(t), nil)
	adminX := selfSignedClientCertWithSubject(t, pkix.Name{CommonName: "admin-x", OrganizationalUnit: []string{"admin"}})
	rr := serveIssueCert(h, issueCertRequest(t, "bob", "bob", adminX))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), ErrForbiddenUserID{}.Error())
}

func TestIssueCert_SameUserAsCaller_Succeeds(t *testing.T) {
	h := guardedHandlerWithCA(newAuthTestCA(t), nil)
	rr := serveIssueCert(h, issueCertRequest(t, "alice", "alice", selfSignedClientCert(t, "alice")))

	assert.Equal(t, http.StatusCreated, rr.Code)
}

// A caller may not have the platform CA sign a CSR that names someone else:
// alice asking for a certificate whose CN is bob is refused before signing.
func TestIssueCert_CSRNamesAnotherUser_Returns403(t *testing.T) {
	h := guardedHandlerWithCA(newAuthTestCA(t), nil)
	rr := serveIssueCert(h, issueCertRequest(t, "alice", "bob", selfSignedClientCert(t, "alice")))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), ErrCSRNotBoundToUser{Field: "CN", Value: "bob"}.Error())
}

// A principal holding the admin role issues another user's certificate when
// the CSR names that user, whatever its certificate's subject says.
func TestIssueCert_AdminRoleForBoundUser_Succeeds(t *testing.T) {
	h := guardedHandlerWithCA(newAuthTestCA(t), certPrincipals{"ops": {common.ROLE_ADMIN}})
	rr := serveIssueCert(h, issueCertRequest(t, "bob", "bob", selfSignedClientCert(t, "ops")))

	assert.Equal(t, http.StatusCreated, rr.Code)
}

// On the webservice replay the caller is the session principal the
// webservice publishes, not the certificate on the connection: its admin role
// admits issuing for another user, and without the role it is refused.
func TestIssueCert_ReplayedCaller(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
		want  int
	}{
		{"admin session", []string{common.ROLE_ADMIN}, http.StatusCreated},
		{"user session", []string{"user"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := guardedHandlerWithCA(newAuthTestCA(t), nil)
			req := issueCertRequest(t, "bob", "bob", selfSignedClientCert(t, "alice"))
			req = req.WithContext(WithCaller(req.Context(), &platformtoken.AuthorizedContext{Subject: "u-ops", Username: "ops", TenantID: authTestTenant, Roles: tc.roles}))
			rr := serveIssueCert(h, req)

			assert.Equal(t, tc.want, rr.Code)
		})
	}
}

// MTLSAdapter.ExtractTenant takes the tenant from the certificate's O, so a
// CSR whose O names another tenant would buy a certificate that logs into
// that tenant. It is refused before the CA is asked to sign.
func TestIssueCert_CSRNamesAnotherTenant_Returns403(t *testing.T) {
	ca := newAuthTestCA(t)
	h := guardedHandlerWithCA(ca, nil)
	subject := pkix.Name{CommonName: "alice", Organization: []string{"tenant-b"}}
	rr := serveIssueCert(h, issueCertRequestForSubject(t, "alice", subject, selfSignedClientCert(t, "alice")))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), ErrCSRNotBoundToUser{Field: "O", Value: "tenant-b"}.Error())
	assert.Zero(t, ca.signCalls, "the CA must not be asked to sign")
}

// The CA is told the subject to issue: the user as CN and the caller's
// tenant as O, whether or not the CSR named one.
func TestIssueCert_IssuedSubjectNamesCallerTenant(t *testing.T) {
	tests := []struct {
		name    string
		subject pkix.Name
	}{
		{"CSR without O", pkix.Name{CommonName: "alice"}},
		{"CSR naming the caller's tenant", pkix.Name{CommonName: "alice", Organization: []string{authTestTenant}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newAuthTestCA(t)
			h := guardedHandlerWithCA(ca, nil)
			rr := serveIssueCert(h, issueCertRequestForSubject(t, "alice", tt.subject, selfSignedClientCert(t, "alice")))

			assert.Equal(t, http.StatusCreated, rr.Code)
			require.NotNil(t, ca.signOpts)
			require.NotNil(t, ca.signOpts.Subject)
			assert.Equal(t, "alice", ca.signOpts.Subject.CommonName)
			assert.Equal(t, authTestTenant, ca.signOpts.Subject.Organization)
		})
	}
}

// A subject attribute other than CN, O and OU is one an identity or tenant
// extractor may read, so it is refused.
func TestIssueCert_CSRExtraSubjectAttribute_Returns403(t *testing.T) {
	ca := newAuthTestCA(t)
	h := guardedHandlerWithCA(ca, nil)
	subject := pkix.Name{CommonName: "alice", SerialNumber: "bob"}
	rr := serveIssueCert(h, issueCertRequestForSubject(t, "alice", subject, selfSignedClientCert(t, "alice")))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), ErrCSRNotBoundToUser{Field: "2.5.4.5", Value: "bob"}.Error())
	assert.Zero(t, ca.signCalls)
}

// A caller with no tenant has no tenant to bind the certificate to, so
// nothing is issued.
func TestIssueCert_CallerWithoutTenant_Returns403(t *testing.T) {
	ca := newAuthTestCA(t)
	h := guardedHandlerWithCA(ca, nil)
	req := issueCertRequest(t, "alice", "alice", nil)
	req = req.WithContext(WithCaller(req.Context(), &platformtoken.AuthorizedContext{Subject: "alice", Username: "alice"}))
	rr := serveIssueCert(h, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), ErrCallerTenantRequired{}.Error())
	assert.Zero(t, ca.signCalls)
}

func TestCSRBoundToUser(t *testing.T) {
	tenantA := selfSignedClientCertWithSubject(t, pkix.Name{CommonName: "alice", OrganizationalUnit: []string{"tenant-a"}})
	admin := selfSignedClientCertWithSubject(t, pkix.Name{CommonName: "ops", OrganizationalUnit: []string{"admin"}})
	subject := func(ou ...string) pkix.Name {
		return pkix.Name{CommonName: "alice", OrganizationalUnit: ou}
	}
	withOrg := func(o ...string) pkix.Name {
		return pkix.Name{CommonName: "alice", Organization: o}
	}
	attribute := func(oid asn1.ObjectIdentifier, value string) pkix.AttributeTypeAndValue {
		return pkix.AttributeTypeAndValue{Type: oid, Value: value}
	}

	tests := []struct {
		name   string
		csr    *x509.CertificateRequest
		caller *x509.Certificate
		// noTenant makes the caller one in no tenant; otherwise it is in
		// authTestTenant.
		noTenant bool
		want     error
	}{
		{name: "CN is the user", csr: &x509.CertificateRequest{Subject: subject()}, caller: tenantA},
		{name: "CN is the user, no client certificate", csr: &x509.CertificateRequest{Subject: subject()}},
		{name: "OU the caller carries", csr: &x509.CertificateRequest{Subject: subject("tenant-a")}, caller: tenantA},
		{name: "O is the caller's tenant", csr: &x509.CertificateRequest{Subject: withOrg("tenant-a")}, caller: tenantA},
		{
			name: "CN names another user",
			csr:  &x509.CertificateRequest{Subject: pkix.Name{CommonName: "bob"}}, caller: tenantA,
			want: ErrCSRNotBoundToUser{Field: "CN", Value: "bob"},
		},
		{
			name: "CN repeated",
			csr: &x509.CertificateRequest{Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
				attribute(oidAttributeCommonName, "bob"), attribute(oidAttributeCommonName, "alice"),
			}}},
			caller: tenantA,
			want:   ErrCSRNotBoundToUser{Field: "CN", Value: "alice"},
		},
		{
			name: "O names another tenant",
			csr:  &x509.CertificateRequest{Subject: withOrg("tenant-b")}, caller: tenantA,
			want: ErrCSRNotBoundToUser{Field: "O", Value: "tenant-b"},
		},
		{
			name: "O repeated",
			csr:  &x509.CertificateRequest{Subject: withOrg("tenant-a", "tenant-b")}, caller: tenantA,
			want: ErrCSRNotBoundToUser{Field: "O", Value: "tenant-a,tenant-b"},
		},
		{
			name: "caller in no tenant",
			csr:  &x509.CertificateRequest{Subject: subject()}, noTenant: true, caller: tenantA,
			want: ErrCallerTenantRequired{},
		},
		{
			name: "SERIALNUMBER attribute",
			csr:  &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice", SerialNumber: "bob"}}, caller: tenantA,
			want: ErrCSRNotBoundToUser{Field: "2.5.4.5", Value: "bob"},
		},
		{
			name: "C attribute",
			csr:  &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice", Country: []string{"US"}}}, caller: tenantA,
			want: ErrCSRNotBoundToUser{Field: "2.5.4.6", Value: "US"},
		},
		{
			name: "emailAddress attribute",
			csr: &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice", ExtraNames: []pkix.AttributeTypeAndValue{
				attribute(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, "bob@example.com"),
			}}},
			caller: tenantA,
			want:   ErrCSRNotBoundToUser{Field: "1.2.840.113549.1.9.1", Value: "bob@example.com"},
		},
		{
			name: "OU names another tenant",
			csr:  &x509.CertificateRequest{Subject: subject("tenant-b")}, caller: tenantA,
			want: ErrCSRNotBoundToUser{Field: "OU", Value: "tenant-b"},
		},
		{
			name: "OU claims admin from an admin caller",
			csr:  &x509.CertificateRequest{Subject: subject("admin")}, caller: admin,
			want: ErrCSRNotBoundToUser{Field: "OU", Value: "admin"},
		},
		{
			name: "OU without a client certificate",
			csr:  &x509.CertificateRequest{Subject: subject("tenant-a")},
			want: ErrCSRNotBoundToUser{Field: "OU", Value: "tenant-a"},
		},
		{
			name: "DNS SAN",
			csr:  &x509.CertificateRequest{Subject: subject(), DNSNames: []string{"bob.example"}}, caller: tenantA,
			want: ErrCSRNotBoundToUser{Field: "SAN"},
		},
		{
			name: "email SAN",
			csr:  &x509.CertificateRequest{Subject: subject(), EmailAddresses: []string{"bob@example.com"}}, caller: tenantA,
			want: ErrCSRNotBoundToUser{Field: "SAN"},
		},
		{
			name: "IP SAN",
			csr:  &x509.CertificateRequest{Subject: subject(), IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}}, caller: tenantA,
			want: ErrCSRNotBoundToUser{Field: "SAN"},
		},
		{
			name: "URI SAN",
			csr:  &x509.CertificateRequest{Subject: subject(), URIs: []*url.URL{{Scheme: "spiffe", Host: "platform", Path: "/user/bob"}}}, caller: tenantA,
			want: ErrCSRNotBoundToUser{Field: "SAN"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := authTestTenant
			if tt.noTenant {
				tenant = ""
			}
			err := csrBoundToUser(generateAuthTestCSR(t, tt.csr), "alice", tenant, tt.caller)
			if tt.want == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

// =============================================================================
// Gap 4 — MFA policy tests
// =============================================================================

func TestMFAPolicy_GetDefaults(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/tenant-x/security/mfa-policy", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var resp MFAPolicyResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "tenant-x", resp.TenantID)
	assert.Equal(t, 1, resp.MinFactorCount)
	assert.False(t, resp.RequireMultipleFactors)
}

func TestMFAPolicy_PutValid_ThenGet(t *testing.T) {
	h := NewAuthFactorHandlers(nil, nil)
	router := registerRoutes(h)

	updateReq := MFAPolicyUpdateRequest{RequireMultipleFactors: true, MinFactorCount: 2}
	body, _ := json.Marshal(updateReq)
	putReq := httptest.NewRequest(http.MethodPut,
		"/api/v1/tenants/tenant-x/security/mfa-policy",
		bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putRR := httptest.NewRecorder()
	router.ServeHTTP(putRR, putReq)
	assert.Equal(t, http.StatusOK, putRR.Code)

	// GET must reflect updated values.
	getReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/tenant-x/security/mfa-policy", nil)
	getRR := httptest.NewRecorder()
	router.ServeHTTP(getRR, getReq)
	assert.Equal(t, http.StatusOK, getRR.Code)
	var resp MFAPolicyResponse
	require.NoError(t, json.NewDecoder(getRR.Body).Decode(&resp))
	assert.True(t, resp.RequireMultipleFactors)
	assert.Equal(t, 2, resp.MinFactorCount)
}

// The console once sent {"require_factor_count":2}, a field the handler does
// not know: it is refused rather than silently storing a policy of false/0,
// and the request body the console sends now is stored as sent.
func TestMFAPolicy_PutConsoleBody(t *testing.T) {
	const path = "/api/v1/tenants/tenant-x/security/mfa-policy"
	tests := []struct {
		name        string
		body        string
		wantCode    int
		wantRequire bool
		wantMin     int
	}{
		{"unknown field", `{"require_factor_count":2}`, http.StatusBadRequest, false, 1},
		{"console body", `{"require_multiple_factors":true,"min_factor_count":2}`, http.StatusOK, true, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := registerRoutes(NewAuthFactorHandlers(nil, nil))
			putReq := httptest.NewRequest(http.MethodPut, path, strings.NewReader(tt.body))
			putReq.Header.Set("Content-Type", "application/json")
			putRR := httptest.NewRecorder()
			router.ServeHTTP(putRR, putReq)
			assert.Equal(t, tt.wantCode, putRR.Code)

			getRR := httptest.NewRecorder()
			router.ServeHTTP(getRR, httptest.NewRequest(http.MethodGet, path, nil))
			require.Equal(t, http.StatusOK, getRR.Code)
			var resp MFAPolicyResponse
			require.NoError(t, json.NewDecoder(getRR.Body).Decode(&resp))
			assert.Equal(t, tt.wantRequire, resp.RequireMultipleFactors)
			assert.Equal(t, tt.wantMin, resp.MinFactorCount)
		})
	}
}

func TestMFAPolicy_PutNegativeMinFactor_Returns400(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	body, _ := json.Marshal(MFAPolicyUpdateRequest{RequireMultipleFactors: true, MinFactorCount: -1})
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/tenants/tenant-x/security/mfa-policy",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestMFAPolicy_PutInvalidJSON_Returns400(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/tenants/tenant-x/security/mfa-policy",
		strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestMFAPolicy_ZeroMinFactorCount_Accepted(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))
	body, _ := json.Marshal(MFAPolicyUpdateRequest{RequireMultipleFactors: false, MinFactorCount: 0})
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/tenants/tenant-y/security/mfa-policy",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}
