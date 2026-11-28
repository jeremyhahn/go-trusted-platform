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
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func (a *authTestCA) SignCSR(_ context.Context, _ []byte, _ *quicbaasca.SignOptions) (*x509.Certificate, error) {
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

// generateTestCSRPEM creates a minimal PEM-encoded CSR for testing.
func generateAuthTestCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-client"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// selfSignedClientCert creates a self-signed cert with the given CN.
func selfSignedClientCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
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

// =============================================================================
// Gap 3 — cert issuance from CSR tests
// =============================================================================

func TestIssueCert_ValidCSR_ReturnsCert(t *testing.T) {
	testCA := newAuthTestCA(t)
	router := newPEPIssueRouter(testCA, &fakeAuthFactorPEP{allowed: true})

	csrPEM := generateAuthTestCSRPEM(t)
	body, _ := json.Marshal(IssueMTLSCertRequest{CSRPEM: csrPEM})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/users/user-abc/factors/mtls/issue-cert",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer alice-token")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)
	var resp IssueMTLSCertResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.NotEmpty(t, resp.CertPEM)
	assert.True(t, strings.Contains(resp.CertPEM, "BEGIN CERTIFICATE"))
}

func TestIssueCert_InvalidCSR_Returns400(t *testing.T) {
	testCA := newAuthTestCA(t)
	router := newPEPIssueRouter(testCA, &fakeAuthFactorPEP{allowed: true})

	body, _ := json.Marshal(IssueMTLSCertRequest{CSRPEM: "not-a-valid-pem"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/users/user-abc/factors/mtls/issue-cert",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer alice-token")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIssueCert_MissingCSRPEM_Returns400(t *testing.T) {
	testCA := newAuthTestCA(t)
	router := newPEPIssueRouter(testCA, &fakeAuthFactorPEP{allowed: true})

	body, _ := json.Marshal(IssueMTLSCertRequest{CSRPEM: ""})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/users/user-abc/factors/mtls/issue-cert",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer alice-token")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestIssueCert_NoCAService_Returns503(t *testing.T) {
	router := registerRoutes(NewAuthFactorHandlers(nil, nil))

	csrPEM := generateAuthTestCSRPEM(t)
	body, _ := json.Marshal(IssueMTLSCertRequest{CSRPEM: csrPEM})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/users/user-abc/factors/mtls/issue-cert",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// aliceTokens is a TokenAuthorizer that authorizes the bearer "alice-token"
// as the member alice of tenant-a and refuses any other token.
type aliceTokens struct{}

func (aliceTokens) AuthorizeToken(_ context.Context, token, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	if token != "alice-token" {
		return nil, errors.New("unknown token")
	}
	return &platformtoken.AuthorizedContext{Subject: "alice", TenantID: "tenant-a", Roles: []string{"member"}}, nil
}

// fakeAuthFactorPEP records every Check request and answers allowed/err.
type fakeAuthFactorPEP struct {
	allowed bool
	err     error
	asked   []*sdkiam.CheckRequest
}

func (p *fakeAuthFactorPEP) Check(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
	p.asked = append(p.asked, req)
	if p.err != nil {
		return nil, p.err
	}
	return &sdkiam.CheckResponse{Allowed: p.allowed}, nil
}

// countingCA counts SignCSR calls on the wrapped CA.
type countingCA struct {
	authCA
	signed int
}

func (c *countingCA) SignCSR(ctx context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error) {
	c.signed++
	return c.authCA.SignCSR(ctx, csrPEM, opts)
}

// newPEPIssueRouter builds the auth-factor routes with the alice token guard
// and the given PEP.
func newPEPIssueRouter(ca authCA, pep AuthFactorPEP) *mux.Router {
	return registerRoutes(newHandlerWithCA(ca).WithAuthorization(NewScopeGuard(aliceTokens{}, nil, nil), pep))
}

// adminCertificateTLS is a TLS state presenting a client certificate whose
// CN and OU are both "admin": the bypass the CN/OU checks used to grant.
func adminCertificateTLS(t *testing.T) *tls.ConnectionState {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "admin", OrganizationalUnit: []string{"admin"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
}

func TestIssueCert_DecidedByPEP(t *testing.T) {
	tests := []struct {
		name       string
		pep        *fakeAuthFactorPEP
		noGuard    bool
		bearer     string
		tls        func(t *testing.T) *tls.ConnectionState
		wantStatus int
		wantAsked  bool
	}{
		{name: "pep allows", pep: &fakeAuthFactorPEP{allowed: true}, bearer: "alice-token", wantStatus: http.StatusCreated, wantAsked: true},
		{name: "pep denies", pep: &fakeAuthFactorPEP{}, bearer: "alice-token", wantStatus: http.StatusForbidden, wantAsked: true},
		{name: "pep errors", pep: &fakeAuthFactorPEP{err: errors.New("iam unavailable")}, bearer: "alice-token", wantStatus: http.StatusForbidden, wantAsked: true},
		{name: "certificate CN/OU admin only", pep: &fakeAuthFactorPEP{allowed: true}, tls: adminCertificateTLS, wantStatus: http.StatusForbidden},
		{name: "no principal no tls", pep: &fakeAuthFactorPEP{allowed: true}, wantStatus: http.StatusForbidden},
		{name: "no authorization configured", pep: &fakeAuthFactorPEP{allowed: true}, noGuard: true, bearer: "alice-token", wantStatus: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := &countingCA{authCA: newAuthTestCA(t)}
			router := newPEPIssueRouter(ca, tt.pep)
			if tt.noGuard {
				router = registerRoutes(newHandlerWithCA(ca))
			}

			body, _ := json.Marshal(IssueMTLSCertRequest{CSRPEM: generateAuthTestCSRPEM(t)})
			req := httptest.NewRequest(http.MethodPost,
				"/api/v1/users/alice/factors/mtls/issue-cert",
				bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tt.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tt.bearer)
			}
			if tt.tls != nil {
				req.TLS = tt.tls(t)
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.wantStatus, rr.Code)
			if tt.wantStatus == http.StatusCreated {
				assert.Equal(t, 1, ca.signed)
			} else {
				assert.Equal(t, 0, ca.signed, "nothing is signed when refused")
				assert.Contains(t, rr.Body.String(), ErrForbiddenUserID{}.Error())
			}
			if !tt.wantAsked {
				assert.Empty(t, tt.pep.asked, "the PEP is not asked without a principal")
				return
			}
			require.Len(t, tt.pep.asked, 1)
			got := tt.pep.asked[0]
			assert.Equal(t, "alice", got.Subject.ID)
			assert.Equal(t, "tenant-a", got.Subject.TenantID)
			assert.Equal(t, []string{"member"}, got.Subject.Roles)
			assert.Equal(t, "user_authfactors", got.Resource)
			assert.Equal(t, "add", got.Action)
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
