package rest

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

func authFactorErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var errResp ErrorResponse
	decodeResponse(t, rec.Body, &errResp)
	return errResp.Error
}

func probeWithPeer(h *AuthFactorHandlers, peer *x509.Certificate) int {
	req := httptest.NewRequest(http.MethodHead, "/api/v1/auth/mtls/probe", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	rec := httptest.NewRecorder()
	h.handleMTLSProbe(rec, req)
	return rec.Code
}

// With a CA wired the probe verifies the client leaf against the trusted
// roots; it degrades to presence-only when the pool cannot be obtained.
func TestAuthFactorAPIRest_MTLSProbeWithCA(t *testing.T) {
	testCA := newAuthTestCA(t)

	// Regression: Verify without KeyUsages checks for serverAuth and so
	// rejected every clientAuth leaf the platform CA issues.
	t.Run("clientAuth leaf chains to the trusted root", func(t *testing.T) {
		h := newHandlerWithCA(testCA)
		assert.Equal(t, http.StatusNoContent, probeWithPeer(h, testCA.signedCert))
	})

	t.Run("leaf from another issuer", func(t *testing.T) {
		h := newHandlerWithCA(testCA)
		assert.Equal(t, http.StatusUnauthorized, probeWithPeer(h, selfSignedClientCert(t, "intruder")))
	})

	t.Run("root pool unavailable", func(t *testing.T) {
		h := newHandlerWithCA(&authTestCA{rootPoolErr: errors.New("keystore sealed")})
		assert.Equal(t, http.StatusNoContent, probeWithPeer(h, selfSignedClientCert(t, "alice")))
	})
}

func TestAuthFactorAPIRest_IssueCertErrors(t *testing.T) {
	t.Run("malformed body", func(t *testing.T) {
		router := registerRoutes(guardedHandlerWithCA(newAuthTestCA(t), nil))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/alice/factors/mtls/issue-cert", strings.NewReader(`{"csr_pem":`))
		withCallerCert(req, selfSignedClientCert(t, "alice"))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, ErrInvalidRequestBody{Reason: "unexpected EOF"}.Error(), authFactorErrorMessage(t, rec))
	})

	t.Run("CA refuses the CSR", func(t *testing.T) {
		testCA := newAuthTestCA(t)
		testCA.signErr = errors.New("profile client disabled")
		h := guardedHandlerWithCA(testCA, nil)
		rec := serveIssueCert(h, issueCertRequest(t, "alice", "alice", selfSignedClientCert(t, "alice")))

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, ErrCertIssueFailed{Reason: "profile client disabled"}.Error(), authFactorErrorMessage(t, rec))
	})
}

// The router never yields an empty {id}; the handlers are driven directly.
func TestAuthFactorAPIRest_EmptyID(t *testing.T) {
	h := newHandlerWithCA(newAuthTestCA(t))
	handlers := map[string]http.HandlerFunc{
		"issue cert":     h.handleIssueCert,
		"get mfa policy": h.handleGetMFAPolicy,
		"put mfa policy": h.handlePutMFAPolicy,
	}
	for name, handle := range handlers {
		t.Run(name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), map[string]string{"id": ""})
			rec := httptest.NewRecorder()
			handle(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, ErrMissingRequiredField{Field: "id"}.Error(), authFactorErrorMessage(t, rec))
		})
	}
}

// Admin comes from the caller's role, never from a common name or
// organizational unit the certificate's holder chose.
func TestAuthFactorAPIRest_AuthorizeCaller(t *testing.T) {
	h := guardedHandlerWithCA(nil, certPrincipals{"ops": {common.ROLE_ADMIN}})
	cases := []struct {
		name       string
		subject    *pkix.Name
		wantStatus int
		wantErr    error
	}{
		{"no client certificate", nil, http.StatusUnauthorized, nil},
		{"the user themselves", &pkix.Name{CommonName: "alice"}, http.StatusOK, nil},
		{"admin role", &pkix.Name{CommonName: "ops"}, http.StatusOK, nil},
		{"admin common name without the role", &pkix.Name{CommonName: "admin"}, http.StatusForbidden, ErrForbiddenUserID{}},
		{"admin-prefixed common name without the role", &pkix.Name{CommonName: "admin-ops"}, http.StatusForbidden, ErrForbiddenUserID{}},
		{"admin organizational unit without the role", &pkix.Name{CommonName: "carol", OrganizationalUnit: []string{"eng", "ADMIN"}}, http.StatusForbidden, ErrForbiddenUserID{}},
		{"another user", &pkix.Name{CommonName: "bob", OrganizationalUnit: []string{"eng"}}, http.StatusForbidden, ErrForbiddenUserID{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tc.subject != nil {
				withCallerCert(req, selfSignedClientCertWithSubject(t, *tc.subject))
			}
			caller, status, err := h.authorizeCaller(req, "alice")
			assert.Equal(t, tc.wantStatus, status)
			if tc.wantStatus == http.StatusOK {
				require.NoError(t, err)
				assert.NotNil(t, caller)
				return
			}
			assert.Nil(t, caller)
			require.Error(t, err)
			if tc.wantErr != nil {
				assert.Equal(t, tc.wantErr, err)
			}
		})
	}
}

func TestAuthFactorAPIRest_NewWiresCA(t *testing.T) {
	// Only the wiring is under test; no CA method is called.
	var ca quicbaasca.CACertificateAuthority = struct {
		quicbaasca.CACertificateAuthority
	}{}
	assert.Equal(t, ca, NewAuthFactorHandlers(ca, nil).ca)
	assert.Nil(t, NewAuthFactorHandlers(nil, nil).ca, "a nil CA leaves the interface nil, not a typed nil")
}

func TestAuthFactorAPIRest_LookupCacheExpiry(t *testing.T) {
	h := NewAuthFactorHandlers(nil, nil)
	fresh := AAGUIDLookupResponse{AAGUID: "fresh"}
	h.cache["fresh"] = aaguidEntry{resp: fresh, cachedAt: time.Now()}
	h.cache["stale"] = aaguidEntry{resp: AAGUIDLookupResponse{AAGUID: "stale"}, cachedAt: time.Now().Add(-aaguidCacheTTL - time.Minute)}

	got, ok := h.lookupCache("fresh")
	assert.True(t, ok)
	assert.Equal(t, fresh, got)

	got, ok = h.lookupCache("stale")
	assert.False(t, ok, "an entry older than the TTL is a miss")
	assert.Equal(t, AAGUIDLookupResponse{}, got)
}

func TestAuthFactorAPIRest_ErrorMessages(t *testing.T) {
	assert.Equal(t, "mTLS client certificate required", ErrMTLSClientCertRequired{}.Error())
	assert.Equal(t, "mTLS certificate validation failed: expired", ErrMTLSCertValidationFailed{Reason: "expired"}.Error())
	assert.Equal(t, "certificate issuance failed: denied", ErrCertIssueFailed{Reason: "denied"}.Error())
}

func TestAuthFactorAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	h := NewAuthFactorHandlers(nil, nil)
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusOK, map[string]interface{}{"ch": make(chan int)})

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.String())
}
