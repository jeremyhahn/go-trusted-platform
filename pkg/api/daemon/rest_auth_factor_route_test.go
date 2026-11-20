package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authFactorRoutePEP is a stub IAM decision point that records whether it
// was asked.
type authFactorRoutePEP struct {
	allow bool
	asked bool
}

func (p *authFactorRoutePEP) Check(_ context.Context, _ *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
	p.asked = true
	return &sdkiam.CheckResponse{Allowed: p.allow}, nil
}

// authFactorRouteCallers are the platform-token callers the auth-factor
// route tests authenticate as.
var authFactorRouteCallers = iamRESTTokens{
	"factor-admin": {Subject: "factor-admin", TenantID: iamRESTTenantA, Scopes: []string{"authfactor:enroll"}},
	"iam-writer":   {Subject: "iam-writer", TenantID: iamRESTTenantA, Scopes: []string{"iam:read", "iam:write", "iam:delete"}},
}

// authFactorRouteServer builds a daemon REST server whose auth-factor routes
// sit behind a scope guard for authFactorRouteCallers and whose PEP is pep.
func authFactorRouteServer(t *testing.T, pep restapi.AuthFactorPEP) *RESTServer {
	t.Helper()
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)
	s.SetCAHandlers(routeTableCA{}, restapi.NewScopeGuard(authFactorRouteCallers, nil, nil))
	s.SetAuthFactorPEP(pep)
	return s
}

// issueCertThroughRouter posts a malformed body to the issuance route: a
// caller the PEP allows gets 400 from body decoding, before the CA is used.
func issueCertThroughRouter(s *RESTServer, token string) int {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/alice/factors/mtls/issue-cert", strings.NewReader("{"))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	s.Router().ServeHTTP(rr, req)
	return rr.Code
}

func TestAuthFactorRoute_AllowedPlatformTokenReachesTheHandler(t *testing.T) {
	pep := &authFactorRoutePEP{allow: true}
	s := authFactorRouteServer(t, pep)
	assert.Equal(t, http.StatusBadRequest, issueCertThroughRouter(s, "factor-admin"),
		"a valid token the PEP allows gets past authorization to body decoding")
	assert.True(t, pep.asked, "the PEP decides the authenticated principal")
}

func TestAuthFactorRoute_DeniedPlatformTokenIsForbidden(t *testing.T) {
	pep := &authFactorRoutePEP{allow: false}
	s := authFactorRouteServer(t, pep)
	assert.Equal(t, http.StatusForbidden, issueCertThroughRouter(s, "factor-admin"))
	assert.True(t, pep.asked)
}

func TestAuthFactorRoute_NoCredentialIsUnauthorized(t *testing.T) {
	pep := &authFactorRoutePEP{allow: true}
	s := authFactorRouteServer(t, pep)
	assert.Equal(t, http.StatusUnauthorized, issueCertThroughRouter(s, ""))
	assert.False(t, pep.asked)
}

// TestAuthFactorRoute_IAMWriteScopeWithoutEnrollIsForbidden pins the scope
// layer: issuance needs the authfactor:enroll scope, and an iam:write token
// is refused before the PEP is asked (#2079 Codex round 1).
func TestAuthFactorRoute_IAMWriteScopeWithoutEnrollIsForbidden(t *testing.T) {
	pep := &authFactorRoutePEP{allow: true}
	s := authFactorRouteServer(t, pep)
	assert.Equal(t, http.StatusForbidden, issueCertThroughRouter(s, "iam-writer"))
	assert.False(t, pep.asked, "a token without authfactor:enroll never reaches the PEP")
}
