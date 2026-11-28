package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// stubIAMTokenVerifier answers verifyIAMToken with fixed claims or a fixed
// error, standing in for the daemon's platform token verifier.
type stubIAMTokenVerifier struct {
	claims *IAMTokenClaims
	err    error
}

func (s stubIAMTokenVerifier) verifyIAMToken(_ context.Context, _ string) (*IAMTokenClaims, error) {
	return s.claims, s.err
}

// verifyServer builds the IAM REST server the way iamRESTServer does, wiring
// svc as the daemon's IAM token service when it is non-nil.
func verifyServer(t *testing.T, svc *IAMTokenService) *RESTServer {
	t.Helper()
	iam := newMemIAM()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(iamRESTCallers, nil, nil)
	if svc != nil {
		s.SetIAMTokenService(svc)
	}
	require.NoError(t, s.SetIAMHandlers(logging.DefaultLogger(), restiam.NewQuicBaaSIAMAdapter(iam), restiam.NewQuicBaaSPEPAdapter(iam.PEP()), guard, iamRESTSystemTenant))
	return s
}

// postVerify posts body to the flat verify route naming tenant-a, the
// callers' tenant: a tenant-bound caller on a flat IAM route names its
// tenant with tenant_id, as the own-tenant guard requires.
func postVerify(s *RESTServer, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tokens/verify?tenant_id="+iamRESTTenantA, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, req)
	return recorder
}

func decodeVerify(t *testing.T, recorder *httptest.ResponseRecorder) restiam.VerifyTokenResponse {
	t.Helper()
	var envelope struct {
		Payload restiam.VerifyTokenResponse `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &envelope), recorder.Body.String())
	return envelope.Payload
}

func TestIAMRESTVerifyToken_AnswersTheDaemonVerifier(t *testing.T) {
	svc := newIAMTokenService(stubIAMTokenVerifier{claims: &IAMTokenClaims{
		Subject:   "svc-a",
		TenantID:  iamRESTTenantA,
		Scopes:    []string{"iam:read"},
		Roles:     []string{"viewer"},
		ExpiresAt: 1893456000,
	}})
	recorder := postVerify(verifyServer(t, svc), "reader", `{"token":"tok-a"}`)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	got := decodeVerify(t, recorder)
	assert.True(t, got.Valid)
	assert.Equal(t, "svc-a", got.Subject)
	assert.Equal(t, iamRESTTenantA, got.TenantID)
	assert.Equal(t, []string{"viewer"}, got.Roles)
	assert.Equal(t, int64(1893456000), got.ExpiresAt)
}

func TestIAMRESTVerifyToken_AnswersARejection(t *testing.T) {
	svc := newIAMTokenService(stubIAMTokenVerifier{err: ErrIAMTokenInvalid{Reason: string(IAMTokenExpired)}})
	recorder := postVerify(verifyServer(t, svc), "reader", `{"token":"tok-a"}`)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	got := decodeVerify(t, recorder)
	assert.False(t, got.Valid)
	assert.Equal(t, "expired", got.Reason)
	assert.Empty(t, got.Subject)
}

func TestIAMRESTVerifyToken_NeedsOnlyRead(t *testing.T) {
	svc := newIAMTokenService(stubIAMTokenVerifier{claims: &IAMTokenClaims{Subject: "svc-a", TenantID: iamRESTTenantA}})
	s := verifyServer(t, svc)

	assertReachedHandler(t, postVerify(s, "reader", `{"token":"tok-a"}`), "an iam:read caller reaches VerifyToken")
	assert.Equal(t, http.StatusForbidden, postVerify(s, "other", `{"token":"tok-a"}`).Code, "a caller without iam:read is refused")
}

func TestIAMRESTVerifyToken_WithoutTheServiceIsUnavailable(t *testing.T) {
	recorder := postVerify(verifyServer(t, nil), "reader", `{"token":"tok-a"}`)
	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, recorder.Body.String())
}

func TestIAMScopeAction_TokensVerifyIsRead(t *testing.T) {
	action, err := iamScopeAction(http.MethodPost, "/api/v1/iam/tokens/verify")
	require.NoError(t, err)
	assert.Equal(t, "read", action)
}

// TestDaemon_IAMRESTTokenVerifier: the accessor serve.go hands the console's
// IAM router answers through the daemon's token service, and is an untyped
// nil when the daemon has none, so the console keeps its 503 (#2053).
func TestDaemon_IAMRESTTokenVerifier(t *testing.T) {
	t.Run("no token service is a nil interface", func(t *testing.T) {
		d := &Daemon{}
		assert.True(t, d.IAMRESTTokenVerifier() == nil)
	})
	t.Run("a token service answers its claims", func(t *testing.T) {
		d := &Daemon{iamTokenService: newIAMTokenService(stubIAMTokenVerifier{claims: &IAMTokenClaims{
			Subject:   "svc-a",
			TenantID:  iamRESTTenantA,
			Roles:     []string{"viewer"},
			ExpiresAt: 1893456000,
		}})}
		v := d.IAMRESTTokenVerifier()
		require.NotNil(t, v)
		got, err := v.Verify(context.Background(), "tok-a")
		require.NoError(t, err)
		assert.True(t, got.Valid)
		assert.Equal(t, "svc-a", got.Subject)
		assert.Equal(t, iamRESTTenantA, got.TenantID)
		assert.Equal(t, int64(1893456000), got.ExpiresAt.Unix())
	})
}
