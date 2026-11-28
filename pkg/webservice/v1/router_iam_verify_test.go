package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// recordingTokenVerifier is the daemon's token verifier as the console's
// IAM router sees it: it records the token it was asked about and answers a
// fixed verdict.
type recordingTokenVerifier struct {
	seen    []string
	verdict *restiam.TokenVerification
}

func (v *recordingTokenVerifier) Verify(_ context.Context, token string) (*restiam.TokenVerification, error) {
	v.seen = append(v.seen, token)
	return v.verdict, nil
}

// postConsoleVerify serves an authenticated system-admin POST
// /api/v1/iam/tokens/verify through the production console router.
func postConsoleVerify(t *testing.T, registry *testHandlerRegistry) *httptest.ResponseRecorder {
	t.Helper()
	registry.tokenHandler = &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}
	router := newGatedTestRouter(t, registry)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/iam/tokens/verify?tenant_id=system",
		strings.NewReader(`{"token":"abc.def.ghi"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

// TestConsoleIAMTokenVerify_AnswersThroughTheRegistryVerifier: the console
// builds its own IAM router, so the advertised verify route answers only when
// the registry hands it the daemon's token verifier (Codex round 6 P1, #2053).
func TestConsoleIAMTokenVerify_AnswersThroughTheRegistryVerifier(t *testing.T) {
	verifier := &recordingTokenVerifier{verdict: &restiam.TokenVerification{
		Valid:     true,
		Subject:   "svc-console",
		TenantID:  "system",
		Scopes:    []string{"iam:read"},
		ExpiresAt: time.Unix(1922832000, 0),
	}}
	recorder := postConsoleVerify(t, &testHandlerRegistry{tokenVerifier: verifier})

	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Equal(t, []string{"abc.def.ghi"}, verifier.seen)
	assert.Contains(t, recorder.Body.String(), "svc-console")
	assert.Contains(t, recorder.Body.String(), "1922832000")
}

// TestConsoleIAMTokenVerify_WithoutAVerifierIsUnavailable: a registry with no
// verifier still answers 503, never a verdict.
func TestConsoleIAMTokenVerify_WithoutAVerifierIsUnavailable(t *testing.T) {
	recorder := postConsoleVerify(t, &testHandlerRegistry{})
	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, recorder.Body.String())
}
