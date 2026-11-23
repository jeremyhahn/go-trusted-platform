package iam

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// fakeTokenVerifier records every token it is asked to verify and answers
// the configured verification or error.
type fakeTokenVerifier struct {
	got    []string
	answer *TokenVerification
	err    error
}

func (f *fakeTokenVerifier) Verify(_ context.Context, token string) (*TokenVerification, error) {
	f.got = append(f.got, token)
	if f.err != nil {
		return nil, f.err
	}
	return f.answer, nil
}

// tokenVerifyServer serves the IAM router for an admin session of tenant-a,
// with the verifier wired when it is non-nil.
func tokenVerifyServer(t *testing.T, verifier TokenVerifier) *httptest.Server {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	writer := response.NewResponseWriter(logger, nil)
	guard, err := iammw.NewSessionGuard(logger, writer)
	require.NoError(t, err)

	session := iammw.NewIAMSession(&iamsdk.User{ID: "admin-a", TenantID: "tenant-a", Roles: []string{"admin"}})
	authenticate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(iammw.SetSessionInContext(r.Context(), session)))
		})
	}

	iamRouter, err := NewIAMRouter(logger, &mockIAMClient{}, &mockPEPClient{}, writer, Authorization{
		Authenticate:        authenticate,
		RequireAdmin:        guard.RequireRoles("admin"),
		RequireSystemTenant: guard.RequireTenant("system"),
		RequireOwnTenant:    guard.RequireOwnTenant(RequestedTenant),
	})
	require.NoError(t, err)
	if verifier != nil {
		iamRouter.SetTokenVerifier(verifier)
	}

	root := mux.NewRouter()
	iamRouter.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)
	return server
}

// postVerify POSTs body to the verify route and decodes the restwire envelope.
func postVerify(t *testing.T, server *httptest.Server, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/iam/tokens/verify", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	envelope := map[string]any{}
	if len(raw) > 0 {
		require.NoError(t, json.Unmarshal(raw, &envelope), "body: %s", raw)
	}
	return resp.StatusCode, envelope
}

func TestVerifyTokenREST(t *testing.T) {
	expires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

	tests := []struct {
		name     string
		verifier *fakeTokenVerifier
		body     string
		check    func(t *testing.T, code int, envelope map[string]any, v *fakeTokenVerifier)
	}{
		{
			name: "valid token answers its claims",
			verifier: &fakeTokenVerifier{answer: &TokenVerification{
				Valid: true, Subject: "user-1", TenantID: "tenant-a",
				Scopes: []string{"iam:read"}, Roles: []string{"admin"}, ExpiresAt: expires,
			}},
			body: `{"token":"tok-1"}`,
			check: func(t *testing.T, code int, envelope map[string]any, v *fakeTokenVerifier) {
				require.Equal(t, http.StatusOK, code, "envelope: %v", envelope)
				payload, ok := envelope["payload"].(map[string]any)
				require.True(t, ok, "envelope: %v", envelope)
				require.Equal(t, true, payload["valid"])
				require.Equal(t, "user-1", payload["subject"])
				require.Equal(t, "tenant-a", payload["tenant_id"])
				require.Equal(t, []any{"iam:read"}, payload["scopes"])
				require.Equal(t, []any{"admin"}, payload["roles"])
				require.Equal(t, float64(1893553445), payload["expires_at"])
				require.Equal(t, []string{"tok-1"}, v.got)
			},
		},
		{
			name:     "invalid token answers its reason",
			verifier: &fakeTokenVerifier{answer: &TokenVerification{Valid: false, Reason: "expired"}},
			body:     `{"token":"tok-1"}`,
			check: func(t *testing.T, code int, envelope map[string]any, _ *fakeTokenVerifier) {
				require.Equal(t, http.StatusOK, code, "envelope: %v", envelope)
				payload, ok := envelope["payload"].(map[string]any)
				require.True(t, ok, "envelope: %v", envelope)
				require.Equal(t, false, payload["valid"])
				require.Equal(t, "expired", payload["reason"])
				require.NotContains(t, payload, "subject")
			},
		},
		{
			name: "foreign tenant claims are not disclosed",
			verifier: &fakeTokenVerifier{answer: &TokenVerification{
				Valid: true, Subject: "user-9", TenantID: "tenant-b",
				Scopes: []string{"iam:read"}, Roles: []string{"admin"}, ExpiresAt: expires,
			}},
			body: `{"token":"tok-1"}`,
			check: func(t *testing.T, code int, envelope map[string]any, _ *fakeTokenVerifier) {
				require.Equal(t, http.StatusOK, code, "envelope: %v", envelope)
				payload, ok := envelope["payload"].(map[string]any)
				require.True(t, ok, "envelope: %v", envelope)
				require.Equal(t, false, payload["valid"])
				require.Equal(t, "foreign_tenant", payload["reason"])
				for _, key := range []string{"subject", "tenant_id", "scopes", "roles", "expires_at"} {
					require.NotContains(t, payload, key)
				}
			},
		},
		{
			name:     "missing token",
			verifier: &fakeTokenVerifier{answer: &TokenVerification{Valid: true, TenantID: "tenant-a"}},
			body:     `{}`,
			check: func(t *testing.T, code int, envelope map[string]any, v *fakeTokenVerifier) {
				require.Equal(t, http.StatusBadRequest, code, "envelope: %v", envelope)
				require.Empty(t, v.got)
			},
		},
		{
			name:     "foreign tenant_id in the body",
			verifier: &fakeTokenVerifier{answer: &TokenVerification{Valid: true, TenantID: "tenant-b"}},
			body:     `{"tenant_id":"tenant-b","token":"tok-1"}`,
			check: func(t *testing.T, code int, envelope map[string]any, v *fakeTokenVerifier) {
				require.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden}, code, "envelope: %v", envelope)
				require.Empty(t, v.got)
			},
		},
		{
			name:     "no verifier wired",
			verifier: nil,
			body:     `{"token":"tok-1"}`,
			check: func(t *testing.T, code int, envelope map[string]any, _ *fakeTokenVerifier) {
				require.Equal(t, http.StatusServiceUnavailable, code, "envelope: %v", envelope)
				require.Equal(t, ErrTokenVerifierMissing{}.Error(), envelope["error"])
			},
		},
		{
			name:     "verifier error",
			verifier: &fakeTokenVerifier{err: errors.New("boom")},
			body:     `{"token":"tok-1"}`,
			check: func(t *testing.T, code int, envelope map[string]any, _ *fakeTokenVerifier) {
				require.NotEqual(t, http.StatusOK, code, "envelope: %v", envelope)
				if payload, ok := envelope["payload"].(map[string]any); ok {
					require.NotEqual(t, true, payload["valid"])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var server *httptest.Server
			if tc.verifier == nil {
				server = tokenVerifyServer(t, nil)
			} else {
				server = tokenVerifyServer(t, tc.verifier)
			}
			code, envelope := postVerify(t, server, tc.body)
			tc.check(t, code, envelope, tc.verifier)
		})
	}
}
