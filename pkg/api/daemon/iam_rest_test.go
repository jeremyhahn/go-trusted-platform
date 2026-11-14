package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

const (
	iamRESTSystemTenant = "system"
	iamRESTTenantA      = "tenant-a"
	iamRESTTenantB      = "tenant-b"
)

// iamRESTTokens grants each bearer token a fixed tenant and scope set.
type iamRESTTokens map[string]platformtoken.AuthorizedContext

func (t iamRESTTokens) AuthorizeToken(_ context.Context, token, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	caller, ok := t[token]
	if !ok {
		return nil, errors.New("token invalid")
	}
	return &caller, nil
}

// iamRESTCallers are the callers the IAM REST tests authenticate as.
var iamRESTCallers = iamRESTTokens{
	"reader":   {Subject: "reader", TenantID: iamRESTTenantA, Scopes: []string{"iam:read"}},
	"reader-b": {Subject: "reader-b", TenantID: iamRESTTenantB, Scopes: []string{"iam:read"}},
	"writer":   {Subject: "writer", TenantID: iamRESTTenantA, Scopes: []string{"iam:write"}},
	"deleter":  {Subject: "deleter", TenantID: iamRESTTenantA, Scopes: []string{"iam:delete"}},
	"operator": {Subject: "operator", TenantID: iamRESTTenantA, Scopes: []string{"*:*"}},
	"system":   {Subject: "system", TenantID: iamRESTSystemTenant, Scopes: []string{"*:*"}},
	"other":    {Subject: "other", TenantID: iamRESTTenantA, Scopes: []string{"tenant:read"}},
}

// iamRESTServer is a RESTServer serving only /api/v1/iam, backed by the
// in-memory IAM.
func iamRESTServer(t *testing.T) *RESTServer {
	t.Helper()
	iam := newMemIAM()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(iamRESTCallers, nil, nil)
	require.NoError(t, s.SetIAMHandlers(logging.DefaultLogger(), restiam.NewQuicBaaSIAMAdapter(iam), restiam.NewQuicBaaSPEPAdapter(iam.PEP()), guard, iamRESTSystemTenant))
	return s
}

func serveIAM(s *RESTServer, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, req)
	return recorder
}

// assertReachedHandler: the guards admitted the request and a mounted IAM
// handler answered it, rather than a guard, or the router finding no route.
func assertReachedHandler(t *testing.T, recorder *httptest.ResponseRecorder, msgAndArgs ...any) {
	t.Helper()
	for _, refused := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusMethodNotAllowed} {
		assert.NotEqual(t, refused, recorder.Code, msgAndArgs...)
	}
	assert.NotEqual(t, "404 page not found\n", recorder.Body.String(), msgAndArgs...)
}

func TestSetIAMHandlers_RefusesAMissingDependency(t *testing.T) {
	iam := newMemIAM()
	logger := logging.DefaultLogger()
	client := restiam.NewQuicBaaSIAMAdapter(iam)
	pep := restiam.NewQuicBaaSPEPAdapter(iam.PEP())
	guard := restapi.NewScopeGuard(iamRESTCallers, nil, nil)
	cases := []struct {
		name   string
		logger *logging.Logger
		client restiam.IAMClient
		pep    restiam.PEPClient
		guard  *restapi.ScopeGuard
		reason string
	}{
		{"no logger", nil, client, pep, guard, "no logger"},
		{"no IAM client", logger, nil, pep, guard, "no IAM client"},
		{"no PEP client", logger, client, nil, guard, "no IAM PEP client"},
		{"no guard", logger, client, pep, nil, "no REST scope guard"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			err := s.SetIAMHandlers(tc.logger, tc.client, tc.pep, tc.guard, iamRESTSystemTenant)
			var unavailable ErrIAMRESTUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Equal(t, tc.reason, unavailable.Reason)
			assert.Equal(t, http.StatusNotFound, serveIAM(s, http.MethodGet, "/api/v1/iam/tenants/tenant-a/users", "operator").Code,
				"a refused mount serves no IAM route")
		})
	}
}

func TestSetIAMHandlers_MountsEveryIAMRoute(t *testing.T) {
	s := iamRESTServer(t)
	routes := 0
	require.NoError(t, s.router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil || !strings.HasPrefix(template, "/api/v1/iam") {
			return nil
		}
		if _, err := route.GetMethods(); err == nil {
			routes++
		}
		return nil
	}))
	assert.Equal(t, 71, routes)
}

func TestIAMREST_ScopePerMethod(t *testing.T) {
	const users = "/api/v1/iam/tenants/" + iamRESTTenantA + "/users"
	const groups = "/api/v1/iam/tenants/" + iamRESTTenantA + "/groups"
	cases := []struct {
		token  string
		method string
		path   string
		scope  string
		admit  bool
	}{
		{"reader", http.MethodGet, users, "iam:read", true},
		{"reader", http.MethodPost, users, "iam:write", false},
		{"reader", http.MethodPut, users + "/u1", "iam:write", false},
		{"reader", http.MethodDelete, users + "/u1", "iam:delete", false},
		{"reader", http.MethodPost, "/api/v1/iam/tenants/" + iamRESTTenantA + "/policies/validate", "iam:read", true},
		{"reader", http.MethodPost, "/api/v1/iam/tenants/" + iamRESTTenantA + "/policies/test", "iam:read", true},
		{"reader", http.MethodPost, "/api/v1/iam/tenants/" + iamRESTTenantA + "/permissions/check", "iam:read", true},
		{"writer", http.MethodGet, users, "iam:read", false},
		{"writer", http.MethodPost, users, "iam:write", true},
		{"writer", http.MethodPut, users + "/u1", "iam:write", true},
		{"writer", http.MethodDelete, users + "/u1", "iam:delete", false},
		{"writer", http.MethodPost, "/api/v1/iam/tenants/" + iamRESTTenantA + "/policies/validate", "iam:read", false},
		{"deleter", http.MethodDelete, users + "/u1", "iam:delete", true},
		{"deleter", http.MethodPost, users, "iam:write", false},
		{"other", http.MethodGet, users, "iam:read", false},
		// RevokeRole and RemoveGroupMember are iam:write in the gRPC
		// catalog, in both the tenant-scoped and the flat form.
		{"writer", http.MethodDelete, users + "/u1/roles/admin", "iam:write", true},
		{"deleter", http.MethodDelete, users + "/u1/roles/admin", "iam:write", false},
		{"writer", http.MethodDelete, groups + "/g1/members/u1", "iam:write", true},
		{"deleter", http.MethodDelete, groups + "/g1/members/u1", "iam:write", false},
		{"writer", http.MethodDelete, "/api/v1/iam/users/u1/roles/admin?tenant_id=" + iamRESTTenantA, "iam:write", true},
		{"deleter", http.MethodDelete, "/api/v1/iam/users/u1/roles/admin?tenant_id=" + iamRESTTenantA, "iam:write", false},
		{"writer", http.MethodDelete, "/api/v1/iam/groups/g1/members/u1?tenant_id=" + iamRESTTenantA, "iam:write", true},
		{"deleter", http.MethodDelete, "/api/v1/iam/groups/g1/members/u1?tenant_id=" + iamRESTTenantA, "iam:write", false},
	}
	s := iamRESTServer(t)
	for _, tc := range cases {
		t.Run(tc.token+" "+tc.method+" "+tc.path, func(t *testing.T) {
			recorder := serveIAM(s, tc.method, tc.path, tc.token)
			if tc.admit {
				assertReachedHandler(t, recorder, recorder.Body.String())
				return
			}
			assert.Equal(t, http.StatusForbidden, recorder.Code)
			assert.Contains(t, recorder.Body.String(), "scope "+tc.scope+" required")
		})
	}
}

// The mTLS operator's *:* scope admits every method on every route.
func TestIAMREST_OperatorPassesEveryMethod(t *testing.T) {
	s := iamRESTServer(t)
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/iam/tenants/tenant-a/users"},
		{http.MethodPost, "/api/v1/iam/tenants/tenant-a/users"},
		{http.MethodPut, "/api/v1/iam/tenants/tenant-a/users/u1"},
		{http.MethodDelete, "/api/v1/iam/tenants/tenant-a/users/u1"},
		{http.MethodPost, "/api/v1/iam/tenants/tenant-a/permissions/check"},
	} {
		recorder := serveIAM(s, route.method, route.path, "operator")
		assertReachedHandler(t, recorder, "%s %s: %s", route.method, route.path, recorder.Body.String())
	}
}

func TestIAMREST_NoCredentialIsUnauthorized(t *testing.T) {
	s := iamRESTServer(t)
	for _, token := range []string{"", "forged"} {
		recorder := serveIAM(s, http.MethodGet, "/api/v1/iam/tenants/tenant-a/users", token)
		assert.Equal(t, http.StatusUnauthorized, recorder.Code, "token %q", token)
	}
}

func TestIAMREST_TenantRules(t *testing.T) {
	cases := []struct {
		name   string
		token  string
		method string
		path   string
		admit  bool
	}{
		{"own tenant", "operator", http.MethodGet, "/api/v1/iam/tenants/" + iamRESTTenantA + "/users", true},
		{"another tenant", "operator", http.MethodGet, "/api/v1/iam/tenants/" + iamRESTTenantB + "/users", false},
		{"another tenant by query", "operator", http.MethodGet, "/api/v1/iam/users?tenant_id=" + iamRESTTenantB, false},
		{"tenant create by a tenant caller", "operator", http.MethodPost, "/api/v1/iam/tenants", false},
		{"tenant list by a tenant caller", "operator", http.MethodGet, "/api/v1/iam/tenants", false},
		{"tenant create by the system tenant", "system", http.MethodPost, "/api/v1/iam/tenants", true},
		{"tenant list by the system tenant", "system", http.MethodGet, "/api/v1/iam/tenants", true},
	}
	s := iamRESTServer(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := serveIAM(s, tc.method, tc.path, tc.token)
			if tc.admit {
				assertReachedHandler(t, recorder, recorder.Body.String())
				return
			}
			assert.Equal(t, http.StatusForbidden, recorder.Code, recorder.Body.String())
		})
	}
}

// A flat route names its tenant in the query, not the path. The handler must
// receive the tenant the guard verified; a caller bound to another tenant is
// refused.
func TestIAMREST_FlatRouteKeepsVerifiedTenant(t *testing.T) {
	s := iamRESTServer(t)
	path := "/api/v1/iam/users?tenant_id=" + iamRESTTenantA

	recorder := serveIAM(s, http.MethodGet, path, "reader")
	assert.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	recorder = serveIAM(s, http.MethodGet, path, "reader-b")
	assert.Equal(t, http.StatusForbidden, recorder.Code, recorder.Body.String())
}

func TestIAMScopeAction(t *testing.T) {
	cases := []struct {
		method string
		route  string
		want   string
	}{
		{http.MethodGet, "/api/v1/iam/tenants/{tenant}/users", "read"},
		{http.MethodPost, "/api/v1/iam/tenants/{tenant}/users", "write"},
		{http.MethodPut, "/api/v1/iam/tenants/{tenant}/users/{id}", "write"},
		{http.MethodPatch, "/api/v1/iam/tenants/{tenant}/users/{id}", "write"},
		{http.MethodDelete, "/api/v1/iam/tenants/{tenant}/users/{id}", "delete"},
		{http.MethodPost, "/api/v1/iam/tenants/{tenant}/policies/validate", "read"},
		{http.MethodPost, "/api/v1/iam/tenants/{tenant}/policies/test", "read"},
		{http.MethodPost, "/api/v1/iam/tenants/{tenant}/permissions/check", "read"},
		{http.MethodPost, "/api/v1/iam/policies/validate", "read"},
		{http.MethodPost, "/api/v1/iam/policies/test", "read"},
		{http.MethodPost, "/api/v1/iam/permissions/check", "read"},
		{http.MethodPost, "/api/v1/iam/tenants/{tenant}/policies", "write"},
		{http.MethodPut, "/api/v1/iam/tenants/{tenant}/policies/test", "write"},
		{http.MethodDelete, "/api/v1/iam/tenants/{tenant}/users/{id}/roles/{role}", "write"},
		{http.MethodDelete, "/api/v1/iam/users/{id}/roles/{role}", "write"},
		{http.MethodDelete, "/api/v1/iam/tenants/{tenant}/groups/{id}/members/{user}", "write"},
		{http.MethodDelete, "/api/v1/iam/groups/{id}/members/{user}", "write"},
		{http.MethodDelete, "/api/v1/iam/tenants/{tenant}/groups/{id}", "delete"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.route, func(t *testing.T) {
			got, err := iamScopeAction(tc.method, tc.route)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	for _, method := range []string{http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodConnect, "BREW"} {
		t.Run("refuses "+method, func(t *testing.T) {
			got, err := iamScopeAction(method, "/api/v1/iam/users")
			var forbidden restapi.ErrRouteForbidden
			require.ErrorAs(t, err, &forbidden)
			assert.Empty(t, got)
		})
	}
}

// A request that reaches an IAM guard without the authenticated caller is
// refused rather than served.
func TestIAMRESTAuthorization_GuardWithoutCallerIsForbidden(t *testing.T) {
	authz := iamRESTAuthorization{respWriter: response.NewResponseWriter(logging.DefaultLogger(), nil), systemTenantID: iamRESTSystemTenant}
	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	for name, guard := range map[string]func(http.Handler) http.Handler{
		"scope":         authz.requireScope,
		"system tenant": authz.requireSystemTenant,
		"own tenant":    authz.requireOwnTenant,
	} {
		t.Run(name, func(t *testing.T) {
			reached = false
			recorder := httptest.NewRecorder()
			guard(next).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/iam/users", nil))
			assert.Equal(t, http.StatusForbidden, recorder.Code)
			assert.False(t, reached)
		})
	}
}

func TestIAMTenantDecisions(t *testing.T) {
	require.NoError(t, iamTenantDecision(iamRESTTenantA, iamRESTTenantA))
	var forbidden ErrIAMTenantForbidden
	require.ErrorAs(t, iamTenantDecision(iamRESTTenantA, iamRESTTenantB), &forbidden)
	assert.Equal(t, iamRESTTenantB, forbidden.Requested)

	require.NoError(t, systemCallerDecision(iamRESTSystemTenant, iamRESTSystemTenant, "POST /api/v1/iam/tenants"))
	require.Error(t, systemCallerDecision(iamRESTSystemTenant, iamRESTTenantA, "POST /api/v1/iam/tenants"))
}

func TestErrIAMRESTUnavailable(t *testing.T) {
	assert.Equal(t, "IAM REST routes unavailable: no logger", ErrIAMRESTUnavailable{Reason: "no logger"}.Error())
}
