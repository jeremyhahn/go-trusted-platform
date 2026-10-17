// Copyright (c) 2026 Automate The Things, LLC
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

package daemon

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

const (
	iamSystemTenant = "tenant-system"
	iamOtherTenant  = "tenant-other"
)

// errFakeUserNotFound is what fakeIAMClient answers for an unknown user; the
// IAM handlers map "not found" to 404.
type errFakeUserNotFound struct{ id string }

func (e errFakeUserNotFound) Error() string { return "user " + e.id + " not found" }

// fakeIAMClient serves the user calls the tests drive and records the tenant
// each was made in. The embedded interface is nil: a route the tests do not
// drive panics rather than answering a made-up result.
type fakeIAMClient struct {
	restiam.IAMClient
	users        map[string]*iamsdk.User
	createdIn    string
	createdUser  *iamsdk.CreateUserRequest
	lookedUpIn   string
	createCalled bool
}

func (f *fakeIAMClient) CreateUser(_ context.Context, tenantID string, req *iamsdk.CreateUserRequest) (*iamsdk.User, error) {
	f.createCalled = true
	f.createdIn = tenantID
	f.createdUser = req
	return &iamsdk.User{ID: "u-1", TenantID: tenantID, Email: req.Email}, nil
}

func (f *fakeIAMClient) GetUser(_ context.Context, tenantID, userID string) (*iamsdk.User, error) {
	f.lookedUpIn = tenantID
	if user, ok := f.users[userID]; ok {
		return user, nil
	}
	return nil, errFakeUserNotFound{id: userID}
}

// iamRESTCallers are the bearer tokens the IAM route tests present.
func iamRESTCallers() parityTokens {
	return parityTokens{
		"system-admin":  {Subject: "system-admin", TenantID: iamSystemTenant, Scopes: []string{"*:*"}},
		"system-reader": {Subject: "system-reader", TenantID: iamSystemTenant, Scopes: []string{"iam:read"}},
		"other-admin":   {Subject: "other-admin", TenantID: iamOtherTenant, Scopes: []string{"*:*"}},
	}
}

// iamRESTRouter builds the daemon REST router with the IAM routes mounted
// over client, behind a guard that knows iamRESTCallers.
func iamRESTRouter(t *testing.T, client restiam.IAMClient, guard *restapi.ScopeGuard) *RESTServer {
	t.Helper()
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := NewRESTServer(cfg, svc, quiet)
	require.NoError(t, err)
	require.NoError(t, s.SetIAMHandlers(client, nil, guard, iamSystemTenant))
	return s
}

func iamRESTGuard() *restapi.ScopeGuard {
	return restapi.NewScopeGuard(iamRESTCallers(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func callIAMREST(t *testing.T, s *RESTServer, method, path, caller, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if caller != "" {
		req.Header.Set("Authorization", "Bearer "+caller)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

// concreteIAMPath fills a route template: {tenant} with tenantID, every other
// variable with a placeholder value.
func concreteIAMPath(template, tenantID string) string {
	path := strings.ReplaceAll(template, "{tenant}", tenantID)
	for strings.Contains(path, "{") {
		start := strings.Index(path, "{")
		end := strings.Index(path[start:], "}")
		path = path[:start] + "x" + path[start+end+1:]
	}
	return path
}

// iamRoutes returns the IAM route templates the daemon mounted.
func iamRoutes(t *testing.T, s *RESTServer) []string {
	t.Helper()
	var routes []string
	for _, route := range testutil.WalkRoutes(t, s.Router()) {
		_, path, _ := strings.Cut(route, " ")
		if strings.HasPrefix(path, "/api/v1/iam/") {
			routes = append(routes, route)
		}
	}
	require.NotEmpty(t, routes, "the daemon mounted no IAM routes")
	return routes
}

func TestDaemonRESTIAM_CreateUserInTheNamedTenant(t *testing.T) {
	client := &fakeIAMClient{}
	s := iamRESTRouter(t, client, iamRESTGuard())

	rec := callIAMREST(t, s, http.MethodPost, "/api/v1/iam/tenants/"+iamSystemTenant+"/users",
		"system-admin", `{"email":"alice@example.com"}`)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, iamSystemTenant, client.createdIn)
	require.NotNil(t, client.createdUser)
	assert.Equal(t, "alice", client.createdUser.Username, "the username derives from the email")
	assert.Contains(t, rec.Body.String(), "alice@example.com")
}

func TestDaemonRESTIAM_GetUser(t *testing.T) {
	client := &fakeIAMClient{users: map[string]*iamsdk.User{
		"u-7": {ID: "u-7", TenantID: iamOtherTenant, Email: "bob@example.com"},
	}}
	s := iamRESTRouter(t, client, iamRESTGuard())

	t.Run("own tenant", func(t *testing.T) {
		rec := callIAMREST(t, s, http.MethodGet, "/api/v1/iam/tenants/"+iamOtherTenant+"/users/u-7", "other-admin", "")
		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		assert.Equal(t, iamOtherTenant, client.lookedUpIn)
		assert.Contains(t, rec.Body.String(), "bob@example.com")
	})
	t.Run("not found", func(t *testing.T) {
		rec := callIAMREST(t, s, http.MethodGet, "/api/v1/iam/tenants/"+iamOtherTenant+"/users/u-missing", "other-admin", "")
		assert.Equal(t, http.StatusNotFound, rec.Code, "body: %s", rec.Body.String())
	})
}

func TestDaemonRESTIAM_InvalidBodyIsRefusedBeforeTheClient(t *testing.T) {
	client := &fakeIAMClient{}
	s := iamRESTRouter(t, client, iamRESTGuard())

	rec := callIAMREST(t, s, http.MethodPost, "/api/v1/iam/tenants/"+iamSystemTenant+"/users", "system-admin", `{"email":`)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
	assert.False(t, client.createCalled)
}

func TestDaemonRESTIAM_EveryRouteRefusesAnUnauthenticatedCaller(t *testing.T) {
	s := iamRESTRouter(t, &fakeIAMClient{}, iamRESTGuard())

	for _, route := range iamRoutes(t, s) {
		method, template, _ := strings.Cut(route, " ")
		rec := callIAMREST(t, s, method, concreteIAMPath(template, iamSystemTenant), "", "")
		assert.Equalf(t, http.StatusUnauthorized, rec.Code, "%s: body %s", route, rec.Body.String())
	}
}

// A caller bound to another tenant reaches no system tenant route and no
// tenant-record route, whatever its scopes (docs/iam/api.md §8).
func TestDaemonRESTIAM_EveryRouteRefusesAnotherTenantsCaller(t *testing.T) {
	client := &fakeIAMClient{}
	s := iamRESTRouter(t, client, iamRESTGuard())

	for _, route := range iamRoutes(t, s) {
		method, template, _ := strings.Cut(route, " ")
		rec := callIAMREST(t, s, method, concreteIAMPath(template, iamSystemTenant), "other-admin", "")
		assert.Equalf(t, http.StatusForbidden, rec.Code, "%s: body %s", route, rec.Body.String())
	}
	assert.False(t, client.createCalled)
	assert.Empty(t, client.lookedUpIn)
}

func TestDaemonRESTIAM_WriteNeedsTheWriteScope(t *testing.T) {
	client := &fakeIAMClient{users: map[string]*iamsdk.User{"u-1": {ID: "u-1", TenantID: iamSystemTenant}}}
	s := iamRESTRouter(t, client, iamRESTGuard())

	rec := callIAMREST(t, s, http.MethodPost, "/api/v1/iam/tenants/"+iamSystemTenant+"/users",
		"system-reader", `{"email":"alice@example.com"}`)
	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	assert.False(t, client.createCalled)

	rec = callIAMREST(t, s, http.MethodGet, "/api/v1/iam/tenants/"+iamSystemTenant+"/users/u-1", "system-reader", "")
	assert.Equal(t, http.StatusOK, rec.Code, "iam:read reads: body %s", rec.Body.String())
}

func TestDaemonRESTIAM_TheTenantRecordRoutesAreTheSystemTenants(t *testing.T) {
	s := iamRESTRouter(t, &fakeIAMClient{}, iamRESTGuard())

	rec := callIAMREST(t, s, http.MethodPost, "/api/v1/iam/tenants", "other-admin", `{"name":"t"}`)

	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
}

// The webservice's flat aliases fall back to a browser session's tenant; the
// daemon holds none, so it does not mount them.
func TestDaemonRESTIAM_FlatAliasesAreNotMounted(t *testing.T) {
	s := iamRESTRouter(t, &fakeIAMClient{}, iamRESTGuard())

	for _, route := range iamRoutes(t, s) {
		_, template, _ := strings.Cut(route, " ")
		assert.Truef(t, strings.HasPrefix(template, "/api/v1/iam/tenants"), "%s is not tenant-scoped", route)
	}
	rec := callIAMREST(t, s, http.MethodPost, "/api/v1/iam/users", "system-admin", `{"email":"alice@example.com"}`)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDaemonRESTIAM_NilGuardRefusesEveryCaller(t *testing.T) {
	client := &fakeIAMClient{}
	s := iamRESTRouter(t, client, nil)

	rec := callIAMREST(t, s, http.MethodPost, "/api/v1/iam/tenants/"+iamSystemTenant+"/users",
		"system-admin", `{"email":"alice@example.com"}`)

	assert.Equal(t, http.StatusForbidden, rec.Code, "body: %s", rec.Body.String())
	assert.False(t, client.createCalled)
}

func TestDaemonRESTIAM_NilClientMountsNothing(t *testing.T) {
	s := iamRESTRouter(t, nil, iamRESTGuard())

	rec := callIAMREST(t, s, http.MethodGet, "/api/v1/iam/tenants/"+iamSystemTenant+"/users/u-1", "system-admin", "")

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

var _ restiam.IAMClient = (*fakeIAMClient)(nil)
