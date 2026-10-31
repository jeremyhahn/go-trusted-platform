package iam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
)

func TestAuthorizedTenant_RoundTrip(t *testing.T) {
	tenantID, ok := AuthorizedTenant(WithAuthorizedTenant(context.Background(), "tenant-a"))
	assert.True(t, ok)
	assert.Equal(t, "tenant-a", tenantID)
}

func TestAuthorizedTenant_AbsentOrEmptyIsNotPublished(t *testing.T) {
	_, ok := AuthorizedTenant(context.Background())
	assert.False(t, ok, "a context without the value publishes no tenant")

	_, ok = AuthorizedTenant(WithAuthorizedTenant(context.Background(), ""))
	assert.False(t, ok, "an empty authorized tenant must not shadow the other sources")
}

func TestGetTenantID_AuthorizedTenantPrecedence(t *testing.T) {
	session := iammw.NewIAMSession(&iamsdk.User{ID: "u1", TenantID: "session-tenant"})
	tests := []struct {
		name       string
		publish    bool
		authorized string
		vars       map[string]string
		session    iammw.IAMSession
		query      string
		want       string
	}{
		{name: "authorized tenant wins over path and session", publish: true, authorized: "tenant-a", vars: map[string]string{"tenant": "path-tenant"}, session: session, want: "tenant-a"},
		{name: "authorized tenant alone serves a flat route", publish: true, authorized: "tenant-a", want: "tenant-a"},
		{name: "path variable when nothing is authorized", vars: map[string]string{"tenant": "path-tenant"}, session: session, want: "path-tenant"},
		{name: "session when nothing is authorized and no path variable", session: session, want: "session-tenant"},
		{name: "empty authorized tenant falls back to the session", publish: true, authorized: "", session: session, want: "session-tenant"},
		{name: "the tenant_id query alone is never read", query: "?tenant_id=tenant-b", want: ""},
	}
	handlers := &IAMHandlers{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/iam/users"+tt.query, nil)
			ctx := req.Context()
			if tt.session != nil {
				ctx = iammw.SetSessionInContext(ctx, tt.session)
			}
			if tt.publish {
				ctx = WithAuthorizedTenant(ctx, tt.authorized)
			}
			req = req.WithContext(ctx)
			if tt.vars != nil {
				req = mux.SetURLVars(req, tt.vars)
			}
			assert.Equal(t, tt.want, handlers.getTenantID(req))
		})
	}
}
