//go:build integration

package iam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRESTAdapterPayload checks that the REST adapter decodes both the
// webservice envelope ({code, success, payload}) and the daemon's bare object.
func TestRESTAdapterPayload(t *testing.T) {
	answers := map[string]string{
		"POST /api/v1/iam/tenants/t-1/users":    `{"code":201,"success":true,"payload":{"id":"u-1","tenant_id":"t-1","email":"a@example.com"}}`,
		"GET /api/v1/iam/tenants/t-1/users/u-1": `{"code":200,"success":true,"payload":{"id":"u-1","tenant_id":"t-1","email":"a@example.com"}}`,
		"GET /api/v1/iam/tenants/t-1/users/u-2": `{"id":"u-2","tenant_id":"t-1","email":"b@example.com"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer, ok := answers[r.Method+" "+r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()

	adapter := &RESTAdapter{endpoint: srv.URL, client: srv.Client()}
	ctx := context.Background()

	created, err := adapter.CreateUser(ctx, CreateUserOptions{TenantID: "t-1", Email: "a@example.com"})
	require.NoError(t, err)
	require.NotNil(t, created.User)
	require.Equal(t, "u-1", created.User.ID)

	enveloped, err := adapter.GetUser(ctx, GetUserOptions{TenantID: "t-1", UserID: "u-1"})
	require.NoError(t, err)
	require.NotNil(t, enveloped.User)
	require.Equal(t, "u-1", enveloped.User.ID)

	bare, err := adapter.GetUser(ctx, GetUserOptions{TenantID: "t-1", UserID: "u-2"})
	require.NoError(t, err)
	require.NotNil(t, bare.User)
	require.Equal(t, "u-2", bare.User.ID)
}
