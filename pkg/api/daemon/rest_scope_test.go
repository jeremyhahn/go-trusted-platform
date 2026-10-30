package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

func TestRESTScopeAction_MapsEveryMethod(t *testing.T) {
	cases := []struct {
		method string
		want   string
	}{
		{http.MethodGet, "read"},
		{http.MethodPost, "write"},
		{http.MethodPut, "write"},
		{http.MethodPatch, "write"},
		{http.MethodDelete, "delete"},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			got, err := restScopeAction("kms", nil, tc.method, "/api/v1/kms/keys")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRESTScopeAction_RefusesAnUnservedMethod(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodConnect, "BREW"} {
		t.Run(method, func(t *testing.T) {
			got, err := restScopeAction("secrets", nil, method, "/api/v1/kms/secrets")
			var forbidden restapi.ErrRouteForbidden
			require.ErrorAs(t, err, &forbidden)
			assert.Equal(t, "secrets:*", forbidden.Scope)
			assert.Contains(t, forbidden.Reason, method)
			assert.Empty(t, got)
		})
	}
}

// Each resource's read-only POSTs are reads; any other POST, and any other
// method on a read-only path, keeps its own action.
func TestRESTScopeAction_ReadOnlyPosts(t *testing.T) {
	cases := []struct {
		name          string
		resource      string
		readOnlyPosts []string
		method        string
		route         string
		want          string
	}{
		{"iam validate", iamScopeResource, iamReadOnlyPosts, http.MethodPost, "/api/v1/iam/tenants/{tenant}/policies/validate", "read"},
		{"iam test", iamScopeResource, iamReadOnlyPosts, http.MethodPost, "/api/v1/iam/policies/test", "read"},
		{"iam check", iamScopeResource, iamReadOnlyPosts, http.MethodPost, "/api/v1/iam/permissions/check", "read"},
		{"iam create", iamScopeResource, iamReadOnlyPosts, http.MethodPost, "/api/v1/iam/tenants/{tenant}/policies", "write"},
		{"kms decrypt", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/decrypt/{name}", "read"},
		{"kms verify", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/verify/{name}", "read"},
		{"kms hmac verify", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/hmac/{name}/verify", "read"},
		{"kms hash", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/hash", "read"},
		{"kms random", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/random", "read"},
		{"kms hmac", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/hmac/{name}", "write"},
		{"kms encrypt", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/encrypt/{name}", "write"},
		{"kms read-only path by PUT", kmsScopeResource, kmsReadOnlyPosts, http.MethodPut, "/api/v1/kms/hash", "write"},
		{"iam path under kms rules", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/iam/permissions/check", "write"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := restScopeAction(tc.resource, tc.readOnlyPosts, tc.method, tc.route)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRESTRouteTemplate(t *testing.T) {
	t.Run("the matched route's template", func(t *testing.T) {
		router := mux.NewRouter()
		var got string
		router.HandleFunc("/api/v1/kms/keys/{name}", func(_ http.ResponseWriter, r *http.Request) {
			got = restRouteTemplate(r)
		})
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/k1", nil))
		assert.Equal(t, "/api/v1/kms/keys/{name}", got)
	})
	t.Run("the request path without a matched route", func(t *testing.T) {
		got := restRouteTemplate(httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/k1", nil))
		assert.Equal(t, "/api/v1/kms/keys/k1", got)
	})
}
