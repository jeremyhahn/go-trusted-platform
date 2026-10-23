// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build integration

package kms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	resttypes "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
)

// restRequest is one request the adapter sent, as the server saw it.
type restRequest struct {
	method string
	path   string
}

// newWebserviceKMSServer serves the real webservice KMS router with no SDK
// clients wired, mounted under /api/v1 as the webservice mounts it. A
// request on a route the router serves answers 503 (service unavailable);
// any other request answers 404 or 405 from the mux. The last request seen
// is returned through the pointer.
func newWebserviceKMSServer(t *testing.T) (*RESTAdapter, *restRequest) {
	t.Helper()
	logger := logging.DefaultLogger()
	parent := mux.NewRouter()
	api := parent.PathPrefix("/api/v1").Subrouter()
	resttypes.NewKMSRouter(logger, nil, nil, nil, nil, response.NewResponseWriter(logger, nil)).RegisterRoutes(api)

	seen := &restRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.path = r.URL.Path
		parent.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	return &RESTAdapter{baseURL: srv.URL, httpClient: srv.Client()}, seen
}

// requireRouted asserts the call reached a route the webservice KMS router
// serves: the unwired handler's 503, never the mux's 404 or 405.
func requireRouted(t *testing.T, err error) {
	t.Helper()
	var apiErr ErrRESTAPIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusServiceUnavailable, apiErr.StatusCode,
		"the adapter called a route the webservice KMS router does not serve")
}

// TestRESTAdapter_WebserviceRoutes pins every REST adapter call to the
// method and path the webservice KMS router (pkg/webservice/v1/rest/kms)
// serves; under #983 the REST rows of the suite reach that router, not the
// daemon's pkg/api/rest KMS handlers.
func TestRESTAdapter_WebserviceRoutes(t *testing.T) {
	ctx := context.Background()
	a, seen := newWebserviceKMSServer(t)

	tests := []struct {
		name   string
		method string
		path   string
		call   func() error
	}{
		{"KeyGenerate", http.MethodPost, "/api/v1/kms/keys", func() error {
			_, err := a.KeyGenerate(ctx, KeyGenerateOptions{KeyID: "k", Name: "k"})
			return err
		}},
		{"KeyGet", http.MethodGet, "/api/v1/kms/keys/k", func() error {
			_, err := a.KeyGet(ctx, "k", 0)
			return err
		}},
		{"KeyList", http.MethodGet, "/api/v1/kms/keys", func() error {
			_, err := a.KeyList(ctx, KeyListOptions{})
			return err
		}},
		{"KeyDelete", http.MethodDelete, "/api/v1/kms/keys/k", func() error {
			_, err := a.KeyDelete(ctx, "k", KeyDeleteOptions{})
			return err
		}},
		{"KeyRotate", http.MethodPost, "/api/v1/kms/keys/k/rotate", func() error {
			_, err := a.KeyRotate(ctx, "k", false)
			return err
		}},
		{"KeyVersions", http.MethodGet, "/api/v1/kms/keys/k/versions", func() error {
			_, err := a.KeyVersions(ctx, "k", KeyVersionsOptions{})
			return err
		}},
		{"KeyStatus", http.MethodPut, "/api/v1/kms/keys/k/status", func() error {
			_, err := a.KeyStatus(ctx, "k", 0, true)
			return err
		}},
		{"KeyRevoke", http.MethodPost, "/api/v1/kms/keys/k/revoke", func() error {
			_, err := a.KeyRevoke(ctx, "k", "test")
			return err
		}},
		{"KeyMetadata", http.MethodGet, "/api/v1/kms/keys/k/metadata", func() error {
			_, err := a.KeyMetadata(ctx, "k")
			return err
		}},
		{"KeyMetadataUpdate", http.MethodPut, "/api/v1/kms/keys/k/metadata", func() error {
			_, err := a.KeyMetadataUpdate(ctx, "k", KeyMetadataUpdateOptions{})
			return err
		}},
		{"KeyPolicy", http.MethodGet, "/api/v1/kms/keys/k/policy", func() error {
			_, err := a.KeyPolicy(ctx, "k")
			return err
		}},
		{"KeyPolicySet", http.MethodPut, "/api/v1/kms/keys/k/policy", func() error {
			_, err := a.KeyPolicySet(ctx, "k", KeyPolicySetOptions{})
			return err
		}},
		{"KeyAlgorithms", http.MethodGet, "/api/v1/kms/algorithms", func() error {
			_, err := a.KeyAlgorithms(ctx)
			return err
		}},
		{"BackendStatus", http.MethodGet, restBackendStatusPath, func() error {
			body, status, err := a.doRequest(ctx, http.MethodGet, restBackendStatusPath, nil)
			if err != nil {
				return err
			}
			return a.parseErrorResponse(body, status)
		}},
		{"CryptoEncrypt", http.MethodPost, "/api/v1/kms/encrypt/k", func() error {
			_, err := a.CryptoEncrypt(ctx, CryptoEncryptOptions{KeyID: "k"})
			return err
		}},
		{"CryptoDecrypt", http.MethodPost, "/api/v1/kms/decrypt/k", func() error {
			_, err := a.CryptoDecrypt(ctx, CryptoDecryptOptions{KeyID: "k"})
			return err
		}},
		{"CryptoSign", http.MethodPost, "/api/v1/kms/sign/k", func() error {
			_, err := a.CryptoSign(ctx, CryptoSignOptions{KeyID: "k"})
			return err
		}},
		{"CryptoVerify", http.MethodPost, "/api/v1/kms/verify/k", func() error {
			_, err := a.CryptoVerify(ctx, CryptoVerifyOptions{KeyID: "k"})
			return err
		}},
		{"CryptoHash", http.MethodPost, "/api/v1/kms/hash", func() error {
			_, err := a.CryptoHash(ctx, []byte("data"), "SHA256")
			return err
		}},
		{"CryptoHMAC", http.MethodPost, "/api/v1/kms/hmac/k", func() error {
			_, err := a.CryptoHMAC(ctx, CryptoHMACOptions{KeyID: "k"})
			return err
		}},
		{"CryptoVerifyHMAC", http.MethodPost, "/api/v1/kms/hmac/k/verify", func() error {
			_, err := a.CryptoVerifyHMAC(ctx, CryptoVerifyHMACOptions{KeyID: "k"})
			return err
		}},
		{"CryptoRandom", http.MethodPost, "/api/v1/kms/random", func() error {
			_, err := a.CryptoRandom(ctx, 16)
			return err
		}},
		{"DEKCreate", http.MethodPost, "/api/v1/kms/deks", func() error {
			_, err := a.DEKCreate(ctx, DEKCreateOptions{Path: "app/db"})
			return err
		}},
		{"DEKGet", http.MethodGet, "/api/v1/kms/deks/app/db", func() error {
			_, err := a.DEKGet(ctx, "app/db")
			return err
		}},
		{"DEKList", http.MethodGet, "/api/v1/kms/deks", func() error {
			_, err := a.DEKList(ctx, DEKListOptions{})
			return err
		}},
		{"DEKDelete", http.MethodDelete, "/api/v1/kms/deks/app/db", func() error {
			_, err := a.DEKDelete(ctx, "app/db", DEKDeleteOptions{})
			return err
		}},
		{"DEKRotate", http.MethodPost, "/api/v1/kms/deks/app/db/rotate", func() error {
			_, err := a.DEKRotate(ctx, "app/db", false)
			return err
		}},
		{"DEKStatus", http.MethodGet, "/api/v1/kms/deks/app/db/status", func() error {
			_, err := a.DEKStatus(ctx, "app/db")
			return err
		}},
		{"SecretsStore", http.MethodPost, "/api/v1/kms/secrets", func() error {
			_, err := a.SecretsStore(ctx, SecretsStoreOptions{Name: "s"})
			return err
		}},
		{"SecretsGet", http.MethodGet, "/api/v1/kms/secrets/s", func() error {
			_, err := a.SecretsGet(ctx, "s")
			return err
		}},
		{"SecretsList", http.MethodGet, "/api/v1/kms/secrets", func() error {
			_, err := a.SecretsList(ctx, SecretsListOptions{})
			return err
		}},
		{"SecretsDelete", http.MethodDelete, "/api/v1/kms/secrets/s", func() error {
			_, err := a.SecretsDelete(ctx, "s", false)
			return err
		}},
		{"SecretsRotate", http.MethodPost, "/api/v1/kms/secrets/s/rotate", func() error {
			_, err := a.SecretsRotate(ctx, SecretsRotateOptions{Name: "s"})
			return err
		}},
		{"SecretsVersions", http.MethodGet, "/api/v1/kms/secrets/s/versions", func() error {
			_, err := a.SecretsVersions(ctx, "s", SecretsVersionsOptions{})
			return err
		}},
		{"SecretsVersion", http.MethodGet, "/api/v1/kms/secrets/s/versions/2", func() error {
			_, err := a.SecretsVersion(ctx, "s", 2)
			return err
		}},
		{"SecretsRollback", http.MethodPost, "/api/v1/kms/secrets/s/rollback", func() error {
			_, err := a.SecretsRollback(ctx, "s", 1)
			return err
		}},
		{"SecretsStatus", http.MethodPut, "/api/v1/kms/secrets/s/status", func() error {
			_, err := a.SecretsStatus(ctx, "s", true)
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*seen = restRequest{}
			requireRouted(t, tt.call())
			assert.Equal(t, tt.method, seen.method)
			assert.Equal(t, tt.path, seen.path)
		})
	}
}

// TestRESTAdapter_WebserviceRoutes_UnservedPathIsNotRouted keeps the oracle
// honest: the daemon-shaped paths the adapter used to call (key in the
// body, daemon status probe) are not webservice routes, and the same server
// answers them 404 or 405, never the 503 a served route returns.
func TestRESTAdapter_WebserviceRoutes_UnservedPathIsNotRouted(t *testing.T) {
	ctx := context.Background()
	a, _ := newWebserviceKMSServer(t)

	unserved := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/kms/encrypt"},
		{http.MethodPost, "/api/v1/kms/hmac"},
		{http.MethodGet, "/api/v1/kms/status"},
		{http.MethodPost, "/api/v1/kms/keys/k/status"},
	}
	for _, u := range unserved {
		t.Run(u.method+" "+u.path, func(t *testing.T) {
			_, status, err := a.doRequest(ctx, u.method, u.path, nil)
			require.NoError(t, err)
			assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, status)
		})
	}
}

// TestRESTAdapter_KeyIDIsPathEscaped: a key ID is one path segment, so a
// character that would split or end the path is escaped, not sent raw.
func TestRESTAdapter_KeyIDIsPathEscaped(t *testing.T) {
	ctx := context.Background()
	a, seen := newWebserviceKMSServer(t)

	_, err := a.CryptoSign(ctx, CryptoSignOptions{KeyID: "a b?c"})
	requireRouted(t, err)
	assert.Equal(t, "/api/v1/kms/sign/a b?c", seen.path)
}

// TestRESTAdapter_MissingKeyIDIsTyped: an empty key ID is refused before
// any request is sent.
func TestRESTAdapter_MissingKeyIDIsTyped(t *testing.T) {
	ctx := context.Background()
	a, seen := newWebserviceKMSServer(t)

	_, err := a.CryptoEncrypt(ctx, CryptoEncryptOptions{})
	var missing ErrRESTMissingParameter
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "key_id", missing.Parameter)
	assert.Empty(t, seen.method, "no request may be sent without a key ID")
}
