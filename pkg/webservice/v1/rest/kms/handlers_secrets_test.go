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

package kms

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
)

// pathSecretsClient holds one secret under its path and answers Get only
// for that exact path, so a handler that mangles the name gets not found.
type pathSecretsClient struct {
	secretsclient.Client

	secret *secretsclient.Secret
}

func (f *pathSecretsClient) Get(_ context.Context, path string, _ ...secretsclient.GetOption) (*secretsclient.Secret, error) {
	if path != f.secret.Path {
		return nil, errors.New("secrets.Get: secret not found")
	}
	return f.secret, nil
}

// A secret path with slashes travels escaped (%2F) in the {name} segment and
// reaches the SDK as the path the caller stored. Before the subrouter matched
// on the encoded path, the decoded slash split the segment and the route 404'd.
func TestSecrets_GetEscapedSlashPathReachesTheSecret(t *testing.T) {
	stored := []byte("nested-secret")
	fake := &pathSecretsClient{secret: &secretsclient.Secret{
		Path:    "db/primary/password",
		Version: 1,
		Data:    map[string]interface{}{"value": base64.StdEncoding.EncodeToString(stored)},
	}}
	parent := mux.NewRouter()
	(&KMSRouter{handlers: newParityTestHandlers(nil, fake)}).RegisterRoutes(parent)

	w := httptest.NewRecorder()
	parent.ServeHTTP(w, httptest.NewRequest(http.MethodGet, basePath+"/secrets/"+url.PathEscape("db/primary/password"), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var got SecretResponse
	decodeEnvelope(t, w, &got)
	if got.Path != "db/primary/password" || string(got.Value) != string(stored) {
		t.Fatalf("got path %q value %q, want db/primary/password %q", got.Path, got.Value, stored)
	}
}

// pathVar unescapes the route variable, and passes a malformed escape on as
// sent rather than guessing at another name.
func TestPathVar(t *testing.T) {
	cases := map[string]string{
		"db%2Fprimary%2Fpassword": "db/primary/password",
		"app-db":                  "app-db",
		"db%zz":                   "db%zz",
	}
	for raw, want := range cases {
		r := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"name": raw})
		if got := pathVar(r, "name"); got != want {
			t.Errorf("pathVar(%q) = %q, want %q", raw, got, want)
		}
	}
}
