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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"

	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
)

// jsonSecretStore is a secrets client whose Store and Get JSON-encode the
// data map, as the go-quicbaas encrypted secrets backend does: a value
// stored as bytes reads back as its base64 text. Verbs the secrets routes
// under test do not call are left to the embedded nil Client.
type jsonSecretStore struct {
	secretsclient.Client
	stored map[string][]byte
	paths  []string
}

func newJSONSecretStore(paths ...string) *jsonSecretStore {
	return &jsonSecretStore{stored: make(map[string][]byte), paths: paths}
}

func (s *jsonSecretStore) Store(_ context.Context, req *secretsclient.StoreSecretRequest) (*secretsclient.StoreSecretResponse, error) {
	encoded, err := json.Marshal(req.Data)
	if err != nil {
		return nil, err
	}
	s.stored[req.Path] = encoded
	return &secretsclient.StoreSecretResponse{Version: 1}, nil
}

func (s *jsonSecretStore) Get(_ context.Context, path string, _ ...secretsclient.GetOption) (*secretsclient.Secret, error) {
	encoded, ok := s.stored[path]
	if !ok {
		return nil, &ErrInvalidRequest{Field: "path", Reason: "not found"}
	}
	var data map[string]interface{}
	if err := json.Unmarshal(encoded, &data); err != nil {
		return nil, err
	}
	return &secretsclient.Secret{Path: path, Data: data, Version: 1}, nil
}

func (s *jsonSecretStore) List(_ context.Context, _ string) (*secretsclient.ListSecretsResponse, error) {
	return &secretsclient.ListSecretsResponse{Paths: s.paths}, nil
}

// secretsServer routes the KMS REST surface over the given secrets client.
func secretsServer(secrets secretsclient.Client) *mux.Router {
	logger := logging.DefaultLogger()
	root := mux.NewRouter()
	NewKMSRouter(logger, nil, nil, nil, secrets, response.NewResponseWriter(logger, nil)).RegisterRoutes(root)
	return root
}

func serve(t *testing.T, router *mux.Router, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(method, target, strings.NewReader(body)))
	return w
}

// TestSecrets_GetReturnsTheStoredBytes stores a value over REST and reads
// it back: the response carries the caller's bytes, not the base64 text
// the backend keeps (docs/kms/api.md §4).
func TestSecrets_GetReturnsTheStoredBytes(t *testing.T) {
	router := secretsServer(newJSONSecretStore())
	stored := []byte("secret-data-for-get\x00\xff")

	body, err := json.Marshal(StoreSecretRequest{Path: "app-db", Value: stored})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if w := serve(t, router, http.MethodPost, "/kms/secrets", string(body)); w.Code != http.StatusCreated {
		t.Fatalf("store status = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}

	w := serve(t, router, http.MethodGet, "/kms/secrets/app-db", "")
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var got SecretResponse
	decodeEnvelope(t, w, &got)
	if !bytes.Equal(got.Value, stored) {
		t.Fatalf("value = %q, want %q", got.Value, stored)
	}
}

// TestSecrets_GetPlainFormValueRoundTrips covers the WebUI form, which
// posts a plain string: it reads back as the same string.
func TestSecrets_GetPlainFormValueRoundTrips(t *testing.T) {
	router := secretsServer(newJSONSecretStore())
	if w := serve(t, router, http.MethodPost, "/kms/secrets", `{"name":"form","value":"s3cr3t!"}`); w.Code != http.StatusCreated {
		t.Fatalf("store status = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}
	w := serve(t, router, http.MethodGet, "/kms/secrets/form", "")
	var got SecretResponse
	decodeEnvelope(t, w, &got)
	if string(got.Value) != "s3cr3t!" {
		t.Fatalf("value = %q, want %q", got.Value, "s3cr3t!")
	}
}

// TestSecrets_GetRefusesAValueThatIsNotBase64 proves a stored value the
// platform did not write is reported, not handed back as if it were the
// caller's bytes.
func TestSecrets_GetRefusesAValueThatIsNotBase64(t *testing.T) {
	store := newJSONSecretStore()
	store.stored["foreign"] = []byte(`{"value":"not base64!"}`)
	w := serve(t, secretsServer(store), http.MethodGet, "/kms/secrets/foreign", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not base64") {
		t.Fatalf("body = %s, want the malformed-value error", w.Body.String())
	}
}

func listPaths(t *testing.T, router *mux.Router, query string) ListSecretsResponse {
	t.Helper()
	w := serve(t, router, http.MethodGet, "/kms/secrets"+query, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list%s status = %d, want 200 (body: %s)", query, w.Code, w.Body.String())
	}
	var got ListSecretsResponse
	decodeEnvelope(t, w, &got)
	return got
}

func summaryPaths(list ListSecretsResponse) []string {
	paths := make([]string, 0, len(list.Secrets))
	for _, s := range list.Secrets {
		paths = append(paths, s.Path)
	}
	return paths
}

// TestSecrets_ListHonoursLimitAndCursor pages through the store: each
// page holds at most limit paths and next_cursor resumes after the last.
func TestSecrets_ListHonoursLimitAndCursor(t *testing.T) {
	router := secretsServer(newJSONSecretStore("c", "a", "e", "b", "d"))

	all := listPaths(t, router, "")
	if got := strings.Join(summaryPaths(all), ","); got != "a,b,c,d,e" || all.NextCursor != "" {
		t.Fatalf("unpaged list = %q cursor %q, want a,b,c,d,e and no cursor", got, all.NextCursor)
	}

	var pages []string
	cursor := ""
	for i := 0; i < 5; i++ {
		query := "?limit=2"
		if cursor != "" {
			query += "&cursor=" + cursor
		}
		page := listPaths(t, router, query)
		if len(page.Secrets) > 2 {
			t.Fatalf("page %d holds %d paths, want at most 2", i, len(page.Secrets))
		}
		pages = append(pages, strings.Join(summaryPaths(page), ","))
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if got := strings.Join(pages, "|"); got != "a,b|c,d|e" {
		t.Fatalf("pages = %q, want a,b|c,d|e", got)
	}
}

// TestSecrets_ListRefusesABadLimit rejects a limit that is not a positive
// integer with 400 rather than ignoring it.
func TestSecrets_ListRefusesABadLimit(t *testing.T) {
	router := secretsServer(newJSONSecretStore("a"))
	for _, limit := range []string{"0", "-1", "two"} {
		w := serve(t, router, http.MethodGet, "/kms/secrets?limit="+limit, "")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("limit=%s status = %d, want 400 (body: %s)", limit, w.Code, w.Body.String())
		}
	}
}
