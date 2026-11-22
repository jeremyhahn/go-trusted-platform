// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package kms

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const listLimitEntries = 5

// fakeListDEKClient answers ListDEKs with five DEKs.
type fakeListDEKClient struct {
	dekclient.Client
}

func (f *fakeListDEKClient) ListDEKs(_ context.Context, _ *dekclient.ListDEKsRequest) (*dekclient.ListDEKsResponse, error) {
	resp := &dekclient.ListDEKsResponse{}
	for i := 0; i < listLimitEntries; i++ {
		resp.DEKs = append(resp.DEKs, dekclient.DEKInfo{Path: fmt.Sprintf("dek-%d", i), Version: 1})
	}
	resp.TotalCount = len(resp.DEKs)
	return resp, nil
}

// fakeListSecretsClient answers List with five secret paths.
type fakeListSecretsClient struct {
	secretsclient.Client
	prefix string
}

func (f *fakeListSecretsClient) List(_ context.Context, prefix string) (*secretsclient.ListSecretsResponse, error) {
	f.prefix = prefix
	resp := &secretsclient.ListSecretsResponse{}
	for i := 0; i < listLimitEntries; i++ {
		resp.Paths = append(resp.Paths, fmt.Sprintf("app/secret-%d", i))
	}
	return resp, nil
}

func newListLimitTestHandlers(dek dekclient.Client, secrets secretsclient.Client) *Handlers {
	logger := logging.DefaultLogger()
	return NewHandlers(logger, nil, nil, dek, secrets, response.NewResponseWriter(logger, nil))
}

func TestListDEKs_HonoursLimit(t *testing.T) {
	h := newListLimitTestHandlers(&fakeListDEKClient{}, nil)
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", listLimitEntries},
		{"?limit=0", listLimitEntries},
		{"?limit=2", 2},
		{"?limit=9", listLimitEntries},
	} {
		t.Run("q"+tc.query, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ListDEKs(w, parityRequest(t, http.MethodGet, "/api/v1/kms/deks"+tc.query, "", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
			}
			var out ListDEKsResponse
			decodeEnvelope(t, w, &out)
			if len(out.DEKs) != tc.want {
				t.Fatalf("got %d DEKs, want %d", len(out.DEKs), tc.want)
			}
		})
	}
}

func TestListDEKs_BadLimitIsRefused(t *testing.T) {
	h := newListLimitTestHandlers(&fakeListDEKClient{}, nil)
	for _, limit := range []string{"-1", "x"} {
		t.Run(limit, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ListDEKs(w, parityRequest(t, http.MethodGet, "/api/v1/kms/deks?limit="+limit, "", nil))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

func TestListSecrets_HonoursLimit(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", listLimitEntries},
		{"?limit=0", listLimitEntries},
		{"?limit=2", 2},
		{"?prefix=app/&limit=2", 2},
		{"?limit=9", listLimitEntries},
	} {
		t.Run("q"+tc.query, func(t *testing.T) {
			secrets := &fakeListSecretsClient{}
			h := newListLimitTestHandlers(nil, secrets)
			w := httptest.NewRecorder()
			h.ListSecrets(w, parityRequest(t, http.MethodGet, "/api/v1/kms/secrets"+tc.query, "", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
			}
			var out ListSecretsResponse
			decodeEnvelope(t, w, &out)
			if len(out.Secrets) != tc.want {
				t.Fatalf("got %d secrets, want %d", len(out.Secrets), tc.want)
			}
		})
	}
}

func TestListSecrets_KeepsPrefix(t *testing.T) {
	secrets := &fakeListSecretsClient{}
	h := newListLimitTestHandlers(nil, secrets)
	w := httptest.NewRecorder()
	h.ListSecrets(w, parityRequest(t, http.MethodGet, "/api/v1/kms/secrets?prefix=app/&limit=2", "", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if secrets.prefix != "app/" {
		t.Fatalf("prefix = %q, want app/", secrets.prefix)
	}
}

func TestListSecrets_BadLimitIsRefused(t *testing.T) {
	for _, limit := range []string{"-1", "x"} {
		t.Run(limit, func(t *testing.T) {
			secrets := &fakeListSecretsClient{}
			h := newListLimitTestHandlers(nil, secrets)
			w := httptest.NewRecorder()
			h.ListSecrets(w, parityRequest(t, http.MethodGet, "/api/v1/kms/secrets?limit="+limit, "", nil))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}
