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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
)

// listKeysKMSClient returns a fixed, unsorted key collection from ListKeys.
type listKeysKMSClient struct {
	kmsclient.Client
	keys []kmsclient.KeyInfo
}

func (f *listKeysKMSClient) ListKeys(_ context.Context) (*kmsclient.ListKeysResponse, error) {
	return &kmsclient.ListKeysResponse{Keys: f.keys}, nil
}

// TestListKeys_PagesAndFilters: GET /api/v1/kms/keys keeps the legacy
// daemon route's semantics: limit and an offset cursor page a collection
// sorted by key ID, name and algorithm filter it, and the reply carries
// next_cursor, has_more and total_count (#2030 Codex round 2 P1).
func TestListKeys_PagesAndFilters(t *testing.T) {
	fake := &listKeysKMSClient{keys: []kmsclient.KeyInfo{
		{KeyID: "k3", Name: "k3", Algorithm: kmsclient.AlgorithmAES256GCM, Version: 1},
		{KeyID: "k1", Name: "k1", Algorithm: kmsclient.AlgorithmECDSAP256, Version: 1},
		{KeyID: "k2", Name: "k2", Algorithm: kmsclient.AlgorithmAES256GCM, Version: 1},
	}}
	h := newParityTestHandlers(fake, nil)

	list := func(target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ListKeys(w, parityRequest(t, http.MethodGet, target, "", nil))
		return w
	}
	ids := func(resp ListKeysResponse) []string {
		out := make([]string, 0, len(resp.Keys))
		for _, k := range resp.Keys {
			out = append(out, k.KeyID)
		}
		return out
	}

	w := list("/api/v1/kms/keys?limit=2")
	if w.Code != http.StatusOK {
		t.Fatalf("first page: status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var page1 ListKeysResponse
	decodeEnvelope(t, w, &page1)
	if got := ids(page1); len(got) != 2 || got[0] != "k1" || got[1] != "k2" {
		t.Fatalf("first page keys = %v, want [k1 k2]", got)
	}
	if !page1.HasMore || page1.NextCursor != "2" || page1.TotalCount != 3 {
		t.Fatalf("first page = has_more %v next_cursor %q total_count %d, want true \"2\" 3",
			page1.HasMore, page1.NextCursor, page1.TotalCount)
	}

	w = list("/api/v1/kms/keys?limit=2&cursor=2")
	if w.Code != http.StatusOK {
		t.Fatalf("second page: status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var page2 ListKeysResponse
	decodeEnvelope(t, w, &page2)
	if got := ids(page2); len(got) != 1 || got[0] != "k3" {
		t.Fatalf("second page keys = %v, want [k3]", got)
	}
	if page2.HasMore || page2.NextCursor != "" || page2.TotalCount != 3 {
		t.Fatalf("second page = has_more %v next_cursor %q total_count %d, want false \"\" 3",
			page2.HasMore, page2.NextCursor, page2.TotalCount)
	}

	w = list("/api/v1/kms/keys?name=k2")
	if w.Code != http.StatusOK {
		t.Fatalf("name filter: status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var byName ListKeysResponse
	decodeEnvelope(t, w, &byName)
	if got := ids(byName); len(got) != 1 || got[0] != "k2" || byName.TotalCount != 1 {
		t.Fatalf("name filter keys = %v total %d, want [k2] 1", got, byName.TotalCount)
	}

	// The algorithm filter is case-insensitive.
	w = list("/api/v1/kms/keys?algorithm=" + url.QueryEscape(strings.ToLower(kmsclient.AlgorithmECDSAP256.String())))
	if w.Code != http.StatusOK {
		t.Fatalf("algorithm filter: status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var byAlg ListKeysResponse
	decodeEnvelope(t, w, &byAlg)
	if got := ids(byAlg); len(got) != 1 || got[0] != "k1" {
		t.Fatalf("algorithm filter keys = %v, want [k1]", got)
	}

	for _, target := range []string{
		"/api/v1/kms/keys?owner=x",
		"/api/v1/kms/keys?cursor=bad",
		"/api/v1/kms/keys?limit=-1",
	} {
		if w := list(target); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body: %s)", target, w.Code, w.Body.String())
		}
	}
}
