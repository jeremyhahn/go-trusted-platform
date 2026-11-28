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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestKMSHashRoutes_UnknownHashIsBadRequest checks that the REST crypto
// routes refuse a hash name they do not know with 400 naming the hash
// field, instead of silently using SHA-256 (#2057).
func TestKMSHashRoutes_UnknownHashIsBadRequest(t *testing.T) {
	cases := []struct {
		name   string
		call   func(h *Handlers) http.HandlerFunc
		body   string
		vars   map[string]string
		called func(f *covFakes) bool
	}{
		{
			"Hash",
			func(h *Handlers) http.HandlerFunc { return h.Hash },
			`{"data":"aGVsbG8=","hash":"md5"}`,
			nil,
			func(f *covFakes) bool { return f.crypto.hash != nil },
		},
		{
			"HMAC",
			func(h *Handlers) http.HandlerFunc { return h.HMAC },
			`{"data":"aGVsbG8=","hash":"md5"}`,
			nameVars,
			func(f *covFakes) bool { return f.crypto.hmac != nil },
		},
		{
			"VerifyHMAC",
			func(h *Handlers) http.HandlerFunc { return h.VerifyHMAC },
			`{"data":"aGVsbG8=","hmac":"bQ==","hash":"md5"}`,
			nameVars,
			func(f *covFakes) bool { return f.crypto.verifyMAC != nil },
		},
		{
			"Verify",
			func(h *Handlers) http.HandlerFunc { return h.Verify },
			`{"data":"aGVsbG8=","signature":"cw==","hash":"md5"}`,
			nameVars,
			func(f *covFakes) bool { return f.crypto.verify != nil },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCovFakes(nil)
			w := covServe(tc.call(f.handlers()), covRequest(http.MethodPost, "/", tc.body, tc.vars))
			covStatus(t, w, http.StatusBadRequest)
			if !strings.Contains(w.Body.String(), "hash") {
				t.Fatalf("body %s does not name the hash field", w.Body.String())
			}
			if tc.called(f) {
				t.Fatal("SDK was called with an unknown hash name")
			}
		})
	}

	t.Run("Sign", func(t *testing.T) {
		fake := &fakeCryptoClient{}
		h := newSignTestHandlers(fake)
		w := httptest.NewRecorder()
		h.Sign(w, signRequest(t, &SignRequest{Data: []byte("m"), Hash: "md5"}))
		covStatus(t, w, http.StatusBadRequest)
		if !strings.Contains(w.Body.String(), "hash") {
			t.Fatalf("body %s does not name the hash field", w.Body.String())
		}
		if fake.signReq != nil {
			t.Fatal("SDK was called with an unknown hash name")
		}
	})
}
