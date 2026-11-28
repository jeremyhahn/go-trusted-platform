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
	"strings"
	"testing"
)

// TestBatchRoutes_RefuseAnItemContext: the pinned crypto service drops a
// batch item's context, so a caller would believe the ciphertext is bound
// to AAD it is not bound to. Both batch routes refuse it before the call.
func TestBatchRoutes_RefuseAnItemContext(t *testing.T) {
	cases := []struct{ path, body string }{
		{"/api/v1/kms/batch-encrypt", `{"key_id":"kek","items":[{"item_id":"a","plaintext":"b25l","context":"YWFk"}]}`},
		{"/api/v1/kms/batch-decrypt", `{"key_id":"kek","items":[{"item_id":"a","ciphertext":"Y3Q=","context":"YWFk"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			fake := &batchCrypto{}
			w := postBatch(batchRouter(fake), tc.path, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "items[0].context") {
				t.Errorf("body %s does not name items[0].context", w.Body.String())
			}
			if fake.encReq != nil || fake.decReq != nil {
				t.Error("the crypto service saw a request")
			}
		})
	}
}

// TestBatchEncryptRoute_PublishesNoPlaceholderKeyVersion: the pinned crypto
// service does not report the batch key version truthfully, so the reply
// carries none.
func TestBatchEncryptRoute_PublishesNoPlaceholderKeyVersion(t *testing.T) {
	fake := &batchCrypto{}
	w := postBatch(batchRouter(fake), "/api/v1/kms/batch-encrypt",
		`{"key_id":"kek","items":[{"item_id":"a","plaintext":"b25l"},{"item_id":"b","plaintext":"dHdv"}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"key_version"`) {
		t.Errorf("reply publishes a key version: %s", w.Body.String())
	}
}

// TestRewrapRoute_PublishesNoPlaceholderVersions: the pinned crypto service
// does not report the rewrap versions truthfully, so the reply carries none.
func TestRewrapRoute_PublishesNoPlaceholderVersions(t *testing.T) {
	fake := &rewrapCrypto{}
	rec := postRewrap(t, fake, `{"source_key_id":"kek","ciphertext":"`+b64("old")+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	for _, field := range []string{`"source_key_version"`, `"dest_key_version"`} {
		if strings.Contains(rec.Body.String(), field) {
			t.Errorf("reply publishes %s: %s", field, rec.Body.String())
		}
	}
}
