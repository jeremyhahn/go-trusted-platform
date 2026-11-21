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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
)

// generateRecordingKMS counts the GenerateKey calls that reach the key
// service.
type generateRecordingKMS struct {
	kmsclient.Client
	calls int
}

func (k *generateRecordingKMS) GenerateKey(ctx context.Context, req *kmsclient.GenerateKeyRequest) (*kmsclient.GenerateKeyResponse, error) {
	k.calls++
	return &kmsclient.GenerateKeyResponse{KeyID: req.Name}, nil
}

// TestGenerateKey_RejectsDescriptionAndTags pins that GenerateKey refuses
// the fields the pinned key service cannot carry, instead of answering
// success with data it dropped.
func TestGenerateKey_RejectsDescriptionAndTags(t *testing.T) {
	cases := map[string]string{
		"description": `{"name":"k1","algorithm":"AES_256","description":"x"}`,
		"tags":        `{"name":"k1","algorithm":"AES_256","tags":{"a":"b"}}`,
	}
	for field, body := range cases {
		t.Run(field, func(t *testing.T) {
			kms := &generateRecordingKMS{}
			logger := logging.DefaultLogger()
			h := NewHandlers(logger, kms, nil, nil, nil, response.NewResponseWriter(logger, nil))
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			h.GenerateKey(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), field) {
				t.Fatalf("400 body does not name %q: %s", field, w.Body.String())
			}
			if kms.calls != 0 {
				t.Fatalf("a request carrying %s reached the key service", field)
			}
		})
	}
}
