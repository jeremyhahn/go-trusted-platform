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
	"errors"
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
	calls   int
	meta    *kmsclient.UpdateKeyMetadataRequest
	metaErr error
}

func (k *generateRecordingKMS) GenerateKey(ctx context.Context, req *kmsclient.GenerateKeyRequest) (*kmsclient.GenerateKeyResponse, error) {
	k.calls++
	return &kmsclient.GenerateKeyResponse{KeyID: req.Name}, nil
}

func (k *generateRecordingKMS) UpdateKeyMetadata(ctx context.Context, req *kmsclient.UpdateKeyMetadataRequest) (*kmsclient.KeyMetadataResponse, error) {
	k.meta = req
	if k.metaErr != nil {
		return nil, k.metaErr
	}
	return &kmsclient.KeyMetadataResponse{}, nil
}

// TestGenerateKey_RejectsDescriptionAndTags pins that GenerateKey refuses
// the fields the pinned key service cannot carry, instead of answering
// success with data it dropped.
func TestGenerateKey_PersistsDescriptionAndTags(t *testing.T) {
	post := func(kms *generateRecordingKMS, body string) *httptest.ResponseRecorder {
		logger := logging.DefaultLogger()
		h := NewHandlers(logger, kms, nil, nil, nil, response.NewResponseWriter(logger, nil))
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		h.GenerateKey(w, r)
		return w
	}

	t.Run("description and tags reach UpdateKeyMetadata", func(t *testing.T) {
		kms := &generateRecordingKMS{}
		w := post(kms, `{"name":"k1","algorithm":"AES_256","description":"x","tags":{"a":"b"}}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		if kms.calls != 1 {
			t.Fatalf("GenerateKey calls = %d, want 1", kms.calls)
		}
		if kms.meta == nil {
			t.Fatal("description and tags never reached UpdateKeyMetadata")
		}
		if kms.meta.KeyID != "k1" || kms.meta.Description != "x" || kms.meta.Tags["a"] != "b" {
			t.Fatalf("UpdateKeyMetadata = %+v, want key k1, description x, tag a=b", kms.meta)
		}
	})

	t.Run("no metadata means no update", func(t *testing.T) {
		kms := &generateRecordingKMS{}
		w := post(kms, `{"name":"k1","algorithm":"AES_256"}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body: %s)", w.Code, w.Body.String())
		}
		if kms.meta != nil {
			t.Fatalf("UpdateKeyMetadata called without metadata: %+v", kms.meta)
		}
	})

	t.Run("a failed metadata update fails the request", func(t *testing.T) {
		kms := &generateRecordingKMS{metaErr: errors.New("metadata store down")}
		w := post(kms, `{"name":"k1","algorithm":"AES_256","description":"x"}`)
		if w.Code < 400 {
			t.Fatalf("status = %d, want an error (body: %s)", w.Code, w.Body.String())
		}
	})
}
