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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// TestRESTAdapterKeyGenerateDaemonResponse checks that KeyGenerate decodes
// the body the mounted REST handler writes (a bare KMSGenerateKeyResponse
// with nested key and metadata) instead of reporting an empty key.
func TestRESTAdapterKeyGenerateDaemonResponse(t *testing.T) {
	serve := func(t *testing.T, status int, body []byte) *RESTAdapter {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodPost || req.URL.Path != "/api/v1/kms/keys" {
				http.NotFound(w, req)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}))
		t.Cleanup(srv.Close)
		return &RESTAdapter{baseURL: srv.URL, httpClient: srv.Client()}
	}
	opts := KeyGenerateOptions{KeyID: "gen-key-1", Algorithm: "AES-256-GCM", Purpose: "encrypt"}

	t.Run("nested key and metadata", func(t *testing.T) {
		body, err := json.Marshal(restapi.KMSGenerateKeyResponse{
			Key: &restapi.KMSKeyHandleResponse{KeyID: "gen-key-1", Version: 3, Algorithm: 1, Status: 1, CreatedAt: 1700000000},
			Metadata: &restapi.KMSKeyMetadataResponse{
				KeyID: "gen-key-1", Name: "gen-key-1", Description: "d", Version: 3,
				Exportable: true, DeletionProtection: true,
			},
			Timestamp: 1700000000,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r := serve(t, http.StatusCreated, body)
		res, err := r.KeyGenerate(context.Background(), opts)
		if err != nil {
			t.Fatalf("KeyGenerate: %v", err)
		}
		if res.KeyID != "gen-key-1" || res.Version != 3 {
			t.Fatalf("result key_id=%q version=%d, want gen-key-1/3", res.KeyID, res.Version)
		}
		if !res.Exportable || !res.DeletionProtection {
			t.Fatalf("result exportable=%v deletion_protection=%v, want true/true", res.Exportable, res.DeletionProtection)
		}
		if res.Algorithm != "AES-256-GCM" {
			t.Fatalf("result algorithm=%q, want AES-256-GCM", res.Algorithm)
		}
	})

	t.Run("empty body is an error", func(t *testing.T) {
		r := serve(t, http.StatusOK, []byte(`{}`))
		if res, err := r.KeyGenerate(context.Background(), opts); err == nil {
			t.Fatalf("KeyGenerate on {} = %+v, want error", res)
		}
	})
}

// TestRESTAdapterGenerateKeyBodyKeySpec checks that the body the REST
// adapter sends for key generation carries key_spec.algorithm, the field
// the daemon's handler requires (docs/kms/api.md).
func TestRESTAdapterGenerateKeyBodyKeySpec(t *testing.T) {
	r := &RESTAdapter{}
	for _, alg := range []string{"AES-128-GCM", "AES-256-GCM", "RSA-2048", "ECDSA-P256"} {
		t.Run(alg, func(t *testing.T) {
			req := &service.GenerateKeyRequest{
				Name:          "keyspec-" + alg,
				KeyAttributes: r.algorithmStringToKeyAttributes(alg),
				Usage:         r.purposeToKeyUsage("encrypt"),
			}
			body, err := json.Marshal(r.convertToGenerateKeyRequest(req))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var wire struct {
				KeySpec *struct {
					Algorithm string `json:"algorithm"`
				} `json:"key_spec"`
			}
			if err := json.Unmarshal(body, &wire); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if wire.KeySpec == nil {
				t.Fatalf("body has no key_spec object: %s", body)
			}
			if wire.KeySpec.Algorithm != alg {
				t.Fatalf("key_spec.algorithm = %q, want %q: %s", wire.KeySpec.Algorithm, alg, body)
			}
		})
	}
}
