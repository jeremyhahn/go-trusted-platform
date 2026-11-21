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
	resttypes "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
)

// generateKeyEnvelope is the body the webservice KMS handler writes for
// POST /api/v1/kms/keys: the response envelope around a GenerateKeyResponse.
func generateKeyEnvelope(t *testing.T, payload any) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	body, err := json.Marshal(restEnvelope{Code: http.StatusCreated, Success: true, Payload: raw})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return body
}

// TestRESTAdapterKeyGenerateDaemonResponse checks that KeyGenerate decodes
// the body the mounted webservice KMS handler writes (the envelope around a
// GenerateKeyResponse with a string algorithm) instead of reporting an empty
// key, and that the algorithm is the server's, never the request echo.
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
	withAlgorithm := func(t *testing.T, alg string) []byte {
		t.Helper()
		return generateKeyEnvelope(t, resttypes.GenerateKeyResponse{KeyID: "gen-key-1", Version: 1, Algorithm: alg})
	}

	t.Run("envelope payload", func(t *testing.T) {
		body := generateKeyEnvelope(t, resttypes.GenerateKeyResponse{
			KeyID: "gen-key-1", Version: 3, Algorithm: "RSA-2048",
			Exportable: true, DeletionProtection: true,
		})
		res, err := serve(t, http.StatusCreated, body).KeyGenerate(context.Background(), opts)
		if err != nil {
			t.Fatalf("KeyGenerate: %v", err)
		}
		if res.KeyID != "gen-key-1" || res.Version != 3 {
			t.Fatalf("result key_id=%q version=%d, want gen-key-1/3", res.KeyID, res.Version)
		}
		if !res.Exportable || !res.DeletionProtection {
			t.Fatalf("result exportable=%v deletion_protection=%v, want true/true", res.Exportable, res.DeletionProtection)
		}
		// The request asked for AES-256-GCM; the result reports what the
		// server generated.
		if res.Algorithm != "RSA-2048" {
			t.Fatalf("result algorithm=%q, want RSA-2048 (the server's key type)", res.Algorithm)
		}
	})

	t.Run("matching algorithm", func(t *testing.T) {
		res, err := serve(t, http.StatusCreated, withAlgorithm(t, "AES-256-GCM")).KeyGenerate(context.Background(), opts)
		if err != nil {
			t.Fatalf("KeyGenerate: %v", err)
		}
		if res.Algorithm != "AES-256-GCM" {
			t.Fatalf("result algorithm=%q, want AES-256-GCM", res.Algorithm)
		}
	})

	t.Run("mismatched algorithm is reported, not masked", func(t *testing.T) {
		res, err := serve(t, http.StatusCreated, withAlgorithm(t, "RSA-2048")).KeyGenerate(context.Background(), opts)
		if err != nil {
			t.Fatalf("KeyGenerate: %v", err)
		}
		if res.Algorithm != "RSA-2048" {
			t.Fatalf("result algorithm=%q for an RSA-2048 response, want RSA-2048", res.Algorithm)
		}
	})

	errorCases := []struct {
		name   string
		status int
		body   func(t *testing.T) []byte
	}{
		{"empty algorithm is an error", http.StatusCreated, func(t *testing.T) []byte { return withAlgorithm(t, "") }},
		{"UNKNOWN algorithm is an error", http.StatusCreated, func(t *testing.T) []byte { return withAlgorithm(t, "UNKNOWN") }},
		{"payload without key_id is an error", http.StatusCreated, func(t *testing.T) []byte {
			return generateKeyEnvelope(t, resttypes.GenerateKeyResponse{Version: 1, Algorithm: "AES-256-GCM"})
		}},
		{"legacy bare KMSGenerateKeyResponse is an error", http.StatusCreated, func(t *testing.T) []byte {
			body, err := json.Marshal(restapi.KMSGenerateKeyResponse{
				Key: &restapi.KMSKeyHandleResponse{KeyID: "gen-key-1", Version: 1, Algorithm: 22, Status: 1},
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			return body
		}},
		{"empty body is an error", http.StatusOK, func(*testing.T) []byte { return []byte(`{}`) }},
	}
	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			if res, err := serve(t, tc.status, tc.body(t)).KeyGenerate(context.Background(), opts); err == nil {
				t.Fatalf("KeyGenerate = %+v, want error", res)
			}
		})
	}
}

// TestRESTAdapterKeyGenerateWithDisplay pins the follow-up a KeyGenerate
// with Name or Description makes: PUT /api/v1/kms/keys/{id}/metadata
// carrying both, whose reply sets the result's Name (#646 Codex r2).
func TestRESTAdapterKeyGenerateWithDisplay(t *testing.T) {
	genBody := generateKeyEnvelope(t, resttypes.GenerateKeyResponse{KeyID: "gen-key-1", Version: 1, Algorithm: "AES-256-GCM"})
	metaPayload, err := json.Marshal(resttypes.KeyMetadataResponse{KeyID: "gen-key-1", Name: "server-name"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	metaBody, err := json.Marshal(restEnvelope{Code: http.StatusOK, Success: true, Payload: metaPayload})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var gotMeta *resttypes.UpdateKeyMetadataRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/api/v1/kms/keys":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(genBody)
		case req.Method == http.MethodPut && req.URL.Path == "/api/v1/kms/keys/gen-key-1/metadata":
			var m resttypes.UpdateKeyMetadataRequest
			if err := json.NewDecoder(req.Body).Decode(&m); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			gotMeta = &m
			_, _ = w.Write(metaBody)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(srv.Close)
	r := &RESTAdapter{baseURL: srv.URL, httpClient: srv.Client()}

	res, err := r.KeyGenerate(context.Background(), KeyGenerateOptions{
		KeyID: "gen-key-1", Algorithm: "AES-256-GCM", Purpose: "encrypt",
		Name: "display", Description: "desc",
	})
	if err != nil {
		t.Fatalf("KeyGenerate: %v", err)
	}
	if gotMeta == nil {
		t.Fatal("KeyGenerate with Name/Description sent no PUT .../metadata")
	}
	if gotMeta.Name != "display" || gotMeta.Description != "desc" {
		t.Fatalf("metadata request name=%q description=%q, want display/desc", gotMeta.Name, gotMeta.Description)
	}
	if res.Name != "server-name" || res.Description != "desc" {
		t.Fatalf("result name=%q description=%q, want server-name/desc", res.Name, res.Description)
	}
}

// TestRESTAdapterGenerateKeyBodyKeySpec checks that the body the REST
// adapter sends for key generation is the flat GenerateKeyRequest the
// webservice KMS handler reads (types.go): a top-level algorithm and no
// legacy key_spec object, which the handler never reads.
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
			var wire map[string]json.RawMessage
			if err := json.Unmarshal(body, &wire); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if _, ok := wire["key_spec"]; ok {
				t.Fatalf("body carries the legacy key_spec object the handler never reads: %s", body)
			}
			var got string
			if err := json.Unmarshal(wire["algorithm"], &got); err != nil || got != alg {
				t.Fatalf("algorithm = %q (err %v), want %q: %s", got, err, alg, body)
			}
		})
	}
}
