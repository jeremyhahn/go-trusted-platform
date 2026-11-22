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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// rewrapCrypto is a crypto client that records the Rewrap request it is
// given and answers with the next key version.
type rewrapCrypto struct {
	cryptoclient.Client
	got *cryptoclient.RewrapRequest
}

func (f *rewrapCrypto) Rewrap(_ context.Context, req *cryptoclient.RewrapRequest) (*cryptoclient.RewrapResponse, error) {
	f.got = req
	return &cryptoclient.RewrapResponse{
		KeyID:         req.KeyID,
		OldKeyVersion: 1,
		NewKeyVersion: 2,
		Ciphertext:    []byte("new"),
		Nonce:         []byte("nn"),
	}, nil
}

// TestSDKRoundTrip_Rewrap drives the platform SDK's REST Rewrap through the
// served router: the call reaches the crypto client with the request's key,
// ciphertext, context and nonce, and the reply carries both versions.
func TestSDKRoundTrip_Rewrap(t *testing.T) {
	fake := &rewrapCrypto{}
	client := kmsOverSDK(t, nil, fake)

	resp, err := client.Rewrap(context.Background(), &platformv1.RewrapRequest{
		KeyId:      "kek",
		Ciphertext: []byte("old"),
		Context:    []byte("aad"),
		Nonce:      []byte("on"),
	})
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	if fake.got == nil {
		t.Fatal("crypto client saw no Rewrap request")
	}
	if fake.got.KeyID != "kek" || string(fake.got.Ciphertext) != "old" ||
		string(fake.got.Context) != "aad" || string(fake.got.Nonce) != "on" {
		t.Fatalf("crypto request = %+v", fake.got)
	}
	if resp.GetKeyId() != "kek" || resp.GetSourceVersion() != 1 || resp.GetTargetVersion() != 2 ||
		string(resp.GetCiphertext()) != "new" || string(resp.GetNonce()) != "nn" {
		t.Fatalf("reply = %+v", resp)
	}
}

// postRewrap posts body to /api/v1/kms/rewrap on a router serving fake.
func postRewrap(t *testing.T, fake *rewrapCrypto, body string) *httptest.ResponseRecorder {
	t.Helper()
	logger := logging.DefaultLogger()
	root := mux.NewRouter()
	parent := root.PathPrefix("/api/v1").Subrouter()
	NewKMSRouter(logger, nil, fake, nil, nil, response.NewResponseWriter(logger, nil)).RegisterRoutes(parent)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/rewrap", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec
}

// TestRewrapRoute_RefusesAnotherDestinationKey: the crypto service rewraps
// under one key, so a destination key other than the source is refused.
func TestRewrapRoute_RefusesAnotherDestinationKey(t *testing.T) {
	fake := &rewrapCrypto{}
	rec := postRewrap(t, fake,
		`{"source_key_id":"kek","destination_key_id":"other","ciphertext":"`+b64("old")+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if fake.got != nil {
		t.Fatalf("crypto client saw %+v, want no request", fake.got)
	}
}

// TestRewrapRoute_RefusesASourceKeyVersion: the crypto service rewraps from
// the ciphertext's own version, so a named source version is refused.
func TestRewrapRoute_RefusesASourceKeyVersion(t *testing.T) {
	fake := &rewrapCrypto{}
	rec := postRewrap(t, fake,
		`{"source_key_id":"kek","ciphertext":"`+b64("old")+`","source_key_version":3}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if fake.got != nil {
		t.Fatalf("crypto client saw %+v, want no request", fake.got)
	}
}
