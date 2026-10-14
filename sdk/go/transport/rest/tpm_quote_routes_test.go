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
package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// tpmQuoteServer answers every request with statusCode and body, recording
// the request path and its decoded JSON body.
func tpmQuoteServer(t *testing.T, statusCode int, body string, path *string, sent *map[string]any) *Adapter {
	t.Helper()
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			w.WriteHeader(http.StatusOK)
			return
		}
		*path = r.URL.Path
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, sent); err != nil {
				t.Errorf("decode request body: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	})
	return a
}

// TestTPMQuoteRoutes_SchemeTravels pins the declared signature scheme to
// both legs of a TPM quote over REST (#482): Quote decodes the scheme the
// server names, and VerifyQuote carries it to the verify route, where a
// request without it fails.
func TestTPMQuoteRoutes_SchemeTravels(t *testing.T) {
	t.Run("Quote decodes the declared scheme", func(t *testing.T) {
		var path string
		var sent map[string]any
		a := tpmQuoteServer(t, http.StatusOK,
			envelope(`{"quote":"AQI=","signature":"AwQ=","signatureAlgorithm":"SHA256-RSAPSS"}`), &path, &sent)

		reply := &platformv1.QuoteResponse{}
		if err := a.Connection().Invoke(context.Background(), platformv1.TPMService_Quote_FullMethodName,
			&platformv1.QuoteRequest{Nonce: []byte{9}}, reply); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if path != "/api/v1/tpm/quote" {
			t.Errorf("path = %s, want /api/v1/tpm/quote", path)
		}
		if got := reply.GetSignatureAlgorithm(); got != "SHA256-RSAPSS" {
			t.Errorf("signature_algorithm = %q, want SHA256-RSAPSS", got)
		}
	})

	t.Run("VerifyQuote sends the declared scheme to the verify route", func(t *testing.T) {
		var path string
		var sent map[string]any
		a := tpmQuoteServer(t, http.StatusOK, envelope(`{"verified":true}`), &path, &sent)

		reply := &platformv1.VerifyQuoteResponse{}
		if err := a.Connection().Invoke(context.Background(), platformv1.TPMService_VerifyQuote_FullMethodName,
			&platformv1.VerifyQuoteRequest{
				Quote:              []byte{1, 2},
				Signature:          []byte{3, 4},
				SignatureAlgorithm: "SHA256-RSAPSS",
			}, reply); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if path != "/api/v1/tpm/quote/verify" {
			t.Errorf("path = %s, want /api/v1/tpm/quote/verify", path)
		}
		if got := sent["signature_algorithm"]; got != "SHA256-RSAPSS" {
			t.Errorf("body signature_algorithm = %v, want SHA256-RSAPSS", got)
		}
		if !reply.GetVerified() {
			t.Error("verified = false, want the decoded true")
		}
	})
}

func TestTPMQuoteRoutes_VerifyRefusalIsTranslated(t *testing.T) {
	var path string
	var sent map[string]any
	a := tpmQuoteServer(t, http.StatusBadRequest,
		`{"code":400,"error":"missing required field: quote","success":false}`, &path, &sent)

	err := a.Connection().Invoke(context.Background(), platformv1.TPMService_VerifyQuote_FullMethodName,
		&platformv1.VerifyQuoteRequest{SignatureAlgorithm: "SHA256-RSAPSS"}, &platformv1.VerifyQuoteResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Invoke error = %v, want InvalidArgument", err)
	}
	if path != "/api/v1/tpm/quote/verify" {
		t.Errorf("path = %s, want /api/v1/tpm/quote/verify", path)
	}
}
