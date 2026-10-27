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
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestAttestationQuoteRoutes_RouteAndDecode pins the three quote rpcs to the
// routes server_router.go serves. They were keyed by method names the proto
// never declared (GetQuote, VerifyQuote), so every SDK quote over REST fell
// back to a derived path that 404s.
func TestAttestationQuoteRoutes_RouteAndDecode(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		path    string
		payload string
		req     proto.Message
		reply   proto.Message
		check   func(t *testing.T, reply proto.Message)
	}{
		{
			name:    "GetAttestationQuote",
			method:  platformv1.AttestationService_GetAttestationQuote_FullMethodName,
			path:    "/api/v1/attestation/quote",
			payload: `{"quote":{"nonce":"BAU="},"channelBinding":"AQID"}`,
			req:     &platformv1.GetAttestationQuoteRequest{Nonce: []byte{9}},
			reply:   &platformv1.GetAttestationQuoteResponse{},
			check: func(t *testing.T, reply proto.Message) {
				resp := reply.(*platformv1.GetAttestationQuoteResponse)
				if !bytes.Equal(resp.GetChannelBinding(), []byte{1, 2, 3}) {
					t.Errorf("channel_binding = %x, want 010203", resp.GetChannelBinding())
				}
				if !bytes.Equal(resp.GetQuote().GetNonce(), []byte{4, 5}) {
					t.Errorf("quote.nonce = %x, want 0405", resp.GetQuote().GetNonce())
				}
			},
		},
		{
			name:    "VerifyAttestationQuote",
			method:  platformv1.AttestationService_VerifyAttestationQuote_FullMethodName,
			path:    "/api/v1/attestation/quote/verify",
			payload: `{"verified":true}`,
			req:     &platformv1.VerifyAttestationQuoteRequest{ChannelBinding: []byte{1}},
			reply:   &platformv1.VerifyAttestationQuoteResponse{},
			check: func(t *testing.T, reply proto.Message) {
				if !reply.(*platformv1.VerifyAttestationQuoteResponse).GetVerified() {
					t.Error("verified = false, want the decoded true")
				}
			},
		},
		{
			name:    "CollectHostAttestation",
			method:  platformv1.AttestationService_CollectHostAttestation_FullMethodName,
			path:    "/api/v1/attestation/host",
			payload: `{"attestation":{"nonce":"BAU="}}`,
			req:     &platformv1.CollectHostAttestationRequest{Nonce: []byte{9}},
			reply:   &platformv1.CollectHostAttestationResponse{},
			check: func(t *testing.T, reply proto.Message) {
				got := reply.(*platformv1.CollectHostAttestationResponse).GetAttestation().GetNonce()
				if !bytes.Equal(got, []byte{4, 5}) {
					t.Errorf("attestation.nonce = %x, want 0405", got)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captured capturedRequest
			a := attestationServer(t, http.StatusOK, envelope(tc.payload), &captured)

			if err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.reply); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != http.MethodPost || captured.path != tc.path {
				t.Errorf("request = %s %s, want POST %s", captured.method, captured.path, tc.path)
			}
			tc.check(t, tc.reply)
		})
	}
}

// TestAttestationQuoteRoutes_ServerRefusalIsTranslated pins the error half:
// the node refusing an unbound quote (FailedPrecondition, which protorest
// writes as 409, #665) reaches the caller as an error carrying the refusal,
// never as a decoded empty quote.
func TestAttestationQuoteRoutes_ServerRefusalIsTranslated(t *testing.T) {
	var captured capturedRequest
	a := attestationServer(t, http.StatusConflict,
		`{"code":409,"error":"channel binding required","success":false}`, &captured)

	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_GetAttestationQuote_FullMethodName,
		&platformv1.GetAttestationQuoteRequest{Nonce: []byte{9}}, &platformv1.GetAttestationQuoteResponse{})
	if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "channel binding required") {
		t.Fatalf("Invoke error = %v, want AlreadyExists carrying the refusal", err)
	}
	if captured.path != "/api/v1/attestation/quote" {
		t.Errorf("path = %s, want /api/v1/attestation/quote", captured.path)
	}
}
