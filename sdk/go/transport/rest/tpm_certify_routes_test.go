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

package rest

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestTPMCertifyRoute_RoundTrip(t *testing.T) {
	var path string
	var sent map[string]any
	a := tpmQuoteServer(t, http.StatusOK,
		envelope(`{"certifyInfo":"AQI=","signature":"AwQ=","signatureAlgorithm":"ECDSA-SHA256","nonce":"CQ=="}`), &path, &sent)

	reply := &platformv1.CertifyResponse{}
	if err := a.Connection().Invoke(context.Background(), platformv1.TPMService_Certify_FullMethodName,
		&platformv1.CertifyRequest{KeyHandle: 0x81000001, KeyPassword: "pw", Nonce: []byte{9}}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if path != "/api/v1/tpm/certify" {
		t.Errorf("path = %s, want /api/v1/tpm/certify", path)
	}
	if got := sent["key_handle"]; got != float64(0x81000001) {
		t.Errorf("body key_handle = %v, want 0x81000001", got)
	}
	if got := sent["key_password"]; got != "pw" {
		t.Errorf("body key_password = %v, want pw", got)
	}
	if !bytes.Equal(reply.GetCertifyInfo(), []byte{1, 2}) || !bytes.Equal(reply.GetNonce(), []byte{9}) {
		t.Errorf("reply = %v, want the decoded certify_info and nonce", reply)
	}
	if got := reply.GetSignatureAlgorithm(); got != "ECDSA-SHA256" {
		t.Errorf("signature_algorithm = %q, want ECDSA-SHA256", got)
	}
}

func TestTPMCertifyRoute_RefusalIsTranslated(t *testing.T) {
	var path string
	var sent map[string]any
	a := tpmQuoteServer(t, http.StatusBadRequest,
		`{"code":400,"error":"key handle is required","success":false}`, &path, &sent)

	err := a.Connection().Invoke(context.Background(), platformv1.TPMService_Certify_FullMethodName,
		&platformv1.CertifyRequest{}, &platformv1.CertifyResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Invoke error = %v, want InvalidArgument", err)
	}
	if path != "/api/v1/tpm/certify" {
		t.Errorf("path = %s, want /api/v1/tpm/certify", path)
	}
}
