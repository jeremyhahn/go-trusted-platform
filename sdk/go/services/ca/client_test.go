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

package ca

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingCAClient records the requests it is sent and answers with resp
// or err; the CA methods a test does not exercise are never called.
type recordingCAClient struct {
	platformv1.CAServiceClient
	issueReq *platformv1.IssueCertificateRequest
	signReq  *platformv1.SignCSRRequest
	resp     *platformv1.IssueCertificateResponse
	err      error
}

func (c *recordingCAClient) IssueCertificate(_ context.Context, req *platformv1.IssueCertificateRequest, _ ...grpc.CallOption) (*platformv1.IssueCertificateResponse, error) {
	c.issueReq = req
	return c.resp, c.err
}

func (c *recordingCAClient) SignCSR(_ context.Context, req *platformv1.SignCSRRequest, _ ...grpc.CallOption) (*platformv1.IssueCertificateResponse, error) {
	c.signReq = req
	return c.resp, c.err
}

func issued(serial string) *platformv1.IssueCertificateResponse {
	return &platformv1.IssueCertificateResponse{
		Certificate: &platformv1.Certificate{Serial: serial, Pem: []byte("PEM")},
	}
}

func TestSignCSRDomain_SendsTheCSRToSignCSR(t *testing.T) {
	grpcClient := &recordingCAClient{resp: issued("01")}
	client := NewClientFromGRPC(grpcClient)

	result, err := client.SignCSRDomain(context.Background(), &SignCSRParams{CSRPEM: "csr", ValidDays: 30})
	if err != nil {
		t.Fatalf("SignCSRDomain: %v", err)
	}
	if grpcClient.signReq.GetCsrPem() != "csr" || grpcClient.signReq.GetValidDays() != 30 {
		t.Errorf("SignCSR request = %v", grpcClient.signReq)
	}
	if grpcClient.issueReq != nil {
		t.Error("a CSR was sent to IssueCertificate")
	}
	if result.Certificate == nil || result.Certificate.Serial != "01" {
		t.Errorf("result = %+v", result.Certificate)
	}
}

func TestSignCSRDomain_Errors(t *testing.T) {
	refused := errors.New("permission denied: ca:sign-csr")
	cases := []struct {
		name   string
		params *SignCSRParams
		cause  error
	}{
		{"server refusal", &SignCSRParams{CSRPEM: "csr"}, refused},
		{"no parameters", nil, ErrNilSignCSRParams{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			grpcClient := &recordingCAClient{err: refused}
			_, err := NewClientFromGRPC(grpcClient).SignCSRDomain(context.Background(), tc.params)
			var failed *ErrSignCSRFailed
			if !errors.As(err, &failed) || !errors.Is(err, tc.cause) {
				t.Fatalf("SignCSRDomain = %v, want ErrSignCSRFailed wrapping %v", err, tc.cause)
			}
		})
	}
}

func TestIssueCertificateDomain_ConvertsTheRequest(t *testing.T) {
	grpcClient := &recordingCAClient{resp: issued("02")}
	client := NewClientFromGRPC(grpcClient)

	result, err := client.IssueCertificateDomain(context.Background(), &IssueCertificateParams{
		Subject:     &Subject{CommonName: "node-1"},
		ValidDays:   7,
		ExtKeyUsage: []string{"serverAuth"},
		SANs:        &SubjectAlternativeNames{DNSNames: []string{"node-1.local"}},
	})
	if err != nil {
		t.Fatalf("IssueCertificateDomain: %v", err)
	}
	req := grpcClient.issueReq.GetRequest()
	if req.GetSubject().GetCommonName() != "node-1" || req.GetValidDays() != 7 ||
		req.GetSans().GetDnsNames()[0] != "node-1.local" || req.GetExtKeyUsage()[0] != "serverAuth" {
		t.Errorf("IssueCertificate request = %v", req)
	}
	if result.Certificate.Serial != "02" {
		t.Errorf("result = %+v", result.Certificate)
	}
}

func TestIssueCertificateDomain_Error(t *testing.T) {
	cause := errors.New("sealed")
	_, err := NewClientFromGRPC(&recordingCAClient{err: cause}).IssueCertificateDomain(context.Background(), &IssueCertificateParams{})
	var failed *ErrIssueCertificateFailed
	if !errors.As(err, &failed) || !errors.Is(err, cause) {
		t.Fatalf("IssueCertificateDomain = %v, want ErrIssueCertificateFailed wrapping %v", err, cause)
	}
}

func TestErrSignCSRFailed_Message(t *testing.T) {
	err := &ErrSignCSRFailed{Cause: ErrNilSignCSRParams{}}
	if err.Error() != "failed to sign CSR: sign CSR parameters are required" {
		t.Errorf("Error() = %q", err.Error())
	}
}
