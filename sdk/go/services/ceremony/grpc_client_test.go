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

package ceremony

import (
	"context"
	"errors"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type stubCeremonyClient struct {
	initResp       *platformv1.CeremonyInitResponse
	statusResp     *platformv1.CeremonyStatusResponse
	beginResp      *platformv1.CeremonyClaimCertBeginResponse
	completeResp   *platformv1.CeremonyClaimCertCompleteResponse
	shareBeginResp *platformv1.CeremonyClaimShareBeginResponse
	shareResp      *platformv1.CeremonyClaimShareCompleteResponse
	signResp       *platformv1.CeremonySignCSRResponse
	err            error
}

func (s *stubCeremonyClient) Init(_ context.Context, _ *platformv1.CeremonyInitRequest, _ ...grpc.CallOption) (*platformv1.CeremonyInitResponse, error) {
	return s.initResp, s.err
}

func (s *stubCeremonyClient) Status(_ context.Context, _ *platformv1.CeremonyStatusRequest, _ ...grpc.CallOption) (*platformv1.CeremonyStatusResponse, error) {
	return s.statusResp, s.err
}

func (s *stubCeremonyClient) ClaimCertBegin(_ context.Context, _ *platformv1.CeremonyClaimCertBeginRequest, _ ...grpc.CallOption) (*platformv1.CeremonyClaimCertBeginResponse, error) {
	return s.beginResp, s.err
}

func (s *stubCeremonyClient) ClaimCertComplete(_ context.Context, _ *platformv1.CeremonyClaimCertCompleteRequest, _ ...grpc.CallOption) (*platformv1.CeremonyClaimCertCompleteResponse, error) {
	return s.completeResp, s.err
}

func (s *stubCeremonyClient) ClaimShareBegin(_ context.Context, _ *platformv1.CeremonyClaimShareBeginRequest, _ ...grpc.CallOption) (*platformv1.CeremonyClaimShareBeginResponse, error) {
	return s.shareBeginResp, s.err
}

func (s *stubCeremonyClient) ClaimShareComplete(_ context.Context, _ *platformv1.CeremonyClaimShareCompleteRequest, _ ...grpc.CallOption) (*platformv1.CeremonyClaimShareCompleteResponse, error) {
	return s.shareResp, s.err
}

func (s *stubCeremonyClient) SignCSR(_ context.Context, _ *platformv1.CeremonySignCSRRequest, _ ...grpc.CallOption) (*platformv1.CeremonySignCSRResponse, error) {
	return s.signResp, s.err
}

func TestGRPCClient_Success(t *testing.T) {
	stub := &stubCeremonyClient{
		initResp: &platformv1.CeremonyInitResponse{
			CeremonyId:    "cid",
			State:         platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS,
			InitializedAt: timestamppb.New(time.Unix(1000, 0)),
		},
		statusResp: &platformv1.CeremonyStatusResponse{
			CeremonyId:       "cid",
			State:            platformv1.CeremonyState_CEREMONY_STATE_COMPLETE,
			OfficersEnrolled: 3,
			OfficersRequired: 5,
		},
		beginResp: &platformv1.CeremonyClaimCertBeginResponse{
			Nonce:       "n",
			ChallengeId: "ch",
			ExpiresAt:   timestamppb.New(time.Unix(2000, 0)),
		},
		completeResp: &platformv1.CeremonyClaimCertCompleteResponse{
			CertificatePem: "CERT",
			ChainPem:       "CHAIN",
		},
		shareBeginResp: &platformv1.CeremonyClaimShareBeginResponse{
			Nonce:     "sn",
			ExpiresAt: timestamppb.New(time.Unix(3000, 0)),
		},
		shareResp: &platformv1.CeremonyClaimShareCompleteResponse{Share: "s", Index: 2},
		signResp:  &platformv1.CeremonySignCSRResponse{CertificatePem: "SIGN"},
	}
	client := NewGRPCClientFromClient(stub)
	ctx := context.Background()

	if resp, err := client.Init(ctx, &InitRequest{SOPIN: "x"}); err != nil || resp.CeremonyID != "cid" {
		t.Errorf("Init: %v %+v", err, resp)
	}
	if resp, err := client.Status(ctx); err != nil || resp.State != StateComplete {
		t.Errorf("Status: %v %+v", err, resp)
	}
	if resp, err := client.ClaimCertBegin(ctx, &ClaimCertBeginRequest{Username: "a", AuthenticatorType: AuthenticatorFIDO2}); err != nil || resp.Nonce != "n" {
		t.Errorf("ClaimCertBegin: %v %+v", err, resp)
	}
	if resp, err := client.ClaimCertComplete(ctx, &ClaimCertCompleteRequest{Username: "a", Nonce: "n", Signature: "s"}); err != nil || resp.Certificate != "CERT" {
		t.Errorf("ClaimCertComplete: %v %+v", err, resp)
	}
	if resp, err := client.ClaimShareBegin(ctx, &ClaimShareBeginRequest{Username: "a"}); err != nil || resp.Nonce != "sn" {
		t.Errorf("ClaimShareBegin: %v %+v", err, resp)
	}
	if resp, err := client.ClaimShareComplete(ctx, &ClaimShareCompleteRequest{Username: "a", Nonce: "sn", Signature: []byte("s")}); err != nil || resp.Share != "s" {
		t.Errorf("ClaimShareComplete: %v %+v", err, resp)
	}
	if resp, err := client.SignCSR(ctx, &SignCSRRequest{Username: "a", CSRPEM: "pem", Role: RoleSO}); err != nil || resp.Certificate != "SIGN" {
		t.Errorf("SignCSR: %v %+v", err, resp)
	}
}

func TestGRPCClient_Error(t *testing.T) {
	wantErr := errors.New("rpc-boom")
	client := NewGRPCClientFromClient(&stubCeremonyClient{err: wantErr})
	ctx := context.Background()

	_, err := client.Init(ctx, &InitRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	var initErr *ErrInitFailed
	if !errors.As(err, &initErr) {
		t.Errorf("want ErrInitFailed, got %T", err)
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error chain does not include %v", wantErr)
	}
}
