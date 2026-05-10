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

package daemon

import (
	"context"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newCeremonyGRPC(backend CeremonyBackend) *CeremonyGRPCService {
	return NewCeremonyGRPCService(logging.DefaultLogger(), NewCeremonyService(logging.DefaultLogger(), backend))
}

func TestCeremonyGRPC_Unavailable(t *testing.T) {
	svc := newCeremonyGRPC(nil)
	ctx := context.Background()
	_, err := svc.Status(ctx, &platformv1.CeremonyStatusRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("not a gRPC status: %v", err)
	}
	if st.Code() != codes.Unavailable {
		t.Errorf("status = %v, want Unavailable", st.Code())
	}
}

func TestCeremonyGRPC_InvalidArgument(t *testing.T) {
	svc := newCeremonyGRPC(&fakeCeremonyBackend{})
	ctx := context.Background()
	_, err := svc.ClaimCertBegin(ctx, &platformv1.CeremonyClaimCertBeginRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("status = %v, want InvalidArgument", st.Code())
	}
}

func TestCeremonyGRPC_Success(t *testing.T) {
	backend := &fakeCeremonyBackend{}
	svc := newCeremonyGRPC(backend)
	ctx := context.Background()

	initResp, err := svc.Init(ctx, &platformv1.CeremonyInitRequest{SoPin: "x"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if initResp.GetCeremonyId() != "cid" {
		t.Errorf("CeremonyId = %q", initResp.GetCeremonyId())
	}
	if initResp.GetState() != platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS {
		t.Errorf("state = %v", initResp.GetState())
	}

	beginResp, err := svc.ClaimCertBegin(ctx, &platformv1.CeremonyClaimCertBeginRequest{
		Username:          "alice",
		AuthenticatorType: platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_FIDO2,
	})
	if err != nil {
		t.Fatalf("ClaimCertBegin: %v", err)
	}
	if beginResp.GetNonce() != "deadbeef" {
		t.Errorf("nonce = %q", beginResp.GetNonce())
	}

	completeResp, err := svc.ClaimCertComplete(ctx, &platformv1.CeremonyClaimCertCompleteRequest{
		Username:  "alice",
		Nonce:     "deadbeef",
		Signature: "sig",
	})
	if err != nil {
		t.Fatalf("ClaimCertComplete: %v", err)
	}
	if completeResp.GetCertificatePem() != "CERT" {
		t.Errorf("cert = %q", completeResp.GetCertificatePem())
	}

	shareResp, err := svc.ClaimShare(ctx, &platformv1.CeremonyClaimShareRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("ClaimShare: %v", err)
	}
	if shareResp.GetShare() != "SHARE" || shareResp.GetIndex() != 1 {
		t.Errorf("share resp = %+v", shareResp)
	}

	signResp, err := svc.SignCSR(ctx, &platformv1.CeremonySignCSRRequest{
		Username: "alice",
		CsrPem:   "pem",
		Role:     platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_SO,
	})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if signResp.GetCertificatePem() != "SIGNED" {
		t.Errorf("sign resp = %+v", signResp)
	}
}
