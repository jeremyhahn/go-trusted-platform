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
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

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
	if initResp.GetAdminCertPem() != "ADMIN-CERT" || initResp.GetAdminKeyPem() != "ADMIN-KEY" || initResp.GetSpkiPin() != "PIN" {
		t.Errorf("admin bundle not carried: %+v", initResp)
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

	shareBeginResp, err := svc.ClaimShareBegin(ctx, &platformv1.CeremonyClaimShareBeginRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("ClaimShareBegin: %v", err)
	}
	if shareBeginResp.GetNonce() != "deadbeef" {
		t.Errorf("share begin resp = %+v", shareBeginResp)
	}

	shareResp, err := svc.ClaimShareComplete(ctx, &platformv1.CeremonyClaimShareCompleteRequest{
		Username:  "alice",
		Nonce:     "deadbeef",
		Signature: []byte("sig"),
	})
	if err != nil {
		t.Fatalf("ClaimShareComplete: %v", err)
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

// An M-of-N init names one officer per share; the gRPC Init carries each
// officer's username and CSR on to the backend, which forwards them upstream.
func TestCeremonyGRPC_InitForwardsOfficers(t *testing.T) {
	var got *CeremonyInitRequest
	backend := &fakeCeremonyBackend{}
	backend.initFn = func(_ context.Context, req *CeremonyInitRequest) (*CeremonyInitResult, error) {
		got = req
		return &CeremonyInitResult{CeremonyID: "cid", State: CeremonyStateInProgress}, nil
	}
	svc := newCeremonyGRPC(backend)

	_, err := svc.Init(context.Background(), &platformv1.CeremonyInitRequest{
		SoPin:     "x",
		Threshold: "2-of-2",
		Officers: []*platformv1.CeremonyInitOfficer{
			{Username: "alice", CsrPem: "CSR-A"},
			{Username: "bob", CsrPem: "CSR-B"},
		},
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got == nil {
		t.Fatal("backend Init was not called")
	}
	want := []CeremonyOfficer{{Username: "alice", CSRPEM: "CSR-A"}, {Username: "bob", CSRPEM: "CSR-B"}}
	if !reflect.DeepEqual(got.Officers, want) {
		t.Errorf("Officers = %+v, want %+v", got.Officers, want)
	}
}

// An officer without a username or without a CSR cannot be given a custodian
// certificate: Init refuses it before the backend is reached.
func TestCeremonyGRPC_InitRefusesAnIncompleteOfficer(t *testing.T) {
	cases := map[string]*platformv1.CeremonyInitOfficer{
		"empty username": {Username: "", CsrPem: "CSR-A"},
		"empty csr":      {Username: "alice", CsrPem: ""},
	}
	for name, officer := range cases {
		t.Run(name, func(t *testing.T) {
			backend := &fakeCeremonyBackend{}
			svc := newCeremonyGRPC(backend)
			_, err := svc.Init(context.Background(), &platformv1.CeremonyInitRequest{
				SoPin:     "x",
				Threshold: "2-of-2",
				Officers: []*platformv1.CeremonyInitOfficer{
					officer,
					{Username: "bob", CsrPem: "CSR-B"},
				},
			})
			if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
				t.Errorf("status = %v (%v), want InvalidArgument", st.Code(), err)
			}
			if backend.initCalled != 0 {
				t.Errorf("backend Init called %d times, want 0", backend.initCalled)
			}
		})
	}
}
