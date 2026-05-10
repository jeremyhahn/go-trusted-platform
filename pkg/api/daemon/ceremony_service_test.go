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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeCeremonyBackend implements CeremonyBackend for unit tests.
type fakeCeremonyBackend struct {
	initFn          func(context.Context, *CeremonyInitRequest) (*CeremonyInitResult, error)
	statusFn        func(context.Context) (*CeremonyStatusInfo, error)
	beginFn         func(context.Context, *CeremonyClaimCertBeginRequest) (*CeremonyClaimCertBeginResult, error)
	completeFn      func(context.Context, *CeremonyClaimCertCompleteRequest) (*CeremonyClaimCertCompleteResult, error)
	claimShareFn    func(context.Context, string) (*CeremonyClaimShareResult, error)
	signCSRFn       func(context.Context, *CeremonySignCSRRequest) (*CeremonySignCSRResult, error)
	initCalled      int
	completeCalled  int
	signCSRCalled   int
	claimShareCalls int
}

func (f *fakeCeremonyBackend) Initialize(ctx context.Context, req *CeremonyInitRequest) (*CeremonyInitResult, error) {
	f.initCalled++
	if f.initFn != nil {
		return f.initFn(ctx, req)
	}
	return &CeremonyInitResult{CeremonyID: "cid", State: CeremonyStateInProgress, InitializedAt: time.Unix(1000, 0)}, nil
}

func (f *fakeCeremonyBackend) Status(ctx context.Context) (*CeremonyStatusInfo, error) {
	if f.statusFn != nil {
		return f.statusFn(ctx)
	}
	return &CeremonyStatusInfo{CeremonyID: "cid", State: CeremonyStateInProgress}, nil
}

func (f *fakeCeremonyBackend) ClaimCertBegin(ctx context.Context, req *CeremonyClaimCertBeginRequest) (*CeremonyClaimCertBeginResult, error) {
	if f.beginFn != nil {
		return f.beginFn(ctx, req)
	}
	return &CeremonyClaimCertBeginResult{Nonce: "deadbeef", ChallengeID: "chal-1", ExpiresAt: time.Unix(2000, 0)}, nil
}

func (f *fakeCeremonyBackend) ClaimCertComplete(ctx context.Context, req *CeremonyClaimCertCompleteRequest) (*CeremonyClaimCertCompleteResult, error) {
	f.completeCalled++
	if f.completeFn != nil {
		return f.completeFn(ctx, req)
	}
	return &CeremonyClaimCertCompleteResult{CertificatePEM: "CERT", ChainPEM: "CHAIN"}, nil
}

func (f *fakeCeremonyBackend) ClaimShare(ctx context.Context, username string) (*CeremonyClaimShareResult, error) {
	f.claimShareCalls++
	if f.claimShareFn != nil {
		return f.claimShareFn(ctx, username)
	}
	return &CeremonyClaimShareResult{Share: "SHARE", Index: 1}, nil
}

func (f *fakeCeremonyBackend) SignCSR(ctx context.Context, req *CeremonySignCSRRequest) (*CeremonySignCSRResult, error) {
	f.signCSRCalled++
	if f.signCSRFn != nil {
		return f.signCSRFn(ctx, req)
	}
	return &CeremonySignCSRResult{CertificatePEM: "SIGNED", ChainPEM: "CHAIN"}, nil
}

func TestCeremonyService_NotConfigured(t *testing.T) {
	svc := NewCeremonyService(logging.DefaultLogger(), nil)
	ctx := context.Background()

	if _, err := svc.Init(ctx, &CeremonyInitRequest{}); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("Init: want ErrCeremonyNotConfigured, got %v", err)
	}
	if _, err := svc.Status(ctx); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("Status: want ErrCeremonyNotConfigured, got %v", err)
	}
	if _, err := svc.ClaimCertBegin(ctx, &CeremonyClaimCertBeginRequest{Username: "alice"}); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("ClaimCertBegin: want ErrCeremonyNotConfigured, got %v", err)
	}
	req := &CeremonyClaimCertCompleteRequest{Username: "alice", Nonce: "n", Signature: "s"}
	if _, err := svc.ClaimCertComplete(ctx, req); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("ClaimCertComplete: want ErrCeremonyNotConfigured, got %v", err)
	}
	if _, err := svc.ClaimShare(ctx, "alice"); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("ClaimShare: want ErrCeremonyNotConfigured, got %v", err)
	}
	if _, err := svc.SignCSR(ctx, &CeremonySignCSRRequest{Username: "alice", CSRPEM: "pem"}); !errors.Is(err, ErrCeremonyNotConfigured) {
		t.Errorf("SignCSR: want ErrCeremonyNotConfigured, got %v", err)
	}
}

func TestCeremonyService_Validation(t *testing.T) {
	backend := &fakeCeremonyBackend{}
	svc := NewCeremonyService(logging.DefaultLogger(), backend)
	ctx := context.Background()

	cases := []struct {
		name string
		run  func() error
		want error
	}{
		{
			name: "ClaimCertBegin missing username",
			run: func() error {
				_, err := svc.ClaimCertBegin(ctx, &CeremonyClaimCertBeginRequest{})
				return err
			},
			want: ErrCeremonyOfficerRequired,
		},
		{
			name: "ClaimCertComplete missing nonce",
			run: func() error {
				_, err := svc.ClaimCertComplete(ctx, &CeremonyClaimCertCompleteRequest{Username: "a"})
				return err
			},
			want: ErrCeremonyChallengeRequired,
		},
		{
			name: "ClaimShare missing username",
			run: func() error {
				_, err := svc.ClaimShare(ctx, "")
				return err
			},
			want: ErrCeremonyOfficerRequired,
		},
		{
			name: "SignCSR missing username",
			run: func() error {
				_, err := svc.SignCSR(ctx, &CeremonySignCSRRequest{CSRPEM: "x"})
				return err
			},
			want: ErrCeremonyOfficerRequired,
		},
		{
			name: "SignCSR missing CSR",
			run: func() error {
				_, err := svc.SignCSR(ctx, &CeremonySignCSRRequest{Username: "a"})
				return err
			},
			want: ErrCeremonyCSRRequired,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run()
			if !errors.Is(err, c.want) {
				t.Errorf("want %v got %v", c.want, err)
			}
		})
	}
}

func TestCeremonyService_BackendSuccess(t *testing.T) {
	backend := &fakeCeremonyBackend{}
	svc := NewCeremonyService(logging.DefaultLogger(), backend)
	ctx := context.Background()

	if _, err := svc.Init(ctx, &CeremonyInitRequest{SOPIN: "x"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if backend.initCalled != 1 {
		t.Errorf("Initialize called %d times, want 1", backend.initCalled)
	}
	if _, err := svc.Status(ctx); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if _, err := svc.ClaimCertBegin(ctx, &CeremonyClaimCertBeginRequest{Username: "alice", AuthenticatorType: CeremonyAuthenticatorFIDO2}); err != nil {
		t.Fatalf("ClaimCertBegin: %v", err)
	}
	if _, err := svc.ClaimCertComplete(ctx, &CeremonyClaimCertCompleteRequest{Username: "alice", Nonce: "n", Signature: "s"}); err != nil {
		t.Fatalf("ClaimCertComplete: %v", err)
	}
	if backend.completeCalled != 1 {
		t.Errorf("ClaimCertComplete called %d times, want 1", backend.completeCalled)
	}
	if _, err := svc.ClaimShare(ctx, "alice"); err != nil {
		t.Fatalf("ClaimShare: %v", err)
	}
	if _, err := svc.SignCSR(ctx, &CeremonySignCSRRequest{Username: "alice", CSRPEM: "pem"}); err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
}

func TestCeremonyService_BackendSwap(t *testing.T) {
	svc := NewCeremonyService(logging.DefaultLogger(), nil)
	if svc.Backend() != nil {
		t.Fatal("backend should be nil initially")
	}
	b := &fakeCeremonyBackend{}
	svc.SetBackend(b)
	if svc.Backend() != b {
		t.Fatal("SetBackend did not update backend")
	}
}
