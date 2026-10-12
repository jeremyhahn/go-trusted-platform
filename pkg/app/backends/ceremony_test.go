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

package backends

import (
	"context"
	"errors"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeCeremonyClient answers CeremonyInitialize with a canned response.
type fakeCeremonyClient struct {
	quicbaassdk.QRDBCeremonyClient
	resp *quicbaassdk.QRDBCeremonyInitializeResponse
	err  error
}

func (f *fakeCeremonyClient) CeremonyInitialize(_ context.Context, _ *quicbaassdk.QRDBCeremonyInitializeRequest) (*quicbaassdk.QRDBCeremonyInitializeResponse, error) {
	return f.resp, f.err
}

// fakeCeremonyMgmt hands out the fake ceremony client.
type fakeCeremonyMgmt struct {
	quicbaassdk.BarrierCeremonyService
	ceremony *fakeCeremonyClient
}

func (f *fakeCeremonyMgmt) Ceremony() (quicbaassdk.QRDBCeremonyClient, error) {
	return f.ceremony, nil
}

// fakeCeremonySDK is an SDK client exposing only the ceremony management service.
type fakeCeremonySDK struct {
	quicbaassdk.Client
	mgmt *fakeCeremonyMgmt
}

func (f *fakeCeremonySDK) BarrierCeremonyMgmt() quicbaassdk.BarrierCeremonyService {
	return f.mgmt
}

func newFakeCeremonyBackend(ceremony *fakeCeremonyClient) *CeremonyBackend {
	sdk := &fakeCeremonySDK{mgmt: &fakeCeremonyMgmt{ceremony: ceremony}}
	return NewCeremonyBackend(logging.DefaultLogger(), sdk)
}

func TestCeremonyBackend_Initialize_ReturnsSPKIPin(t *testing.T) {
	b := newFakeCeremonyBackend(&fakeCeremonyClient{
		resp: &quicbaassdk.QRDBCeremonyInitializeResponse{SPKIPin: "sha256/abc", State: "complete"},
	})

	res, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{SOPIN: "so", UserPIN: "user"})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if res.SPKIPin != "sha256/abc" {
		t.Fatalf("SPKIPin = %q, want sha256/abc", res.SPKIPin)
	}
	if res.State != daemon.CeremonyStateComplete {
		t.Fatalf("State = %v, want complete", res.State)
	}
}

func TestCeremonyBackend_Initialize_PropagatesUpstreamError(t *testing.T) {
	boom := errors.New("ceremony failed")
	b := newFakeCeremonyBackend(&fakeCeremonyClient{err: boom})

	res, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the upstream error", err)
	}
	if res != nil {
		t.Fatalf("expected no result, got %+v", res)
	}
}

func TestCeremonyBackend_NilClient_ReturnsTypedError(t *testing.T) {
	b := NewCeremonyBackend(logging.DefaultLogger(), nil)

	t.Run("Initialize", func(t *testing.T) {
		_, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("Status", func(t *testing.T) {
		_, err := b.Status(context.Background())
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("ClaimCertBegin", func(t *testing.T) {
		_, err := b.ClaimCertBegin(context.Background(), &daemon.CeremonyClaimCertBeginRequest{Username: "u"})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("ClaimCertComplete", func(t *testing.T) {
		_, err := b.ClaimCertComplete(context.Background(), &daemon.CeremonyClaimCertCompleteRequest{Username: "u", Nonce: "x", Signature: "y"})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("ClaimShareBegin", func(t *testing.T) {
		_, err := b.ClaimShareBegin(context.Background(), &daemon.CeremonyClaimShareBeginRequest{Username: "u"})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("ClaimShareComplete", func(t *testing.T) {
		_, err := b.ClaimShareComplete(context.Background(), &daemon.CeremonyClaimShareCompleteRequest{Username: "u", Nonce: "x", Signature: []byte("y")})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("SignCSR", func(t *testing.T) {
		_, err := b.SignCSR(context.Background(), &daemon.CeremonySignCSRRequest{Username: "u", CSRPEM: "pem"})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})
}

func TestMapCeremonyState(t *testing.T) {
	cases := []struct {
		in   string
		want daemon.CeremonyStateValue
	}{
		{"", daemon.CeremonyStateUnknown},
		{"uninitialized", daemon.CeremonyStateUninitialized},
		{"in_progress", daemon.CeremonyStateInProgress},
		{"in-progress", daemon.CeremonyStateInProgress},
		{"inprogress", daemon.CeremonyStateInProgress},
		{"complete", daemon.CeremonyStateComplete},
		{"completed", daemon.CeremonyStateComplete},
		{"bogus", daemon.CeremonyStateUnknown},
	}
	for _, tc := range cases {
		if got := mapCeremonyState(tc.in); got != tc.want {
			t.Errorf("mapCeremonyState(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestThresholdTotal(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"3-of-5", 5},
		{"2-of-3", 3},
		{"1-of-1", 1},
		{"garbage", 0},
		{"10-of-25", 25},
	}
	for _, tc := range cases {
		if got := thresholdTotal(tc.in); got != tc.want {
			t.Errorf("thresholdTotal(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestCeremonyBackend_ImplementsInterface(t *testing.T) {
	// Compile-time check is the real test; this asserts the pointer satisfies
	// the interface in a way that is visible to go vet.
	var _ daemon.CeremonyBackend = (*CeremonyBackend)(nil)
}
