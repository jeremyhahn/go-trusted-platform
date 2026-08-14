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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

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
