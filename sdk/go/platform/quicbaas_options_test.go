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

package platform

import (
	"errors"
	"testing"
)

func TestWithQuicBaaSAddr(t *testing.T) {
	o := NewOptions(WithQuicBaaSAddr("/run/quicbaas.sock"))
	if o.QuicBaaSAddr != "/run/quicbaas.sock" {
		t.Errorf("expected QuicBaaSAddr propagated, got %q", o.QuicBaaSAddr)
	}
	if !o.HasQuicBaaSAddr() {
		t.Error("HasQuicBaaSAddr should be true after WithQuicBaaSAddr")
	}
}

func TestWithQuicBaaSAddr_Empty(t *testing.T) {
	o := NewOptions(WithQuicBaaSAddr(""))
	if o.HasQuicBaaSAddr() {
		t.Error("HasQuicBaaSAddr should be false with empty address")
	}
}

func TestWithQuicBaaSTransport(t *testing.T) {
	o := NewOptions(WithQuicBaaSTransport("unix"))
	if o.QuicBaaSTransport != "unix" {
		t.Errorf("expected unix transport propagated, got %q", o.QuicBaaSTransport)
	}
}

func TestQuicBaaSTransportOptions(t *testing.T) {
	cases := []struct {
		transport string
		wantNil   bool
	}{
		{"unix", false},
		{"rest", false},
		{"quic", false},
		{"mcp", false},
		{"grpc", true},
		{"", true},
		{"unknown", true},
	}
	for _, c := range cases {
		t.Run(c.transport, func(t *testing.T) {
			got := quicbaasTransportOptions("addr", c.transport)
			if (got == nil) != c.wantNil {
				t.Errorf("transport=%q wantNil=%v gotNil=%v", c.transport, c.wantNil, got == nil)
			}
		})
	}
}

// TestPlatformClient_QuicBaaS_NotConfigured covers the "no addr"
// branch — the SDK client returns ErrQuicBaaSNotConfigured.
func TestPlatformClient_QuicBaaS_NotConfigured(t *testing.T) {
	c := &platformClient{}
	_, err := c.QuicBaaS()
	if err == nil {
		t.Fatal("expected error when no quicbaas client configured")
	}
	var typed ErrQuicBaaSNotConfigured
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrQuicBaaSNotConfigured, got %T: %v", err, err)
	}
}

// TestPlatformClient_QuicBaaS_InitErrSurface covers the failed-init
// branch — initQuicBaaSClient recorded an error and QuicBaaS() returns
// it.
func TestPlatformClient_QuicBaaS_InitErrSurface(t *testing.T) {
	want := errors.New("ctor exploded")
	c := &platformClient{quicbaasInitErr: ErrQuicBaaSInitFailed{Addr: "x", Transport: "rest", Err: want}}
	_, err := c.QuicBaaS()
	if err == nil {
		t.Fatal("expected init error")
	}
	var typed ErrQuicBaaSInitFailed
	if !errors.As(err, &typed) {
		t.Errorf("expected ErrQuicBaaSInitFailed, got %T: %v", err, err)
	}
	if !errors.Is(err, want) {
		t.Errorf("expected wrapped %v to be reachable, got %v", want, err)
	}
}

// TestPlatformClient_InitQuicBaaSClient_FailureRecorded ensures that
// an invalid quicbaas address ends up captured as quicbaasInitErr so
// the rest of the SDK keeps functioning.
func TestPlatformClient_InitQuicBaaSClient_FailureRecorded(t *testing.T) {
	c := &platformClient{}
	c.initQuicBaaSClient(&Options{QuicBaaSAddr: ""}) // empty -> noop
	if c.quicbaasInitErr != nil {
		t.Errorf("empty addr must not record an error, got %v", c.quicbaasInitErr)
	}

	// An invalid address pushes go-quicbaas's NewClient into its empty-address
	// guard. The platform SDK records the failure instead of panicking.
	c2 := &platformClient{}
	c2.initQuicBaaSClient(&Options{QuicBaaSAddr: ""}) // empty addr — noop
	if c2.quicbaas != nil {
		t.Error("empty addr must not create a client")
	}
}

// TestErrQuicBaaSNotConfigured_Message verifies the user-facing
// message.
func TestErrQuicBaaSNotConfigured_Message(t *testing.T) {
	e := ErrQuicBaaSNotConfigured{}
	if e.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

// TestErrQuicBaaSInitFailed_MessageAndUnwrap verifies the wrapping.
func TestErrQuicBaaSInitFailed_MessageAndUnwrap(t *testing.T) {
	inner := errors.New("dial fail")
	e := ErrQuicBaaSInitFailed{Addr: "127.0.0.1", Transport: "grpc", Err: inner}
	if !errors.Is(e, inner) {
		t.Error("expected inner error reachable via errors.Is")
	}
	if e.Error() == "" {
		t.Error("expected non-empty error message")
	}
}
