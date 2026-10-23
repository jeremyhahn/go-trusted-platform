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
	"crypto/tls"
	"errors"
	"path/filepath"
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
	}
	for _, c := range cases {
		t.Run(c.transport, func(t *testing.T) {
			got, err := quicbaasTransportOptions("addr", c.transport)
			if err != nil {
				t.Fatalf("transport=%q: unexpected error %v", c.transport, err)
			}
			if (got == nil) != c.wantNil {
				t.Errorf("transport=%q wantNil=%v gotNil=%v", c.transport, c.wantNil, got == nil)
			}
		})
	}
}

// TestQuicBaaSTransportOptions_Unsupported pins that a transport name the
// side-client cannot dial is refused, not silently auto-detected: "embedded"
// is a platform protocol but not a QuicBaaS one, and names are case-sensitive.
func TestQuicBaaSTransportOptions_Unsupported(t *testing.T) {
	for _, transport := range []string{"embedded", "GRPC", "unknown"} {
		t.Run(transport, func(t *testing.T) {
			got, err := quicbaasTransportOptions("addr", transport)
			var unsupported ErrProtocolNotSupported
			if !errors.As(err, &unsupported) {
				t.Fatalf("err = %v, want ErrProtocolNotSupported", err)
			}
			if unsupported.Transport != transport {
				t.Errorf("Transport = %q, want %q", unsupported.Transport, transport)
			}
			if got != nil {
				t.Errorf("options = %v, want nil on error", got)
			}
		})
	}
}

// TestPlatformClient_InitQuicBaaSClient_UnsupportedTransport pins that the
// refusal reaches QuicBaaS() as ErrQuicBaaSInitFailed wrapping
// ErrProtocolNotSupported, so platformd verbs keep working.
func TestPlatformClient_InitQuicBaaSClient_UnsupportedTransport(t *testing.T) {
	c := &platformClient{}
	c.initQuicBaaSClient(&Options{QuicBaaSAddr: "/run/quicbaas.sock", QuicBaaSTransport: "embedded"})

	_, err := c.QuicBaaS()
	var initFailed ErrQuicBaaSInitFailed
	if !errors.As(err, &initFailed) {
		t.Fatalf("err = %v, want ErrQuicBaaSInitFailed", err)
	}
	if initFailed.Transport != "embedded" {
		t.Errorf("Transport = %q, want %q", initFailed.Transport, "embedded")
	}
	var unsupported ErrProtocolNotSupported
	if !errors.As(err, &unsupported) {
		t.Errorf("err = %v, want it to wrap ErrProtocolNotSupported", err)
	}
	if c.quicbaas != nil {
		t.Error("an unsupported transport must not create a client")
	}
}

// TestWithQuicBaaSTLSConfig verifies the option stores the quicbaasd TLS
// configuration apart from the platformd one.
func TestWithQuicBaaSTLSConfig(t *testing.T) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	o := NewOptions(WithQuicBaaSTLSConfig(cfg))
	if o.QuicBaaSTLSConfig != cfg {
		t.Errorf("QuicBaaSTLSConfig = %p, want %p", o.QuicBaaSTLSConfig, cfg)
	}
	if o.TLSConfig != nil {
		t.Error("the quicbaasd TLS configuration must not become the platformd one")
	}
}

// TestPlatformClient_InitQuicBaaSClient_TLSReachesSDK verifies the TLS
// configuration is handed to the go-quicbaas SDK: its Unix transport
// refuses to build without one, so a client exists only if it arrived.
func TestPlatformClient_InitQuicBaaSClient_TLSReachesSDK(t *testing.T) {
	c := &platformClient{}
	c.initQuicBaaSClient(&Options{
		QuicBaaSAddr:      filepath.Join(t.TempDir(), "quicbaas.sock"),
		QuicBaaSTransport: "unix",
		QuicBaaSTLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	})
	t.Cleanup(func() {
		if c.quicbaas != nil {
			if err := c.quicbaas.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}
	})

	q, err := c.QuicBaaS()
	if err != nil {
		t.Fatalf("QuicBaaS() = %v, want a client built with the TLS configuration", err)
	}
	if q == nil {
		t.Fatal("QuicBaaS() returned a nil client")
	}
}

// TestPlatformClient_InitQuicBaaSClient_WithoutTLS verifies a quicbaasd
// address without a TLS configuration is refused with the typed error
// before the go-quicbaas SDK is called.
func TestPlatformClient_InitQuicBaaSClient_WithoutTLS(t *testing.T) {
	c := &platformClient{}
	c.initQuicBaaSClient(&Options{QuicBaaSAddr: "/run/quicbaas.sock", QuicBaaSTransport: "unix"})

	_, err := c.QuicBaaS()
	var initFailed ErrQuicBaaSInitFailed
	if !errors.As(err, &initFailed) {
		t.Fatalf("err = %v, want ErrQuicBaaSInitFailed", err)
	}
	if !errors.As(err, new(ErrQuicBaaSTLSNotConfigured)) {
		t.Errorf("err = %v, want it to wrap ErrQuicBaaSTLSNotConfigured", err)
	}
	if c.quicbaas != nil {
		t.Error("a connection without TLS must not create a client")
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
