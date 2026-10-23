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

package nbd

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// serveInBackground runs Serve on a loopback listener and returns its
// address and the channel Serve's result arrives on.
func serveInBackground(t *testing.T, ctx context.Context, server *Server) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx, ln) }()
	return ln.Addr().String(), result
}

func TestServe_CloseEndsOpenSessions(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	server := newTestServer(t, testConfig(t, bundle))
	addr, result := serveInBackground(t, t.Context(), server)

	c := attach(t, addr, bundle)
	c.request(cmdFlush, 0, 1, 0, 0, nil)
	if code := c.simpleReply(1); code != errNone {
		t.Fatalf("FLUSH error = %d", code)
	}

	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("Serve = %v, want nil on Close", err)
	}
	c.expectClosed()
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestServe_ContextCancelStopsTheServer(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	server := newTestServer(t, testConfig(t, bundle))
	ctx, cancel := context.WithCancel(t.Context())
	addr, result := serveInBackground(t, ctx, server)

	c := dialClient(t, addr, clientFlagFixedNewstyle|clientFlagNoZeroes)
	cancel()
	if err := awaitResult(t, result); err != nil {
		t.Fatalf("Serve = %v, want nil on cancel", err)
	}
	c.expectClosed()
	if _, err := net.Dial("tcp", addr); err == nil {
		t.Fatal("the listener still accepts after shutdown")
	}
}

func TestServe_ListenerFailureIsReported(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	server := newTestServer(t, testConfig(t, bundle))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var failed ErrServeFailed
	if err := server.Serve(t.Context(), ln); !errors.As(err, &failed) || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve = %v, want ErrServeFailed wrapping net.ErrClosed", err)
	}
}

func TestNewServer_RejectsInvalidConfig(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	cfg := testConfig(t, bundle)
	cfg.Anchor = nil

	var invalid ErrInvalidConfig
	if _, err := NewServer(cfg); !errors.As(err, &invalid) || invalid.Field != "Anchor" {
		t.Fatalf("NewServer = %v, want ErrInvalidConfig for Anchor", err)
	}
}

func TestNewServer_AppliesDefaultsAndFoldsIdentities(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	cfg := testConfig(t, bundle)
	cfg.Identities = []string{"Node-01"}
	cfg.Logger = nil

	server := newTestServer(t, cfg)
	if server.handshakeTimeout != DefaultHandshakeTimeout {
		t.Fatalf("handshake timeout = %v", server.handshakeTimeout)
	}
	if server.logger == nil {
		t.Fatal("no default logger")
	}
	if _, ok := server.identities["node-01"]; !ok {
		t.Fatalf("identities = %v, want the lowercased hostname", server.identities)
	}
}
