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

package quicagent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startAgentWithConfigForClient runs a Server whose TLS configuration
// carries a GetConfigForClient callback returning cb's config.
func startAgentWithConfigForClient(t *testing.T, ca *testCA, cb func(*tls.ClientHelloInfo) (*tls.Config, error)) string {
	t.Helper()
	srv, err := NewServer(&tls.Config{
		Certificates:       []tls.Certificate{ca.issue(t, testServerName, x509.ExtKeyUsageServerAuth, testServerName)},
		ClientCAs:          ca.pool,
		GetConfigForClient: cb,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, pc) }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		<-done
		_ = pc.Close()
	})
	return pc.LocalAddr().String()
}

// A GetConfigForClient callback returning a default configuration must not
// drop the client certificate requirement.
func TestServerConfigForClientKeepsClientAuth(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	leaf := ca.issue(t, testServerName, x509.ExtKeyUsageServerAuth, testServerName)
	addr := startAgentWithConfigForClient(t, ca, func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{Certificates: []tls.Certificate{leaf}, NextProtos: []string{ALPN}}, nil
	})

	c, err := NewClient(addr, &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil
		},
		RootCAs:    ca.pool,
		ServerName: testServerName,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	marker := filepath.Join(t.TempDir(), "ran")
	ctx := testCtx(t)
	err = c.Connect(ctx)
	if err == nil {
		_, err = c.Run(ctx, "touch '"+marker+"'")
	}
	if err == nil {
		t.Fatalf("a client with no certificate was accepted through GetConfigForClient")
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the agent ran a command for a client with no certificate (stat: %v)", statErr)
	}
}

// A callback returning a nil configuration falls back to the hardened base.
func TestServerConfigForClientNilFallsBack(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	addr := startAgentWithConfigForClient(t, ca, func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return nil, nil
	})
	c := newTestClient(t, addr, ca, ca)
	ctx := testCtx(t)
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	out, err := c.Run(ctx, "printf ok")
	if err != nil || out != "ok" {
		t.Fatalf("Run = (%q, %v), want (\"ok\", nil)", out, err)
	}
}

// TestServeCancelStopsRunningCommand cancels Serve's context while a
// long-running command is in flight: the command's process group is
// killed, so the client's Run and Serve both return promptly instead of
// waiting out the sleep (Codex round 3 finding 3 on #1853).
func TestServeCancelStopsRunningCommand(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	srv, err := NewServer(&tls.Config{
		Certificates: []tls.Certificate{ca.issue(t, testServerName, x509.ExtKeyUsageServerAuth, testServerName)},
		ClientCAs:    ca.pool,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	serveCtx, cancelServe := context.WithCancel(context.Background())
	defer cancelServe()
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(serveCtx, pc) }()

	c := newTestClient(t, pc.LocalAddr().String(), ca, ca)
	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelConnect()
	if err := c.Connect(connectCtx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	type runResult struct {
		out string
		err error
	}
	runDone := make(chan runResult, 1)
	runCtx, cancelRun := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelRun()
	go func() {
		out, err := c.Run(runCtx, "sleep 300; echo done")
		runDone <- runResult{out: out, err: err}
	}()

	// Give the agent time to start the shell before cancelling.
	time.Sleep(500 * time.Millisecond)
	select {
	case r := <-runDone:
		t.Fatalf("Run returned before cancel: out=%q err=%v", r.out, r.err)
	default:
	}
	cancelServe()

	const limit = 5 * time.Second
	deadline := time.After(limit)
	select {
	case r := <-runDone:
		if r.err == nil {
			t.Fatalf("Run after cancel: err = nil, out = %q; want an error", r.out)
		}
		if strings.Contains(r.out, "done") {
			t.Fatalf("Run output = %q: the command ran to completion", r.out)
		}
	case <-deadline:
		t.Fatalf("Run did not return within %s of cancelling Serve", limit)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve after cancel: %v", err)
		}
	case <-deadline:
		t.Fatalf("Serve did not return within %s of cancel", limit)
	}
}
