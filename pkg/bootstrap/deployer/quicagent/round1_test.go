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

// startAgentWithConf serves an agent built from conf and returns its address.
func startAgentWithConf(t *testing.T, conf *tls.Config) string {
	t.Helper()
	srv, err := NewServer(conf, slog.New(slog.NewTextHandler(io.Discard, nil)))
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

// within fails the test when fn does not return inside d.
func within(t *testing.T, d time.Duration, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("call did not return within %s", d)
		return nil
	}
}

// A per-client TLS configuration from GetConfigForClient must not drop the
// mandatory client authentication.
func TestGetConfigForClientKeepsClientAuth(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	agentCert := ca.issue(t, testServerName, x509.ExtKeyUsageServerAuth, testServerName)
	addr := startAgentWithConf(t, &tls.Config{
		Certificates: []tls.Certificate{agentCert},
		ClientCAs:    ca.pool,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				Certificates: []tls.Certificate{agentCert},
				ClientCAs:    ca.pool,
				NextProtos:   []string{ALPN},
			}, nil
		},
	})

	// A client without a certificate, built past NewClient's own check.
	c := &Client{addr: addr, tlsConf: &tls.Config{
		RootCAs:          ca.pool,
		ServerName:       testServerName,
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		NextProtos:       []string{ALPN},
		CurvePreferences: fipsCurves,
	}}
	t.Cleanup(func() { _ = c.Close() })

	marker := filepath.Join(t.TempDir(), "ran")
	ctx := testCtx(t)
	err := c.Connect(ctx)
	if err == nil {
		_, err = c.Run(ctx, "touch '"+marker+"'")
	}
	if err == nil {
		t.Fatalf("a client without a certificate was accepted through GetConfigForClient")
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the agent ran a command for a client without a certificate (stat: %v)", statErr)
	}
}

// NewClient must refuse a configuration that skips agent verification.
func TestNewClientRejectsInsecureSkipVerify(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	_, err := NewClient("127.0.0.1:1", &tls.Config{
		Certificates:       []tls.Certificate{ca.issue(t, "deployer", x509.ExtKeyUsageClientAuth)},
		RootCAs:            ca.pool,
		ServerName:         testServerName,
		InsecureSkipVerify: true,
	})
	var cfgErr ErrInvalidTLSConfig
	if !errors.As(err, &cfgErr) {
		t.Fatalf("NewClient(InsecureSkipVerify) error = %v, want ErrInvalidTLSConfig", err)
	}
}

// A request frame over the size limit fails locally; the call must return
// that error instead of waiting for an answer the agent cannot send.
func TestOversizedRequestReturns(t *testing.T) {
	c := connectedPair(t)
	err := within(t, 5*time.Second, func() error {
		_, err := c.Run(context.Background(), strings.Repeat("x", maxFrameSize+1))
		return err
	})
	var tooLarge ErrFrameTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("Run(oversized) error = %v, want ErrFrameTooLarge", err)
	}
}

// A body reader that fails part way must end the call with its error.
func TestFailingBodyReaderReturns(t *testing.T) {
	c := connectedPair(t)
	readErr := errors.New("local read failed")
	dst := filepath.Join(t.TempDir(), "dst")
	err := within(t, 5*time.Second, func() error {
		_, err := c.roundTrip(context.Background(), request{Op: opCopy, Path: dst, Size: 1 << 20},
			func(w io.Writer) error {
				if _, err := w.Write([]byte("partial")); err != nil {
					return err
				}
				return readErr
			})
		return err
	})
	if !errors.Is(err, readErr) {
		t.Fatalf("roundTrip(failing body) error = %v, want %v", err, readErr)
	}
}
