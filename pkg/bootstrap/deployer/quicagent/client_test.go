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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewClientRejectsInsecureSkipVerify(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	cfg := &tls.Config{
		Certificates: []tls.Certificate{ca.issue(t, "deployer", x509.ExtKeyUsageClientAuth)},
		RootCAs:      ca.pool,
		ServerName:   testServerName,
	}
	// The test asserts NewClient refuses a config that skips verification.
	cfg.InsecureSkipVerify = true
	_, err := NewClient(idleAddr(), cfg)
	var cfgErr ErrInvalidTLSConfig
	if !errors.As(err, &cfgErr) {
		t.Fatalf("NewClient with InsecureSkipVerify error = %v, want ErrInvalidTLSConfig", err)
	}
}

func TestConnectRejectsUntrustedServer(t *testing.T) {
	agentCA := newTestCA(t, "agent-ca")
	otherCA := newTestCA(t, "other-ca")
	addr := startAgent(t, agentCA, agentCA)
	c := newTestClient(t, addr, otherCA, agentCA)
	if err := c.Connect(testCtx(t)); err == nil {
		t.Fatalf("Connect accepted an agent certificate from an untrusted CA")
	}
}

// promptCtx bounds a call that must fail on its own, well before the
// deadline.
func promptCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestRunOversizedCommandFailsPromptly(t *testing.T) {
	c := connectedPair(t)
	ctx := promptCtx(t)
	_, err := c.Run(ctx, strings.Repeat("x", maxFrameSize+1))
	var tooLarge ErrFrameTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("Run error = %v, want ErrFrameTooLarge", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("Run waited for the deadline: %v", ctx.Err())
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestRoundTripBodyFailureReturnsPromptly(t *testing.T) {
	c := connectedPair(t)
	ctx := promptCtx(t)
	boom := errors.New("body source failed")
	body := func(w io.Writer) error {
		_, err := io.Copy(w, failingReader{err: boom})
		return err
	}
	dst := filepath.Join(t.TempDir(), "dst")
	_, err := c.roundTrip(ctx, request{Op: opCopy, Path: dst, Size: 1 << 20}, body)
	if !errors.Is(err, boom) {
		t.Fatalf("roundTrip error = %v, want the body error", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("roundTrip waited for the deadline: %v", ctx.Err())
	}
}
