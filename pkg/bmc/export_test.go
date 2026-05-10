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

package bmc

import (
	"context"
	"log/slog"
)

// TestRMCPSession is a test-only wrapper exposing a minimal view over
// the unexported rmcpSession so external test packages (e.g.
// pkg/bmc_test, which has to live outside package bmc to break the
// import cycle with test/integration/bmc/rmcpsim) can exercise
// handshake internals.
type TestRMCPSession struct {
	inner *rmcpSession
}

// NewTestRMCPSession constructs a TestRMCPSession bound to config.
// Must only be used from _test.go files.
func NewTestRMCPSession(config *Config, logger *slog.Logger) *TestRMCPSession {
	return &TestRMCPSession{inner: newRMCPSession(config, logger)}
}

// Open opens the RMCP+ session against the configured BMC address.
func (t *TestRMCPSession) Open(ctx context.Context) error {
	return t.inner.Open(ctx)
}

// Close tears the session down.
func (t *TestRMCPSession) Close() error {
	return t.inner.Close()
}

// SIK returns the derived Session Integrity Key, or nil pre-handshake.
func (t *TestRMCPSession) SIK() []byte { return t.inner.sik }

// K1 returns the derived integrity key, or nil pre-handshake.
func (t *TestRMCPSession) K1() []byte { return t.inner.k1 }

// K2 returns the derived confidentiality key, or nil pre-handshake.
func (t *TestRMCPSession) K2() []byte { return t.inner.k2 }

// BMCSessionID returns the negotiated BMC session identifier, or 0
// pre-handshake.
func (t *TestRMCPSession) BMCSessionID() uint32 { return t.inner.bmcSessionID }
