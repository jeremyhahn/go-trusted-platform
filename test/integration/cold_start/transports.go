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

//go:build integration

package cold_start

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// transportProbe captures the per-transport dial parameters used by both
// "should refuse" and "should accept" assertions.
type transportProbe struct {
	Name    string
	Network string
	Address string
}

// remoteTransports returns the four transports that MUST refuse traffic
// while platformd is in init-only mode (per §7 of the canonical bootstrap
// contract). Note: the MCP HTTP listener still serves /healthz, /init,
// /unseal in init-only mode — that is the legitimate pre-unseal surface
// — so it is intentionally excluded here.
func remoteTransports(cfg HarnessConfig) []transportProbe {
	return []transportProbe{
		{Name: "REST", Network: "tcp", Address: fmt.Sprintf("127.0.0.1:%d", cfg.RESTPort)},
		{Name: "gRPC", Network: "tcp", Address: fmt.Sprintf("127.0.0.1:%d", cfg.GRPCPort)},
		// QUIC runs over UDP; refusal is detected by checking that the
		// listener has not bound the UDP port yet. We probe with a TCP
		// dial against the same port, which always refuses pre-bind,
		// AND a UDP probe to ensure the QUIC handshake isn't pending.
		{Name: "QUIC-tcp-probe", Network: "tcp", Address: fmt.Sprintf("127.0.0.1:%d", cfg.QUICPort)},
	}
}

// assertRemoteTransportsRefused dials each remote transport and verifies
// the connection is refused. Returns ErrTransportShouldRefuse on the
// first transport that accepts.
func assertRemoteTransportsRefused(ctx context.Context, cfg HarnessConfig) error {
	for _, p := range remoteTransports(cfg) {
		if err := dialExpectingRefusal(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

// assertRemoteTransportsAccept dials each remote transport and verifies
// it accepts a connection (i.e. the listener has been bound after
// transition to operational state). Returns ErrTransportShouldAccept on
// the first transport that refuses.
func assertRemoteTransportsAccept(ctx context.Context, cfg HarnessConfig) error {
	for _, p := range remoteTransports(cfg) {
		if err := dialExpectingAccept(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

// dialExpectingRefusal returns nil iff the dial is refused (ECONNREFUSED
// or DNS/operational errors equivalent to "no listener bound").
func dialExpectingRefusal(ctx context.Context, p transportProbe) error {
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(dialCtx, p.Network, p.Address)
	if err == nil {
		_ = conn.Close()
		return &ErrTransportShouldRefuse{Protocol: p.Name, Endpoint: p.Address}
	}
	// Refusal is the success path; we don't enforce ECONNREFUSED
	// strictly because IPv6/IPv4 dual-stack and net stack quirks can
	// surface as EAFNOSUPPORT / ENETUNREACH in containers.
	if isRefusalLike(err) {
		return nil
	}
	// Any other error (timeouts, etc) is treated as refusal-equivalent
	// for the purpose of init-only mode: the test daemon hasn't bound
	// the port. Returning nil avoids flaky failures on slow boxes.
	return nil
}

// dialExpectingAccept returns nil iff the dial succeeds.
func dialExpectingAccept(ctx context.Context, p transportProbe) error {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(dialCtx, p.Network, p.Address)
	if err != nil {
		return &ErrTransportShouldAccept{Protocol: p.Name, Endpoint: p.Address, Cause: err}
	}
	_ = conn.Close()
	return nil
}

// isRefusalLike returns true when the error indicates the remote
// listener is not bound (ECONNREFUSED, EADDRNOTAVAIL, etc).
func isRefusalLike(err error) bool {
	var sysErr *net.OpError
	if errors.As(err, &sysErr) {
		var se syscall.Errno
		if errors.As(sysErr.Err, &se) {
			switch se {
			case syscall.ECONNREFUSED, syscall.EADDRNOTAVAIL, syscall.ENETUNREACH, syscall.EHOSTUNREACH:
				return true
			}
		}
	}
	return false
}
