//go:build fips

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

package tunnel

import (
	"context"

	vnl "github.com/vishvananda/netlink"
)

// wireGuardAvailable is false in FIPS builds: WireGuard's primitives
// (Curve25519, ChaCha20-Poly1305, BLAKE2s) are not FIPS-approved, so the
// transport is compiled out and refused at configuration time.
const wireGuardAvailable = false

const wireGuardUnavailableReason = "WireGuard is compiled out of FIPS builds (non-approved primitives); use the ipsec transport"

// wgOps has no implementation in a FIPS build.
type wgOps interface {
	Close() error
}

func (m *Manager) createWireGuard(_ context.Context, config TunnelConfig) error {
	return &ErrTransportUnavailable{Name: config.Name, Transport: TransportWireGuard, Reason: wireGuardUnavailableReason}
}

func (m *Manager) rekeyWireGuard(_ context.Context, config TunnelConfig) error {
	return &ErrTransportUnavailable{Name: config.Name, Transport: TransportWireGuard, Reason: wireGuardUnavailableReason}
}

// adoptWireGuard adopts nothing in a FIPS build: the transport is refused
// before any link is looked at.
func (m *Manager) adoptWireGuard(_ context.Context, _ vnl.Link, _ TunnelConfig) (bool, error) {
	return false, nil
}
