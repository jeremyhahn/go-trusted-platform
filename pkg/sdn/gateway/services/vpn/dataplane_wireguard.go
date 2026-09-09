//go:build !fips

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

package vpn

// DataPlaneWireGuard is the kernel WireGuard data plane. Its primitives
// (Curve25519, ChaCha20-Poly1305, BLAKE2s) are not FIPS 140-3 approved, so
// this symbol does not exist in a `fips` build and a configuration naming it
// there is refused at load.
const DataPlaneWireGuard DataPlaneKind = "wireguard"

func init() {
	dataPlaneKinds[DataPlaneWireGuard] = true
}
