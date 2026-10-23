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

package vpn

import "github.com/jeremyhahn/go-trusted-platform/pkg/vpn/agent"

// kernelDataPlanes is empty in a FIPS build: WireGuard's primitives are not
// FIPS-approved, so the gateway's hub and this client are both absent.
func kernelDataPlanes() []agent.DataPlane {
	return nil
}
