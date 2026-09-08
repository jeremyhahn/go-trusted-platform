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

//go:build !fips

package bgp

// md5SessionAuthPermitted reports whether TCP-MD5 (RFC 2385) session
// authentication may be configured. Outside a FIPS build it is permitted as
// the compatibility path for peers that speak nothing newer; TCP-AO is the
// standard (ruling R1, 2026-09-07).
func md5SessionAuthPermitted() bool {
	return true
}
