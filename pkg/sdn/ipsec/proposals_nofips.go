// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ipsec

// The proposals add ML-KEM-768 as a second key exchange after ECP-384
// (RFC 9370), so a session key holds while either exchange does. The ESP
// proposal carries its own key exchange, which makes every CHILD_SA rekey
// perfect forward secret, and requires extended sequence numbers.
const (
	ikeProposal = "aes256gcm16-prfsha384-ecp384-ke1_mlkem768"
	espProposal = "aes256gcm16-ecp384-ke1_mlkem768-esn"
)
