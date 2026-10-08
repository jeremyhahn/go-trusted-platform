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

//go:build fips

package ipsec

// The FIPS proposals hold to the validated module's algorithms: the hybrid
// ML-KEM exchange of the default build is left out. The ESP proposal still
// carries its own key exchange, so every CHILD_SA rekey is perfect forward
// secret, and requires extended sequence numbers.
const (
	ikeProposal = "aes256gcm16-prfsha384-ecp384"
	espProposal = "aes256gcm16-ecp384-esn"
)
