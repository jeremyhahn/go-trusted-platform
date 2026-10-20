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

import "testing"

func TestProposalsAreHybrid(t *testing.T) {
	if ikeProposal != "aes256gcm16-prfsha384-ecp384-ke1_mlkem768" {
		t.Errorf("IKE proposal = %q, want ECP-384 with ML-KEM-768 as the additional exchange", ikeProposal)
	}
	if espProposal != "aes256gcm16-ecp384-ke1_mlkem768-esn" {
		t.Errorf("ESP proposal = %q, want PFS with ML-KEM-768 and ESN", espProposal)
	}
}
