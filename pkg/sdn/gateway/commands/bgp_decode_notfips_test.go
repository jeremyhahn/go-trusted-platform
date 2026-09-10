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

package commands

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// assertMD5NeighborValidateContract: outside the FIPS build, TCP-MD5 is the
// per-peer compatibility option the ASRs and the VPS BIRD nodes use today,
// so a configuration naming it validates.
func assertMD5NeighborValidateContract(t *testing.T, b *bgp.BGPConfig) {
	t.Helper()
	require.NoError(t, b.Validate())
}

// assertShippedTemplateValidateContract is the non-FIPS half: the shipped
// gatewayd template is a configuration the daemon accepts as it stands,
// traffic-engineering ladder included.
func assertShippedTemplateValidateContract(t *testing.T, b *bgp.BGPConfig) {
	t.Helper()
	require.NoError(t, b.Validate())
}
