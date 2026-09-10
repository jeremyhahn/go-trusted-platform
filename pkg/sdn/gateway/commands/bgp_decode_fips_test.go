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

//go:build fips

package commands

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// assertMD5NeighborValidateContract: in the FIPS build TCP-MD5 does not
// exist (handbook configuration.md: only approved algorithms exist), so the
// same configuration is refused with the typed error naming the peer and
// pointing at tcp-ao.
func assertMD5NeighborValidateContract(t *testing.T, b *bgp.BGPConfig) {
	t.Helper()
	err := b.Validate()
	var unavailable bgp.ErrAuthTypeUnavailableInFIPS
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, "10.255.0.2", unavailable.Peer)
	assert.Equal(t, bgp.AuthTypeMD5, unavailable.AuthType)
}

// assertShippedTemplateValidateContract is the FIPS half of the shipped
// gatewayd template's contract. The template's four sessions use the MD5
// compatibility path the relays speak today, so a FIPS build refuses them —
// that refusal is the point of ruling R1, not a defect in the template.
func assertShippedTemplateValidateContract(t *testing.T, b *bgp.BGPConfig) {
	t.Helper()
	err := b.Validate()
	var unavailable bgp.ErrAuthTypeUnavailableInFIPS
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, "10.255.0.34", unavailable.Peer, "the first peer in the shipped file")
	assert.Equal(t, bgp.AuthTypeMD5, unavailable.AuthType)
}
