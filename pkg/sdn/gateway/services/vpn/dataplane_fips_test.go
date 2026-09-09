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

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWireGuardIsAbsentUnderFIPS: the kind is not Known, so a configuration
// naming it is refused at load — there is no WireGuard symbol to reach.
func TestWireGuardIsAbsentUnderFIPS(t *testing.T) {
	assert.False(t, DataPlaneKind("wireguard").Known())
	cfg := testConfig()
	cfg.DataPlanes = []DataPlaneKind{"wireguard"}
	err := cfg.WithDefaults().Validate()
	var invalid *ErrInvalidConfig
	require.True(t, errors.As(err, &invalid))
	assert.Equal(t, "data-planes", invalid.Field)
}
