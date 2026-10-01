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

package sdn_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestNetworkSummaries projects every zone of a dual-stack plan.
func TestNetworkSummaries(t *testing.T) {
	plan, err := netplan.New(netplan.Environment{ID: 4, ULA: netip.MustParsePrefix("fd12:3456:789a::/48")}, zone.Defaults())
	require.NoError(t, err)

	nets := sdn.NetworkSummaries(plan)
	require.Len(t, nets, 9)
	cp := nets[zone.ZoneControlPlane]
	assert.Equal(t, uint16(406), cp.VLAN)
	assert.Equal(t, "10.4.6.0/24", cp.Subnet)
	assert.Equal(t, "fd12:3456:789a:406::/64", cp.Subnet6)
}

// TestNetworkSummaries_NilPlan yields an empty map, never a default.
func TestNetworkSummaries_NilPlan(t *testing.T) {
	nets := sdn.NetworkSummaries(nil)
	require.NotNil(t, nets)
	assert.Empty(t, nets)
}
