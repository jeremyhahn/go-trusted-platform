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

package zoneflows_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestIngress_Match keys tagged ingress on the VLAN and untagged ingress on
// the absence of an 802.1Q header.
func TestIngress_Match(t *testing.T) {
	assert.Equal(t, "dl_vlan=405", zoneflows.Tagged(405).Match())
	assert.Equal(t, "vlan_tci=0x0000/0x1fff", zoneflows.Untagged(405).Match())
	assert.True(t, zoneflows.Tagged(1).Tagged)
	assert.False(t, zoneflows.Untagged(1).Tagged)
}

// TestGenerate_UntaggedIngress makes every template rule of an access port's
// zone match untagged frames: the flow tables never see dl_vlan on them.
func TestGenerate_UntaggedIngress(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	flows := gs.Generate("eth0", zone.ZoneProvisioning, zoneflows.Untagged(405))
	require.NotEmpty(t, flows)
	for _, f := range flows {
		assert.Contains(t, f.Match, "in_port=eth0,vlan_tci=0x0000/0x1fff", f.Match)
		assert.NotContains(t, f.Match, "dl_vlan", f.Match)
	}
}

// TestCompileMatrixRulesForPort emits the source zone's rows only, keyed on
// the port and untagged ingress, with the same verdicts as the tagged rules.
func TestCompileMatrixRulesForPort(t *testing.T) {
	defaults := zone.Defaults()
	cfg := zoneflows.MatrixRuleConfig{
		Matrix:         zone.CompileMatrix(defaults),
		Zones:          defaults,
		NetworksByZone: buildNetworks(defaults),
	}
	tagged := zoneflows.CompileMatrixRules(cfg)
	src := cfg.NetworksByZone[zone.ZoneBackup]
	var taggedFromBackup int
	for _, f := range tagged {
		if strings.HasPrefix(f.Match, zoneflows.Tagged(src.VLAN).Match()+",") {
			taggedFromBackup++
		}
	}

	port := zoneflows.CompileMatrixRulesForPort(cfg, "eth0", zone.ZoneBackup)
	require.NotEmpty(t, port)
	assert.Equal(t, taggedFromBackup, len(port), "one untagged rule per tagged rule of the zone")
	for _, f := range port {
		assert.True(t, strings.HasPrefix(f.Match, "in_port=eth0,vlan_tci=0x0000/0x1fff,"), f.Match)
	}
}

// TestCompileMatrixRulesForPort_Empty returns nothing without a port or a
// zone, or for a zone with no network.
func TestCompileMatrixRulesForPort_Empty(t *testing.T) {
	defaults := zone.Defaults()
	cfg := zoneflows.MatrixRuleConfig{
		Matrix: zone.CompileMatrix(defaults), Zones: defaults, NetworksByZone: buildNetworks(defaults),
	}
	assert.Nil(t, zoneflows.CompileMatrixRulesForPort(cfg, "", zone.ZoneBackup))
	assert.Nil(t, zoneflows.CompileMatrixRulesForPort(cfg, "eth0", ""))
	assert.Empty(t, zoneflows.CompileMatrixRulesForPort(cfg, "eth0", "nowhere"))
}
