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

func TestTerminal_String(t *testing.T) {
	assert.Equal(t, "normal", zoneflows.Terminal("").String())
	assert.Equal(t, "normal", zoneflows.TerminalNormal.String())
	assert.Equal(t, "goto_table:10", zoneflows.TerminalGatewayPipeline.String())
}

func TestApplyTerminal_RewritesOnlyTheNormalTerminal(t *testing.T) {
	rules := []zoneflows.FlowRule{
		{Actions: "normal"},
		{Actions: "mod_vlan_vid:100,normal"},
		{Actions: "drop"},
		{Actions: "output:3"},
		{Actions: "normalize"},
	}
	out := zoneflows.ApplyTerminal(rules, zoneflows.TerminalGatewayPipeline)
	assert.Equal(t, "goto_table:10", out[0].Actions)
	assert.Equal(t, "mod_vlan_vid:100,goto_table:10", out[1].Actions)
	assert.Equal(t, "drop", out[2].Actions)
	assert.Equal(t, "output:3", out[3].Actions)
	assert.Equal(t, "normalize", out[4].Actions, "a prefix is not the terminal")

	// The normal terminal and the empty terminal leave rules alone.
	same := zoneflows.ApplyTerminal([]zoneflows.FlowRule{{Actions: "normal"}}, zoneflows.TerminalNormal)
	assert.Equal(t, "normal", same[0].Actions)
	same = zoneflows.ApplyTerminal([]zoneflows.FlowRule{{Actions: "normal"}}, "")
	assert.Equal(t, "normal", same[0].Actions)
	assert.Nil(t, zoneflows.ApplyTerminal(nil, zoneflows.TerminalGatewayPipeline))
}

// TestGeneratorSet_TerminalReachesEveryTemplate pins the seam #567 adds: with
// the gateway-pipeline terminal configured, no built-in zone template still
// ends an allow rule in `normal`, and no drop is touched.
func TestGeneratorSet_TerminalReachesEveryTemplate(t *testing.T) {
	plain := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	handoff := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0", Terminal: zoneflows.TerminalGatewayPipeline})

	for _, z := range []zone.Zone{zone.ZoneQuarantine, zone.ZoneProvisioning, zone.ZoneControlPlane, zone.ZoneBackup, zone.ZoneStorage, zone.ZoneManagement} {
		before := plain.Generate("port-1", z, zoneflows.Tagged(200))
		after := handoff.Generate("port-1", z, zoneflows.Tagged(200))
		require.Len(t, after, len(before), "zone %s", z)
		normals := 0
		for i := range before {
			if strings.HasSuffix(before[i].Actions, "normal") {
				normals++
				assert.True(t, strings.HasSuffix(after[i].Actions, "goto_table:10"), "zone %s rule %d: %s", z, i, after[i].Actions)
			} else {
				assert.Equal(t, before[i].Actions, after[i].Actions, "zone %s rule %d must be untouched", z, i)
			}
			assert.Equal(t, before[i].Match, after[i].Match, "the terminal never changes a match")
		}
		assert.Positive(t, normals, "zone %s template has no allow rule to rewrite", z)
	}
}

func TestCompileMatrixRules_Terminal(t *testing.T) {
	defaults := zone.Defaults()
	matrix := zone.CompileMatrix(defaults)
	nets := map[zone.Zone]zoneflows.NetworkSummary{}
	for _, z := range defaults {
		nets[z.Name] = zoneflows.NetworkSummary{VLAN: 200, Subnet: "10.4.6.0/24"}
	}
	flows := zoneflows.CompileMatrixRules(zoneflows.MatrixRuleConfig{
		Matrix: matrix, Zones: defaults, NetworksByZone: nets, Terminal: zoneflows.TerminalGatewayPipeline,
	})
	require.NotEmpty(t, flows)
	for _, f := range flows {
		assert.NotEqual(t, "normal", f.Actions, "%s", f.Match)
		assert.True(t, f.Actions == "drop" || strings.HasSuffix(f.Actions, "goto_table:10"), "%s -> %s", f.Match, f.Actions)
	}
}

func TestTerminalForBridge(t *testing.T) {
	term, owner := zoneflows.TerminalForBridge(nil)
	assert.Equal(t, zoneflows.TerminalNormal, term)
	assert.Empty(t, owner)

	term, owner = zoneflows.TerminalForBridge(map[string]string{zoneflows.PipelineOwnerKey: ""})
	assert.Equal(t, zoneflows.TerminalNormal, term, "a cleared owner is no owner")
	assert.Empty(t, owner)

	term, owner = zoneflows.TerminalForBridge(map[string]string{
		zoneflows.PipelineOwnerKey:    "gatewayd:lab-node-1-gateway",
		zoneflows.PipelineTerminalKey: "normal",
	})
	assert.Equal(t, zoneflows.TerminalGatewayPipeline, term)
	assert.Equal(t, "gatewayd:lab-node-1-gateway", owner)
}
