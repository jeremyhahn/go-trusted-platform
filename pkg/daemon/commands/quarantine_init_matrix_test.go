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

package commands

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// recordingOVSPort accepts every OVS operation and records the flow rules
// each InstallFlows batch carries.
type recordingOVSPort struct {
	nullOVSPort
	rules []zoneflows.FlowRule
}

func (r *recordingOVSPort) InstallFlows(_ string, rules []zoneflows.FlowRule) error {
	r.rules = append(r.rules, rules...)
	return nil
}

// TestSharedZoneFlowManagerCarriesTheZoneMatrix requires the zone flow
// manager initSDNPolicy shares with the policy engine, the quarantine loop
// and the PXE backend to install the inter-zone matrix rules of the
// resolved zones: without the matrix every AllowTo path (quarantine ->
// control-plane among them) is denied on every port it moves (#1896 F48).
func TestSharedZoneFlowManagerCarriesTheZoneMatrix(t *testing.T) {
	zones := zone.Defaults()
	plan, err := netplan.New(netplan.Environment{ID: 4}, zones)
	require.NoError(t, err)

	build := func(rec *recordingOVSPort, matrix zone.Matrix, shared bool) *policy.ZoneFlowManager {
		cfg := policy.ZoneFlowManagerConfig{
			BridgeName:     "br-fabric",
			FlowController: rec,
			PortController: rec,
			Plan:           plan,
			Zones:          zones,
			Matrix:         matrix,
		}
		var zfm *policy.ZoneFlowManager
		if shared {
			zfm, err = newSharedZoneFlowManager(cfg)
		} else {
			zfm, err = policy.NewZoneFlowManager(cfg)
		}
		require.NoError(t, err)
		return zfm
	}

	gotRec, wantRec, noneRec := &recordingOVSPort{}, &recordingOVSPort{}, &recordingOVSPort{}
	got := build(gotRec, zone.Matrix{}, true)
	want := build(wantRec, zone.CompileMatrix(zones), false)
	none := build(noneRec, zone.Matrix{}, false)

	ctx := context.Background()
	for _, m := range []*policy.ZoneFlowManager{got, want, none} {
		require.NoError(t, m.ApplyZoneFlows(ctx, "tap0", zone.ZoneQuarantine))
	}

	require.NotEqual(t, noneRec.rules, wantRec.rules,
		"the compiled matrix must open rules the zero matrix does not")
	require.ElementsMatch(t, wantRec.rules, gotRec.rules)
}
