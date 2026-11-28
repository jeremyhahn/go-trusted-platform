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
	"net"
	"slices"
	"strings"
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
			cfg.GeneratorSet = zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
				BridgeName: cfg.BridgeName,
				Quarantine: zoneflows.QuarantineConfig{DNSServerIP: net.IP(netplan.HostServices4.AsSlice())},
			})
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

// TestSharedZoneFlowManagerQuarantineAllowsDNS checks the production manager
// opens quarantine DNS to the host-services resolver and to nothing else.
func TestSharedZoneFlowManagerQuarantineAllowsDNS(t *testing.T) {
	zones := zone.Defaults()
	plan, err := netplan.New(netplan.Environment{ID: 4}, zones)
	require.NoError(t, err)

	rec := &recordingOVSPort{}
	zfm, err := newSharedZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName:     "br-fabric",
		FlowController: rec,
		PortController: rec,
		Plan:           plan,
		Zones:          zones,
	})
	require.NoError(t, err)
	require.NoError(t, zfm.ApplyZoneFlows(context.Background(), "tap0", zone.ZoneQuarantine))

	// Rules below the quarantine default drop (1100) never forward.
	const dnsPriority, quarantineDropPriority = 1800, 1100
	hostDNS := "nw_dst=" + netplan.HostServices4.String()
	var allowed []zoneflows.FlowRule
	for _, r := range rec.rules {
		fields := strings.Split(r.Match, ",")
		if r.Actions == "drop" || r.Priority <= quarantineDropPriority || !slices.Contains(fields, "tp_dst=53") {
			continue
		}
		require.True(t, slices.Contains(fields, hostDNS),
			"quarantine DNS rule open to a destination other than host services: %s", r.Match)
		allowed = append(allowed, r)
	}
	require.Len(t, allowed, 1, "quarantine must open exactly one DNS rule")
	require.Equal(t, dnsPriority, allowed[0].Priority)
	require.Contains(t, strings.Split(allowed[0].Match, ","), "nw_proto=17")
}

// TestSharedZoneFlowManagerServiceScopedPairDeniesOtherTraffic: through
// the shared wiring, a dns-only hypervisor → storage path opens DNS to
// storage above the matrix deny (200) and drops every other flow to the
// storage subnet at 200, below which the hypervisor template's catch-all
// normal rule sits (#1896).
func TestSharedZoneFlowManagerServiceScopedPairDeniesOtherTraffic(t *testing.T) {
	zones := zone.Defaults()
	for i := range zones {
		if zones[i].Name == zone.ZoneHypervisor {
			zones[i].AllowTo = append(zones[i].AllowTo,
				zone.ZonePath{Zone: zone.ZoneStorage, Services: []string{"dns"}})
		}
	}
	plan, err := netplan.New(netplan.Environment{ID: 4}, zones)
	require.NoError(t, err)
	storage, ok := plan.Zone(zone.ZoneStorage)
	require.True(t, ok)

	rec := &recordingOVSPort{}
	zfm, err := newSharedZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName:     "br-fabric",
		FlowController: rec,
		PortController: rec,
		Plan:           plan,
		Zones:          zones,
	})
	require.NoError(t, err)
	require.NoError(t, zfm.ApplyZoneFlows(context.Background(), "tap0", zone.ZoneHypervisor))

	const deny = 200
	dst := "nw_dst=" + storage.Subnet4.String()
	var dnsPermits, drops int
	for _, r := range rec.rules {
		fields := strings.Split(r.Match, ",")
		if !slices.Contains(fields, dst) {
			continue
		}
		switch {
		case r.Actions == "drop" && r.Priority == deny && !strings.Contains(r.Match, "tp_dst="):
			drops++
		case slices.Contains(fields, "tp_dst=53") && r.Actions == "normal":
			require.Greater(t, r.Priority, deny, "DNS permit below the destination drop: %s", r.Match)
			dnsPermits++
		case r.Actions != "drop":
			require.Greater(t, r.Priority, deny, "rule forwards unlisted traffic to storage: %+v", r)
		}
	}
	require.Positive(t, dnsPermits, "DNS to storage must be permitted")
	require.Positive(t, drops, "other traffic to storage must be dropped at %d", deny)
}
