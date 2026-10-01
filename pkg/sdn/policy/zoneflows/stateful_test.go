// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-control-plane-platform.
//
// go-control-plane-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package zoneflows

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// statefulTestConfig builds a two-zone matrix: control-plane may reach backup,
// backup is isolated from control-plane. Both zones have VLAN-backed networks.
func statefulTestConfig(defaultPolicy string) (MatrixRuleConfig, map[zone.Zone]uint16) {
	zones := []zone.ZoneConfig{
		{Name: zone.ZoneControlPlane, AllowTo: []zone.ZonePath{{Zone: zone.ZoneBackup}}},
		{Name: zone.ZoneBackup, IsolateFrom: []zone.Zone{zone.ZoneControlPlane}},
	}
	cfg := MatrixRuleConfig{
		Matrix: zone.CompileMatrix(zones),
		Zones:  zones,
		NetworksByZone: map[zone.Zone]NetworkSummary{
			zone.ZoneControlPlane: {VLAN: 100, Subnet: "10.0.100.0/24"},
			zone.ZoneBackup:       {VLAN: 200, Subnet: "10.0.200.0/24"},
		},
		DefaultPolicy: defaultPolicy,
	}
	ctZones := map[zone.Zone]uint16{
		zone.ZoneControlPlane: 11,
		zone.ZoneBackup:       22,
	}
	return cfg, ctZones
}

// TestCompileStatefulMatrixRules_Golden asserts the exact rule set for the
// two-zone matrix, pinning the string grammar the ovs parser consumes.
func TestCompileStatefulMatrixRules_Golden(t *testing.T) {
	cfg, ctZones := statefulTestConfig("deny")

	got := CompileStatefulMatrixRules(cfg, ctZones)

	want := []FlowRule{
		// Table 20 base: non-IP / unclassified bypass.
		{Table: 20, Priority: 1, Match: "", Actions: "goto_table:30"},

		// control-plane (VLAN 100, ct zone 11): gate + scaffolding.
		{Table: 20, Priority: 100, Match: "dl_vlan=100,dl_type=0x0800", Actions: "ct(table=21,zone=11)"},
		{Table: 20, Priority: 100, Match: "dl_vlan=100,dl_type=0x86dd", Actions: "ct(table=21,zone=11)"},
		{Table: 20, Priority: 200, Match: "dl_vlan=100,dl_type=0x86dd,nw_proto=58,icmp_type=133", Actions: "goto_table:30"},
		{Table: 20, Priority: 200, Match: "dl_vlan=100,dl_type=0x86dd,nw_proto=58,icmp_type=134", Actions: "goto_table:30"},
		{Table: 20, Priority: 200, Match: "dl_vlan=100,dl_type=0x86dd,nw_proto=58,icmp_type=135", Actions: "goto_table:30"},
		{Table: 20, Priority: 200, Match: "dl_vlan=100,dl_type=0x86dd,nw_proto=58,icmp_type=136", Actions: "goto_table:30"},
		{Table: 20, Priority: 200, Match: "dl_vlan=100,dl_type=0x86dd,nw_proto=58,icmp_type=137", Actions: "goto_table:30"},
		{Table: 21, Priority: 400, Match: "ct_state=+inv+trk,dl_vlan=100", Actions: "drop"},
		{Table: 21, Priority: 300, Match: "ct_state=+est+trk,dl_vlan=100", Actions: "goto_table:30"},
		{Table: 21, Priority: 300, Match: "ct_state=+rel+trk,dl_vlan=100", Actions: "goto_table:30"},

		// control-plane → control-plane (intra-zone allowed) and control-plane → backup (allowed).
		{Table: 21, Priority: 100, Match: "ct_state=+new+trk,dl_vlan=100,dl_type=0x0800,nw_dst=10.0.100.0/24", Actions: "ct(commit,zone=11),goto_table:30"},
		{Table: 21, Priority: 100, Match: "ct_state=+new+trk,dl_vlan=100,dl_type=0x0800,nw_dst=10.0.200.0/24", Actions: "ct(commit,zone=11),goto_table:30"},

		// backup (VLAN 200, ct zone 22): gate + scaffolding.
		{Table: 20, Priority: 100, Match: "dl_vlan=200,dl_type=0x0800", Actions: "ct(table=21,zone=22)"},
		{Table: 20, Priority: 100, Match: "dl_vlan=200,dl_type=0x86dd", Actions: "ct(table=21,zone=22)"},
		{Table: 20, Priority: 200, Match: "dl_vlan=200,dl_type=0x86dd,nw_proto=58,icmp_type=133", Actions: "goto_table:30"},
		{Table: 20, Priority: 200, Match: "dl_vlan=200,dl_type=0x86dd,nw_proto=58,icmp_type=134", Actions: "goto_table:30"},
		{Table: 20, Priority: 200, Match: "dl_vlan=200,dl_type=0x86dd,nw_proto=58,icmp_type=135", Actions: "goto_table:30"},
		{Table: 20, Priority: 200, Match: "dl_vlan=200,dl_type=0x86dd,nw_proto=58,icmp_type=136", Actions: "goto_table:30"},
		{Table: 20, Priority: 200, Match: "dl_vlan=200,dl_type=0x86dd,nw_proto=58,icmp_type=137", Actions: "goto_table:30"},
		{Table: 21, Priority: 400, Match: "ct_state=+inv+trk,dl_vlan=200", Actions: "drop"},
		{Table: 21, Priority: 300, Match: "ct_state=+est+trk,dl_vlan=200", Actions: "goto_table:30"},
		{Table: 21, Priority: 300, Match: "ct_state=+rel+trk,dl_vlan=200", Actions: "goto_table:30"},

		// backup → control-plane (denied) and backup → backup (intra-zone allowed).
		{Table: 21, Priority: 200, Match: "ct_state=+new+trk,dl_vlan=200,dl_type=0x0800,nw_dst=10.0.100.0/24", Actions: "drop"},
		{Table: 21, Priority: 100, Match: "ct_state=+new+trk,dl_vlan=200,dl_type=0x0800,nw_dst=10.0.200.0/24", Actions: "ct(commit,zone=22),goto_table:30"},

		// Verdict table miss: DefaultPolicy deny.
		{Table: 21, Priority: 0, Match: "", Actions: "drop"},
	}

	if len(got) != len(want) {
		t.Fatalf("rule count = %d, want %d\ngot: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule %d:\n got  %+v\n want %+v", i, got[i], want[i])
		}
	}
}

func TestCompileStatefulMatrixRules_DefaultPolicyAllow(t *testing.T) {
	cfg, ctZones := statefulTestConfig(DefaultPolicyAllow)

	got := CompileStatefulMatrixRules(cfg, ctZones)

	miss := got[len(got)-1]
	want := FlowRule{Table: 21, Priority: 0, Match: "", Actions: "goto_table:30"}
	if miss != want {
		t.Errorf("miss rule = %+v, want %+v", miss, want)
	}
}

func TestCompileStatefulMatrixRules_SkipsUnbackedZones(t *testing.T) {
	cfg, ctZones := statefulTestConfig("deny")

	// A zone with no network mapping produces no gate or verdict rules.
	cfg.Zones = append(cfg.Zones, zone.ZoneConfig{Name: zone.Zone("ether")})

	// A zone with a network but no allocated ct zone is skipped too.
	cfg.Zones = append(cfg.Zones, zone.ZoneConfig{Name: zone.ZoneStorage})
	cfg.NetworksByZone[zone.ZoneStorage] = NetworkSummary{VLAN: 300, Subnet: "10.0.300.0/24"}

	got := CompileStatefulMatrixRules(cfg, ctZones)

	for _, rule := range got {
		if rule.Match == "dl_vlan=300,dl_type=0x0800" {
			t.Errorf("zone without ct allocation must not get a gate: %+v", rule)
		}
	}

	// The storage subnet still appears as a destination for gated zones:
	// control-plane → storage is denied by the matrix (no AllowTo path).
	found := false
	for _, rule := range got {
		if rule.Match == "ct_state=+new+trk,dl_vlan=100,dl_type=0x0800,nw_dst=10.0.300.0/24" && rule.Actions == "drop" {
			found = true
		}
	}
	if !found {
		t.Error("expected control-plane → storage deny verdict")
	}
}

func TestCompileStatefulMatrixRules_EmptyConfig(t *testing.T) {
	got := CompileStatefulMatrixRules(MatrixRuleConfig{}, nil)

	// Only the table 20 bypass and the table 21 miss remain, and the
	// empty DefaultPolicy defaults to deny.
	want := []FlowRule{
		{Table: 20, Priority: 1, Match: "", Actions: "goto_table:30"},
		{Table: 21, Priority: 0, Match: "", Actions: "drop"},
	}
	if len(got) != len(want) {
		t.Fatalf("rule count = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
