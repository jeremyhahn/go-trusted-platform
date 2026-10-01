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

package bgp

import (
	"context"
	"net/netip"
	"testing"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Acceptance against a real GoBGP server.
//
// Every other test in this package drives a mock BGPServerInterface, which
// accepts whatever it is handed. That proves what the speaker *sends* and
// says nothing about whether GoBGP will take it — which is how #620 stayed
// invisible: the shipped dual-stack configuration built a prefix set GoBGP
// refuses outright, so gatewayd could not start, and every test passed.
//
// These tests hand the real thing the policy the speaker builds. The server
// is never started (no StartBgp), so nothing binds a port and nothing talks
// to a peer; only the policy conversion runs, which is the part that
// rejects malformed input.

// realGoBGP returns a running-but-unstarted GoBGP server for policy
// acceptance checks.
func realGoBGP(t *testing.T) *server.BgpServer {
	t.Helper()
	srv := server.NewBgpServer()
	go srv.Serve()
	t.Cleanup(srv.Stop)
	return srv
}

// TestRealGoBGP_AcceptsDualStackPolicySet is the #620 regression: a peer
// whose allowlist and whose speaker's announce list both span IPv4 and
// IPv6 must produce a policy set GoBGP accepts. Before the per-family
// split this failed with "multiple families" and took Speaker.Start with
// it.
func TestRealGoBGP_AcceptsDualStackPolicySet(t *testing.T) {
	cfg := baseConfig() // announces both 23.143.36.0/24 and 2602:f5bb::/36
	cfg.Neighbors = []NeighborConfig{{
		Name:            "miami-att",
		Address:         netip.MustParseAddr("10.255.0.34"),
		ASN:             401870,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast, AFamilyIPv6Unicast},
		Policy: PeerPolicyConfig{
			ImportAllow: []PrefixMatch{
				{Prefix: netip.MustParsePrefix("0.0.0.0/0")},
				{Prefix: netip.MustParsePrefix("::/0")},
			},
		},
	}}
	require.NoError(t, cfg.Validate())

	s := &Speaker{config: cfg}
	set, err := s.policySet()
	require.NoError(t, err)
	require.NoError(t, realGoBGP(t).SetPolicies(context.Background(), set),
		"gobgp must accept the policy a dual-stack peer produces")
}

// TestRealGoBGP_AcceptsTrafficEngineering hands GoBGP every attribute the
// configuration can express. It is the difference between "we built the
// statement we meant to" and "GoBGP will program it": an action GoBGP
// cannot convert fails here rather than on the hardware at start.
func TestRealGoBGP_AcceptsTrafficEngineering(t *testing.T) {
	cfg := baseConfig()
	cfg.Neighbors = []NeighborConfig{{
		Name:            "miami-att",
		Address:         netip.MustParseAddr("10.255.0.34"),
		ASN:             401870,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast, AFamilyIPv6Unicast},
		Policy: PeerPolicyConfig{
			ImportAllow: []PrefixMatch{{Prefix: netip.MustParsePrefix("0.0.0.0/0")}},
			Import: &PeerAttributesConfig{
				LocalPref:   u32(200),
				Communities: &CommunitySetConfig{Action: CommunityOpRemove, Values: []string{"^65001:"}},
			},
			Export: &PeerAttributesConfig{
				MED:              u32(50),
				Prepend:          &ASPathPrependConfig{Count: 3},
				Communities:      &CommunitySetConfig{Action: CommunityOpAdd, Values: []string{"no-export"}},
				LargeCommunities: &CommunitySetConfig{Action: CommunityOpReplace, Values: []string{"401870:1:200"}},
			},
		},
	}}
	require.NoError(t, cfg.Validate())

	s := &Speaker{config: cfg}
	set, err := s.policySet()
	require.NoError(t, err)
	require.NoError(t, realGoBGP(t).SetPolicies(context.Background(), set),
		"gobgp must accept every traffic-engineering action the config can express")
}

// TestRealGoBGP_AcceptsTheEmptyPolicySet covers the bring-up shape: a peer
// that announces nothing and filters everything still has to install.
func TestRealGoBGP_AcceptsTheEmptyPolicySet(t *testing.T) {
	cfg := baseConfig()
	cfg.Announce = &AnnounceConfig{}
	cfg.Neighbors = []NeighborConfig{{
		Name:            "bring-up",
		Address:         netip.MustParseAddr("10.255.0.34"),
		ASN:             401870,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast},
	}}
	require.NoError(t, cfg.Validate())

	s := &Speaker{config: cfg}
	set, err := s.policySet()
	require.NoError(t, err)
	require.NoError(t, realGoBGP(t).SetPolicies(context.Background(), set))
}

// TestPrefixDefinedSetsByFamily is the unit-level statement of #620's fix:
// one set per family, always both, and each entry in the set whose family
// its emitted prefix string will parse as.
func TestPrefixDefinedSetsByFamily(t *testing.T) {
	tests := []struct {
		name       string
		entries    []string
		wantV4     []string
		wantV6     []string
		wantReason string
	}{
		{
			name:       "a dual-stack allowlist splits",
			entries:    []string{"0.0.0.0/0", "::/0"},
			wantV4:     []string{"0.0.0.0/0"},
			wantV6:     []string{"::/0"},
			wantReason: "the shape that made Start fail",
		},
		{
			name:       "an empty allowlist still yields both sets",
			wantV4:     nil,
			wantV6:     nil,
			wantReason: "an empty set matches nothing, leaving the reject default",
		},
		{
			name:       "a v6-only allowlist leaves the v4 set empty",
			entries:    []string{"2602:f5bb::/36"},
			wantV6:     []string{"2602:f5bb::/36"},
			wantReason: "v4 then falls to the reject default",
		},
		{
			name:       "a 4-in-6 prefix goes where its string parses",
			entries:    []string{"23.143.36.0/24", "::ffff:0.0.0.0/96"},
			wantV4:     []string{"23.143.36.0/24"},
			wantV6:     []string{"::ffff:0.0.0.0/96"},
			wantReason: "netip prints it as v6, so gobgp reads it as v6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := make([]PrefixMatch, 0, len(tt.entries))
			for _, e := range tt.entries {
				entries = append(entries, PrefixMatch{Prefix: netip.MustParsePrefix(e)})
			}
			sets := prefixDefinedSetsByFamily("tp-import-x"+prefixSetSuffix, entries)
			require.Len(t, sets, 2, "both families are always present")
			assert.Equal(t, "tp-import-x"+prefixSetSuffix+familySuffixV4, sets[0].GetName())
			assert.Equal(t, "tp-import-x"+prefixSetSuffix+familySuffixV6, sets[1].GetName())

			var gotV4, gotV6 []string
			for _, p := range sets[0].GetPrefixes() {
				gotV4 = append(gotV4, p.GetIpPrefix())
			}
			for _, p := range sets[1].GetPrefixes() {
				gotV6 = append(gotV6, p.GetIpPrefix())
			}
			assert.Equal(t, tt.wantV4, gotV4, tt.wantReason)
			assert.Equal(t, tt.wantV6, gotV6, tt.wantReason)
		})
	}
}

// TestRealGoBGP_AcceptsRouteTargetsAndGlobalAssignment hands GoBGP the
// shape #717 introduced — neighbor sets, extended-community route-target
// sets, an l2vpn-evpn family condition, a per-peer default-accept
// statement — and then the global assignment that makes it apply.
func TestRealGoBGP_AcceptsRouteTargetsAndGlobalAssignment(t *testing.T) {
	cfg := baseConfig()
	cfg.Neighbors = []NeighborConfig{
		{
			Name: "rr", Address: netip.MustParseAddr("10.255.0.1"), ASN: cfg.ASN,
			EnabledFamilies: []AddressFamily{AFamilyEVPN},
			Policy: PeerPolicyConfig{
				ImportRouteTargets: []string{"65000:100", "192.0.2.1:7"},
				ExportRouteTargets: []string{"4200000000:9"},
			},
		},
		{
			Name: "v6-transit", Address: netip.MustParseAddr("2001:db8::2"), ASN: 401870,
			EnabledFamilies: []AddressFamily{AFamilyIPv6Unicast},
			Policy:          PeerPolicyConfig{ImportDefaultAccept: true},
		},
	}
	require.NoError(t, cfg.Validate())

	s := &Speaker{config: cfg}
	set, err := s.policySet()
	require.NoError(t, err)
	srv := realGoBGP(t)
	require.NoError(t, srv.SetPolicies(context.Background(), set))
	for _, a := range globalAssignments() {
		require.NoError(t, srv.SetPolicyAssignment(context.Background(), &api.SetPolicyAssignmentRequest{Assignment: a}))
	}
	// A second SetPolicies — what a runtime AddPeer does — must keep the
	// assignment, because the policy names never change.
	require.NoError(t, srv.SetPolicies(context.Background(), set))
	var assigned []*api.PolicyAssignment
	require.NoError(t, srv.ListPolicyAssignment(context.Background(), &api.ListPolicyAssignmentRequest{},
		func(a *api.PolicyAssignment) { assigned = append(assigned, a) }))
	require.Len(t, assigned, 2)
	for _, a := range assigned {
		assert.Equal(t, api.RouteAction_ROUTE_ACTION_REJECT, a.GetDefaultAction(), "%s", a.GetDirection())
		require.Len(t, a.GetPolicies(), 1)
	}
}
