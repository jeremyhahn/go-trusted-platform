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
	"errors"
	"net/netip"
	"testing"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouteTargetPatterns(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"none", nil, []string{}},
		{"two-octet AS", []string{"65000:100"}, []string{"rt:^65000:100$"}},
		{"surrounding space is not part of it", []string{" 65000:100 "}, []string{"rt:^65000:100$"}},
		{"IPv4 administrator, dots escaped", []string{"192.0.2.1:100"}, []string{`rt:^192\.0\.2\.1:100$`}},
		{"two-octet AS takes a 32-bit number", []string{"65000:4294967295"}, []string{"rt:^65000:4294967295$"}},
		{"four-octet AS prints in asdot, as GoBGP matches it", []string{"4200000000:7"}, []string{`rt:^64086\.59904:7$`}},
		{"several, in order", []string{"65000:1", "65000:2"}, []string{"rt:^65000:1$", "rt:^65000:2$"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := routeTargetPatterns(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRouteTargetPatterns_RefusesMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "65000", "not-a-target", "65000:abc", "-1:5", "65000:-1",
		"65000:4294967296", // the number overflows 32 bits
		"4200000000:65536", // a four-octet AS takes a 16-bit number; GoBGP would clamp it
		"4294967296:1",     // the AS overflows 32 bits
		"192.0.2.1:65536",  // an address administrator takes a 16-bit number
		"2001:db8::1:5",    // IPv6 is not a route-target administrator
	} {
		_, err := routeTargetPatterns([]string{"65000:100", bad})
		var invalid ErrRouteTargetInvalid
		require.True(t, errors.As(err, &invalid), "%q: got %v", bad, err)
		assert.Equal(t, bad, invalid.RT)
	}
}

func TestRouteTargetDefinedSet(t *testing.T) {
	set, err := routeTargetDefinedSet("x", nil)
	require.NoError(t, err)
	assert.Nil(t, set, "no route targets is no set, so no statement can admit EVPN")

	set, err = routeTargetDefinedSet("x", []string{"65000:100", "65000:200"})
	require.NoError(t, err)
	assert.Equal(t, api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY, set.DefinedType)
	assert.Equal(t, []string{"rt:^65000:100$", "rt:^65000:200$"}, set.List)

	_, err = routeTargetDefinedSet("x", []string{"bogus"})
	var invalid ErrRouteTargetInvalid
	require.True(t, errors.As(err, &invalid))
}

func TestPeerPolicyConfig_ValidateRouteTargets(t *testing.T) {
	ok := PeerPolicyConfig{ImportRouteTargets: []string{"65000:100"}, ExportRouteTargets: []string{"192.0.2.1:5"}}
	require.NoError(t, ok.Validate())

	for name, p := range map[string]PeerPolicyConfig{
		"import": {ImportRouteTargets: []string{"65000"}},
		"export": {ExportRouteTargets: []string{"65000"}},
	} {
		var invalid ErrRouteTargetInvalid
		require.True(t, errors.As(p.Validate(), &invalid), "a malformed %s route target must be refused", name)
	}
}

func TestNeighborConfig_PrefixLimit(t *testing.T) {
	var unset NeighborConfig
	assert.Equal(t, DefaultMaxPrefixes, unset.PrefixLimit(AFamilyIPv4Unicast))
	assert.Equal(t, DefaultMaxPrefixes, unset.PrefixLimit(AFamilyIPv6Unicast))
	assert.Equal(t, DefaultMaxEVPNPrefixes, unset.PrefixLimit(AFamilyEVPN))
	assert.Greater(t, DefaultMaxEVPNPrefixes, DefaultMaxPrefixes, "EVPN is sized by the fabric, not by transit")

	set := NeighborConfig{MaxPrefixes: 10, MaxEVPNPrefixes: 5000}
	assert.Equal(t, uint32(10), set.PrefixLimit(AFamilyIPv4Unicast))
	assert.Equal(t, uint32(10), set.PrefixLimit(AFamilyIPv6Unicast))
	assert.Equal(t, uint32(5000), set.PrefixLimit(AFamilyEVPN), "the unicast limit never reaches EVPN")
}

func TestNeighborConfig_ValidateDefaultsEVPNLimit(t *testing.T) {
	n := NeighborConfig{Address: netip.MustParseAddr("10.0.0.2"), ASN: 65002, MaxPrefixes: 10}
	require.NoError(t, n.Validate())
	assert.Equal(t, uint32(10), n.MaxPrefixes)
	assert.Equal(t, DefaultMaxEVPNPrefixes, n.MaxEVPNPrefixes)

	bad := NeighborConfig{Address: netip.MustParseAddr("10.0.0.2"), ASN: 65002,
		Policy: PeerPolicyConfig{ImportRouteTargets: []string{"nope"}}}
	var invalid ErrRouteTargetInvalid
	require.True(t, errors.As(bad.Validate(), &invalid))
}

func TestNeighborConfigToPeer_PerFamilyPrefixLimits(t *testing.T) {
	s := &Speaker{config: baseConfig()}
	n := &NeighborConfig{
		Address: netip.MustParseAddr("10.0.0.2"), ASN: 65002,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast, AFamilyIPv6Unicast, AFamilyEVPN},
		MaxPrefixes:     10, MaxEVPNPrefixes: 20000,
	}
	require.NoError(t, n.Validate())
	peer := s.neighborConfigToPeer(n)
	require.Len(t, peer.AfiSafis, 3)
	got := map[api.Family_Afi]uint32{}
	for _, as := range peer.AfiSafis {
		got[as.PrefixLimits.Family.Afi] = as.PrefixLimits.MaxPrefixes
	}
	assert.Equal(t, map[api.Family_Afi]uint32{
		api.Family_AFI_IP:    10,
		api.Family_AFI_IP6:   10,
		api.Family_AFI_L2VPN: 20000,
	}, got)
	assert.Nil(t, peer.ApplyPolicy)
}

// TestPolicySet_EVPNRouteTargetStatements pins the EVPN half of the policy:
// one extended-community set per direction, admitted only on the
// l2vpn-evpn family and only for this peer.
func TestPolicySet_EVPNRouteTargetStatements(t *testing.T) {
	cfg := baseConfig()
	peer := netip.MustParseAddr("10.0.0.2")
	cfg.Neighbors = []NeighborConfig{{
		Address: peer, ASN: cfg.ASN, EnabledFamilies: []AddressFamily{AFamilyEVPN},
		Policy: PeerPolicyConfig{ImportRouteTargets: []string{"65000:100"}, ExportRouteTargets: []string{"65000:200"}},
	}}
	require.NoError(t, cfg.Validate())
	set, err := (&Speaker{config: cfg}).policySet()
	require.NoError(t, err)

	for _, tc := range []struct {
		direction, rt string
	}{
		{policyPrefixImport, "rt:^65000:100$"},
		{policyPrefixExport, "rt:^65000:200$"},
	} {
		name := policyName(tc.direction, peer)
		stmts := statementsFor(t, set, tc.direction, name)
		require.Len(t, stmts, 3, "%s: two family prefix filters, then the route-target filter", tc.direction)
		rt := stmts[2]
		assert.Equal(t, name+routeTargetSuffix+"-accept", rt.GetName())
		assert.Equal(t, neighborSetName(peer), rt.GetConditions().GetNeighborSet().GetName())
		require.Len(t, rt.GetConditions().GetAfiSafiIn(), 1)
		assert.Equal(t, api.Family_AFI_L2VPN, rt.GetConditions().GetAfiSafiIn()[0].Afi)
		assert.Equal(t, api.Family_SAFI_EVPN, rt.GetConditions().GetAfiSafiIn()[0].Safi)
		assert.Equal(t, name+routeTargetSuffix, rt.GetConditions().GetExtCommunitySet().GetName())
		assert.Nil(t, rt.GetConditions().GetPrefixSet())

		var found bool
		for _, d := range set.DefinedSets {
			if d.GetName() == name+routeTargetSuffix {
				found = true
				assert.Equal(t, []string{tc.rt}, d.GetList())
			}
		}
		assert.True(t, found, "%s route-target set missing", tc.direction)
	}
}

// TestPolicySet_DefaultAcceptIsAPeerStatement pins how a per-peer opt-in to
// accept-by-default survives a single global reject default: it is a last
// statement matching only that peer.
func TestPolicySet_DefaultAcceptIsAPeerStatement(t *testing.T) {
	cfg := baseConfig()
	open := netip.MustParseAddr("10.0.0.2")
	closed := netip.MustParseAddr("10.0.0.3")
	cfg.Neighbors = []NeighborConfig{
		{Address: open, ASN: 65002, Policy: PeerPolicyConfig{ImportDefaultAccept: true}},
		{Address: closed, ASN: 65003},
	}
	require.NoError(t, cfg.Validate())
	set, err := (&Speaker{config: cfg}).policySet()
	require.NoError(t, err)

	openStmts := statementsFor(t, set, policyPrefixImport, policyName(policyPrefixImport, open))
	last := openStmts[len(openStmts)-1]
	assert.Equal(t, policyName(policyPrefixImport, open)+"-default-accept", last.GetName())
	assert.Equal(t, neighborSetName(open), last.GetConditions().GetNeighborSet().GetName())
	assert.Nil(t, last.GetConditions().GetPrefixSet())
	assert.Equal(t, api.RouteAction_ROUTE_ACTION_ACCEPT, last.GetActions().GetRouteAction())

	for _, st := range statementsFor(t, set, policyPrefixImport, policyName(policyPrefixImport, closed)) {
		assert.NotNil(t, st.GetConditions().GetPrefixSet(), "the closed peer has filters only: %s", st.GetName())
	}
	assert.Empty(t, statementsFor(t, set, policyPrefixExport, policyName(policyPrefixExport, open)+"-default"),
		"the import opt-in does not open export")
}

func TestPolicySet_RefusesAnUnvalidatedRouteTarget(t *testing.T) {
	cfg := baseConfig()
	cfg.Neighbors = []NeighborConfig{{Address: netip.MustParseAddr("10.0.0.2"), ASN: 65002,
		Policy: PeerPolicyConfig{ExportRouteTargets: []string{"bogus"}}}}
	_, err := (&Speaker{config: cfg}).policySet()
	var invalid ErrRouteTargetInvalid
	require.True(t, errors.As(err, &invalid), "got %v", err)
}

func TestPolicySet_WithoutConfigStillDefinesBothPolicies(t *testing.T) {
	set, err := (&Speaker{}).policySet()
	require.NoError(t, err)
	require.Len(t, set.Policies, 2, "the global assignment names both; they must exist")
	assert.Equal(t, policyPrefixImport, set.Policies[0].Name)
	assert.Equal(t, localOriginStatement, set.Policies[0].Statements[0].Name)
	assert.Equal(t, policyPrefixExport, set.Policies[1].Name)
	assert.Empty(t, set.Policies[1].Statements, "nothing is exported without a peer allowlist")
}

func TestSpeaker_StartFailsWhenTheAssignmentIsRefused(t *testing.T) {
	mock := newMockBGPServer()
	mock.setAssignmentErr = errors.New("refused")
	sp, err := NewSpeaker(baseConfig(), speakerTestLogger(), WithBGPServer(mock))
	require.NoError(t, err)

	err = sp.Start(context.Background())
	var failed *ErrServerOperationFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	assert.Equal(t, "set_policy_assignment", failed.Operation)
	assert.False(t, sp.IsStarted(), "a speaker without its policy assignment must not report started")
	assert.True(t, mock.stopped, "the server is stopped again")
}
