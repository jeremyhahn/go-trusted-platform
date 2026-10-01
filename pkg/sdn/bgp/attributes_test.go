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
	"strings"
	"testing"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func u32(v uint32) *uint32 { return &v }

// TestCommunityOp_Valid pins the three operations GoBGP can program and
// rejects anything else, including the empty string a missing key decodes
// to.
func TestCommunityOp_Valid(t *testing.T) {
	for _, op := range []CommunityOp{CommunityOpAdd, CommunityOpRemove, CommunityOpReplace} {
		assert.True(t, op.Valid(), "%s is a programmable operation", op)
		assert.Equal(t, string(op), op.String())
	}
	for _, op := range []CommunityOp{"", "set", "append", "ADD"} {
		assert.False(t, op.Valid(), "%q must not be accepted", op)
	}
}

// TestPeerAttributesConfig_Validate_Accepts covers the attribute sets an
// operator legitimately writes, including the full ASR ladder.
func TestPeerAttributesConfig_Validate_Accepts(t *testing.T) {
	tests := []struct {
		name      string
		direction PolicyDirection
		attrs     *PeerAttributesConfig
	}{
		{"nil is nothing to program", PolicyDirectionImport, nil},
		{"empty is nothing to program", PolicyDirectionImport, &PeerAttributesConfig{}},
		{"local-pref alone", PolicyDirectionImport, &PeerAttributesConfig{LocalPref: u32(200)}},
		{"med zero is a real med", PolicyDirectionExport, &PeerAttributesConfig{MED: u32(0)}},
		{"prepend with the implicit local asn", PolicyDirectionExport,
			&PeerAttributesConfig{Prepend: &ASPathPrependConfig{Count: 3}}},
		{"prepend with an explicit asn", PolicyDirectionExport,
			&PeerAttributesConfig{Prepend: &ASPathPrependConfig{Count: 1, ASN: 401870}}},
		{"prepend at the maximum", PolicyDirectionExport,
			&PeerAttributesConfig{Prepend: &ASPathPrependConfig{Count: MaxASPathPrepend}}},
		{"communities as asn:value with a 16-bit asn", PolicyDirectionExport, &PeerAttributesConfig{
			Communities: &CommunitySetConfig{Action: CommunityOpAdd, Values: []string{"65001:100"}}}},
		{"communities as a bare 32-bit number", PolicyDirectionExport, &PeerAttributesConfig{
			Communities: &CommunitySetConfig{Action: CommunityOpReplace, Values: []string{"4294967295"}}}},
		{"a well-known community name", PolicyDirectionExport, &PeerAttributesConfig{
			Communities: &CommunitySetConfig{Action: CommunityOpAdd, Values: []string{"no-export", "blackhole"}}}},
		{"a remove value is a regular expression", PolicyDirectionImport, &PeerAttributesConfig{
			Communities: &CommunitySetConfig{Action: CommunityOpRemove, Values: []string{"^401870:"}}}},
		{"large communities", PolicyDirectionExport, &PeerAttributesConfig{
			LargeCommunities: &CommunitySetConfig{Action: CommunityOpAdd, Values: []string{"401870:1:100"}}}},
		{"the whole ladder at once", PolicyDirectionExport, &PeerAttributesConfig{
			MED:              u32(50),
			Prepend:          &ASPathPrependConfig{Count: 3},
			Communities:      &CommunitySetConfig{Action: CommunityOpAdd, Values: []string{"65001:200"}},
			LargeCommunities: &CommunitySetConfig{Action: CommunityOpAdd, Values: []string{"401870:1:200"}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.attrs.Validate(tt.direction))
		})
	}
}

// TestPeerAttributesConfig_Validate_Refuses is the load-bearing half: every
// attribute the speaker cannot actually program must be a typed error at
// configuration load, never a field that reads as applied and is dropped.
func TestPeerAttributesConfig_Validate_Refuses(t *testing.T) {
	tests := []struct {
		name   string
		attrs  *PeerAttributesConfig
		target any
	}{
		{
			name:   "local-pref 0 is dropped by gobgp, so it is refused here",
			attrs:  &PeerAttributesConfig{LocalPref: u32(0)},
			target: ErrLocalPrefInvalid{},
		},
		{
			name:   "a prepend count of zero repeats nothing",
			attrs:  &PeerAttributesConfig{Prepend: &ASPathPrependConfig{Count: 0}},
			target: ErrPrependInvalid{},
		},
		{
			name:   "a prepend count past the bound",
			attrs:  &PeerAttributesConfig{Prepend: &ASPathPrependConfig{Count: MaxASPathPrepend + 1}},
			target: ErrPrependInvalid{},
		},
		{
			name:   "a prepend count that would wrap gobgp's byte",
			attrs:  &PeerAttributesConfig{Prepend: &ASPathPrependConfig{Count: 256}},
			target: ErrPrependInvalid{},
		},
		{
			name:   "prepending AS_TRANS would put a placeholder in the path",
			attrs:  &PeerAttributesConfig{Prepend: &ASPathPrependConfig{Count: 1, ASN: 23456}},
			target: ErrPrependInvalid{},
		},
		{
			name:   "prepending the last reserved 32-bit asn",
			attrs:  &PeerAttributesConfig{Prepend: &ASPathPrependConfig{Count: 1, ASN: 4294967295}},
			target: ErrPrependInvalid{},
		},
		{
			name:   "prepending the last reserved 16-bit asn",
			attrs:  &PeerAttributesConfig{Prepend: &ASPathPrependConfig{Count: 1, ASN: 65535}},
			target: ErrPrependInvalid{},
		},
		{
			name: "an unknown community action",
			attrs: &PeerAttributesConfig{Communities: &CommunitySetConfig{
				Action: "set", Values: []string{"65001:1"}}},
			target: ErrCommunityInvalid{},
		},
		{
			name: "a community action with no values programs nothing",
			attrs: &PeerAttributesConfig{Communities: &CommunitySetConfig{
				Action: CommunityOpAdd}},
			target: ErrCommunityInvalid{},
		},
		{
			name: "a community half that does not fit in 16 bits",
			attrs: &PeerAttributesConfig{Communities: &CommunitySetConfig{
				Action: CommunityOpAdd, Values: []string{"401870:70000"}}},
			target: ErrCommunityInvalid{},
		},
		{
			name: "a 32-bit asn cannot be half of a standard community",
			attrs: &PeerAttributesConfig{Communities: &CommunitySetConfig{
				Action: CommunityOpAdd, Values: []string{"401870:100"}}},
			target: ErrCommunityInvalid{},
		},
		{
			name: "a community with text around it is refused, not truncated",
			attrs: &PeerAttributesConfig{Communities: &CommunitySetConfig{
				Action: CommunityOpAdd, Values: []string{"as401870:100"}}},
			target: ErrCommunityInvalid{},
		},
		{
			name: "an unknown well-known community name",
			attrs: &PeerAttributesConfig{Communities: &CommunitySetConfig{
				Action: CommunityOpAdd, Values: []string{"no-transit"}}},
			target: ErrCommunityInvalid{},
		},
		{
			name: "a remove value that is not a valid regular expression",
			attrs: &PeerAttributesConfig{Communities: &CommunitySetConfig{
				Action: CommunityOpRemove, Values: []string{"("}}},
			target: ErrCommunityInvalid{},
		},
		{
			name: "a large community with two parts",
			attrs: &PeerAttributesConfig{LargeCommunities: &CommunitySetConfig{
				Action: CommunityOpAdd, Values: []string{"401870:1"}}},
			target: ErrCommunityInvalid{},
		},
		{
			name: "a large community part past 32 bits",
			attrs: &PeerAttributesConfig{LargeCommunities: &CommunitySetConfig{
				Action: CommunityOpAdd, Values: []string{"401870:1:4294967296"}}},
			target: ErrCommunityInvalid{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.attrs.Validate(PolicyDirectionExport)
			require.Error(t, err)
			assert.IsType(t, tt.target, err, "the refusal must be typed: %v", err)
			assert.NotEmpty(t, err.Error())
		})
	}
}

// TestPeerAttributesConfig_APIActions asserts the exact GoBGP action each
// field becomes. These are the values that reach the speaker, so a change
// here is a change to what the router does.
func TestPeerAttributesConfig_APIActions(t *testing.T) {
	const localASN = uint32(401870)

	t.Run("nothing set programs no actions at all", func(t *testing.T) {
		assert.Nil(t, (*PeerAttributesConfig)(nil).apiActions(localASN))
		assert.Nil(t, (&PeerAttributesConfig{}).apiActions(localASN))
	})

	t.Run("local-pref", func(t *testing.T) {
		actions := (&PeerAttributesConfig{LocalPref: u32(200)}).apiActions(localASN)
		require.NotNil(t, actions)
		require.NotNil(t, actions.LocalPref)
		assert.Equal(t, uint32(200), actions.LocalPref.Value)
		assert.Nil(t, actions.Med)
		assert.Equal(t, api.RouteAction_ROUTE_ACTION_UNSPECIFIED, actions.RouteAction,
			"the attribute statement must fall through to the filter")
	})

	t.Run("med replaces rather than offsets", func(t *testing.T) {
		actions := (&PeerAttributesConfig{MED: u32(50)}).apiActions(localASN)
		require.NotNil(t, actions.Med)
		assert.Equal(t, api.MedAction_TYPE_REPLACE, actions.Med.Type,
			"TYPE_UNSPECIFIED would install an action gobgp applies to nothing")
		assert.Equal(t, int64(50), actions.Med.Value)
	})

	t.Run("prepend defaults to the speaker's own asn", func(t *testing.T) {
		actions := (&PeerAttributesConfig{Prepend: &ASPathPrependConfig{Count: 3}}).apiActions(localASN)
		require.NotNil(t, actions.AsPrepend)
		assert.Equal(t, localASN, actions.AsPrepend.Asn)
		assert.Equal(t, uint32(3), actions.AsPrepend.Repeat)
		assert.False(t, actions.AsPrepend.UseLeftMost)
	})

	t.Run("prepend honours an explicit asn", func(t *testing.T) {
		actions := (&PeerAttributesConfig{
			Prepend: &ASPathPrependConfig{Count: 2, ASN: 64512}}).apiActions(localASN)
		assert.Equal(t, uint32(64512), actions.AsPrepend.Asn)
	})

	t.Run("communities carry the operation and the values", func(t *testing.T) {
		attrs := &PeerAttributesConfig{
			Communities: &CommunitySetConfig{
				Action: CommunityOpAdd, Values: []string{"65001:100", "no-export"}},
			LargeCommunities: &CommunitySetConfig{
				Action: CommunityOpRemove, Values: []string{"^401870:"}},
		}
		actions := attrs.apiActions(localASN)
		require.NotNil(t, actions.Community)
		assert.Equal(t, api.CommunityAction_TYPE_ADD, actions.Community.Type)
		assert.Equal(t, []string{"65001:100", "no-export"}, actions.Community.Communities)
		require.NotNil(t, actions.LargeCommunity)
		assert.Equal(t, api.CommunityAction_TYPE_REMOVE, actions.LargeCommunity.Type)
		assert.Equal(t, []string{"^401870:"}, actions.LargeCommunity.Communities)
	})

	t.Run("the action does not alias the configuration's slice", func(t *testing.T) {
		values := []string{"65001:100"}
		attrs := &PeerAttributesConfig{
			Communities: &CommunitySetConfig{Action: CommunityOpAdd, Values: values}}
		actions := attrs.apiActions(localASN)
		actions.Community.Communities[0] = "mutated"
		assert.Equal(t, "65001:100", values[0], "the config must not be written through")
	})
}

// TestPeerAttributesConfig_Describe keeps the operator log line honest: it
// names every attribute that is set and nothing that is not.
func TestPeerAttributesConfig_Describe(t *testing.T) {
	assert.Empty(t, (*PeerAttributesConfig)(nil).describe())
	assert.Empty(t, (&PeerAttributesConfig{}).describe())

	full := &PeerAttributesConfig{
		LocalPref:        u32(200),
		MED:              u32(50),
		Prepend:          &ASPathPrependConfig{Count: 3},
		Communities:      &CommunitySetConfig{Action: CommunityOpAdd, Values: []string{"65001:1"}},
		LargeCommunities: &CommunitySetConfig{Action: CommunityOpReplace, Values: []string{"401870:1:1"}},
	}
	assert.Equal(t,
		"local-pref=200 med=50 prepend=3 communities=add large-communities=replace",
		full.describe())
}

// TestNeighborConfig_ValidateAttributeDirections covers the one rule that
// needs both ASNs: LOCAL_PREF is never sent to an external peer, so asking
// for it there is a control that would do nothing.
func TestNeighborConfig_ValidateAttributeDirections(t *testing.T) {
	const localASN = uint32(401870)
	exportLocalPref := func(peerASN uint32) *NeighborConfig {
		return &NeighborConfig{
			Address: netip.MustParseAddr("10.255.0.34"),
			ASN:     peerASN,
			Policy: PeerPolicyConfig{
				Export: &PeerAttributesConfig{LocalPref: u32(200)},
			},
		}
	}

	t.Run("ibgp carries local-pref, so export is fine", func(t *testing.T) {
		require.NoError(t, exportLocalPref(localASN).validateAttributeDirections(localASN))
	})

	t.Run("ebgp does not, so export is refused", func(t *testing.T) {
		err := exportLocalPref(64512).validateAttributeDirections(localASN)
		require.Error(t, err)
		assert.IsType(t, ErrAttributeDirectionInvalid{}, err)
		assert.Contains(t, err.Error(), "10.255.0.34")
	})

	t.Run("import local-pref is fine on any session", func(t *testing.T) {
		cfg := &NeighborConfig{
			Address: netip.MustParseAddr("10.255.0.34"),
			ASN:     64512,
			Policy:  PeerPolicyConfig{Import: &PeerAttributesConfig{LocalPref: u32(200)}},
		}
		require.NoError(t, cfg.validateAttributeDirections(localASN))
	})

	t.Run("no attributes at all is fine", func(t *testing.T) {
		cfg := &NeighborConfig{Address: netip.MustParseAddr("10.255.0.34"), ASN: 64512}
		require.NoError(t, cfg.validateAttributeDirections(localASN))
	})
}

// TestPeerPolicyConfig_Validate_ReachesBothDirections proves the peer
// policy actually validates its attribute sets rather than only its prefix
// lists — the drop this issue exists for.
func TestPeerPolicyConfig_Validate_ReachesBothDirections(t *testing.T) {
	t.Run("an import refusal surfaces", func(t *testing.T) {
		p := PeerPolicyConfig{Import: &PeerAttributesConfig{LocalPref: u32(0)}}
		err := p.Validate()
		require.Error(t, err)
		assert.Equal(t, string(PolicyDirectionImport), err.(ErrLocalPrefInvalid).Direction)
	})

	t.Run("an export refusal surfaces", func(t *testing.T) {
		p := PeerPolicyConfig{Export: &PeerAttributesConfig{
			Prepend: &ASPathPrependConfig{Count: 99}}}
		err := p.Validate()
		require.Error(t, err)
		assert.Equal(t, string(PolicyDirectionExport), err.(ErrPrependInvalid).Direction)
	})

	t.Run("a valid policy passes", func(t *testing.T) {
		p := PeerPolicyConfig{
			ImportAllow: []PrefixMatch{{Prefix: netip.MustParsePrefix("0.0.0.0/0")}},
			Import:      &PeerAttributesConfig{LocalPref: u32(200)},
			Export:      &PeerAttributesConfig{MED: u32(50)},
		}
		require.NoError(t, p.Validate())
	})
}

// statementsFor returns the statements of one global policy that belong to
// one peer, in order: every per-peer statement is named after the peer's
// direction prefix (policyName).
func statementsFor(t *testing.T, req *api.SetPoliciesRequest, policy, peerPrefix string) []*api.Statement {
	t.Helper()
	require.NotNil(t, req)
	for _, p := range req.Policies {
		if p.GetName() != policy {
			continue
		}
		var out []*api.Statement
		for _, st := range p.Statements {
			if strings.HasPrefix(st.GetName(), peerPrefix+"-") {
				out = append(out, st)
			}
		}
		return out
	}
	t.Fatalf("policy %q was not installed; got %d policies", policy, len(req.Policies))
	return nil
}

// TestPolicySet_CarriesTrafficEngineering is the end of the chain this
// issue is about: a configured ladder reaches the speaker as GoBGP policy
// statements, in the order that makes both of them take effect, each
// scoped to the peer it was configured for.
func TestPolicySet_CarriesTrafficEngineering(t *testing.T) {
	cfg := baseConfig()
	cfg.Neighbors = []NeighborConfig{{
		Name:            "miami-att",
		Address:         netip.MustParseAddr("10.255.0.34"),
		ASN:             401870,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast},
		Policy: PeerPolicyConfig{
			ImportAllow: []PrefixMatch{{Prefix: netip.MustParsePrefix("0.0.0.0/0")}},
			Import:      &PeerAttributesConfig{LocalPref: u32(200)},
			Export: &PeerAttributesConfig{
				MED:              u32(50),
				Prepend:          &ASPathPrependConfig{Count: 3},
				LargeCommunities: &CommunitySetConfig{Action: CommunityOpAdd, Values: []string{"401870:1:200"}},
			},
		},
	}}
	require.NoError(t, cfg.Validate())

	s, _ := startedSpeaker(t, cfg)
	set, err := s.policySet()
	require.NoError(t, err)
	peerSet := neighborSetName(cfg.Neighbors[0].Address)

	importName := policyName(policyPrefixImport, cfg.Neighbors[0].Address)
	imp := statementsFor(t, set, policyPrefixImport, importName)
	require.Len(t, imp, 3,
		"the attribute statement, then one filter per address family")

	attrs := imp[0]
	assert.Equal(t, importName+"-attributes", attrs.GetName())
	assert.Equal(t, peerSet, attrs.GetConditions().GetNeighborSet().GetName(),
		"the attributes apply to this peer's paths, not to every peer's")
	assert.Nil(t, attrs.GetConditions().GetPrefixSet(),
		"the attributes apply to the direction, not to a prefix list")
	assert.Equal(t, api.RouteAction_ROUTE_ACTION_UNSPECIFIED, attrs.GetActions().GetRouteAction(),
		"a route action here would stop evaluation before the filter")
	assert.Equal(t, uint32(200), attrs.GetActions().GetLocalPref().GetValue())

	for i, suffix := range []string{familySuffixV4, familySuffixV6} {
		filter := imp[i+1]
		setName := importName + prefixSetSuffix + suffix
		assert.Equal(t, setName+"-accept", filter.GetName())
		assert.Equal(t, setName, filter.GetConditions().GetPrefixSet().GetName())
		assert.Equal(t, peerSet, filter.GetConditions().GetNeighborSet().GetName())
		assert.Equal(t, api.RouteAction_ROUTE_ACTION_ACCEPT, filter.GetActions().GetRouteAction())
	}

	exportName := policyName(policyPrefixExport, cfg.Neighbors[0].Address)
	exp := statementsFor(t, set, policyPrefixExport, exportName)
	require.Len(t, exp, 3)
	exportActions := exp[0].GetActions()
	assert.Equal(t, int64(50), exportActions.GetMed().GetValue())
	assert.Equal(t, api.MedAction_TYPE_REPLACE, exportActions.GetMed().GetType())
	assert.Equal(t, uint32(3), exportActions.GetAsPrepend().GetRepeat())
	assert.Equal(t, cfg.ASN, exportActions.GetAsPrepend().GetAsn(),
		"an unnamed prepend asn is the speaker's own")
	assert.Equal(t, []string{"401870:1:200"}, exportActions.GetLargeCommunity().GetCommunities())
}

// TestPolicySet_WithoutAttributesIsUnchanged pins that a peer that asks for
// no traffic engineering gets exactly its two family filters per direction.
func TestPolicySet_WithoutAttributesIsUnchanged(t *testing.T) {
	cfg := baseConfig()
	cfg.Neighbors = []NeighborConfig{{
		Name:            "plain",
		Address:         netip.MustParseAddr("10.255.0.38"),
		ASN:             401870,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast},
		Policy: PeerPolicyConfig{
			ImportAllow: []PrefixMatch{{Prefix: netip.MustParsePrefix("0.0.0.0/0")}},
		},
	}}
	s, _ := startedSpeaker(t, cfg)
	set, err := s.policySet()
	require.NoError(t, err)

	for _, direction := range []string{policyPrefixImport, policyPrefixExport} {
		name := policyName(direction, cfg.Neighbors[0].Address)
		pol := statementsFor(t, set, direction, name)
		require.Len(t, pol, 2, "%s must carry the two filters alone", name)
		assert.Equal(t, name+prefixSetSuffix+familySuffixV4+"-accept", pol[0].GetName())
		assert.Equal(t, name+prefixSetSuffix+familySuffixV6+"-accept", pol[1].GetName())
	}
}

// TestBGPConfig_Validate_RefusesExportLocalPrefToExternalPeer proves the
// cross-field rule fires where a configuration is actually loaded, not only
// on the neighbour helper.
func TestBGPConfig_Validate_RefusesExportLocalPrefToExternalPeer(t *testing.T) {
	cfg := baseConfig()
	cfg.Neighbors = []NeighborConfig{{
		Name:            "upstream",
		Address:         netip.MustParseAddr("192.0.2.1"),
		ASN:             64512,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast},
		Policy:          PeerPolicyConfig{Export: &PeerAttributesConfig{LocalPref: u32(200)}},
	}}
	err := cfg.Validate()
	require.Error(t, err)
	assert.IsType(t, ErrAttributeDirectionInvalid{}, err)

	// The same speaker with the attribute on import is a valid config.
	cfg.Neighbors[0].Policy.Export = nil
	cfg.Neighbors[0].Policy.Import = &PeerAttributesConfig{LocalPref: u32(200)}
	require.NoError(t, cfg.Validate())
}

// TestSpeaker_AddPeerRefusesUnprogrammableAttributes: a peer added at
// runtime goes through the same gate as a configured one, so the runtime
// path cannot install what the config path refuses.
func TestSpeaker_AddPeerRefusesUnprogrammableAttributes(t *testing.T) {
	cfg := baseConfig()
	cfg.Neighbors = nil
	s, _ := startedSpeaker(t, cfg)

	external := &NeighborConfig{
		Address:         netip.MustParseAddr("192.0.2.9"),
		ASN:             64512,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast},
		Policy:          PeerPolicyConfig{Export: &PeerAttributesConfig{LocalPref: u32(200)}},
	}
	err := s.AddPeer(context.Background(), external)
	require.Error(t, err)
	assert.IsType(t, ErrAttributeDirectionInvalid{}, err)
	assert.Empty(t, s.config.Neighbors, "a refused peer must not be registered")

	badCommunity := &NeighborConfig{
		Address:         netip.MustParseAddr("10.255.0.50"),
		ASN:             401870,
		EnabledFamilies: []AddressFamily{AFamilyIPv4Unicast},
		Policy: PeerPolicyConfig{Export: &PeerAttributesConfig{
			Communities: &CommunitySetConfig{Action: CommunityOpAdd, Values: []string{"nope"}}}},
	}
	err = s.AddPeer(context.Background(), badCommunity)
	require.Error(t, err)
	assert.IsType(t, ErrCommunityInvalid{}, err)
	assert.Empty(t, s.config.Neighbors)
}
