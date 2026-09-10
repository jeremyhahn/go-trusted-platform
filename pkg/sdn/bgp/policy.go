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
	"net/netip"
	"strings"

	api "github.com/osrg/gobgp/v4/api"
)

// Routing policy (RFC 8212).
//
// Every peer's import and export directions default to REJECT. What a peer
// may send us is its import allowlist; what we announce to it is its export
// allowlist, which defaults to exactly the speaker's own Announce prefixes.
// The policy set is built once from the configuration and installed with
// SetPolicies before any peer is added; each peer's ApplyPolicy then names
// its two policies with a reject default, so a prefix outside the lists is
// dropped by the speaker itself, not by whatever the peer chose to filter.

const (
	policyPrefixImport = "tp-import"
	policyPrefixExport = "tp-export"
	prefixSetSuffix    = "-prefixes"

	// familySuffixV4 and familySuffixV6 name the two prefix sets a
	// direction is split into. GoBGP refuses a prefix set holding both
	// families ("multiple families", NewPrefixSetFromApiStruct), so a
	// dual-stack allowlist has to arrive as two sets — see #620.
	familySuffixV4 = "-v4"
	familySuffixV6 = "-v6"
)

// policyName returns the import or export policy name for a peer.
func policyName(direction string, peer netip.Addr) string {
	return direction + "-" + strings.NewReplacer(":", "-", ".", "-").Replace(peer.String())
}

// policySet builds the defined sets and policies for every configured peer.
func (s *Speaker) policySet() *api.SetPoliciesRequest {
	req := &api.SetPoliciesRequest{}
	if s.config == nil {
		return req
	}
	announce := s.announcePrefixes()
	for i := range s.config.Neighbors {
		n := &s.config.Neighbors[i]
		importName := policyName(policyPrefixImport, n.Address)
		exportName := policyName(policyPrefixExport, n.Address)

		exportAllow := n.Policy.ExportAllow
		if len(exportAllow) == 0 {
			exportAllow = announce
		}
		importSets := prefixDefinedSetsByFamily(importName+prefixSetSuffix, n.Policy.ImportAllow)
		exportSets := prefixDefinedSetsByFamily(exportName+prefixSetSuffix, exportAllow)
		req.DefinedSets = append(req.DefinedSets, importSets...)
		req.DefinedSets = append(req.DefinedSets, exportSets...)
		req.Policies = append(req.Policies,
			peerPolicy(importName, importSets, n.Policy.Import, s.config.ASN),
			peerPolicy(exportName, exportSets, n.Policy.Export, s.config.ASN))
	}
	return req
}

// announcePrefixes returns the configured Announce prefixes as exact-match
// policy entries.
func (s *Speaker) announcePrefixes() []PrefixMatch {
	if s.config == nil || s.config.Announce == nil {
		return nil
	}
	prefixes, err := s.config.Announce.AllPrefixes()
	if err != nil {
		return nil
	}
	out := make([]PrefixMatch, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, PrefixMatch{Prefix: p})
	}
	return out
}

// prefixDefinedSetsByFamily splits an allowlist into one GoBGP prefix set
// per address family, IPv4 first.
//
// GoBGP stores a prefix set's family on the set and refuses one holding
// both (#620), so a dual-stack allowlist cannot be a single set. Both sets
// are always returned, empty ones included: an empty set matches nothing,
// which leaves that family to the direction's reject default and keeps the
// statement layout the same whatever the configuration lists.
func prefixDefinedSetsByFamily(name string, entries []PrefixMatch) []*api.DefinedSet {
	var v4, v6 []PrefixMatch
	for _, e := range entries {
		if e.Prefix.Addr().Is4() {
			v4 = append(v4, e)
			continue
		}
		v6 = append(v6, e)
	}
	return []*api.DefinedSet{
		prefixDefinedSet(name+familySuffixV4, v4),
		prefixDefinedSet(name+familySuffixV6, v6),
	}
}

// prefixDefinedSet turns an allowlist into a GoBGP prefix set. An empty
// list yields an empty set, which matches nothing — the reject default then
// applies to everything. Every entry must be of one family; the caller
// splits them.
func prefixDefinedSet(name string, entries []PrefixMatch) *api.DefinedSet {
	set := &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
		Name:        name,
		Prefixes:    make([]*api.Prefix, 0, len(entries)),
	}
	for _, e := range entries {
		maxLen := uint32(e.Prefix.Bits())
		if e.MaxLength != 0 {
			maxLen = uint32(e.MaxLength)
		}
		set.Prefixes = append(set.Prefixes, &api.Prefix{
			IpPrefix:      e.Prefix.Masked().String(),
			MaskLengthMin: uint32(e.Prefix.Bits()),
			MaskLengthMax: maxLen,
		})
	}
	return set
}

// peerPolicy is one direction of one peer's policy: the traffic
// engineering the configuration asks for, then one prefix filter per
// address family.
//
// The attribute statement carries no conditions and no route action, so
// GoBGP applies its actions to every path in the direction and moves on to
// the next statement (table.Statement.Apply returns ROUTE_TYPE_NONE when a
// statement names no route action). Stamping the attributes before the
// filter rather than inside it is what makes the attributes hold when a
// direction is opted into accept-by-default: the filter statements match
// only the allowlist, but the attributes are what the operator asked to
// apply to the session, not to a prefix list.
//
// A path is only ever admitted by its own family's statement, because a
// prefix condition evaluates false when the set's AFI differs from the
// path's (table.PrefixCondition.Evaluate). Anything outside both lists
// falls through every statement to the direction's reject default.
func peerPolicy(name string, prefixSets []*api.DefinedSet, attrs *PeerAttributesConfig, localASN uint32) *api.Policy {
	policy := &api.Policy{Name: name}
	if actions := attrs.apiActions(localASN); actions != nil {
		policy.Statements = append(policy.Statements, &api.Statement{
			Name:    name + "-attributes",
			Actions: actions,
		})
	}
	for _, set := range prefixSets {
		policy.Statements = append(policy.Statements, &api.Statement{
			Name: set.GetName() + "-accept",
			Conditions: &api.Conditions{
				PrefixSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: set.GetName()},
			},
			Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
		})
	}
	return policy
}

// peerApplyPolicy names the peer's two policies with the RFC 8212 reject
// default, unless the configuration opts a direction into accept-by-default.
func (s *Speaker) peerApplyPolicy(cfg *NeighborConfig) *api.ApplyPolicy {
	importDefault := api.RouteAction_ROUTE_ACTION_REJECT
	if cfg.Policy.ImportDefaultAccept {
		importDefault = api.RouteAction_ROUTE_ACTION_ACCEPT
	}
	exportDefault := api.RouteAction_ROUTE_ACTION_REJECT
	if cfg.Policy.ExportDefaultAccept {
		exportDefault = api.RouteAction_ROUTE_ACTION_ACCEPT
	}
	return &api.ApplyPolicy{
		ImportPolicy: &api.PolicyAssignment{
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			Policies:      []*api.Policy{{Name: policyName(policyPrefixImport, cfg.Address)}},
			DefaultAction: importDefault,
		},
		ExportPolicy: &api.PolicyAssignment{
			Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
			Policies:      []*api.Policy{{Name: policyName(policyPrefixExport, cfg.Address)}},
			DefaultAction: exportDefault,
		},
	}
}
