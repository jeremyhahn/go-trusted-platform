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
		req.DefinedSets = append(req.DefinedSets,
			prefixDefinedSet(importName+prefixSetSuffix, n.Policy.ImportAllow),
			prefixDefinedSet(exportName+prefixSetSuffix, exportAllow))
		req.Policies = append(req.Policies,
			acceptPrefixSetPolicy(importName, importName+prefixSetSuffix),
			acceptPrefixSetPolicy(exportName, exportName+prefixSetSuffix))
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

// prefixDefinedSet turns an allowlist into a GoBGP prefix set. An empty
// list yields an empty set, which matches nothing — the reject default then
// applies to everything.
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

// acceptPrefixSetPolicy is a one-statement policy accepting the prefix set.
func acceptPrefixSetPolicy(name, prefixSet string) *api.Policy {
	return &api.Policy{
		Name: name,
		Statements: []*api.Statement{{
			Name: name + "-accept",
			Conditions: &api.Conditions{
				PrefixSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: prefixSet},
			},
			Actions: &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
		}},
	}
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
