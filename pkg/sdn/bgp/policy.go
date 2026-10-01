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
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	api "github.com/osrg/gobgp/v4/api"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Routing policy (RFC 8212).
//
// Every peer's import and export directions default to REJECT. What a peer
// may send us is its import allowlist; what we announce to it is its export
// allowlist, which for unicast defaults to exactly the speaker's own Announce
// prefixes. l2vpn-evpn routes are admitted by route target instead of by
// prefix.
//
// GoBGP evaluates a peer against a per-peer policy assignment only when the
// peer is a route-server client (server.go setPeerPolicy; ApplyPolicy looks
// the assignment up by peer.TableID(), which is the global RIB name for
// every other peer). The speaker has no route-server clients, so a per-peer
// assignment is stored nowhere and filters nothing — the defect #717 fixed.
// The policy is therefore ONE global import policy and ONE global export
// policy, each assigned to the global RIB with a reject default, whose
// statements carry a neighbor-set condition naming the peer they are for.
// On import GoBGP matches the neighbor set against the peer the path came
// from; on export, against the peer it is about to be sent to
// (table.NeighborCondition.Evaluate reads PolicyOptions.Info, which
// propagateUpdate and prePolicyFilterpath set to that peer).
//
// The two policies keep the same names across every SetPolicies call, so the
// global assignment made once at Start keeps resolving to the current
// statements: GoBGP's SetPolicies re-applies the existing assignments by
// name after it reloads the definitions.

const (
	// policyPrefixImport and policyPrefixExport name the two global
	// policies, and prefix every per-peer statement and defined set.
	policyPrefixImport = "tp-import"
	policyPrefixExport = "tp-export"
	prefixSetSuffix    = "-prefixes"
	routeTargetSuffix  = "-route-targets"
	neighborSetPrefix  = "tp-peer"

	// familySuffixV4 and familySuffixV6 name the two prefix sets a
	// direction is split into. GoBGP refuses a prefix set holding both
	// families ("multiple families", NewPrefixSetFromApiStruct), so a
	// dual-stack allowlist has to arrive as two sets — see #620.
	familySuffixV4 = "-v4"
	familySuffixV6 = "-v6"

	// localOriginStatement admits the speaker's own paths into its RIB.
	// GoBGP runs a locally originated path through the global IMPORT
	// policy too (propagateUpdate with no source peer), so without it the
	// reject default would drop every route the speaker originates. What
	// leaves the speaker is still decided by the export policy.
	localOriginStatement = policyPrefixImport + "-local-origin"
)

// policyName returns the import or export statement prefix for a peer.
func policyName(direction string, peer netip.Addr) string {
	return direction + "-" + addrLabel(peer)
}

// neighborSetName returns the name of the defined set holding one peer's
// address.
func neighborSetName(peer netip.Addr) string {
	return neighborSetPrefix + "-" + addrLabel(peer)
}

// addrLabel renders an address as a defined-set-safe label.
func addrLabel(peer netip.Addr) string {
	return strings.NewReplacer(":", "-", ".", "-").Replace(peer.String())
}

// policySet builds the defined sets and the two global policies covering
// every configured peer. It fails only on a route target that does not
// parse, which configuration validation refuses first.
func (s *Speaker) policySet() (*api.SetPoliciesRequest, error) {
	importPolicy := &api.Policy{Name: policyPrefixImport, Statements: []*api.Statement{{
		Name:       localOriginStatement,
		Conditions: &api.Conditions{RouteType: api.Conditions_ROUTE_TYPE_LOCAL},
		Actions:    &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT},
	}}}
	exportPolicy := &api.Policy{Name: policyPrefixExport}
	req := &api.SetPoliciesRequest{Policies: []*api.Policy{importPolicy, exportPolicy}}
	if s.config == nil {
		return req, nil
	}

	announce := s.announcePrefixes()
	for i := range s.config.Neighbors {
		n := &s.config.Neighbors[i]
		neighbors := &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
			Name:        neighborSetName(n.Address),
			List:        []string{netip.PrefixFrom(n.Address, n.Address.BitLen()).String()},
		}
		req.DefinedSets = append(req.DefinedSets, neighbors)

		exportAllow := n.Policy.ExportAllow
		if len(exportAllow) == 0 {
			exportAllow = announce
		}
		for _, dir := range []peerDirection{
			{
				name:          policyName(policyPrefixImport, n.Address),
				prefixes:      n.Policy.ImportAllow,
				routeTargets:  n.Policy.ImportRouteTargets,
				attributes:    n.Policy.Import,
				defaultAccept: n.Policy.ImportDefaultAccept,
				policy:        importPolicy,
			},
			{
				name:          policyName(policyPrefixExport, n.Address),
				prefixes:      exportAllow,
				routeTargets:  n.Policy.ExportRouteTargets,
				attributes:    n.Policy.Export,
				defaultAccept: n.Policy.ExportDefaultAccept,
				policy:        exportPolicy,
			},
		} {
			sets := prefixDefinedSetsByFamily(dir.name+prefixSetSuffix, dir.prefixes)
			rts, err := routeTargetDefinedSet(dir.name+routeTargetSuffix, dir.routeTargets)
			if err != nil {
				return nil, err
			}
			if rts != nil {
				sets = append(sets, rts)
			}
			req.DefinedSets = append(req.DefinedSets, sets...)
			dir.policy.Statements = append(dir.policy.Statements,
				peerStatements(dir, neighbors.GetName(), sets, s.addressFamilyToAPI(AFamilyEVPN), s.config.ASN)...)
		}
	}
	return req, nil
}

// peerDirection is one direction of one peer's configured policy.
type peerDirection struct {
	name          string
	prefixes      []PrefixMatch
	routeTargets  []string
	attributes    *PeerAttributesConfig
	defaultAccept bool
	policy        *api.Policy
}

// globalAssignments assigns the two global policies to the global RIB with
// the RFC 8212 reject default. A per-peer opt-in to accept-by-default is a
// statement inside the policy, not a different default, because GoBGP has
// one default per direction for every non-route-server peer.
func globalAssignments() []*api.PolicyAssignment {
	return []*api.PolicyAssignment{
		{
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			Policies:      []*api.Policy{{Name: policyPrefixImport}},
			DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
		{
			Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
			Policies:      []*api.Policy{{Name: policyPrefixExport}},
			DefaultAction: api.RouteAction_ROUTE_ACTION_REJECT,
		},
	}
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

// routeTargetDefinedSet turns a route-target allowlist into a GoBGP
// extended-community set. An empty allowlist yields no set at all, not an
// empty one: the statement that would reference it is then never built, so
// EVPN in that direction falls to the reject default.
func routeTargetDefinedSet(name string, routeTargets []string) (*api.DefinedSet, error) {
	patterns, err := routeTargetPatterns(routeTargets)
	if err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	return &api.DefinedSet{
		DefinedType: api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY,
		Name:        name,
		List:        patterns,
	}, nil
}

// routeTargetPatterns parses each route target and renders it as the
// anchored, literal "rt:" pattern a GoBGP extended-community set matches.
// GoBGP compares the pattern against the community's printed form — a
// four-octet AS prints in asdot, 4200000000:7 as 64086.59904:7 — so the
// pattern is built from the constructed community rather than from the
// configured spelling, and its dots are escaped so 192.0.2.1:100 cannot
// match 192x0x2x1:100.
func routeTargetPatterns(routeTargets []string) ([]string, error) {
	out := make([]string, 0, len(routeTargets))
	for _, rt := range routeTargets {
		ec, err := parseRouteTarget(rt)
		if err != nil {
			return nil, err
		}
		out = append(out, "rt:^"+regexp.QuoteMeta(ec.String())+"$")
	}
	return out, nil
}

// parseRouteTarget parses "<administrator>:<number>" (RFC 4360 §4) into
// the extended community it names. The administrator is an IPv4 address
// (type 0x01, 16-bit number), an AS up to 65535 (type 0x00, 32-bit number)
// or a larger AS (type 0x02, 16-bit number).
//
// It does not use GoBGP's ParseRouteTarget, which discards its range
// errors: "4200000000:7" comes back as 65535:7 and "192.0.2.1:70000" as
// 192.0.2.1:65535, a different route target admitted without complaint.
func parseRouteTarget(rt string) (gobgp.ExtendedCommunityInterface, error) {
	admin, number, ok := strings.Cut(strings.TrimSpace(rt), ":")
	if !ok {
		return nil, ErrRouteTargetInvalid{RT: rt, Reason: "want <asn>:<number> or <ipv4>:<number>"}
	}
	local, err := strconv.ParseUint(number, 10, 32)
	if err != nil {
		return nil, ErrRouteTargetInvalid{RT: rt, Reason: "the number is not a 32-bit unsigned integer"}
	}
	const routeTarget = gobgp.EC_SUBTYPE_ROUTE_TARGET
	if addr, err := netip.ParseAddr(admin); err == nil {
		if !addr.Is4() || local > math.MaxUint16 {
			return nil, ErrRouteTargetInvalid{RT: rt, Reason: "an address administrator must be IPv4 with a number up to 65535"}
		}
		return gobgp.NewIPv4AddressSpecificExtended(routeTarget, addr, uint16(local), true)
	}
	asn, err := strconv.ParseUint(admin, 10, 32)
	if err != nil {
		return nil, ErrRouteTargetInvalid{RT: rt, Reason: "the administrator is neither an AS number nor an IPv4 address"}
	}
	if asn <= math.MaxUint16 {
		return gobgp.NewTwoOctetAsSpecificExtended(routeTarget, uint16(asn), uint32(local), true), nil
	}
	if local > math.MaxUint16 {
		return nil, ErrRouteTargetInvalid{RT: rt, Reason: "a four-octet AS administrator takes a number up to 65535"}
	}
	return gobgp.NewFourOctetAsSpecificExtended(routeTarget, uint32(asn), uint16(local), true), nil
}

// peerStatements is one direction of one peer's policy: the traffic
// engineering the configuration asks for, then one filter per defined set,
// then the opt-in accept-by-default. Every statement is conditioned on the
// peer's neighbor set, so it only ever sees that peer's paths.
//
// The attribute statement carries no route action, so GoBGP applies its
// actions and moves on to the next statement (table.Statement.Apply returns
// ROUTE_TYPE_NONE when a statement names no route action). Stamping the
// attributes before the filters rather than inside them is what makes the
// attributes hold when a direction is opted into accept-by-default: the
// filters match only the allowlist, but the attributes are what the
// operator asked to apply to the session, not to a prefix list.
//
// A unicast path is only ever admitted by its own family's prefix
// statement, because a prefix condition evaluates false when the set's AFI
// differs from the path's (table.PrefixCondition.Evaluate); that also keeps
// prefix sets from ever matching an l2vpn-evpn path. The route-target
// statement is restricted to evpn (the l2vpn-evpn family), so a unicast
// path carrying a route target is not admitted by it. Anything no statement
// accepts falls through to the reject default.
func peerStatements(dir peerDirection, neighborSet string, sets []*api.DefinedSet, evpn *api.Family, localASN uint32) []*api.Statement {
	forPeer := func() *api.Conditions {
		return &api.Conditions{NeighborSet: &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: neighborSet}}
	}
	accept := &api.Actions{RouteAction: api.RouteAction_ROUTE_ACTION_ACCEPT}

	var out []*api.Statement
	if actions := dir.attributes.apiActions(localASN); actions != nil {
		out = append(out, &api.Statement{Name: dir.name + "-attributes", Conditions: forPeer(), Actions: actions})
	}
	for _, set := range sets {
		cond := forPeer()
		switch set.GetDefinedType() {
		case api.DefinedType_DEFINED_TYPE_PREFIX:
			cond.PrefixSet = &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: set.GetName()}
		case api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY:
			cond.AfiSafiIn = []*api.Family{evpn}
			cond.ExtCommunitySet = &api.MatchSet{Type: api.MatchSet_TYPE_ANY, Name: set.GetName()}
		}
		out = append(out, &api.Statement{Name: set.GetName() + "-accept", Conditions: cond, Actions: accept})
	}
	if dir.defaultAccept {
		out = append(out, &api.Statement{Name: dir.name + "-default-accept", Conditions: forPeer(), Actions: accept})
	}
	return out
}
