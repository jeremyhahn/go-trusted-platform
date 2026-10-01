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
	"regexp"
	"strconv"
	"strings"

	api "github.com/osrg/gobgp/v4/api"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Per-peer traffic engineering.
//
// A session that comes up with the right filters and no path preference is
// not the session the operator asked for: with more than one path to the
// same destination, selection falls to the speaker's tie-breaks rather than
// to policy. These types let a configuration say what the attributes are,
// per peer and per direction, and refuse anything the speaker cannot
// actually program rather than accept it and drop it silently.

// Bounds on the configurable attributes.
const (
	// MaxASPathPrepend is the largest prepend count a configuration may
	// ask for. Beyond a handful of repetitions the path is already the
	// least preferred one anywhere it is compared, so a larger number is
	// almost always a typo; GoBGP also narrows the count to a byte when it
	// programs the action, so an unbounded value would wrap silently.
	MaxASPathPrepend uint32 = 10

	// maxStandardCommunityHalf is the largest value either half of an
	// "asn:value" standard community may take (RFC 1997 packs two 16-bit
	// halves into one 32-bit attribute).
	maxStandardCommunityHalf = 65535
)

// PolicyDirection names the direction a policy attribute applies to.
type PolicyDirection string

// The two policy directions.
const (
	// PolicyDirectionImport applies to paths received from the peer.
	PolicyDirectionImport PolicyDirection = "import"

	// PolicyDirectionExport applies to paths announced to the peer.
	PolicyDirectionExport PolicyDirection = "export"
)

// CommunityOp is how a community set is applied to a path.
type CommunityOp string

// The community operations GoBGP can program.
const (
	// CommunityOpAdd appends the values to the path's communities.
	CommunityOpAdd CommunityOp = "add"

	// CommunityOpRemove drops the matching communities from the path. Its
	// values are matched as regular expressions, so "^64512:" removes a
	// whole block.
	CommunityOpRemove CommunityOp = "remove"

	// CommunityOpReplace discards the path's communities and sets these.
	CommunityOpReplace CommunityOp = "replace"
)

// communityOpAPIType maps an operation to the GoBGP action type. A missing
// key is an unknown operation, which Validate refuses.
var communityOpAPIType = map[CommunityOp]api.CommunityAction_Type{
	CommunityOpAdd:     api.CommunityAction_TYPE_ADD,
	CommunityOpRemove:  api.CommunityAction_TYPE_REMOVE,
	CommunityOpReplace: api.CommunityAction_TYPE_REPLACE,
}

// Valid reports whether the operation is one the speaker can program.
func (o CommunityOp) Valid() bool {
	_, ok := communityOpAPIType[o]
	return ok
}

// String returns the operation as written in configuration.
func (o CommunityOp) String() string {
	return string(o)
}

// CommunitySetConfig is one community action: an operation and the values
// it applies. GoBGP carries a single community action per direction, so a
// configuration names one operation rather than several lists; asking for
// two would mean programming one and dropping the other.
type CommunitySetConfig struct {
	// Action is add, remove or replace.
	Action CommunityOp `yaml:"action" json:"action" mapstructure:"action"`

	// Values are the communities the action applies. For add and replace
	// each is a literal community; for remove each is a regular expression
	// matched against the path's communities.
	Values []string `yaml:"values" json:"values" mapstructure:"values"`
}

// ASPathPrependConfig repeats an AS number on the path, which lengthens it
// and de-preferences it wherever AS-path length decides.
type ASPathPrependConfig struct {
	// Count is how many times to prepend, 1..MaxASPathPrepend.
	Count uint32 `yaml:"count" json:"count" mapstructure:"count"`

	// ASN is the AS number to prepend. Zero means the speaker's own ASN,
	// which is what prepending normally means.
	ASN uint32 `yaml:"asn" json:"asn" mapstructure:"asn"`
}

// PeerAttributesConfig is the set of path attributes applied in one
// direction of one peer's policy. Every field is optional; a nil or unset
// field programs no action at all, which is distinct from a field set to
// zero.
type PeerAttributesConfig struct {
	// LocalPref sets LOCAL_PREF (RFC 4271 §5.1.5). It is the usual way to
	// rank several sessions carrying the same prefix: the highest value
	// wins before any other tie-break.
	LocalPref *uint32 `yaml:"local-pref" json:"local_pref" mapstructure:"local-pref"`

	// MED sets MULTI_EXIT_DISC (RFC 4271 §5.1.4), the hint a neighbouring
	// AS uses to choose between several entry points into this one.
	MED *uint32 `yaml:"med" json:"med" mapstructure:"med"`

	// Prepend repeats an AS number on the path.
	Prepend *ASPathPrependConfig `yaml:"prepend" json:"prepend" mapstructure:"prepend"`

	// Communities is the standard community action (RFC 1997).
	Communities *CommunitySetConfig `yaml:"communities" json:"communities" mapstructure:"communities"`

	// LargeCommunities is the large community action (RFC 8092).
	LargeCommunities *CommunitySetConfig `yaml:"large-communities" json:"large_communities" mapstructure:"large-communities"`
}

// isZero reports whether the attribute set programs nothing.
func (c *PeerAttributesConfig) isZero() bool {
	return c == nil ||
		(c.LocalPref == nil &&
			c.MED == nil &&
			c.Prepend == nil &&
			c.Communities == nil &&
			c.LargeCommunities == nil)
}

// Validate checks that every attribute set in this direction is one the
// speaker can program, and reports the first that is not.
func (c *PeerAttributesConfig) Validate(direction PolicyDirection) error {
	if c == nil {
		return nil
	}
	if c.LocalPref != nil && *c.LocalPref == 0 {
		// GoBGP treats a local-pref action of zero as "no action", so a
		// configuration asking for it would be accepted and dropped.
		return ErrLocalPrefInvalid{
			Direction: string(direction),
			Reason:    "local-pref 0 cannot be programmed; omit the field to leave LOCAL_PREF alone",
		}
	}
	if err := c.Prepend.validate(direction); err != nil {
		return err
	}
	if err := c.Communities.validate(direction, "communities", parseStandardCommunity); err != nil {
		return err
	}
	return c.LargeCommunities.validate(direction, "large-communities", parseLargeCommunity)
}

// validate checks the prepend request.
func (p *ASPathPrependConfig) validate(direction PolicyDirection) error {
	if p == nil {
		return nil
	}
	if p.Count == 0 {
		return ErrPrependInvalid{
			Direction: string(direction),
			Reason:    "prepend count 0 repeats nothing; omit the block to prepend nothing",
		}
	}
	if p.Count > MaxASPathPrepend {
		return ErrPrependInvalid{
			Direction: string(direction),
			Reason: "prepend count " + strconv.FormatUint(uint64(p.Count), 10) +
				" exceeds the maximum of " + strconv.FormatUint(uint64(MaxASPathPrepend), 10),
		}
	}
	// Zero is the sentinel for "the speaker's own ASN", filled in when the
	// action is built. AS 0 is forbidden in an AS_PATH anyway (RFC 7607),
	// so nothing legitimate is lost by spending the value that way.
	if reserver, reserved := reservedASNs[p.ASN]; reserved {
		return ErrPrependInvalid{
			Direction: string(direction),
			Reason: "prepend asn " + strconv.FormatUint(uint64(p.ASN), 10) +
				" must not appear in an AS_PATH (" + reserver + ")",
		}
	}
	return nil
}

// reservedASNs are the AS numbers a speaker must never place in an AS_PATH,
// mapped to the document that reserves them. AS 0 is absent because the
// configuration spends it as "the speaker's own ASN" before this check.
var reservedASNs = map[uint32]string{
	23456:      "AS_TRANS, RFC 6793 §9",
	65535:      "RFC 7300",
	4294967295: "RFC 7300",
}

// communityParser reports why a community value cannot be used, or nil.
type communityParser func(value string) error

// validate checks one community action. An action with no values, or a
// value neither the speaker nor GoBGP can turn into a community, is
// refused: both would install an action that changes nothing.
func (c *CommunitySetConfig) validate(direction PolicyDirection, attribute string, parse communityParser) error {
	if c == nil {
		return nil
	}
	if !c.Action.Valid() {
		return ErrCommunityInvalid{
			Direction: string(direction),
			Attribute: attribute,
			Value:     c.Action.String(),
			Reason:    "unknown action; use add, remove or replace",
		}
	}
	if len(c.Values) == 0 {
		return ErrCommunityInvalid{
			Direction: string(direction),
			Attribute: attribute,
			Reason:    "action " + c.Action.String() + " has no values",
		}
	}
	for _, v := range c.Values {
		var err error
		if c.Action == CommunityOpRemove {
			// A remove value is matched as a regular expression, so the
			// only thing to check is that it compiles.
			_, err = regexp.Compile(v)
			if err != nil {
				err = ErrCommunityInvalid{
					Direction: string(direction),
					Attribute: attribute,
					Value:     v,
					Reason:    "remove value is not a valid regular expression",
				}
			}
		} else if perr := parse(v); perr != nil {
			err = ErrCommunityInvalid{
				Direction: string(direction),
				Attribute: attribute,
				Value:     v,
				Reason:    perr.Error(),
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// standardCommunityPattern is the "asn:value" spelling of a standard
// community, anchored so a value with anything around it is refused rather
// than silently truncated to the digits GoBGP happens to find.
var standardCommunityPattern = regexp.MustCompile(`^(\d+):(\d+)$`)

// parseStandardCommunity reports whether value is a standard community:
// a bare 32-bit number, an "asn:value" pair of 16-bit halves, or one of the
// well-known names ("no-export", "blackhole", …).
func parseStandardCommunity(value string) error {
	if _, err := strconv.ParseUint(value, 10, 32); err == nil {
		return nil
	}
	if halves := standardCommunityPattern.FindStringSubmatch(value); halves != nil {
		for _, half := range halves[1:] {
			n, err := strconv.ParseUint(half, 10, 32)
			if err != nil || n > maxStandardCommunityHalf {
				return ErrCommunityHalfOutOfRange{Half: half}
			}
		}
		return nil
	}
	for _, name := range gobgp.WellKnownCommunityNameMap {
		if value == name {
			return nil
		}
	}
	return ErrCommunityUnparseable{Value: value, Form: "asn:value, a 32-bit number, or a well-known name"}
}

// parseLargeCommunity reports whether value is a large community
// (RFC 8092): three 32-bit numbers separated by colons.
func parseLargeCommunity(value string) error {
	if _, err := gobgp.ParseLargeCommunity(value); err != nil {
		return ErrCommunityUnparseable{Value: value, Form: "global:local1:local2, each a 32-bit number"}
	}
	return nil
}

// apiActions turns the attribute set into the GoBGP actions that program
// it. localASN fills in a prepend that named no AS number. It returns nil
// when nothing is set, which is the caller's signal to emit no statement.
func (c *PeerAttributesConfig) apiActions(localASN uint32) *api.Actions {
	if c.isZero() {
		return nil
	}
	actions := &api.Actions{}
	if c.LocalPref != nil {
		actions.LocalPref = &api.LocalPrefAction{Value: *c.LocalPref}
	}
	if c.MED != nil {
		// REPLACE, not MOD: the configuration states the MED it wants,
		// it does not offset whatever arrived.
		actions.Med = &api.MedAction{
			Type:  api.MedAction_TYPE_REPLACE,
			Value: int64(*c.MED),
		}
	}
	if c.Prepend != nil {
		asn := c.Prepend.ASN
		if asn == 0 {
			asn = localASN
		}
		actions.AsPrepend = &api.AsPrependAction{Asn: asn, Repeat: c.Prepend.Count}
	}
	if c.Communities != nil {
		actions.Community = c.Communities.apiAction()
	}
	if c.LargeCommunities != nil {
		actions.LargeCommunity = c.LargeCommunities.apiAction()
	}
	return actions
}

// apiAction turns one community set into its GoBGP action.
func (c *CommunitySetConfig) apiAction() *api.CommunityAction {
	return &api.CommunityAction{
		Type:        communityOpAPIType[c.Action],
		Communities: append([]string(nil), c.Values...),
	}
}

// describe summarises the attribute set for a log line, in a stable order.
func (c *PeerAttributesConfig) describe() string {
	if c.isZero() {
		return ""
	}
	parts := make([]string, 0, 5)
	if c.LocalPref != nil {
		parts = append(parts, "local-pref="+strconv.FormatUint(uint64(*c.LocalPref), 10))
	}
	if c.MED != nil {
		parts = append(parts, "med="+strconv.FormatUint(uint64(*c.MED), 10))
	}
	if c.Prepend != nil {
		parts = append(parts, "prepend="+strconv.FormatUint(uint64(c.Prepend.Count), 10))
	}
	if c.Communities != nil {
		parts = append(parts, "communities="+c.Communities.Action.String())
	}
	if c.LargeCommunities != nil {
		parts = append(parts, "large-communities="+c.LargeCommunities.Action.String())
	}
	return strings.Join(parts, " ")
}

// validateAttributeDirections checks the rules that need both the peer's
// ASN and the speaker's own. LOCAL_PREF is the one attribute BGP does not
// carry in every direction: RFC 4271 §5.1.5 says a speaker never includes
// it in an UPDATE to an external peer, so an export local-pref toward an
// eBGP session is a control that would read as configured and do nothing.
func (c *NeighborConfig) validateAttributeDirections(localASN uint32) error {
	if c.Policy.Export == nil || c.Policy.Export.LocalPref == nil {
		return nil
	}
	if c.ASN == localASN {
		return nil
	}
	return ErrAttributeDirectionInvalid{
		Peer:      c.Address.String(),
		Attribute: "local-pref",
		Direction: string(PolicyDirectionExport),
		Reason: "LOCAL_PREF is not carried to an external peer (RFC 4271 §5.1.5); " +
			"set it on import, or on an iBGP session",
	}
}
