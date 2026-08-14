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

package openflow

import (
	"net/netip"
)

// NXVendorID is the Nicira experimenter/vendor ID used by OVS extensions.
const NXVendorID uint32 = 0x00002320

// Nicira experimenter action subtypes (NXAST_*)
const (
	// NXASTCT is the connection tracking action subtype (NXAST_CT)
	NXASTCT uint16 = 35

	// NXASTNAT is the network address translation action subtype (NXAST_NAT)
	NXASTNAT uint16 = 36

	// NXASTCTClear is the clear connection tracking state action subtype (NXAST_CT_CLEAR)
	NXASTCTClear uint16 = 43
)

// NXM1 conntrack field types (Nicira extension, class 0x0001)
const (
	// NXMFieldCTState is the connection tracking state field (4 bytes, maskable)
	NXMFieldCTState uint8 = 105

	// NXMFieldCTZone is the connection tracking zone field (2 bytes)
	NXMFieldCTZone uint8 = 106

	// NXMFieldCTMark is the connection tracking mark field (4 bytes, maskable)
	NXMFieldCTMark uint8 = 107

	// NXMFieldCTLabel is the connection tracking label field (16 bytes, maskable)
	NXMFieldCTLabel uint8 = 108
)

// Conntrack field lengths
const (
	CTStateLength = 4  // 32-bit ct_state bitmap
	CTZoneLength  = 2  // 16-bit ct_zone
	CTMarkLength  = 4  // 32-bit ct_mark
	CTLabelLength = 16 // 128-bit ct_label
)

// ct_state bits (CS_* in OVS)
const (
	CTStateNew  uint32 = 1 << 0 // +new: new, uncommitted connection
	CTStateEst  uint32 = 1 << 1 // +est: established connection
	CTStateRel  uint32 = 1 << 2 // +rel: related connection
	CTStateRpl  uint32 = 1 << 3 // +rpl: reply direction
	CTStateInv  uint32 = 1 << 4 // +inv: invalid connection
	CTStateTrk  uint32 = 1 << 5 // +trk: packet is tracked
	CTStateSNAT uint32 = 1 << 6 // +snat: source NAT applied
	CTStateDNAT uint32 = 1 << 7 // +dnat: destination NAT applied
)

// Conntrack action flags (NX_CT_F_*)
const (
	// NXCTFCommit commits the connection to the tracker
	NXCTFCommit uint16 = 1 << 0

	// NXCTFForce forcibly commits, terminating an existing opposite-direction connection
	NXCTFForce uint16 = 1 << 1
)

// NAT action flags (NX_NAT_F_*)
const (
	NXNATFSrc         uint16 = 1 << 0 // Source NAT
	NXNATFDst         uint16 = 1 << 1 // Destination NAT
	NXNATFPersistent  uint16 = 1 << 2 // Persistent mappings
	NXNATFProtoHash   uint16 = 1 << 3 // Hash-based port selection
	NXNATFProtoRandom uint16 = 1 << 4 // Random port selection
)

// NAT range present bits (NX_NAT_RANGE_*)
const (
	NXNATRangeIPv4Min  uint16 = 1 << 0 // IPv4 range minimum present
	NXNATRangeIPv4Max  uint16 = 1 << 1 // IPv4 range maximum present
	NXNATRangeIPv6Min  uint16 = 1 << 2 // IPv6 range minimum present
	NXNATRangeIPv6Max  uint16 = 1 << 3 // IPv6 range maximum present
	NXNATRangeProtoMin uint16 = 1 << 4 // L4 port range minimum present
	NXNATRangeProtoMax uint16 = 1 << 5 // L4 port range maximum present
)

// CTRecircNone disables recirculation after conntrack (NX_CT_RECIRC_NONE)
const CTRecircNone uint8 = 0xff

// ctActionFixedLength is the fixed portion of struct nx_action_conntrack
const ctActionFixedLength = 24

// natActionFixedLength is the fixed portion of struct nx_action_nat
const natActionFixedLength = 16

// ctClearActionLength is the length of the NXAST_CT_CLEAR nx_action_header
const ctClearActionLength = 16

// ActionCT represents the Nicira conntrack action (struct nx_action_conntrack).
// It sends the packet through the connection tracker with the given zone and
// optionally recirculates to another table. Only NAT and set-field actions
// are legal as nested actions.
type ActionCT struct {
	Flags       uint16 // Zero or more NXCTF* flags
	Zone        uint16 // Immediate conntrack zone
	RecircTable uint8  // Table to recirculate to, or CTRecircNone
	Alg         uint16 // Well-known port number of ALG protocol, or zero
	Actions     []Action
}

// NewActionCT creates a new conntrack action with the given flags, immediate
// zone, recirculation table, and nested actions.
func NewActionCT(flags, zone uint16, recircTable uint8, nested ...Action) *ActionCT {
	return &ActionCT{
		Flags:       flags,
		Zone:        zone,
		RecircTable: recircTable,
		Actions:     nested,
	}
}

// NewActionCTCommit creates a committing conntrack action for the given zone
// with no recirculation.
func NewActionCTCommit(zone uint16, nested ...Action) *ActionCT {
	return NewActionCT(NXCTFCommit, zone, CTRecircNone, nested...)
}

// Length returns the action length (fixed part plus nested actions, padded to 8 bytes)
func (a *ActionCT) Length() uint16 {
	length := ctActionFixedLength
	for _, action := range a.Actions {
		length += int(action.Length())
	}
	return uint16((length + 7) & ^7)
}

// MarshalBinary encodes the conntrack action
func (a *ActionCT) MarshalBinary() ([]byte, error) {
	for _, action := range a.Actions {
		switch action.(type) {
		case *ActionNAT, *ActionSetField:
		default:
			return nil, ErrInvalidAction
		}
	}

	length := a.Length()
	data := make([]byte, length)

	// Experimenter action header
	ByteOrder.PutUint16(data[0:2], OFPATExperimenter)
	ByteOrder.PutUint16(data[2:4], length)
	ByteOrder.PutUint32(data[4:8], NXVendorID)
	ByteOrder.PutUint16(data[8:10], NXASTCT)

	// Conntrack body
	ByteOrder.PutUint16(data[10:12], a.Flags)
	// zone_src (data[12:16]) is zero: use the immediate zone value
	ByteOrder.PutUint16(data[16:18], a.Zone)
	data[18] = a.RecircTable
	// 3 bytes padding (data[19:22])
	ByteOrder.PutUint16(data[22:24], a.Alg)

	// Nested actions
	offset := ctActionFixedLength
	for _, action := range a.Actions {
		actionData, err := action.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[offset:], actionData)
		offset += len(actionData)
	}

	return data, nil
}

// ActionNAT represents the Nicira NAT action (struct nx_action_nat). It is
// only legal nested inside an ActionCT with the commit flag set.
type ActionNAT struct {
	Flags        uint16 // Zero or more NXNATF* flags
	RangePresent uint16 // NXNATRange* bits describing the variable part
	IPv4Min      netip.Addr
	IPv4Max      netip.Addr
	ProtoMin     uint16
	ProtoMax     uint16
}

// NewActionNATSrc creates a source NAT action translating to the address
// range [min, max] and L4 port range [pmin, pmax]. A zero-value max produces
// a single-address range; a zero or equal pmax produces a single-port or
// open-ended range.
func NewActionNATSrc(min, max netip.Addr, pmin, pmax uint16) *ActionNAT {
	a := &ActionNAT{
		Flags:    NXNATFSrc,
		IPv4Min:  min,
		IPv4Max:  max,
		ProtoMin: pmin,
		ProtoMax: pmax,
	}
	a.RangePresent = natRangePresent(min, max, pmin, pmax)
	return a
}

// NewActionNATDst creates a destination NAT action translating to a single
// address and, when port is non-zero, a single L4 port.
func NewActionNATDst(addr netip.Addr, port uint16) *ActionNAT {
	a := &ActionNAT{
		Flags:    NXNATFDst,
		IPv4Min:  addr,
		ProtoMin: port,
	}
	a.RangePresent = natRangePresent(addr, netip.Addr{}, port, 0)
	return a
}

// natRangePresent computes the NXNATRange* bits for the given range values
func natRangePresent(min, max netip.Addr, pmin, pmax uint16) uint16 {
	var present uint16
	if min.IsValid() {
		present |= NXNATRangeIPv4Min
	}
	if max.IsValid() && max != min {
		present |= NXNATRangeIPv4Max
	}
	if pmin > 0 {
		present |= NXNATRangeProtoMin
	}
	if pmax > 0 && pmax != pmin {
		present |= NXNATRangeProtoMax
	}
	return present
}

// Length returns the action length (fixed part plus range values, padded to 8 bytes)
func (a *ActionNAT) Length() uint16 {
	length := natActionFixedLength
	if a.RangePresent&NXNATRangeIPv4Min != 0 {
		length += 4
	}
	if a.RangePresent&NXNATRangeIPv4Max != 0 {
		length += 4
	}
	if a.RangePresent&NXNATRangeProtoMin != 0 {
		length += 2
	}
	if a.RangePresent&NXNATRangeProtoMax != 0 {
		length += 2
	}
	return uint16((length + 7) & ^7)
}

// MarshalBinary encodes the NAT action
func (a *ActionNAT) MarshalBinary() ([]byte, error) {
	if a.RangePresent&(NXNATRangeIPv6Min|NXNATRangeIPv6Max) != 0 {
		return nil, ErrInvalidAction
	}
	if a.RangePresent&NXNATRangeIPv4Min != 0 && !a.IPv4Min.Is4() {
		return nil, ErrInvalidAction
	}
	if a.RangePresent&NXNATRangeIPv4Max != 0 && !a.IPv4Max.Is4() {
		return nil, ErrInvalidAction
	}

	length := a.Length()
	data := make([]byte, length)

	// Experimenter action header
	ByteOrder.PutUint16(data[0:2], OFPATExperimenter)
	ByteOrder.PutUint16(data[2:4], length)
	ByteOrder.PutUint32(data[4:8], NXVendorID)
	ByteOrder.PutUint16(data[8:10], NXASTNAT)

	// NAT body: 2 bytes padding (data[10:12]), flags, range_present
	ByteOrder.PutUint16(data[12:14], a.Flags)
	ByteOrder.PutUint16(data[14:16], a.RangePresent)

	// Variable range values, in range_present bit order
	offset := natActionFixedLength
	if a.RangePresent&NXNATRangeIPv4Min != 0 {
		ipBytes := a.IPv4Min.As4()
		copy(data[offset:offset+4], ipBytes[:])
		offset += 4
	}
	if a.RangePresent&NXNATRangeIPv4Max != 0 {
		ipBytes := a.IPv4Max.As4()
		copy(data[offset:offset+4], ipBytes[:])
		offset += 4
	}
	if a.RangePresent&NXNATRangeProtoMin != 0 {
		ByteOrder.PutUint16(data[offset:offset+2], a.ProtoMin)
		offset += 2
	}
	if a.RangePresent&NXNATRangeProtoMax != 0 {
		ByteOrder.PutUint16(data[offset:offset+2], a.ProtoMax)
	}

	return data, nil
}

// ActionCTClear represents the Nicira clear-conntrack-state action
// (NXAST_CT_CLEAR, encoded as a 16-byte nx_action_header).
type ActionCTClear struct{}

// NewActionCTClear creates a new clear-conntrack-state action
func NewActionCTClear() *ActionCTClear {
	return &ActionCTClear{}
}

// Length returns the action length
func (a *ActionCTClear) Length() uint16 {
	return ctClearActionLength
}

// MarshalBinary encodes the clear-conntrack-state action
func (a *ActionCTClear) MarshalBinary() ([]byte, error) {
	data := make([]byte, ctClearActionLength)
	ByteOrder.PutUint16(data[0:2], OFPATExperimenter)
	ByteOrder.PutUint16(data[2:4], ctClearActionLength)
	ByteOrder.PutUint32(data[4:8], NXVendorID)
	ByteOrder.PutUint16(data[8:10], NXASTCTClear)
	// 6 bytes padding
	return data, nil
}

// AddCTState adds a masked conntrack state match field
func (m *Match) AddCTState(value, mask uint32) {
	valueBytes := make([]byte, CTStateLength)
	ByteOrder.PutUint32(valueBytes, value)
	maskBytes := make([]byte, CTStateLength)
	ByteOrder.PutUint32(maskBytes, mask)
	m.AddField(OFPXMCNxm1, NXMFieldCTState, valueBytes, maskBytes)
}

// AddCTZone adds a conntrack zone match field
func (m *Match) AddCTZone(zone uint16) {
	value := make([]byte, CTZoneLength)
	ByteOrder.PutUint16(value, zone)
	m.AddField(OFPXMCNxm1, NXMFieldCTZone, value, nil)
}

// AddCTMark adds a masked conntrack mark match field
func (m *Match) AddCTMark(mark, mask uint32) {
	valueBytes := make([]byte, CTMarkLength)
	ByteOrder.PutUint32(valueBytes, mark)
	maskBytes := make([]byte, CTMarkLength)
	ByteOrder.PutUint32(maskBytes, mask)
	m.AddField(OFPXMCNxm1, NXMFieldCTMark, valueBytes, maskBytes)
}

// MatchCTState adds a masked conntrack state match
func (b *FlowModBuilder) MatchCTState(value, mask uint32) *FlowModBuilder {
	b.flowMod.Match.AddCTState(value, mask)
	return b
}

// MatchCTZone adds a conntrack zone match
func (b *FlowModBuilder) MatchCTZone(zone uint16) *FlowModBuilder {
	b.flowMod.Match.AddCTZone(zone)
	return b
}

// MatchCTMark adds a masked conntrack mark match
func (b *FlowModBuilder) MatchCTMark(mark, mask uint32) *FlowModBuilder {
	b.flowMod.Match.AddCTMark(mark, mask)
	return b
}

// ActionCT adds a conntrack action
func (b *FlowModBuilder) ActionCT(action *ActionCT) *FlowModBuilder {
	b.actions = append(b.actions, action)
	return b
}

// ActionCTClear adds a clear-conntrack-state action
func (b *FlowModBuilder) ActionCTClear() *FlowModBuilder {
	b.actions = append(b.actions, NewActionCTClear())
	return b
}
