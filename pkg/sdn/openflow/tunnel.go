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

// NXM1 tunnel field types (Nicira extension, widely supported by OVS)
// These are used for VXLAN, GRE, and other tunnel protocols
const (
	// NXMFieldTunID is the tunnel ID field (VNI for VXLAN, key for GRE)
	// 64-bit value, though VXLAN VNI only uses lower 24 bits
	NXMFieldTunID uint8 = 16

	// NXMFieldTunIPv4Src is the tunnel source IPv4 address
	NXMFieldTunIPv4Src uint8 = 31

	// NXMFieldTunIPv4Dst is the tunnel destination IPv4 address
	NXMFieldTunIPv4Dst uint8 = 32
)

// Tunnel field lengths
const (
	TunnelIDLength   = 8 // 64-bit tunnel ID
	TunnelIPv4Length = 4 // 32-bit IPv4 address
)

// VXLAN VNI mask (24 bits)
const VXLANVNIMask uint64 = 0x00FFFFFF

// TunnelMatch represents tunnel-related match fields
type TunnelMatch struct {
	// TunnelID is the VNI (24-bit in VXLAN, stored in 64-bit field)
	TunnelID uint64

	// TunnelIDMask is the mask for partial matching (nil for exact match)
	TunnelIDMask *uint64

	// TunSrc is the tunnel source IP
	TunSrc netip.Addr

	// TunDst is the tunnel destination IP
	TunDst netip.Addr
}

// NewTunnelMatch creates a new TunnelMatch with default values
func NewTunnelMatch() *TunnelMatch {
	return &TunnelMatch{}
}

// SetTunnelID sets the tunnel ID for exact matching
func (tm *TunnelMatch) SetTunnelID(vni uint64) *TunnelMatch {
	tm.TunnelID = vni
	tm.TunnelIDMask = nil
	return tm
}

// SetTunnelIDMasked sets the tunnel ID with a mask for partial matching
func (tm *TunnelMatch) SetTunnelIDMasked(vni, mask uint64) *TunnelMatch {
	tm.TunnelID = vni
	tm.TunnelIDMask = &mask
	return tm
}

// SetTunSrc sets the tunnel source IP
func (tm *TunnelMatch) SetTunSrc(src netip.Addr) *TunnelMatch {
	tm.TunSrc = src
	return tm
}

// SetTunDst sets the tunnel destination IP
func (tm *TunnelMatch) SetTunDst(dst netip.Addr) *TunnelMatch {
	tm.TunDst = dst
	return tm
}

// AddTunnelID adds a tunnel ID (VNI) match field to the match
// Uses NXM1 class (0x0001) for tunnel ID field
func (m *Match) AddTunnelID(tunnelID uint64) {
	value := make([]byte, TunnelIDLength)
	ByteOrder.PutUint64(value, tunnelID)
	m.AddField(OFPXMCNxm1, NXMFieldTunID, value, nil)
}

// AddTunnelIDMasked adds a tunnel ID (VNI) match field with mask
func (m *Match) AddTunnelIDMasked(tunnelID, mask uint64) {
	value := make([]byte, TunnelIDLength)
	ByteOrder.PutUint64(value, tunnelID)
	maskBytes := make([]byte, TunnelIDLength)
	ByteOrder.PutUint64(maskBytes, mask)
	m.AddField(OFPXMCNxm1, NXMFieldTunID, value, maskBytes)
}

// AddTunIPv4Src adds a tunnel source IPv4 address match field
func (m *Match) AddTunIPv4Src(ip netip.Addr) {
	if !ip.Is4() {
		return
	}
	value := ip.As4()
	m.AddField(OFPXMCNxm1, NXMFieldTunIPv4Src, value[:], nil)
}

// AddTunIPv4SrcMasked adds a tunnel source IPv4 address match field with mask
func (m *Match) AddTunIPv4SrcMasked(ip netip.Addr, mask netip.Addr) {
	if !ip.Is4() || !mask.Is4() {
		return
	}
	value := ip.As4()
	maskBytes := mask.As4()
	m.AddField(OFPXMCNxm1, NXMFieldTunIPv4Src, value[:], maskBytes[:])
}

// AddTunIPv4Dst adds a tunnel destination IPv4 address match field
func (m *Match) AddTunIPv4Dst(ip netip.Addr) {
	if !ip.Is4() {
		return
	}
	value := ip.As4()
	m.AddField(OFPXMCNxm1, NXMFieldTunIPv4Dst, value[:], nil)
}

// AddTunIPv4DstMasked adds a tunnel destination IPv4 address match field with mask
func (m *Match) AddTunIPv4DstMasked(ip netip.Addr, mask netip.Addr) {
	if !ip.Is4() || !mask.Is4() {
		return
	}
	value := ip.As4()
	maskBytes := mask.As4()
	m.AddField(OFPXMCNxm1, NXMFieldTunIPv4Dst, value[:], maskBytes[:])
}

// ActionSetTunnelID represents an action to set the tunnel ID for encapsulation
// This uses the OFPAT_SET_FIELD action with NXM1 tunnel ID field
type ActionSetTunnelID struct {
	TunnelID uint64
}

// NewActionSetTunnelID creates a new set tunnel ID action
func NewActionSetTunnelID(tunnelID uint64) *ActionSetTunnelID {
	return &ActionSetTunnelID{TunnelID: tunnelID}
}

// Length returns the action length (padded to 8 bytes)
// Format: action header (4) + OXM header (4) + value (8) = 16 bytes
func (a *ActionSetTunnelID) Length() uint16 {
	return 16
}

// MarshalBinary encodes the set tunnel ID action
func (a *ActionSetTunnelID) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16)

	// Action header
	ByteOrder.PutUint16(data[0:2], OFPATSetField)
	ByteOrder.PutUint16(data[2:4], 16) // action length

	// OXM TLV for tunnel ID
	// Class: NXM1 (0x0001)
	// Field: TunID (16)
	// HasMask: 0
	// Length: 8
	ByteOrder.PutUint16(data[4:6], OFPXMCNxm1)
	data[6] = NXMFieldTunID << 1 // field << 1 | hasMask
	data[7] = TunnelIDLength     // payload length

	// Value (64-bit tunnel ID)
	ByteOrder.PutUint64(data[8:16], a.TunnelID)

	return data, nil
}

// ActionSetTunDst represents an action to set the tunnel destination IP
type ActionSetTunDst struct {
	IPv4 netip.Addr
}

// NewActionSetTunDst creates a new set tunnel destination action
func NewActionSetTunDst(dst netip.Addr) *ActionSetTunDst {
	return &ActionSetTunDst{IPv4: dst}
}

// Length returns the action length (padded to 8 bytes)
// Format: action header (4) + OXM header (4) + value (4) + pad (4) = 16 bytes
func (a *ActionSetTunDst) Length() uint16 {
	return 16
}

// MarshalBinary encodes the set tunnel destination action
func (a *ActionSetTunDst) MarshalBinary() ([]byte, error) {
	if !a.IPv4.Is4() {
		return nil, ErrInvalidAction
	}

	data := make([]byte, 16)

	// Action header
	ByteOrder.PutUint16(data[0:2], OFPATSetField)
	ByteOrder.PutUint16(data[2:4], 16) // action length

	// OXM TLV for tunnel destination
	// Class: NXM1 (0x0001)
	// Field: TunIPv4Dst (32)
	// HasMask: 0
	// Length: 4
	ByteOrder.PutUint16(data[4:6], OFPXMCNxm1)
	data[6] = NXMFieldTunIPv4Dst << 1 // field << 1 | hasMask
	data[7] = TunnelIPv4Length        // payload length

	// Value (32-bit IPv4)
	ipBytes := a.IPv4.As4()
	copy(data[8:12], ipBytes[:])
	// 4 bytes padding (12-16)

	return data, nil
}

// ActionSetTunSrc represents an action to set the tunnel source IP
type ActionSetTunSrc struct {
	IPv4 netip.Addr
}

// NewActionSetTunSrc creates a new set tunnel source action
func NewActionSetTunSrc(src netip.Addr) *ActionSetTunSrc {
	return &ActionSetTunSrc{IPv4: src}
}

// Length returns the action length (padded to 8 bytes)
func (a *ActionSetTunSrc) Length() uint16 {
	return 16
}

// MarshalBinary encodes the set tunnel source action
func (a *ActionSetTunSrc) MarshalBinary() ([]byte, error) {
	if !a.IPv4.Is4() {
		return nil, ErrInvalidAction
	}

	data := make([]byte, 16)

	// Action header
	ByteOrder.PutUint16(data[0:2], OFPATSetField)
	ByteOrder.PutUint16(data[2:4], 16)

	// OXM TLV for tunnel source
	ByteOrder.PutUint16(data[4:6], OFPXMCNxm1)
	data[6] = NXMFieldTunIPv4Src << 1
	data[7] = TunnelIPv4Length

	// Value (32-bit IPv4)
	ipBytes := a.IPv4.As4()
	copy(data[8:12], ipBytes[:])

	return data, nil
}

// FlowModBuilder provides a builder pattern for creating FlowMod messages
// with support for tunnel matching and actions
type FlowModBuilder struct {
	flowMod *FlowMod
	actions []Action
}

// NewFlowModBuilder creates a new FlowMod builder with the given priority
func NewFlowModBuilder(priority uint16) *FlowModBuilder {
	fm := NewFlowMod(0)
	fm.Priority = priority
	return &FlowModBuilder{
		flowMod: fm,
		actions: make([]Action, 0),
	}
}

// SetTableID sets the table ID
func (b *FlowModBuilder) SetTableID(tableID uint8) *FlowModBuilder {
	b.flowMod.TableID = tableID
	return b
}

// SetCookie sets the cookie value
func (b *FlowModBuilder) SetCookie(cookie uint64) *FlowModBuilder {
	b.flowMod.Cookie = cookie
	return b
}

// SetIdleTimeout sets the idle timeout
func (b *FlowModBuilder) SetIdleTimeout(timeout uint16) *FlowModBuilder {
	b.flowMod.IdleTimeout = timeout
	return b
}

// SetHardTimeout sets the hard timeout
func (b *FlowModBuilder) SetHardTimeout(timeout uint16) *FlowModBuilder {
	b.flowMod.HardTimeout = timeout
	return b
}

// SetFlags sets the flow mod flags
func (b *FlowModBuilder) SetFlags(flags uint16) *FlowModBuilder {
	b.flowMod.Flags = flags
	return b
}

// MatchInPort adds an input port match
func (b *FlowModBuilder) MatchInPort(port uint32) *FlowModBuilder {
	b.flowMod.Match.AddInPort(port)
	return b
}

// MatchEthDst adds an Ethernet destination match
func (b *FlowModBuilder) MatchEthDst(mac []byte) *FlowModBuilder {
	b.flowMod.Match.AddEthDst(mac)
	return b
}

// MatchEthSrc adds an Ethernet source match
func (b *FlowModBuilder) MatchEthSrc(mac []byte) *FlowModBuilder {
	b.flowMod.Match.AddEthSrc(mac)
	return b
}

// MatchEthType adds an EtherType match
func (b *FlowModBuilder) MatchEthType(ethType uint16) *FlowModBuilder {
	b.flowMod.Match.AddEthType(ethType)
	return b
}

// MatchTunnelID adds a tunnel ID (VNI) match
func (b *FlowModBuilder) MatchTunnelID(vni uint64) *FlowModBuilder {
	b.flowMod.Match.AddTunnelID(vni)
	return b
}

// MatchTunnelIDMasked adds a tunnel ID match with mask
func (b *FlowModBuilder) MatchTunnelIDMasked(vni, mask uint64) *FlowModBuilder {
	b.flowMod.Match.AddTunnelIDMasked(vni, mask)
	return b
}

// MatchTunSrc adds a tunnel source IP match
func (b *FlowModBuilder) MatchTunSrc(src netip.Addr) *FlowModBuilder {
	b.flowMod.Match.AddTunIPv4Src(src)
	return b
}

// MatchTunDst adds a tunnel destination IP match
func (b *FlowModBuilder) MatchTunDst(dst netip.Addr) *FlowModBuilder {
	b.flowMod.Match.AddTunIPv4Dst(dst)
	return b
}

// MatchTunSrcMasked adds a tunnel source IP match with mask
func (b *FlowModBuilder) MatchTunSrcMasked(src, mask netip.Addr) *FlowModBuilder {
	b.flowMod.Match.AddTunIPv4SrcMasked(src, mask)
	return b
}

// MatchTunDstMasked adds a tunnel destination IP match with mask
func (b *FlowModBuilder) MatchTunDstMasked(dst, mask netip.Addr) *FlowModBuilder {
	b.flowMod.Match.AddTunIPv4DstMasked(dst, mask)
	return b
}

// MatchVLANVid adds a VLAN ID match
func (b *FlowModBuilder) MatchVLANVid(vid uint16) *FlowModBuilder {
	b.flowMod.Match.AddVLANVid(vid)
	return b
}

// MatchIPv4Src adds an IPv4 source match
func (b *FlowModBuilder) MatchIPv4Src(ip netip.Addr) *FlowModBuilder {
	if ip.Is4() {
		ipBytes := ip.As4()
		b.flowMod.Match.AddIPv4Src(ipBytes[:])
	}
	return b
}

// MatchIPv4Dst adds an IPv4 destination match
func (b *FlowModBuilder) MatchIPv4Dst(ip netip.Addr) *FlowModBuilder {
	if ip.Is4() {
		ipBytes := ip.As4()
		b.flowMod.Match.AddIPv4Dst(ipBytes[:])
	}
	return b
}

// ActionSetTunnelID adds an action to set the tunnel ID
func (b *FlowModBuilder) ActionSetTunnelID(vni uint64) *FlowModBuilder {
	b.actions = append(b.actions, NewActionSetTunnelID(vni))
	return b
}

// ActionSetTunDst adds an action to set the tunnel destination
func (b *FlowModBuilder) ActionSetTunDst(dst netip.Addr) *FlowModBuilder {
	b.actions = append(b.actions, NewActionSetTunDst(dst))
	return b
}

// ActionSetTunSrc adds an action to set the tunnel source
func (b *FlowModBuilder) ActionSetTunSrc(src netip.Addr) *FlowModBuilder {
	b.actions = append(b.actions, NewActionSetTunSrc(src))
	return b
}

// ActionOutput adds an output action
func (b *FlowModBuilder) ActionOutput(port uint32) *FlowModBuilder {
	b.actions = append(b.actions, NewActionOutput(port, 0))
	return b
}

// ActionOutputController adds an output to controller action
func (b *FlowModBuilder) ActionOutputController(maxLen uint16) *FlowModBuilder {
	b.actions = append(b.actions, NewActionOutput(OFPPController, maxLen))
	return b
}

// ActionPushVLAN adds a push VLAN action
func (b *FlowModBuilder) ActionPushVLAN(etherType uint16) *FlowModBuilder {
	b.actions = append(b.actions, NewActionPushVLAN(etherType))
	return b
}

// ActionPopVLAN adds a pop VLAN action
func (b *FlowModBuilder) ActionPopVLAN() *FlowModBuilder {
	b.actions = append(b.actions, NewActionPopVLAN())
	return b
}

// GotoTable adds a goto table instruction
func (b *FlowModBuilder) GotoTable(tableID uint8) *FlowModBuilder {
	b.flowMod.Instructions = append(b.flowMod.Instructions,
		NewInstructionGotoTable(tableID))
	return b
}

// Build creates the final FlowMod message
func (b *FlowModBuilder) Build() *FlowMod {
	if len(b.actions) > 0 {
		b.flowMod.Instructions = append(b.flowMod.Instructions,
			NewInstructionApplyActions(b.actions...))
	}
	return b.flowMod
}

// encodeTunnelIDOXM encodes a tunnel ID as an OXM field
// Returns the raw OXM bytes that can be used in match or set_field action
func encodeTunnelIDOXM(tunnelID uint64, mask *uint64) []byte {
	var length int
	if mask != nil {
		length = 4 + TunnelIDLength*2 // header + value + mask
	} else {
		length = 4 + TunnelIDLength // header + value
	}

	data := make([]byte, length)

	// OXM header
	ByteOrder.PutUint16(data[0:2], OFPXMCNxm1)
	if mask != nil {
		data[2] = (NXMFieldTunID << 1) | 1 // field << 1 | hasMask
		data[3] = TunnelIDLength * 2       // length with mask
	} else {
		data[2] = NXMFieldTunID << 1 // field << 1
		data[3] = TunnelIDLength     // length without mask
	}

	// Value
	ByteOrder.PutUint64(data[4:12], tunnelID)

	// Mask (if present)
	if mask != nil {
		ByteOrder.PutUint64(data[12:20], *mask)
	}

	return data
}

// encodeTunnelIPv4OXM encodes a tunnel IPv4 address as an OXM field
func encodeTunnelIPv4OXM(field uint8, ip netip.Addr, mask *netip.Addr) []byte {
	var length int
	if mask != nil {
		length = 4 + TunnelIPv4Length*2
	} else {
		length = 4 + TunnelIPv4Length
	}

	data := make([]byte, length)

	// OXM header
	ByteOrder.PutUint16(data[0:2], OFPXMCNxm1)
	if mask != nil {
		data[2] = (field << 1) | 1
		data[3] = TunnelIPv4Length * 2
	} else {
		data[2] = field << 1
		data[3] = TunnelIPv4Length
	}

	// Value
	if ip.Is4() {
		ipBytes := ip.As4()
		copy(data[4:8], ipBytes[:])
	}

	// Mask (if present)
	if mask != nil && mask.Is4() {
		maskBytes := mask.As4()
		copy(data[8:12], maskBytes[:])
	}

	return data
}

// decodeTunnelIDOXM decodes a tunnel ID from OXM bytes
func decodeTunnelIDOXM(data []byte) (tunnelID uint64, mask *uint64, err error) {
	if len(data) < 4+TunnelIDLength {
		return 0, nil, ErrMessageTooShort
	}

	// Skip OXM header
	tunnelID = ByteOrder.Uint64(data[4:12])

	// Check if mask is present
	hasMask := (data[2] & 1) != 0
	if hasMask {
		if len(data) < 4+TunnelIDLength*2 {
			return 0, nil, ErrMessageTooShort
		}
		m := ByteOrder.Uint64(data[12:20])
		mask = &m
	}

	return tunnelID, mask, nil
}

// decodeTunnelIPv4OXM decodes a tunnel IPv4 address from OXM bytes
func decodeTunnelIPv4OXM(data []byte) (ip netip.Addr, mask *netip.Addr, err error) {
	if len(data) < 4+TunnelIPv4Length {
		return netip.Addr{}, nil, ErrMessageTooShort
	}

	// Skip OXM header
	var ipBytes [4]byte
	copy(ipBytes[:], data[4:8])
	ip = netip.AddrFrom4(ipBytes)

	// Check if mask is present
	hasMask := (data[2] & 1) != 0
	if hasMask {
		if len(data) < 4+TunnelIPv4Length*2 {
			return netip.Addr{}, nil, ErrMessageTooShort
		}
		var maskBytes [4]byte
		copy(maskBytes[:], data[8:12])
		m := netip.AddrFrom4(maskBytes)
		mask = &m
	}

	return ip, mask, nil
}
