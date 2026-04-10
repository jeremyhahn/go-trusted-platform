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
	"encoding/binary"
	"fmt"
	"net"
)

// Hello represents an OpenFlow Hello message
type Hello struct {
	Header Header
	// Optional elements (OpenFlow 1.3.1+)
	Elements []HelloElement
}

// HelloElement represents a hello element
type HelloElement struct {
	Type   uint16
	Length uint16
	// Variable data depending on Type
}

// NewHello creates a new Hello message
func NewHello(xid uint32) *Hello {
	return &Hello{
		Header: Header{
			Version: DefaultVersion,
			Type:    OFPTHello,
			Length:  HeaderSize,
			Xid:     xid,
		},
	}
}

// MarshalBinary encodes the Hello message
func (h *Hello) MarshalBinary() ([]byte, error) {
	return h.Header.MarshalBinary()
}

// UnmarshalBinary decodes a Hello message
func (h *Hello) UnmarshalBinary(data []byte) error {
	return h.Header.UnmarshalBinary(data)
}

// FeaturesRequest represents a Features Request message
type FeaturesRequest struct {
	Header Header
}

// NewFeaturesRequest creates a new Features Request message
func NewFeaturesRequest(xid uint32) *FeaturesRequest {
	return &FeaturesRequest{
		Header: Header{
			Version: DefaultVersion,
			Type:    OFPTFeaturesRequest,
			Length:  HeaderSize,
			Xid:     xid,
		},
	}
}

// MarshalBinary encodes the FeaturesRequest
func (f *FeaturesRequest) MarshalBinary() ([]byte, error) {
	return f.Header.MarshalBinary()
}

// FeaturesReply represents a Features Reply message
type FeaturesReply struct {
	Header       Header
	DatapathID   uint64  // Datapath unique ID
	NBuffers     uint32  // Max packets buffered at once
	NTables      uint8   // Number of tables supported
	AuxiliaryID  uint8   // Identify auxiliary connections
	Pad          [2]byte // Align to 64 bits
	Capabilities uint32  // Bitmap of support capabilities
	Reserved     uint32  // Reserved
}

// UnmarshalBinary decodes a FeaturesReply
func (f *FeaturesReply) UnmarshalBinary(data []byte) error {
	if len(data) < 32 {
		return ErrMessageTooShort
	}
	if err := f.Header.UnmarshalBinary(data[:8]); err != nil {
		return err
	}
	f.DatapathID = ByteOrder.Uint64(data[8:16])
	f.NBuffers = ByteOrder.Uint32(data[16:20])
	f.NTables = data[20]
	f.AuxiliaryID = data[21]
	// Skip 2 bytes padding
	f.Capabilities = ByteOrder.Uint32(data[24:28])
	f.Reserved = ByteOrder.Uint32(data[28:32])
	return nil
}

// EchoRequest represents an Echo Request message
type EchoRequest struct {
	Header Header
	Data   []byte
}

// NewEchoRequest creates a new Echo Request
func NewEchoRequest(xid uint32, data []byte) *EchoRequest {
	return &EchoRequest{
		Header: Header{
			Version: DefaultVersion,
			Type:    OFPTEchoRequest,
			Length:  uint16(HeaderSize + len(data)),
			Xid:     xid,
		},
		Data: data,
	}
}

// MarshalBinary encodes the EchoRequest
func (e *EchoRequest) MarshalBinary() ([]byte, error) {
	header, err := e.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(header, e.Data...), nil
}

// EchoReply represents an Echo Reply message
type EchoReply struct {
	Header Header
	Data   []byte
}

// NewEchoReply creates a new Echo Reply
func NewEchoReply(xid uint32, data []byte) *EchoReply {
	return &EchoReply{
		Header: Header{
			Version: DefaultVersion,
			Type:    OFPTEchoReply,
			Length:  uint16(HeaderSize + len(data)),
			Xid:     xid,
		},
		Data: data,
	}
}

// MarshalBinary encodes the EchoReply
func (e *EchoReply) MarshalBinary() ([]byte, error) {
	header, err := e.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(header, e.Data...), nil
}

// BarrierRequest represents a Barrier Request message
type BarrierRequest struct {
	Header Header
}

// NewBarrierRequest creates a new Barrier Request
func NewBarrierRequest(xid uint32) *BarrierRequest {
	return &BarrierRequest{
		Header: Header{
			Version: DefaultVersion,
			Type:    OFPTBarrierRequest,
			Length:  HeaderSize,
			Xid:     xid,
		},
	}
}

// MarshalBinary encodes the BarrierRequest
func (b *BarrierRequest) MarshalBinary() ([]byte, error) {
	return b.Header.MarshalBinary()
}

// BarrierReply represents a Barrier Reply message
type BarrierReply struct {
	Header Header
}

// UnmarshalBinary decodes a BarrierReply
func (b *BarrierReply) UnmarshalBinary(data []byte) error {
	return b.Header.UnmarshalBinary(data)
}

// Match represents an OpenFlow OXM match
type Match struct {
	Type   uint16 // OFPMT_OXM
	Length uint16 // Length of match (excluding padding)
	Fields []OXMField
}

// OXMField represents an OXM TLV field
type OXMField struct {
	Class   uint16 // Match class
	Field   uint8  // Match field
	HasMask bool   // Has mask flag
	Length  uint8  // Payload length
	Value   []byte // Field value
	Mask    []byte // Optional mask
}

// NewMatch creates a new Match
func NewMatch() *Match {
	return &Match{
		Type:   OFPMTOXM,
		Length: 4, // Minimum: type (2) + length (2)
		Fields: make([]OXMField, 0),
	}
}

// AddField adds an OXM field to the match
func (m *Match) AddField(class uint16, field uint8, value []byte, mask []byte) {
	hasMask := len(mask) > 0
	length := uint8(len(value))
	if hasMask {
		length *= 2
	}

	oxm := OXMField{
		Class:   class,
		Field:   field,
		HasMask: hasMask,
		Length:  length,
		Value:   value,
		Mask:    mask,
	}

	m.Fields = append(m.Fields, oxm)
	// Update length: 4 bytes for OXM header + value + mask
	m.Length += 4 + uint16(len(value))
	if hasMask {
		m.Length += uint16(len(mask))
	}
}

// AddInPort adds an input port match
func (m *Match) AddInPort(port uint32) {
	value := make([]byte, 4)
	ByteOrder.PutUint32(value, port)
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBInPort, value, nil)
}

// AddEthDst adds an Ethernet destination match
func (m *Match) AddEthDst(mac net.HardwareAddr) {
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBEthDst, mac, nil)
}

// AddEthSrc adds an Ethernet source match
func (m *Match) AddEthSrc(mac net.HardwareAddr) {
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBEthSrc, mac, nil)
}

// AddEthType adds an EtherType match
func (m *Match) AddEthType(ethType uint16) {
	value := make([]byte, 2)
	ByteOrder.PutUint16(value, ethType)
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBEthType, value, nil)
}

// AddVLANVid adds a VLAN ID match
func (m *Match) AddVLANVid(vid uint16) {
	value := make([]byte, 2)
	// VLAN VID uses 13 bits, bit 12 is OFPVID_PRESENT
	ByteOrder.PutUint16(value, vid|0x1000)
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBVlanVid, value, nil)
}

// AddIPv4Src adds an IPv4 source match
func (m *Match) AddIPv4Src(ip net.IP) {
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBIPv4Src, ip.To4(), nil)
}

// AddIPv4SrcMasked adds an IPv4 source match with a network mask (for CIDR ranges)
func (m *Match) AddIPv4SrcMasked(ip net.IP, mask net.IPMask) {
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBIPv4Src, ip.To4(), []byte(mask))
}

// AddIPv4Dst adds an IPv4 destination match
func (m *Match) AddIPv4Dst(ip net.IP) {
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBIPv4Dst, ip.To4(), nil)
}

// AddIPv4DstMasked adds an IPv4 destination match with a network mask (for CIDR ranges)
func (m *Match) AddIPv4DstMasked(ip net.IP, mask net.IPMask) {
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBIPv4Dst, ip.To4(), []byte(mask))
}

// AddIPProto adds an IP protocol match
func (m *Match) AddIPProto(proto uint8) {
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBIPProto, []byte{proto}, nil)
}

// AddTCPSrc adds a TCP source port match
func (m *Match) AddTCPSrc(port uint16) {
	value := make([]byte, 2)
	ByteOrder.PutUint16(value, port)
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBTCPSrc, value, nil)
}

// AddTCPDst adds a TCP destination port match
func (m *Match) AddTCPDst(port uint16) {
	value := make([]byte, 2)
	ByteOrder.PutUint16(value, port)
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBTCPDst, value, nil)
}

// AddUDPSrc adds a UDP source port match
func (m *Match) AddUDPSrc(port uint16) {
	value := make([]byte, 2)
	ByteOrder.PutUint16(value, port)
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBUDPSrc, value, nil)
}

// AddUDPDst adds a UDP destination port match
func (m *Match) AddUDPDst(port uint16) {
	value := make([]byte, 2)
	ByteOrder.PutUint16(value, port)
	m.AddField(OFPXMCOpenflowBasic, OFPXMTOFBUDPDst, value, nil)
}

// MarshalBinary encodes the Match
func (m *Match) MarshalBinary() ([]byte, error) {
	// Calculate total length with padding to 8 bytes
	paddedLen := (int(m.Length) + 7) & ^7
	data := make([]byte, paddedLen)

	ByteOrder.PutUint16(data[0:2], m.Type)
	ByteOrder.PutUint16(data[2:4], m.Length)

	offset := 4
	for _, field := range m.Fields {
		// OXM header: class (16 bits) | field (7 bits) | hasMask (1 bit) | length (8 bits)
		ByteOrder.PutUint16(data[offset:offset+2], field.Class)
		data[offset+2] = (field.Field << 1)
		if field.HasMask {
			data[offset+2] |= 1
		}
		data[offset+3] = field.Length
		offset += 4

		copy(data[offset:], field.Value)
		offset += len(field.Value)

		if field.HasMask {
			copy(data[offset:], field.Mask)
			offset += len(field.Mask)
		}
	}

	return data, nil
}

// Action represents an OpenFlow action
type Action interface {
	MarshalBinary() ([]byte, error)
	Length() uint16
}

// ActionOutput represents an output action
type ActionOutput struct {
	Port   uint32 // Output port
	MaxLen uint16 // Max length to send to controller
	Pad    [6]byte
}

// NewActionOutput creates a new output action
func NewActionOutput(port uint32, maxLen uint16) *ActionOutput {
	return &ActionOutput{
		Port:   port,
		MaxLen: maxLen,
	}
}

// Length returns the action length
func (a *ActionOutput) Length() uint16 {
	return 16
}

// MarshalBinary encodes the action
func (a *ActionOutput) MarshalBinary() ([]byte, error) {
	data := make([]byte, 16)
	ByteOrder.PutUint16(data[0:2], OFPATOutput)
	ByteOrder.PutUint16(data[2:4], 16)
	ByteOrder.PutUint32(data[4:8], a.Port)
	ByteOrder.PutUint16(data[8:10], a.MaxLen)
	// 6 bytes padding
	return data, nil
}

// ActionSetField represents a set-field action
type ActionSetField struct {
	Field OXMField
}

// NewActionSetField creates a new set-field action
func NewActionSetField(class uint16, field uint8, value []byte) *ActionSetField {
	return &ActionSetField{
		Field: OXMField{
			Class:  class,
			Field:  field,
			Length: uint8(len(value)),
			Value:  value,
		},
	}
}

// Length returns the action length
func (a *ActionSetField) Length() uint16 {
	// 4 bytes header + 4 bytes OXM header + value, padded to 8 bytes
	l := 8 + len(a.Field.Value)
	return uint16((l + 7) & ^7)
}

// MarshalBinary encodes the action
func (a *ActionSetField) MarshalBinary() ([]byte, error) {
	length := a.Length()
	data := make([]byte, length)
	ByteOrder.PutUint16(data[0:2], OFPATSetField)
	ByteOrder.PutUint16(data[2:4], length)

	// OXM TLV
	ByteOrder.PutUint16(data[4:6], a.Field.Class)
	data[6] = a.Field.Field << 1
	data[7] = a.Field.Length
	copy(data[8:], a.Field.Value)

	return data, nil
}

// ActionPushVLAN represents a push VLAN action
type ActionPushVLAN struct {
	EtherType uint16
}

// NewActionPushVLAN creates a new push VLAN action
func NewActionPushVLAN(etherType uint16) *ActionPushVLAN {
	return &ActionPushVLAN{EtherType: etherType}
}

// Length returns the action length
func (a *ActionPushVLAN) Length() uint16 {
	return 8
}

// MarshalBinary encodes the action
func (a *ActionPushVLAN) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	ByteOrder.PutUint16(data[0:2], OFPATPushVlan)
	ByteOrder.PutUint16(data[2:4], 8)
	ByteOrder.PutUint16(data[4:6], a.EtherType)
	// 2 bytes padding
	return data, nil
}

// ActionPopVLAN represents a pop VLAN action
type ActionPopVLAN struct{}

// NewActionPopVLAN creates a new pop VLAN action
func NewActionPopVLAN() *ActionPopVLAN {
	return &ActionPopVLAN{}
}

// Length returns the action length
func (a *ActionPopVLAN) Length() uint16 {
	return 8
}

// MarshalBinary encodes the action
func (a *ActionPopVLAN) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	ByteOrder.PutUint16(data[0:2], OFPATPopVlan)
	ByteOrder.PutUint16(data[2:4], 8)
	// 4 bytes padding
	return data, nil
}

// Instruction represents an OpenFlow instruction
type Instruction interface {
	MarshalBinary() ([]byte, error)
	InstructionLength() uint16
}

// InstructionApplyActions applies actions immediately
type InstructionApplyActions struct {
	Actions []Action
}

// NewInstructionApplyActions creates a new apply-actions instruction
func NewInstructionApplyActions(actions ...Action) *InstructionApplyActions {
	return &InstructionApplyActions{Actions: actions}
}

// InstructionLength returns the instruction length
func (i *InstructionApplyActions) InstructionLength() uint16 {
	length := uint16(8) // Header + 4 bytes padding
	for _, action := range i.Actions {
		length += action.Length()
	}
	return length
}

// MarshalBinary encodes the instruction
func (i *InstructionApplyActions) MarshalBinary() ([]byte, error) {
	length := i.InstructionLength()
	data := make([]byte, length)

	ByteOrder.PutUint16(data[0:2], OFPITApplyActions)
	ByteOrder.PutUint16(data[2:4], length)
	// 4 bytes padding

	offset := 8
	for _, action := range i.Actions {
		actionData, err := action.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[offset:], actionData)
		offset += len(actionData)
	}

	return data, nil
}

// InstructionGotoTable jumps to another table
type InstructionGotoTable struct {
	TableID uint8
}

// NewInstructionGotoTable creates a new goto-table instruction
func NewInstructionGotoTable(tableID uint8) *InstructionGotoTable {
	return &InstructionGotoTable{TableID: tableID}
}

// InstructionLength returns the instruction length
func (i *InstructionGotoTable) InstructionLength() uint16 {
	return 8
}

// MarshalBinary encodes the instruction
func (i *InstructionGotoTable) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	ByteOrder.PutUint16(data[0:2], OFPITGotoTable)
	ByteOrder.PutUint16(data[2:4], 8)
	data[4] = i.TableID
	// 3 bytes padding
	return data, nil
}

// FlowMod represents a Flow Modification message
type FlowMod struct {
	Header       Header
	Cookie       uint64  // Opaque controller-issued identifier
	CookieMask   uint64  // Mask used to restrict the cookie bits
	TableID      uint8   // ID of the table to put the flow in
	Command      uint8   // One of OFPFC_*
	IdleTimeout  uint16  // Idle time before discarding (seconds)
	HardTimeout  uint16  // Max time before discarding (seconds)
	Priority     uint16  // Priority level of flow entry
	BufferID     uint32  // Buffered packet to apply to (or OFP_NO_BUFFER)
	OutPort      uint32  // For OFPFC_DELETE* commands, require matching entries to include this as an output port
	OutGroup     uint32  // For OFPFC_DELETE* commands, require matching entries to include this as an output group
	Flags        uint16  // One of OFPFF_*
	Pad          [2]byte // Align to 64 bits
	Match        *Match  // Fields to match
	Instructions []Instruction
}

// NewFlowMod creates a new FlowMod message
func NewFlowMod(xid uint32) *FlowMod {
	return &FlowMod{
		Header: Header{
			Version: DefaultVersion,
			Type:    OFPTFlowMod,
			Xid:     xid,
		},
		BufferID: 0xffffffff, // OFP_NO_BUFFER
		OutPort:  OFPPAny,
		OutGroup: 0xffffffff, // OFPG_ANY
		Match:    NewMatch(),
	}
}

// MarshalBinary encodes the FlowMod
func (f *FlowMod) MarshalBinary() ([]byte, error) {
	matchData, err := f.Match.MarshalBinary()
	if err != nil {
		return nil, err
	}

	instructionsData := make([]byte, 0)
	for _, inst := range f.Instructions {
		instData, err := inst.MarshalBinary()
		if err != nil {
			return nil, err
		}
		instructionsData = append(instructionsData, instData...)
	}

	// Total length: header (8) + body (40) + match (padded) + instructions
	length := 48 + len(matchData) + len(instructionsData)
	f.Header.Length = uint16(length)

	data := make([]byte, length)

	// Header
	headerData, err := f.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[0:8], headerData)

	// Body
	ByteOrder.PutUint64(data[8:16], f.Cookie)
	ByteOrder.PutUint64(data[16:24], f.CookieMask)
	data[24] = f.TableID
	data[25] = f.Command
	ByteOrder.PutUint16(data[26:28], f.IdleTimeout)
	ByteOrder.PutUint16(data[28:30], f.HardTimeout)
	ByteOrder.PutUint16(data[30:32], f.Priority)
	ByteOrder.PutUint32(data[32:36], f.BufferID)
	ByteOrder.PutUint32(data[36:40], f.OutPort)
	ByteOrder.PutUint32(data[40:44], f.OutGroup)
	ByteOrder.PutUint16(data[44:46], f.Flags)
	// 2 bytes padding

	// Match
	copy(data[48:], matchData)

	// Instructions
	copy(data[48+len(matchData):], instructionsData)

	return data, nil
}

// MultipartRequest represents a Multipart Request message
type MultipartRequest struct {
	Header Header
	Type   uint16 // One of OFPMP_*
	Flags  uint16 // OFPMPF_REQ_MORE
	Pad    [4]byte
	Body   []byte // Request body (varies by type)
}

// NewMultipartRequest creates a new Multipart Request
func NewMultipartRequest(xid uint32, mpType uint16, body []byte) *MultipartRequest {
	return &MultipartRequest{
		Header: Header{
			Version: DefaultVersion,
			Type:    OFPTMultipartRequest,
			Length:  uint16(16 + len(body)),
			Xid:     xid,
		},
		Type: mpType,
		Body: body,
	}
}

// MarshalBinary encodes the MultipartRequest
func (m *MultipartRequest) MarshalBinary() ([]byte, error) {
	data := make([]byte, m.Header.Length)

	headerData, err := m.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[0:8], headerData)

	ByteOrder.PutUint16(data[8:10], m.Type)
	ByteOrder.PutUint16(data[10:12], m.Flags)
	// 4 bytes padding

	if len(m.Body) > 0 {
		copy(data[16:], m.Body)
	}

	return data, nil
}

// FlowStatsRequest represents the body of a flow stats request
type FlowStatsRequest struct {
	TableID    uint8
	Pad        [3]byte
	OutPort    uint32
	OutGroup   uint32
	Pad2       [4]byte
	Cookie     uint64
	CookieMask uint64
	Match      *Match
}

// NewFlowStatsRequest creates a new flow stats request body
func NewFlowStatsRequest() *FlowStatsRequest {
	return &FlowStatsRequest{
		TableID:  OFPTTAll,
		OutPort:  OFPPAny,
		OutGroup: 0xffffffff, // OFPG_ANY
		Match:    NewMatch(),
	}
}

// MarshalBinary encodes the FlowStatsRequest
func (f *FlowStatsRequest) MarshalBinary() ([]byte, error) {
	matchData, err := f.Match.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Body: 32 bytes fixed + match
	data := make([]byte, 32+len(matchData))

	data[0] = f.TableID
	// 3 bytes padding
	ByteOrder.PutUint32(data[4:8], f.OutPort)
	ByteOrder.PutUint32(data[8:12], f.OutGroup)
	// 4 bytes padding
	ByteOrder.PutUint64(data[16:24], f.Cookie)
	ByteOrder.PutUint64(data[24:32], f.CookieMask)
	copy(data[32:], matchData)

	return data, nil
}

// FlowStats represents a single flow's statistics
type FlowStats struct {
	Length       uint16
	TableID      uint8
	Pad          byte
	DurationSec  uint32
	DurationNsec uint32
	Priority     uint16
	IdleTimeout  uint16
	HardTimeout  uint16
	Flags        uint16
	Pad2         [4]byte
	Cookie       uint64
	PacketCount  uint64
	ByteCount    uint64
	Match        *Match
	Instructions []byte
}

// ParseFlowStats parses flow statistics from multipart reply body
func ParseFlowStats(data []byte) ([]FlowStats, error) {
	var stats []FlowStats
	offset := 0

	for offset < len(data) {
		if len(data)-offset < 48 {
			break
		}

		length := binary.BigEndian.Uint16(data[offset : offset+2])
		if int(length) > len(data)-offset {
			return nil, fmt.Errorf("invalid flow stats length")
		}

		stat := FlowStats{
			Length:       length,
			TableID:      data[offset+2],
			DurationSec:  binary.BigEndian.Uint32(data[offset+4 : offset+8]),
			DurationNsec: binary.BigEndian.Uint32(data[offset+8 : offset+12]),
			Priority:     binary.BigEndian.Uint16(data[offset+12 : offset+14]),
			IdleTimeout:  binary.BigEndian.Uint16(data[offset+14 : offset+16]),
			HardTimeout:  binary.BigEndian.Uint16(data[offset+16 : offset+18]),
			Flags:        binary.BigEndian.Uint16(data[offset+18 : offset+20]),
			Cookie:       binary.BigEndian.Uint64(data[offset+24 : offset+32]),
			PacketCount:  binary.BigEndian.Uint64(data[offset+32 : offset+40]),
			ByteCount:    binary.BigEndian.Uint64(data[offset+40 : offset+48]),
		}

		stats = append(stats, stat)
		offset += int(length)
	}

	return stats, nil
}
