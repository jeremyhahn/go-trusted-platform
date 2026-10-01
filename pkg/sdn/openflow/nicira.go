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

import "fmt"

// Nicira register and resubmit extensions: the NXM_NX_REGn match fields,
// NXAST_REG_LOAD (ovs-ofctl "load:") and NXAST_RESUBMIT_TABLE (ovs-ofctl
// "resubmit(port,table)").

const (
	// NXASTRegLoad is the register load action subtype (NXAST_REG_LOAD).
	NXASTRegLoad uint16 = 7

	// NXASTResubmitTable is the resubmit-to-table action subtype
	// (NXAST_RESUBMIT_TABLE).
	NXASTResubmitTable uint16 = 14

	// NXRegCount is the number of NXM_NX_REGn registers Open vSwitch
	// carries (reg0 through reg15).
	NXRegCount = 16

	// NXRegBits is the width of one NXM_NX_REGn register.
	NXRegBits = 32

	// NXResubmitInPort is the OpenFlow 1.0 OFPP_IN_PORT number that
	// NXAST_RESUBMIT_TABLE takes to mean "the packet's own in_port" — what
	// ovs-ofctl writes for "resubmit(,T)".
	NXResubmitInPort uint16 = 0xfff8

	// regLoadActionLength is the length of nx_action_reg_load.
	regLoadActionLength = 24

	// resubmitActionLength is the length of nx_action_resubmit.
	resubmitActionLength = 16
)

// NXMHeaderReg returns the 32-bit NXM header of NXM_NX_REGn: class 0x0001,
// field n, no mask, four bytes.
func NXMHeaderReg(index uint8) uint32 {
	return uint32(OFPXMCNxm1)<<16 | uint32(index)<<9 | 4
}

// AddReg adds an NXM_NX_REGn match. A mask of 0xffffffff matches the
// whole register and is sent without a mask, as ovs-ofctl does.
func (m *Match) AddReg(index uint8, value, mask uint32) {
	valueBytes := make([]byte, 4)
	ByteOrder.PutUint32(valueBytes, value)
	if mask == 0xffffffff {
		m.AddField(OFPXMCNxm1, index, valueBytes, nil)
		return
	}
	maskBytes := make([]byte, 4)
	ByteOrder.PutUint32(maskBytes, mask)
	m.AddField(OFPXMCNxm1, index, valueBytes, maskBytes)
}

// ActionRegLoad loads an immediate value into a bit range of a register
// (NXAST_REG_LOAD; ovs-ofctl "load:value->NXM_NX_REGn[ofs..ofs+nbits-1]").
type ActionRegLoad struct {
	Register uint8  // Register index, 0..15
	Offset   uint16 // First bit written
	NBits    uint16 // Number of bits written, 1..32
	Value    uint64 // Value written; must fit in NBits
}

// NewActionRegLoad builds a register load, refusing a register, bit range
// or value the switch would reject or silently truncate.
func NewActionRegLoad(register uint8, offset, nbits uint16, value uint64) (*ActionRegLoad, error) {
	if register >= NXRegCount {
		return nil, &MessageError{Msg: fmt.Sprintf("openflow: register %d out of range (0-%d)", register, NXRegCount-1)}
	}
	if nbits == 0 || uint32(offset)+uint32(nbits) > NXRegBits {
		return nil, &MessageError{Msg: fmt.Sprintf("openflow: bit range [%d..%d] outside a %d-bit register",
			offset, int(offset)+int(nbits)-1, NXRegBits)}
	}
	if nbits < 64 && value>>nbits != 0 {
		return nil, &MessageError{Msg: fmt.Sprintf("openflow: value %d does not fit in %d bits", value, nbits)}
	}
	return &ActionRegLoad{Register: register, Offset: offset, NBits: nbits, Value: value}, nil
}

// Length returns the action length.
func (a *ActionRegLoad) Length() uint16 {
	return regLoadActionLength
}

// MarshalBinary encodes nx_action_reg_load.
func (a *ActionRegLoad) MarshalBinary() ([]byte, error) {
	data := make([]byte, regLoadActionLength)
	ByteOrder.PutUint16(data[0:2], OFPATExperimenter)
	ByteOrder.PutUint16(data[2:4], regLoadActionLength)
	ByteOrder.PutUint32(data[4:8], NXVendorID)
	ByteOrder.PutUint16(data[8:10], NXASTRegLoad)
	ByteOrder.PutUint16(data[10:12], a.Offset<<6|(a.NBits-1))
	ByteOrder.PutUint32(data[12:16], NXMHeaderReg(a.Register))
	ByteOrder.PutUint64(data[16:24], a.Value)
	return data, nil
}

// ActionResubmit re-runs the packet through a table (NXAST_RESUBMIT_TABLE;
// ovs-ofctl "resubmit(,T)"). Unlike goto_table it may target any table,
// including an earlier one, and processing continues afterwards.
type ActionResubmit struct {
	InPort uint16 // OpenFlow 1.0 port number; NXResubmitInPort for the packet's own
	Table  uint8  // Table to resubmit to
}

// NewActionResubmit resubmits to table with the packet's own in_port.
func NewActionResubmit(table uint8) *ActionResubmit {
	return &ActionResubmit{InPort: NXResubmitInPort, Table: table}
}

// Length returns the action length.
func (a *ActionResubmit) Length() uint16 {
	return resubmitActionLength
}

// MarshalBinary encodes nx_action_resubmit.
func (a *ActionResubmit) MarshalBinary() ([]byte, error) {
	data := make([]byte, resubmitActionLength)
	ByteOrder.PutUint16(data[0:2], OFPATExperimenter)
	ByteOrder.PutUint16(data[2:4], resubmitActionLength)
	ByteOrder.PutUint32(data[4:8], NXVendorID)
	ByteOrder.PutUint16(data[8:10], NXASTResubmitTable)
	ByteOrder.PutUint16(data[10:12], a.InPort)
	data[12] = a.Table
	// 3 bytes padding
	return data, nil
}
