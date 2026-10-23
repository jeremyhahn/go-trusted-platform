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

// Nicira NXAST_CONTROLLER2: a controller action carrying its own meter
// (ovs-ofctl "controller(max_len=65535,meter_id=N)").
//
// An OpenFlow 1.3 meter instruction runs before apply-actions and
// goto-table, so a drop band on it discards the packet for the whole flow
// entry. A meter attached to the controller action instead limits only the
// copy punted to the controller: Open vSwitch compiles it to
// clone(meter(N), userspace(...)), and the rest of the flow entry is
// unaffected by the meter.

const (
	// NXASTController2 is the property-based controller action subtype
	// (NXAST_CONTROLLER2).
	NXASTController2 uint16 = 37

	// NXAC2PTMaxLen is the NXAST_CONTROLLER2 max_len property (u16).
	NXAC2PTMaxLen uint16 = 0

	// NXAC2PTMeterID is the NXAST_CONTROLLER2 meter_id property (u32).
	NXAC2PTMeterID uint16 = 5

	// controller2HeaderLength is the length of the NX extension action
	// header: type, len, vendor, subtype and six bytes of padding.
	controller2HeaderLength = 16

	// controller2PropertyLength is the padded length of one u16 or u32
	// property: a four-byte property header, the value, padding to eight.
	controller2PropertyLength = 8

	// controller2ActionLength is the header plus the max_len and meter_id
	// properties.
	controller2ActionLength = controller2HeaderLength + 2*controller2PropertyLength
)

// ActionController2 sends the whole packet to the controller through a
// meter that applies to the punt alone.
type ActionController2 struct {
	MaxLen  uint16 // Bytes of the packet sent; OFPCMLNoBuffer sends all of it
	MeterID uint32 // Meter limiting the punt, 1..OFPMMax
}

// NewActionController2 punts the whole packet through meterID, refusing
// a meter ID the switch cannot hold.
func NewActionController2(meterID uint32) (*ActionController2, error) {
	if meterID == 0 || meterID > OFPMMax {
		return nil, &MessageError{Msg: fmt.Sprintf("openflow: meter id %d outside 1-%d", meterID, OFPMMax)}
	}
	return &ActionController2{MaxLen: OFPCMLNoBuffer, MeterID: meterID}, nil
}

// Length returns the action length.
func (a *ActionController2) Length() uint16 {
	return controller2ActionLength
}

// MarshalBinary encodes nx_action_controller2 with its max_len and
// meter_id properties.
func (a *ActionController2) MarshalBinary() ([]byte, error) {
	data := make([]byte, controller2ActionLength)
	ByteOrder.PutUint16(data[0:2], OFPATExperimenter)
	ByteOrder.PutUint16(data[2:4], controller2ActionLength)
	ByteOrder.PutUint32(data[4:8], NXVendorID)
	ByteOrder.PutUint16(data[8:10], NXASTController2)
	// data[10:16] is padding

	maxLen := data[controller2HeaderLength:]
	ByteOrder.PutUint16(maxLen[0:2], NXAC2PTMaxLen)
	ByteOrder.PutUint16(maxLen[2:4], 6) // property header plus a u16
	ByteOrder.PutUint16(maxLen[4:6], a.MaxLen)

	meter := data[controller2HeaderLength+controller2PropertyLength:]
	ByteOrder.PutUint16(meter[0:2], NXAC2PTMeterID)
	ByteOrder.PutUint16(meter[2:4], 8) // property header plus a u32
	ByteOrder.PutUint32(meter[4:8], a.MeterID)
	return data, nil
}
