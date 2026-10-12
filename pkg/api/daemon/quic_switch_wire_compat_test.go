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

package daemon

import (
	"testing"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

// The tests in this file guard the QUIC wire contract for the Switch surface
// between the platform SDK client and the daemon. Every SwitchService method is
// routed by the SDK QUIC transport adapter to OpSwitchCategory with a
// sub-opcode prefix, and the generated platform.v1 request/response protobuf
// messages ARE the wire shape: the SDK encodes the pb request and the daemon
// decodes into the same pb type (and vice versa for responses). Each message is
// round-tripped through the payload codec and compared with proto.Equal so a
// codec or field-shape regression on either side fails here first.
//
// This surface previously used independently-authored flat wire structs whose
// Go field names diverged from the pb messages (VlanId vs VLANID, AccessVlan vs
// AccessVLAN, TrunkVlans vs TrunkVLANs). The divergence silently dropped the
// VLAN id on SetPortVLAN and the access/trunk VLANs on port-status responses.

// roundTripSwitchWire encodes src through the QUIC payload codec and decodes it
// into dst, then asserts proto equality.
func roundTripSwitchWire(t *testing.T, src, dst proto.Message) {
	t.Helper()
	payload, err := quicwire.EncodePayload(src)
	if err != nil {
		t.Fatalf("encode %T: %v", src, err)
	}
	if err := quicwire.DecodePayload(payload, dst); err != nil {
		t.Fatalf("decode %T into %T: %v", src, dst, err)
	}
	if !proto.Equal(src, dst) {
		t.Fatalf("round trip mismatch:\n src: %+v\n dst: %+v", src, dst)
	}
}

// compatTestSwitchPortStatus builds a fully-populated SwitchPortStatus covering
// the access_vlan and trunk_vlans fields that previously diverged.
func compatTestSwitchPortStatus() *platformv1.SwitchPortStatus {
	return &platformv1.SwitchPortStatus{
		Port:        "Eth1/3",
		Mode:        "trunk",
		AccessVlan:  100,
		TrunkVlans:  []uint32{10, 20, 30},
		Enabled:     true,
		LinkUp:      true,
		Description: "uplink to nexus-1",
		NativeVlan:  10,
	}
}

// TestQUICSwitchWireCompatListPorts round-trips ListPorts.
func TestQUICSwitchWireCompatListPorts(t *testing.T) {
	roundTripSwitchWire(t,
		&platformv1.ListSwitchPortsRequest{SwitchName: "nexus-1"},
		&platformv1.ListSwitchPortsRequest{})
	roundTripSwitchWire(t,
		&platformv1.ListSwitchPortsResponse{
			Ports: []*platformv1.SwitchPortStatus{compatTestSwitchPortStatus()},
		},
		&platformv1.ListSwitchPortsResponse{})
}

// TestQUICSwitchWireCompatGetPortStatus round-trips GetPortStatus.
func TestQUICSwitchWireCompatGetPortStatus(t *testing.T) {
	roundTripSwitchWire(t,
		&platformv1.GetSwitchPortStatusRequest{SwitchName: "nexus-1", PortName: "Eth1/3"},
		&platformv1.GetSwitchPortStatusRequest{})
	roundTripSwitchWire(t,
		&platformv1.GetSwitchPortStatusResponse{Port: compatTestSwitchPortStatus()},
		&platformv1.GetSwitchPortStatusResponse{})
}

// TestQUICSwitchWireCompatSetPortVLAN round-trips SetPortVLAN. The vlan_id field
// is the one that silently dropped under the old flat wire struct (VlanId vs
// VLANID), so it is asserted explicitly in addition to proto.Equal.
func TestQUICSwitchWireCompatSetPortVLAN(t *testing.T) {
	src := &platformv1.SetSwitchPortVLANRequest{
		SwitchName: "nexus-1",
		PortName:   "Eth1/3",
		VlanId:     250,
	}
	dst := &platformv1.SetSwitchPortVLANRequest{}
	roundTripSwitchWire(t, src, dst)
	if dst.GetVlanId() != 250 {
		t.Fatalf("VlanId = %d, want 250 (field silently dropped)", dst.GetVlanId())
	}

	roundTripSwitchWire(t,
		&platformv1.SetSwitchPortVLANResponse{
			Status: &platformv1.Status{Success: true, Message: "port VLAN updated successfully"},
		},
		&platformv1.SetSwitchPortVLANResponse{})
}

// TestQUICSwitchWireCompatEnablePort round-trips EnablePort.
func TestQUICSwitchWireCompatEnablePort(t *testing.T) {
	roundTripSwitchWire(t,
		&platformv1.EnableSwitchPortRequest{SwitchName: "nexus-1", PortName: "Eth1/3"},
		&platformv1.EnableSwitchPortRequest{})
	roundTripSwitchWire(t,
		&platformv1.EnableSwitchPortResponse{
			Status: &platformv1.Status{Success: true, Message: "port enabled successfully"},
		},
		&platformv1.EnableSwitchPortResponse{})
}

// TestQUICSwitchWireCompatDisablePort round-trips DisablePort.
func TestQUICSwitchWireCompatDisablePort(t *testing.T) {
	roundTripSwitchWire(t,
		&platformv1.DisableSwitchPortRequest{SwitchName: "nexus-1", PortName: "Eth1/3"},
		&platformv1.DisableSwitchPortRequest{})
	roundTripSwitchWire(t,
		&platformv1.DisableSwitchPortResponse{
			Status: &platformv1.Status{Success: true, Message: "port disabled successfully"},
		},
		&platformv1.DisableSwitchPortResponse{})
}

// TestQUICSwitchPortStatusToPb guards the native->pb conversion used by the
// daemon handlers, in particular the uint16->uint32 widening of the access and
// trunk VLAN fields.
func TestQUICSwitchPortStatusToPb(t *testing.T) {
	native := &switchwire.PortStatus{
		Port:        "Eth1/3",
		Mode:        switchwire.PortMode("trunk"),
		AccessVLAN:  100,
		TrunkVLANs:  []uint16{10, 20, 30},
		Enabled:     true,
		LinkUp:      true,
		Description: "uplink to nexus-1",
		NativeVLAN:  10,
	}

	pb := portStatusToPb(native)
	if !proto.Equal(pb, compatTestSwitchPortStatus()) {
		t.Fatalf("portStatusToPb mismatch:\n got: %+v\n want: %+v", pb, compatTestSwitchPortStatus())
	}
	if grpcPB := portStatusToProto(native); !proto.Equal(grpcPB, compatTestSwitchPortStatus()) {
		t.Fatalf("portStatusToProto mismatch:\n got: %+v\n want: %+v", grpcPB, compatTestSwitchPortStatus())
	}
	if portStatusToProto(nil) != nil {
		t.Fatal("portStatusToProto(nil) = non-nil, want nil")
	}

	if portStatusToPb(nil) != nil {
		t.Fatal("portStatusToPb(nil) = non-nil, want nil")
	}
}
