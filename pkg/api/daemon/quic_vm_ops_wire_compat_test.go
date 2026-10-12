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

	quic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// The operational VM verbs converge on the platformv1 pb messages exactly like
// the container verbs: the SDK QUIC adapter encodes the pb request and the
// daemon (handleVMPB) decodes into the SAME pb message, then encodes the pb
// response. None of the five request messages nor their responses use a proto
// oneof, so a plain EncodePayload -> DecodePayload cycle must be lossless. These
// tests pin that contract through the real msgpack payload codec.

// encodePBRoundTrip encodes src through the QUIC payload codec and decodes it
// back into dst.
func encodePBRoundTrip(t *testing.T, src, dst proto.Message) {
	t.Helper()
	payload, err := quicwire.EncodePayload(src)
	if err != nil {
		t.Fatalf("encode %T: %v", src, err)
	}
	if err := quicwire.DecodePayload(payload, dst); err != nil {
		t.Fatalf("decode into %T: %v", dst, err)
	}
	if !proto.Equal(src, dst) {
		t.Fatalf("round-trip mismatch:\n got: %v\nwant: %v", dst, src)
	}
}

func TestVMOpsWireCompat_GetVMMetricsRequest(t *testing.T) {
	encodePBRoundTrip(t, &platformv1.GetVMMetricsRequest{Id: "vm-1"}, &platformv1.GetVMMetricsRequest{})
}

func TestVMOpsWireCompat_VMMetricsResponse(t *testing.T) {
	src := &platformv1.VMMetricsResponse{Metrics: &platformv1.VMMetrics{
		CpuUsagePercent:   42.5,
		MemoryUsedMb:      2048,
		MemoryAvailableMb: 6144,
		DiskReadBytes:     1 << 20,
		DiskWriteBytes:    2 << 20,
		NetworkRxBytes:    3 << 20,
		NetworkTxBytes:    4 << 20,
		UptimeSeconds:     3600,
	}}
	encodePBRoundTrip(t, src, &platformv1.VMMetricsResponse{})
}

func TestVMOpsWireCompat_AttachDiskRequest(t *testing.T) {
	src := &platformv1.AttachDiskRequest{
		VmId: "vm-1",
		Disk: &platformv1.DiskConfig{
			Id:       "disk-1",
			Path:     "/vms/vm1/data.qcow2",
			Bus:      platformv1.DiskBus_DISK_BUS_VIRTIO,
			SizeGb:   40,
			Readonly: true,
		},
	}
	encodePBRoundTrip(t, src, &platformv1.AttachDiskRequest{})
}

func TestVMOpsWireCompat_AttachDiskResponse(t *testing.T) {
	src := &platformv1.AttachDiskResponse{Status: &platformv1.Status{Success: true, Message: "disk attached"}}
	encodePBRoundTrip(t, src, &platformv1.AttachDiskResponse{})
}

func TestVMOpsWireCompat_DetachDiskRequest(t *testing.T) {
	encodePBRoundTrip(t, &platformv1.DetachDiskRequest{VmId: "vm-1", DiskId: "disk-1"}, &platformv1.DetachDiskRequest{})
}

func TestVMOpsWireCompat_ResizeDiskRequest(t *testing.T) {
	encodePBRoundTrip(t, &platformv1.ResizeDiskRequest{VmId: "vm-1", DiskId: "disk-1", NewSizeGb: 80}, &platformv1.ResizeDiskRequest{})
}

func TestVMOpsWireCompat_MigrateVMRequest(t *testing.T) {
	src := &platformv1.MigrateVMRequest{
		VmId:               "vm-1",
		DestinationHost:    "dest.example:10443",
		LiveMigration:      true,
		BandwidthLimitMbps: 500,
	}
	encodePBRoundTrip(t, src, &platformv1.MigrateVMRequest{})
}

func TestVMOpsWireCompat_MigrateVMResponse(t *testing.T) {
	src := &platformv1.MigrateVMResponse{Status: &platformv1.Status{Success: true, Message: "migration completed"}}
	encodePBRoundTrip(t, src, &platformv1.MigrateVMResponse{})
}

// TestVMOpsSubOpcodesAreVMFamily verifies the new operational VM sub-opcodes are
// recognized as VM sub-opcodes (routed to handleVMPB) and NOT as container
// sub-opcodes, so handleVMServiceOperation dispatches them to the VM pb handler
// rather than the container handler or the flat VMHandler.
func TestVMOpsSubOpcodesAreVMFamily(t *testing.T) {
	subs := []byte{
		quicwire.OpVMMetrics,
		quicwire.OpVMAttachDisk,
		quicwire.OpVMDetachDisk,
		quicwire.OpVMResizeDisk,
		quicwire.OpVMMigrate,
	}
	for _, sub := range subs {
		if !quicwire.IsVMSubOpcode(sub) {
			t.Errorf("sub-opcode 0x%02X: IsVMSubOpcode = false, want true", sub)
		}
		if quic.IsContainerSubOpcode(sub) {
			t.Errorf("sub-opcode 0x%02X: collides with a container sub-opcode", sub)
		}
	}
}
