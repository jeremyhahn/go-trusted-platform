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

package compute

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewGetCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newGetCommand(getFlags)

	if cmd == nil {
		t.Fatal("newGetCommand returned nil")
	}

	if cmd.Use != "get <vm-id>" {
		t.Errorf("expected Use to be 'get <vm-id>', got %q", cmd.Use)
	}

	if cmd.Short != "Get virtual machine details" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}

	// Verify aliases
	expectedAliases := []string{"inspect", "describe"}
	if len(cmd.Aliases) != len(expectedAliases) {
		t.Fatalf("expected %d aliases, got %d", len(expectedAliases), len(cmd.Aliases))
	}
	for i, alias := range expectedAliases {
		if cmd.Aliases[i] != alias {
			t.Errorf("expected alias[%d] to be %q, got %q", i, alias, cmd.Aliases[i])
		}
	}
}

func TestNewGetCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newGetCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 50 {
		t.Error("Long description should be descriptive")
	}
}

func TestNewGetCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newGetCommand(getFlags)

	tests := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{name: "zero_args", args: []string{}, expectErr: true},
		{name: "one_arg", args: []string{"my-vm"}, expectErr: false},
		{name: "two_args", args: []string{"my-vm", "extra"}, expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cmd.Args(cmd, tt.args)
			if tt.expectErr && err == nil {
				t.Error("expected error for invalid args count")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestPrintFullVMDetails_NilVM(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	err := printFullVMDetails(printer, nil)
	if err != nil {
		t.Errorf("expected nil error for nil VM, got: %v", err)
	}
}

func TestPrintFullVMDetails_WithFullConfig(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	now := timestamppb.Now()

	vm := &platformv1.VM{
		Id:     "full-vm-123456789012",
		State:  platformv1.VMState_VM_STATE_RUNNING,
		HostId: "host-001",
		Config: &platformv1.VMConfig{
			Name:        "full-test-vm",
			Description: "A fully configured test VM",
			Firmware:    platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT,
			SecureBoot:  true,
			Tpm:         &platformv1.TPMConfig{Enabled: true, Emulated: true},
			Cpu: &platformv1.CPUConfig{
				Cores:    8,
				Sockets:  2,
				Threads:  2,
				Model:    "host",
				Features: []string{"aes", "avx2"},
			},
			Memory: &platformv1.MemoryConfig{
				SizeMb:    8192,
				Hugepages: true,
				Shared:    false,
			},
			Disks: []*platformv1.DiskConfig{
				{
					Id:       "disk-001",
					SizeGb:   100,
					Type:     platformv1.DiskType_DISK_TYPE_QCOW2,
					Bus:      platformv1.DiskBus_DISK_BUS_VIRTIO,
					Bootable: true,
					Path:     "/var/lib/vms/full-test-vm/disk0.qcow2",
				},
			},
			Networks: []*platformv1.NetworkConfig{
				{
					Id:                 "nic-001",
					Bridge:             "br0",
					MacAddress:         "52:54:00:ab:cd:ef",
					Vlan:               100,
					Model:              platformv1.NetworkModel_NETWORK_MODEL_VIRTIO,
					BandwidthLimitMbps: 1000,
				},
			},
			Labels:   map[string]string{"env": "production", "team": "platform"},
			Metadata: map[string]string{"created-by": "test"},
		},
		Metrics: &platformv1.VMMetrics{
			CpuUsagePercent:   45.67,
			MemoryUsedMb:      4096,
			MemoryAvailableMb: 4096,
			DiskReadBytes:     1073741824,
			DiskWriteBytes:    536870912,
			NetworkRxBytes:    104857600,
			NetworkTxBytes:    52428800,
			UptimeSeconds:     86400,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	err := printFullVMDetails(printer, vm)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Error("expected output for fully configured VM")
	}

	// Verify key sections are present
	expectedStrings := []string{
		"full-vm-123456789012",
		"full-test-vm",
		"RUNNING",
		"host-001",
		"UEFI Secure Boot",
	}
	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain %q", expected)
		}
	}
}

func TestPrintFullVMDetails_MinimalVM(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	vm := &platformv1.VM{
		Id:    "minimal-vm",
		State: platformv1.VMState_VM_STATE_STOPPED,
	}

	err := printFullVMDetails(printer, vm)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "minimal-vm") {
		t.Error("expected output to contain VM ID")
	}
}

func TestRunGet_EmptyVMID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	err := runGet(flags, "")
	if err == nil {
		t.Fatal("expected error for empty VM ID")
	}

	if _, ok := err.(ErrInvalidVMConfig); !ok {
		t.Errorf("expected ErrInvalidVMConfig, got %T: %v", err, err)
	}
}

func TestDiskBusToString_AllValues(t *testing.T) {
	tests := []struct {
		bus      platformv1.DiskBus
		expected string
	}{
		{platformv1.DiskBus_DISK_BUS_IDE, "IDE"},
		{platformv1.DiskBus_DISK_BUS_SATA, "SATA"},
		{platformv1.DiskBus_DISK_BUS_SCSI, "SCSI"},
		{platformv1.DiskBus_DISK_BUS_VIRTIO, "VirtIO"},
		{platformv1.DiskBus_DISK_BUS_NVME, "NVMe"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result, ok := diskBusToString[tt.bus]
			if !ok {
				t.Fatalf("disk bus %v not found in map", tt.bus)
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDiskTypeToString_AllValues(t *testing.T) {
	tests := []struct {
		diskType platformv1.DiskType
		expected string
	}{
		{platformv1.DiskType_DISK_TYPE_RAW, "RAW"},
		{platformv1.DiskType_DISK_TYPE_QCOW2, "QCOW2"},
		{platformv1.DiskType_DISK_TYPE_VDI, "VDI"},
		{platformv1.DiskType_DISK_TYPE_VMDK, "VMDK"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result, ok := diskTypeToString[tt.diskType]
			if !ok {
				t.Fatalf("disk type %v not found in map", tt.diskType)
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestNetworkModelToString_AllValues(t *testing.T) {
	tests := []struct {
		model    platformv1.NetworkModel
		expected string
	}{
		{platformv1.NetworkModel_NETWORK_MODEL_E1000, "e1000"},
		{platformv1.NetworkModel_NETWORK_MODEL_VIRTIO, "virtio"},
		{platformv1.NetworkModel_NETWORK_MODEL_RTL8139, "rtl8139"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result, ok := networkModelToString[tt.model]
			if !ok {
				t.Fatalf("network model %v not found in map", tt.model)
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestPrintFullVMDetails_WithMetrics_NoUptime(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	vm := &platformv1.VM{
		Id:    "metrics-vm",
		State: platformv1.VMState_VM_STATE_RUNNING,
		Metrics: &platformv1.VMMetrics{
			CpuUsagePercent: 10.5,
			MemoryUsedMb:    512,
			DiskReadBytes:   1024,
			DiskWriteBytes:  2048,
			NetworkRxBytes:  4096,
			NetworkTxBytes:  8192,
			UptimeSeconds:   0,
		},
	}

	err := printFullVMDetails(printer, vm)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, fmt.Sprintf("%.2f%%", 10.5)) {
		t.Error("expected output to contain CPU usage percentage")
	}
}
