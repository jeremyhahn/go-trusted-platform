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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
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

	now := time.Now()

	vm := &computesvc.VM{
		ID:     "full-vm-123456789012",
		State:  computesvc.StateRunning,
		HostID: "host-001",
		Config: &computesvc.VMConfig{
			Name:        "full-test-vm",
			Description: "A fully configured test VM",
			Firmware:    computesvc.FirmwareUEFISecureBoot,
			SecureBoot:  true,
			TPM:         &computesvc.TPMConfig{Enabled: true, Emulated: true},
			CPU: &computesvc.CPUConfig{
				Cores:    8,
				Sockets:  2,
				Threads:  2,
				Model:    "host",
				Features: []string{"aes", "avx2"},
			},
			Memory: &computesvc.MemoryConfig{
				SizeMB:    8192,
				Hugepages: true,
				Shared:    false,
			},
			Disks: []*computesvc.DiskConfig{
				{
					ID:       "disk-001",
					SizeGB:   100,
					Type:     computesvc.DiskTypeQCOW2,
					Bus:      computesvc.DiskBusVirtIO,
					Bootable: true,
					Path:     "/var/lib/vms/full-test-vm/disk0.qcow2",
				},
			},
			Networks: []*computesvc.NetworkConfig{
				{
					ID:                 "nic-001",
					Bridge:             "br0",
					MACAddress:         "52:54:00:ab:cd:ef",
					VLAN:               100,
					Model:              computesvc.NetworkModelVirtIO,
					BandwidthLimitMbps: 1000,
				},
			},
			Labels:   map[string]string{"env": "production", "team": "platform"},
			Metadata: map[string]string{"created-by": "test"},
		},
		Metrics: &computesvc.VMMetrics{
			CPUUsagePercent:   45.67,
			MemoryUsedMB:      4096,
			MemoryAvailableMB: 4096,
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

	vm := &computesvc.VM{
		ID:    "minimal-vm",
		State: computesvc.StateStopped,
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

func TestDiskBusValues(t *testing.T) {
	tests := []struct {
		bus      computesvc.DiskBus
		expected string
	}{
		{computesvc.DiskBusIDE, "IDE"},
		{computesvc.DiskBusSATA, "SATA"},
		{computesvc.DiskBusSCSI, "SCSI"},
		{computesvc.DiskBusVirtIO, "VirtIO"},
		{computesvc.DiskBusNVMe, "NVMe"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := string(tt.bus)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestDiskTypeValues(t *testing.T) {
	tests := []struct {
		diskType computesvc.DiskType
		expected string
	}{
		{computesvc.DiskTypeRAW, "RAW"},
		{computesvc.DiskTypeQCOW2, "QCOW2"},
		{computesvc.DiskTypeVDI, "VDI"},
		{computesvc.DiskTypeVMDK, "VMDK"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := string(tt.diskType)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestNetworkModelValues(t *testing.T) {
	tests := []struct {
		model    computesvc.NetworkModel
		expected string
	}{
		{computesvc.NetworkModelE1000, "e1000"},
		{computesvc.NetworkModelVirtIO, "virtio"},
		{computesvc.NetworkModelRTL8139, "rtl8139"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := string(tt.model)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestPrintFullVMDetails_WithMetrics_NoUptime(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	vm := &computesvc.VM{
		ID:    "metrics-vm",
		State: computesvc.StateRunning,
		Metrics: &computesvc.VMMetrics{
			CPUUsagePercent: 10.5,
			MemoryUsedMB:    512,
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
