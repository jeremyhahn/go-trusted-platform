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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

func TestNewCreateCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCreateCommand(getFlags)

	if cmd == nil {
		t.Fatal("newCreateCommand returned nil")
	}

	if cmd.Use != "create" {
		t.Errorf("expected Use to be 'create', got %q", cmd.Use)
	}

	if cmd.Short != "Create a new virtual machine" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewCreateCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCreateCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 100 {
		t.Error("Long description should be descriptive (at least 100 chars)")
	}
}

func TestNewCreateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCreateCommand(getFlags)

	expectedFlags := []struct {
		name      string
		shorthand string
	}{
		{name: "name", shorthand: "n"},
		{name: "cpus", shorthand: ""},
		{name: "memory", shorthand: ""},
		{name: "disk-size", shorthand: ""},
		{name: "firmware", shorthand: ""},
		{name: "secure-boot", shorthand: ""},
		{name: "tpm", shorthand: ""},
		{name: "boot-device", shorthand: ""},
		{name: "network-bridge", shorthand: ""},
		{name: "label", shorthand: "l"},
		{name: "start", shorthand: ""},
	}

	for _, ef := range expectedFlags {
		t.Run(ef.name, func(t *testing.T) {
			f := cmd.Flags().Lookup(ef.name)
			if f == nil {
				t.Fatalf("flag %q not found", ef.name)
			}
			if ef.shorthand != "" && f.Shorthand != ef.shorthand {
				t.Errorf("flag %q: expected shorthand %q, got %q", ef.name, ef.shorthand, f.Shorthand)
			}
		})
	}
}

func TestNewCreateCommand_RequiredFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCreateCommand(getFlags)

	nameFlag := cmd.Flags().Lookup("name")
	if nameFlag == nil {
		t.Fatal("name flag not found")
	}

	// Cobra marks required flags with a "required" annotation
	annotations := nameFlag.Annotations
	if annotations == nil {
		t.Fatal("name flag should have annotations for required marking")
	}
	if _, ok := annotations["cobra_annotation_bash_completion_one_required_flag"]; !ok {
		t.Error("name flag should be marked as required")
	}
}

func TestNewCreateCommand_FlagDefaults(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCreateCommand(getFlags)

	defaults := map[string]string{
		"cpus":        "2",
		"memory":      "2048",
		"disk-size":   "20",
		"firmware":    "uefi",
		"secure-boot": "false",
		"tpm":         "true",
		"boot-device": "disk",
		"start":       "false",
	}

	for name, expected := range defaults {
		t.Run(name, func(t *testing.T) {
			f := cmd.Flags().Lookup(name)
			if f == nil {
				t.Fatalf("flag %q not found", name)
			}
			if f.DefValue != expected {
				t.Errorf("flag %q: expected default %q, got %q", name, expected, f.DefValue)
			}
		})
	}
}

func TestPrintVMDetails_NilVM(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	// Should not panic with nil VM
	printVMDetails(printer, nil)
}

func TestPrintVMDetails_WithConfig(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	vm := &computesvc.VM{
		ID:    "test-vm-123",
		State: computesvc.StateRunning,
		Config: &computesvc.VMConfig{
			Name:       "test-vm",
			Firmware:   computesvc.FirmwareUEFI,
			SecureBoot: true,
			CPU:        &computesvc.CPUConfig{Cores: 4},
			Memory:     &computesvc.MemoryConfig{SizeMB: 4096},
			Disks:      []*computesvc.DiskConfig{{SizeGB: 50, Bootable: true}},
			TPM:        &computesvc.TPMConfig{Enabled: true},
		},
	}

	// Should not panic
	printVMDetails(printer, vm)

	output := buf.String()
	if len(output) == 0 {
		t.Error("expected output for VM with full config")
	}
}

func TestPrintVMDetails_MinimalConfig(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	vm := &computesvc.VM{
		ID:    "minimal-vm",
		State: computesvc.StateStopped,
	}

	// Should not panic with nil Config
	printVMDetails(printer, vm)

	output := buf.String()
	if len(output) == 0 {
		t.Error("expected output for minimal VM (at least ID and state)")
	}
}

func TestStringToFirmwareType(t *testing.T) {
	tests := []struct {
		input    string
		expected computesvc.FirmwareType
	}{
		{input: "bios", expected: computesvc.FirmwareBIOS},
		{input: "uefi", expected: computesvc.FirmwareUEFI},
		{input: "uefi-secure-boot", expected: computesvc.FirmwareUEFISecureBoot},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, ok := computesvc.StringToFirmwareType[tt.input]
			if !ok {
				t.Fatalf("firmware type %q not found in map", tt.input)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestStringToFirmwareType_Invalid(t *testing.T) {
	invalidInputs := []string{"invalid", "BIOS", "UEFI", "", "qemu"}

	for _, input := range invalidInputs {
		t.Run(input, func(t *testing.T) {
			_, ok := computesvc.StringToFirmwareType[input]
			if ok {
				t.Errorf("expected firmware type %q to not be found in map", input)
			}
		})
	}
}

func TestStringToBootDevice(t *testing.T) {
	tests := []struct {
		input    string
		expected computesvc.BootDevice
	}{
		{input: "disk", expected: computesvc.BootDeviceDisk},
		{input: "cdrom", expected: computesvc.BootDeviceCDROM},
		{input: "network", expected: computesvc.BootDeviceNetwork},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, ok := computesvc.StringToBootDevice[tt.input]
			if !ok {
				t.Fatalf("boot device %q not found in map", tt.input)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestStringToBootDevice_Invalid(t *testing.T) {
	invalidInputs := []string{"invalid", "DISK", "usb", "", "floppy"}

	for _, input := range invalidInputs {
		t.Run(input, func(t *testing.T) {
			_, ok := computesvc.StringToBootDevice[input]
			if ok {
				t.Errorf("expected boot device %q to not be found in map", input)
			}
		})
	}
}

func TestRunCreate_EmptyName(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &createOptions{
		name: "",
	}

	err := runCreate(flags, opts)
	if err == nil {
		t.Fatal("expected error for empty name")
	}

	if _, ok := err.(ErrInvalidVMConfig); !ok {
		t.Errorf("expected ErrInvalidVMConfig, got %T: %v", err, err)
	}
}

// Suppress unused import warning for time
var _ = time.Now
