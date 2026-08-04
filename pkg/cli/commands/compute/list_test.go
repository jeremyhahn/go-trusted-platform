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
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

func TestNewListCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newListCommand(getFlags)

	if cmd == nil {
		t.Fatal("newListCommand returned nil")
	}

	if cmd.Use != "list" {
		t.Errorf("expected Use to be 'list', got %q", cmd.Use)
	}

	if cmd.Short != "List virtual machines" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}

	// Verify aliases
	if len(cmd.Aliases) != 1 || cmd.Aliases[0] != "ls" {
		t.Errorf("expected aliases [ls], got %v", cmd.Aliases)
	}
}

func TestNewListCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newListCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(cmd.Long) < 50 {
		t.Error("Long description should be descriptive")
	}
}

func TestNewListCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newListCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
		defValue  string
	}{
		{name: "all", shorthand: "a", defValue: "false"},
		{name: "filter", shorthand: "f", defValue: "[]"},
		{name: "limit", shorthand: "l", defValue: "100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := cmd.Flags().Lookup(tt.name)
			if f == nil {
				t.Fatalf("flag %q not found", tt.name)
			}
			if f.Shorthand != tt.shorthand {
				t.Errorf("flag %q shorthand: expected %q, got %q", tt.name, tt.shorthand, f.Shorthand)
			}
			if f.DefValue != tt.defValue {
				t.Errorf("flag %q default: expected %q, got %q", tt.name, tt.defValue, f.DefValue)
			}
		})
	}
}

func TestParseVMFilters_ValidState(t *testing.T) {
	filters := []string{"state=running"}

	selector, states, err := parseVMFilters(filters)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(selector) != 0 {
		t.Error("expected empty selector for state-only filter")
	}

	if len(states) != 1 {
		t.Fatalf("expected 1 state, got %d", len(states))
	}

	if states[0] != computesvc.StateRunning {
		t.Errorf("expected VM_STATE_RUNNING, got %v", states[0])
	}
}

func TestParseVMFilters_ValidLabel(t *testing.T) {
	filters := []string{"label=env=prod"}

	selector, states, err := parseVMFilters(filters)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(states) != 0 {
		t.Error("expected no states for label-only filter")
	}

	if selector == nil {
		t.Fatal("expected non-nil selector for label filter")
	}

	if val, ok := selector["env"]; !ok || val != "prod" {
		t.Errorf("expected label env=prod, got %v", selector)
	}
}

func TestParseVMFilters_LabelWithoutValue(t *testing.T) {
	filters := []string{"label=mykey"}

	selector, _, err := parseVMFilters(filters)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if selector == nil {
		t.Fatal("expected non-nil selector")
	}

	if val, ok := selector["mykey"]; !ok || val != "" {
		t.Errorf("expected label mykey with empty value, got %v", selector)
	}
}

func TestParseVMFilters_InvalidFilter(t *testing.T) {
	filters := []string{"badformat"}

	_, _, err := parseVMFilters(filters)
	if err == nil {
		t.Fatal("expected error for invalid filter format")
	}

	if _, ok := err.(ErrInvalidFilter); !ok {
		t.Errorf("expected ErrInvalidFilter, got %T: %v", err, err)
	}
}

func TestParseVMFilters_InvalidState(t *testing.T) {
	filters := []string{"state=bogus"}

	_, _, err := parseVMFilters(filters)
	if err == nil {
		t.Fatal("expected error for invalid state")
	}

	if _, ok := err.(ErrInvalidVMState); !ok {
		t.Errorf("expected ErrInvalidVMState, got %T: %v", err, err)
	}
}

func TestParseVMFilters_UnknownKey(t *testing.T) {
	filters := []string{"unknown=value"}

	_, _, err := parseVMFilters(filters)
	if err == nil {
		t.Fatal("expected error for unknown filter key")
	}

	if _, ok := err.(ErrInvalidFilter); !ok {
		t.Errorf("expected ErrInvalidFilter, got %T: %v", err, err)
	}
}

func TestParseVMFilters_MultipleFilters(t *testing.T) {
	filters := []string{"state=stopped", "label=env=staging"}

	selector, states, err := parseVMFilters(filters)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(states) != 1 || states[0] != computesvc.StateStopped {
		t.Errorf("expected VM_STATE_STOPPED, got %v", states)
	}

	if selector == nil || selector["env"] != "staging" {
		t.Errorf("expected label env=staging, got %v", selector)
	}
}

func TestParseVMFilters_EmptyFilters(t *testing.T) {
	selector, states, err := parseVMFilters([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(selector) != 0 {
		t.Error("expected empty selector for empty filters")
	}

	if len(states) != 0 {
		t.Error("expected no states for empty filters")
	}
}

func TestParseVMFilters_AllValidStates(t *testing.T) {
	validStates := []struct {
		input    string
		expected computesvc.VMState
	}{
		{"stopped", computesvc.StateStopped},
		{"starting", computesvc.StateStarting},
		{"running", computesvc.StateRunning},
		{"paused", computesvc.StatePaused},
		{"stopping", computesvc.StateStopping},
		{"rebooting", computesvc.StateRebooting},
		{"migrating", computesvc.StateMigrating},
		{"error", computesvc.StateError},
	}

	for _, tt := range validStates {
		t.Run(tt.input, func(t *testing.T) {
			filters := []string{"state=" + tt.input}
			_, states, err := parseVMFilters(filters)
			if err != nil {
				t.Fatalf("unexpected error for state %q: %v", tt.input, err)
			}
			if len(states) != 1 || states[0] != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, states)
			}
		})
	}
}

func TestPrintVMList_EmptyList(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	resp := &computesvc.ListVMsResult{
		VMs: []*computesvc.VM{},
	}

	err := printVMList(printer, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No virtual machines found") {
		t.Error("expected 'No virtual machines found' message for empty list")
	}
}

func TestPrintVMList_WithVMs(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	resp := &computesvc.ListVMsResult{
		VMs: []*computesvc.VM{
			{
				ID:    "vm-001-abcdef123456",
				State: computesvc.StateRunning,
				Config: &computesvc.VMConfig{
					Name:     "web-server",
					Firmware: computesvc.FirmwareUEFI,
					CPU:      &computesvc.CPUConfig{Cores: 4},
					Memory:   &computesvc.MemoryConfig{SizeMB: 4096},
				},
				CreatedAt: time.Now(),
			},
			{
				ID:    "vm-002-abcdef789012",
				State: computesvc.StateStopped,
				Config: &computesvc.VMConfig{
					Name:     "db-server",
					Firmware: computesvc.FirmwareBIOS,
					CPU:      &computesvc.CPUConfig{Cores: 8},
					Memory:   &computesvc.MemoryConfig{SizeMB: 16384},
				},
				CreatedAt: time.Now(),
			},
		},
	}

	err := printVMList(printer, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "2 VM(s)") {
		t.Error("expected total count in output")
	}
}

func TestPrintVMList_WithNilConfig(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	resp := &computesvc.ListVMsResult{
		VMs: []*computesvc.VM{
			{
				ID:    "vm-no-config-12345",
				State: computesvc.StateError,
			},
		},
	}

	err := printVMList(printer, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "1 VM(s)") {
		t.Error("expected total count in output")
	}
}

func TestPrintVMList_WithPartialConfig(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	resp := &computesvc.ListVMsResult{
		VMs: []*computesvc.VM{
			{
				ID:    "vm-partial-123456",
				State: computesvc.StateRunning,
				Config: &computesvc.VMConfig{
					Name:     "partial-vm",
					Firmware: computesvc.FirmwareUEFI,
					// No CPU or memory config
				},
			},
		},
	}

	err := printVMList(printer, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "1 VM(s)") {
		t.Error("expected total count in output")
	}
}

func TestNewListCommand_HasRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newListCommand(getFlags)

	if cmd.RunE == nil {
		t.Error("list command should have RunE set")
	}
}

func TestNewListCommand_AcceptsNoArgs(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newListCommand(getFlags)

	// List command has no Args validator set, so it should accept any args
	// (including none) without error from the validator itself
	if cmd.Args != nil {
		err := cmd.Args(cmd, []string{})
		if err != nil {
			t.Errorf("list command should accept no args: %v", err)
		}
	}
}
