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

package switchmgmt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// mockSSHExecutor is a test double for SSHExecutor.
type mockSSHExecutor struct {
	commands []string
	outputs  map[string]string
	err      error
	closed   bool
}

func newMockSSHExecutor() *mockSSHExecutor {
	return &mockSSHExecutor{
		outputs: make(map[string]string),
	}
}

func (m *mockSSHExecutor) Execute(_ context.Context, command string) (string, error) {
	m.commands = append(m.commands, command)
	if m.err != nil {
		return "", m.err
	}
	output, ok := m.outputs[command]
	if ok {
		return output, nil
	}
	return "", nil
}

func (m *mockSSHExecutor) Close() error {
	m.closed = true
	return nil
}

// --- VLAN command generation tests ---

func TestCiscoNexus_GenerateVLANCommands(t *testing.T) {
	vlans := []VLANConfig{
		{ID: 5, Name: "management"},
		{ID: 6, Name: "quarantine", Description: "quarantine network"},
		{ID: 10, Name: "production"},
	}

	commands := GenerateVLANCommands(vlans)

	if len(commands) == 0 {
		t.Fatal("expected commands, got none")
	}

	if commands[0] != "configure terminal" {
		t.Fatalf("expected first command 'configure terminal', got: %s", commands[0])
	}

	// Check that VLAN IDs appear
	joined := strings.Join(commands, "\n")
	for _, vlan := range vlans {
		expected := fmt.Sprintf("vlan %d", vlan.ID)
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected command %q not found in output", expected)
		}
	}

	// Check description is included
	if !strings.Contains(joined, "description quarantine network") {
		t.Fatal("expected description for quarantine vlan")
	}

	// Check ends with save
	last := commands[len(commands)-1]
	if last != "copy running-config startup-config" {
		t.Fatalf("expected last command to save config, got: %s", last)
	}
}

func TestCiscoNexus_GenerateVLANCommands_Empty(t *testing.T) {
	commands := GenerateVLANCommands(nil)
	if commands != nil {
		t.Fatalf("expected nil for empty vlans, got: %v", commands)
	}
}

// --- Port command generation tests ---

func TestCiscoNexus_GeneratePortCommands(t *testing.T) {
	tests := []struct {
		name    string
		ports   []PortConfig
		want    []string
		absent  []string
		wantMTU int
	}{
		{
			name:  "trunk",
			ports: []PortConfig{{Port: "Eth1/1", Mode: "trunk", VLANs: []int{5, 6, 10}, Description: "gateway-01"}},
			want: []string{"interface Eth1/1", "switchport mode trunk", "switchport trunk allowed vlan 5,6,10",
				"description gateway-01", "no shutdown"},
		},
		{
			name:  "access",
			ports: []PortConfig{{Port: "Eth1/2", Mode: "access", AccessVLAN: 10}},
			want:  []string{"switchport mode access", "switchport access vlan 10"},
		},
		{
			name:  "port range expands to one interface per port",
			ports: []PortConfig{{Port: "Eth1/3-5", Mode: "trunk", VLANs: []int{10, 20}}},
			want:  []string{"interface Eth1/3", "interface Eth1/4", "interface Eth1/5"},
		},
		{
			name: "native VLAN and an mtu line per port",
			ports: []PortConfig{
				{Port: "Eth1/25", Mode: "trunk", VLANs: []int{401, 403, 405}, NativeVLAN: 405, MTU: 9216},
				{Port: "Eth1/41", Mode: "access", AccessVLAN: 402, MTU: 9216},
			},
			want:    []string{"switchport trunk native vlan 405", "mtu 9216", "switchport access vlan 402"},
			absent:  []string{"no switchport trunk native vlan"},
			wantMTU: 2,
		},
		{
			name:  "trunk without a native VLAN clears it",
			ports: []PortConfig{{Port: "Eth1/3", Mode: "trunk", VLANs: []int{400, 401}, MTU: 9216}},
			want:  []string{"no switchport trunk native vlan"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commands, err := GeneratePortCommands(tt.ports)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			joined := strings.Join(commands, "\n")
			for _, want := range tt.want {
				if !strings.Contains(joined, want) {
					t.Fatalf("expected %q in:\n%s", want, joined)
				}
			}
			for _, absent := range tt.absent {
				if strings.Contains(joined, absent) {
					t.Fatalf("unexpected %q in:\n%s", absent, joined)
				}
			}
			if tt.wantMTU > 0 && strings.Count(joined, "mtu 9216") != tt.wantMTU {
				t.Fatalf("expected %d mtu lines in:\n%s", tt.wantMTU, joined)
			}
		})
	}
}

func TestCiscoNexus_GeneratePortCommands_Empty(t *testing.T) {
	commands, err := GeneratePortCommands(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if commands != nil {
		t.Fatalf("expected nil for empty ports, got: %v", commands)
	}
}

func TestCiscoNexus_GeneratePortCommands_InvalidRange(t *testing.T) {
	ports := []PortConfig{
		{Port: "Eth1/abc-def", Mode: "trunk", VLANs: []int{10}},
	}
	_, err := GeneratePortCommands(ports)
	if err == nil {
		t.Fatal("expected error for invalid port range")
	}
	var portRangeErr ErrInvalidPortRange
	if !errors.As(err, &portRangeErr) {
		t.Fatalf("expected ErrInvalidPortRange, got: %T %v", err, err)
	}
}

// --- Port range expansion tests ---

func TestCiscoNexus_ExpandPortRange(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
		wantErr  bool
	}{
		{
			name:     "single port",
			input:    "Eth1/1",
			expected: []string{"Eth1/1"},
		},
		{
			name:     "range",
			input:    "Eth1/3-5",
			expected: []string{"Eth1/3", "Eth1/4", "Eth1/5"},
		},
		{
			name:     "single element range",
			input:    "Eth1/3-3",
			expected: []string{"Eth1/3"},
		},
		{
			name:     "simple name without slash",
			input:    "mgmt0",
			expected: []string{"mgmt0"},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid range start",
			input:   "Eth1/abc-5",
			wantErr: true,
		},
		{
			name:    "invalid range end",
			input:   "Eth1/3-xyz",
			wantErr: true,
		},
		{
			name:    "reversed range",
			input:   "Eth1/5-3",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ExpandPortRange(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != len(tc.expected) {
				t.Fatalf("expected %d ports, got %d: %v", len(tc.expected), len(result), result)
			}
			for i, expected := range tc.expected {
				if result[i] != expected {
					t.Fatalf("port[%d]: expected %s, got %s", i, expected, result[i])
				}
			}
		})
	}
}

// --- Configure with mock SSH tests ---

func TestCiscoNexus_Configure_VLANsOnly(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
		VLANs: []VLANConfig{
			{ID: 10, Name: "production"},
		},
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	if err := c.Configure(ctx, config); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have VLAN commands but no port commands
	joined := strings.Join(mock.commands, "\n")
	if !strings.Contains(joined, "vlan 10") {
		t.Fatal("expected vlan commands")
	}
}

func TestCiscoNexus_Configure_PortsOnly(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
		Ports: []PortConfig{
			{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10}},
		},
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	if err := c.Configure(ctx, config); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	joined := strings.Join(mock.commands, "\n")
	if !strings.Contains(joined, "interface Eth1/1") {
		t.Fatal("expected port commands")
	}
}

func TestCiscoNexus_Configure_EmptyConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()

	switchConfig := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(switchConfig, logger, mock)
	ctx := context.Background()

	// Config with no VLANs or ports should succeed with no commands
	emptyConfig := &Config{}
	if err := c.Configure(ctx, emptyConfig); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.commands) != 0 {
		t.Fatalf("expected no commands, got %d", len(mock.commands))
	}
}

func TestCiscoNexus_Configure_NilConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	err := c.Configure(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	var nilCfg ErrNilConfig
	if !errors.As(err, &nilCfg) {
		t.Fatalf("expected ErrNilConfig, got: %T %v", err, err)
	}
}

func TestCiscoNexus_Configure_VLANError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()
	mock.err = errors.New("ssh broken")

	switchConfig := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(switchConfig, logger, mock)
	ctx := context.Background()

	config := &Config{
		VLANs: []VLANConfig{{ID: 10, Name: "test"}},
		Ports: []PortConfig{{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10}}},
	}

	err := c.Configure(ctx, config)
	if err == nil {
		t.Fatal("expected error from VLAN configuration failure")
	}
}

func TestCiscoNexus_Configure_PortError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Fail only after every VLAN command has succeeded.
	vlans := []VLANConfig{{ID: 10, Name: "test"}}
	mock := &countingMockExecutor{failAfter: len(GenerateVLANCommands(vlans))}

	switchConfig := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(switchConfig, logger, mock)
	ctx := context.Background()

	config := &Config{
		VLANs: vlans,
		Ports: []PortConfig{{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10}}},
	}

	err := c.Configure(ctx, config)
	if err == nil {
		t.Fatal("expected error from port configuration failure")
	}
}

// countingMockExecutor fails after a specific number of calls.
type countingMockExecutor struct {
	callCount int
	failAfter int
}

func (m *countingMockExecutor) Execute(_ context.Context, _ string) (string, error) {
	m.callCount++
	if m.failAfter >= 0 && m.callCount > m.failAfter {
		return "", errors.New("simulated failure")
	}
	return "", nil
}

func (m *countingMockExecutor) Close() error {
	return nil
}

func TestCiscoNexus_ConfigureVLANs_SSHError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()
	mock.err = errors.New("ssh broken")

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	vlans := []VLANConfig{{ID: 10, Name: "test"}}
	err := c.ConfigureVLANs(ctx, vlans)
	if err == nil {
		t.Fatal("expected error from SSH failure")
	}
	var vlanErr ErrVLANConfigFailed
	if !errors.As(err, &vlanErr) {
		t.Fatalf("expected ErrVLANConfigFailed, got: %T %v", err, err)
	}
}

func TestCiscoNexus_ConfigureVLANs_ErrorOutput(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()
	mock.outputs["configure terminal"] = "% Error: permission denied"

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	vlans := []VLANConfig{{ID: 10, Name: "test"}}
	err := c.ConfigureVLANs(ctx, vlans)
	if err == nil {
		t.Fatal("expected error from error output")
	}
}

func TestCiscoNexus_ConfigurePorts_SSHError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()
	mock.err = errors.New("ssh broken")

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	ports := []PortConfig{{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10}}}
	err := c.ConfigurePorts(ctx, ports)
	if err == nil {
		t.Fatal("expected error from SSH failure")
	}
	var portErr ErrPortConfigFailed
	if !errors.As(err, &portErr) {
		t.Fatalf("expected ErrPortConfigFailed, got: %T %v", err, err)
	}
}

func TestCiscoNexus_ConfigurePorts_ErrorOutput(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()
	mock.outputs["configure terminal"] = "% Invalid command"

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	ports := []PortConfig{{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10}}}
	err := c.ConfigurePorts(ctx, ports)
	if err == nil {
		t.Fatal("expected error from error output")
	}
	var portErr ErrPortConfigFailed
	if !errors.As(err, &portErr) {
		t.Fatalf("expected ErrPortConfigFailed, got: %T %v", err, err)
	}
}

func TestCiscoNexus_ConfigurePorts_InvalidRange(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	ports := []PortConfig{{Port: "Eth1/abc-def", Mode: "trunk", VLANs: []int{10}}}
	err := c.ConfigurePorts(ctx, ports)
	if err == nil {
		t.Fatal("expected error for invalid port range")
	}
}

// --- Verify tests ---

func TestCiscoNexus_Verify_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()
	mock.outputs["show vlan brief"] = "VLAN Name\n10   production\n20   staging"
	mock.outputs["show interface status"] = "Eth1/1  connected trunk"

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
		VLANs:  []VLANConfig{{ID: 10, Name: "production"}},
		Ports:  []PortConfig{{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10}}},
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	if err := c.Verify(ctx, config); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCiscoNexus_Verify_MissingVLAN(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()
	mock.outputs["show vlan brief"] = "VLAN Name\n20   staging"

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
		VLANs:  []VLANConfig{{ID: 10, Name: "production"}},
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	err := c.Verify(ctx, config)
	if err == nil {
		t.Fatal("expected verification error for missing VLAN")
	}
	var verifyErr ErrVerificationFailed
	if !errors.As(err, &verifyErr) {
		t.Fatalf("expected ErrVerificationFailed, got: %T %v", err, err)
	}
}

func TestCiscoNexus_Verify_MissingPort(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()
	mock.outputs["show interface status"] = "Eth1/2  connected trunk"

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
		Ports:  []PortConfig{{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10}}},
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	err := c.Verify(ctx, config)
	if err == nil {
		t.Fatal("expected verification error for missing port")
	}
	var verifyErr ErrVerificationFailed
	if !errors.As(err, &verifyErr) {
		t.Fatalf("expected ErrVerificationFailed, got: %T %v", err, err)
	}
}

func TestCiscoNexus_Verify_PortSSHError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Need a mock that succeeds on VLAN check but fails on interface check
	mock := &selectiveMockExecutor{
		outputs: map[string]string{},
		errors:  map[string]error{},
	}
	mock.outputs["show vlan brief"] = "VLAN Name\n10   production"
	mock.errors["show interface status"] = errors.New("timeout")

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
		VLANs:  []VLANConfig{{ID: 10, Name: "production"}},
		Ports:  []PortConfig{{Port: "Eth1/1", Mode: "trunk", VLANs: []int{10}}},
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	err := c.Verify(ctx, config)
	if err == nil {
		t.Fatal("expected verification error for port SSH failure")
	}
}

func TestCiscoNexus_Verify_NilConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()

	switchConfig := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(switchConfig, logger, mock)
	ctx := context.Background()

	err := c.Verify(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestCiscoNexus_Verify_SSHError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()
	mock.err = errors.New("connection lost")

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
		VLANs:  []VLANConfig{{ID: 10, Name: "test"}},
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)
	ctx := context.Background()

	err := c.Verify(ctx, config)
	if err == nil {
		t.Fatal("expected verification error for SSH failure")
	}
}

func TestCiscoNexus_Verify_NoVLANsOrPorts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()

	switchConfig := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(switchConfig, logger, mock)
	ctx := context.Background()

	// Empty config with no VLANs or ports should succeed
	emptyConfig := &Config{}
	if err := c.Verify(ctx, emptyConfig); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.commands) != 0 {
		t.Fatalf("expected no commands, got %d", len(mock.commands))
	}
}

// selectiveMockExecutor allows per-command error configuration.
type selectiveMockExecutor struct {
	outputs map[string]string
	errors  map[string]error
}

func (m *selectiveMockExecutor) Execute(_ context.Context, command string) (string, error) {
	if err, ok := m.errors[command]; ok {
		return "", err
	}
	output, ok := m.outputs[command]
	if ok {
		return output, nil
	}
	return "", nil
}

func (m *selectiveMockExecutor) Close() error {
	return nil
}

// --- Close tests ---

func TestCiscoNexus_Close(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mock := newMockSSHExecutor()

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(config, logger, mock)

	if err := c.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.closed {
		t.Fatal("expected executor to be closed")
	}
}

func TestCiscoNexus_Close_NilExecutor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	config := &Config{
		Vendor: VendorCiscoNexus,
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}

	c := newCiscoNexusWithExecutor(config, logger, nil)

	if err := c.Close(); err != nil {
		t.Fatalf("expected nil error for nil executor, got: %v", err)
	}
}

// --- Validation tests ---

func TestValidateConfig_Valid(t *testing.T) {
	config := &Config{
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/tmp/key",
	}
	if err := validateConfig(config); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfig_Nil(t *testing.T) {
	err := validateConfig(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestValidateConfig_MissingField(t *testing.T) {
	tests := []struct {
		field  string
		config *Config
	}{
		{"host", &Config{User: "admin", SSHKey: "/tmp/key"}},
		{"user", &Config{Host: "10.0.0.1", SSHKey: "/tmp/key"}},
		{"ssh_key", &Config{Host: "10.0.0.1", User: "admin"}},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			var invalidCfg ErrInvalidConfig
			if err := validateConfig(tt.config); !errors.As(err, &invalidCfg) {
				t.Fatalf("expected ErrInvalidConfig, got: %T %v", err, err)
			}
			if invalidCfg.Field != tt.field {
				t.Fatalf("expected field %q, got: %s", tt.field, invalidCfg.Field)
			}
		})
	}
}

// --- containsError tests ---

func TestContainsError(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"error keyword", "Error: something failed", true},
		{"invalid keyword", "Invalid command", true},
		{"percent sign", "% Unknown command", true},
		{"clean output", "vlan 10 configured", false},
		{"empty output", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := containsError(tc.output)
			if got != tc.want {
				t.Fatalf("containsError(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}

// --- joinInts tests ---

func TestJoinInts_Empty(t *testing.T) {
	result := joinInts(nil, ",")
	if result != "" {
		t.Fatalf("expected empty string, got: %s", result)
	}
}

// TestCiscoNexus_GeneratePortCommands_NativeAndMTU emits the native VLAN and
// MTU of a hypervisor-class trunk and the MTU of a BMC access port.
// TestCiscoNexus_GeneratePortCommands_Invalid refuses an invalid port
// before generating anything.
func TestCiscoNexus_GeneratePortCommands_Invalid(t *testing.T) {
	_, err := GeneratePortCommands([]PortConfig{{Port: "Eth1/25", Mode: "trunk", VLANs: []int{401}, NativeVLAN: 405}})
	var failed ErrPortConfigFailed
	if !errors.As(err, &failed) || failed.Port != "Eth1/25" {
		t.Fatalf("want ErrPortConfigFailed for Eth1/25, got %v", err)
	}
	var invalid ErrInvalidConfig
	if !errors.As(err, &invalid) {
		t.Fatalf("want the ErrInvalidConfig cause, got %v", err)
	}
}

// TestGeneratePortCommands_TrunkWithoutNativeClearsIt checks a trunk with
// no native VLAN removes any native VLAN a re-used port still carries, and
// a trunk with one sets it.
