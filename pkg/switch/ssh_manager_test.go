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
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

func testSSHConfig() *Config {
	return &Config{
		Name:     "test-switch",
		Vendor:   VendorCiscoNexus,
		Host:     "10.0.0.1",
		User:     "admin",
		Password: "secret",
	}
}

func testSSHLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// --- Manager interface compliance ---

var _ Manager = (*sshManager)(nil)

// --- buildConfigCommands tests ---

func TestBuildConfigCommands(t *testing.T) {
	commands := buildConfigCommands(
		"interface Eth1/3",
		"switchport mode access",
		"switchport access vlan 100",
	)

	expected := []string{
		"configure terminal",
		"interface Eth1/3",
		"switchport mode access",
		"switchport access vlan 100",
		"end",
	}

	if len(commands) != len(expected) {
		t.Fatalf("expected %d commands, got %d", len(expected), len(commands))
	}
	for i, cmd := range commands {
		if cmd != expected[i] {
			t.Fatalf("command[%d]: expected %q, got %q", i, expected[i], cmd)
		}
	}
}

func TestBuildConfigCommands_EnablePort(t *testing.T) {
	commands := buildConfigCommands(
		"interface Eth1/5",
		"no shutdown",
	)

	if len(commands) != 4 {
		t.Fatalf("expected 4 commands, got %d", len(commands))
	}
	if commands[0] != "configure terminal" {
		t.Fatalf("expected 'configure terminal', got %q", commands[0])
	}
	if commands[1] != "interface Eth1/5" {
		t.Fatalf("expected 'interface Eth1/5', got %q", commands[1])
	}
	if commands[2] != "no shutdown" {
		t.Fatalf("expected 'no shutdown', got %q", commands[2])
	}
	if commands[3] != "end" {
		t.Fatalf("expected 'end', got %q", commands[3])
	}
}

func TestBuildConfigCommands_DisablePort(t *testing.T) {
	commands := buildConfigCommands(
		"interface Eth1/5",
		"shutdown",
	)

	if len(commands) != 4 {
		t.Fatalf("expected 4 commands, got %d", len(commands))
	}
	if commands[2] != "shutdown" {
		t.Fatalf("expected 'shutdown', got %q", commands[2])
	}
}

// --- parseAccessVLANFromSwitchport tests ---

func TestParseAccessVLANFromSwitchport(t *testing.T) {
	output := `Name: Eth1/3
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Access Mode VLAN: 100 (provisioning)
Trunking Native Mode VLAN: 1 (default)
`
	vlan, err := parseAccessVLANFromSwitchport(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vlan != 100 {
		t.Fatalf("expected vlan 100, got %d", vlan)
	}
}

func TestParseAccessVLANFromSwitchport_VLAN1(t *testing.T) {
	output := `Access Mode VLAN: 1 (default)`
	vlan, err := parseAccessVLANFromSwitchport(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vlan != 1 {
		t.Fatalf("expected vlan 1, got %d", vlan)
	}
}

func TestParseAccessVLANFromSwitchport_NotFound(t *testing.T) {
	output := `Name: Eth1/3
Switchport: Enabled
Administrative Mode: trunk
`
	_, err := parseAccessVLANFromSwitchport(output)
	if err == nil {
		t.Fatal("expected error for missing access vlan line")
	}
}

func TestParseAccessVLANFromSwitchport_EmptyOutput(t *testing.T) {
	_, err := parseAccessVLANFromSwitchport("")
	if err == nil {
		t.Fatal("expected error for empty output")
	}
}

// --- parseSwitchportOutput tests ---

func TestParseSwitchportOutput_AccessMode(t *testing.T) {
	output := `Name: Eth1/3
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Access Mode VLAN: 100 (provisioning)
Trunking Native Mode VLAN: 1 (default)
`
	status, err := parseSwitchportOutput("Eth1/3", output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Port != "Eth1/3" {
		t.Fatalf("expected port Eth1/3, got %s", status.Port)
	}
	if status.Mode != switchwire.PortModeAccess {
		t.Fatalf("expected access mode, got %s", status.Mode)
	}
	if status.AccessVLAN != 100 {
		t.Fatalf("expected access vlan 100, got %d", status.AccessVLAN)
	}
	if !status.Enabled {
		t.Fatal("expected port to be enabled")
	}
}

func TestParseSwitchportOutput_TrunkMode(t *testing.T) {
	output := `Name: Eth1/1
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk
Access Mode VLAN: 1 (default)
Trunking Native Mode VLAN: 1 (default)
Trunking VLANs Allowed: 10,20,30
`
	status, err := parseSwitchportOutput("Eth1/1", output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Mode != switchwire.PortModeTrunk {
		t.Fatalf("expected trunk mode, got %s", status.Mode)
	}
	if len(status.TrunkVLANs) != 3 {
		t.Fatalf("expected 3 trunk vlans, got %d", len(status.TrunkVLANs))
	}
	if status.TrunkVLANs[0] != 10 || status.TrunkVLANs[1] != 20 || status.TrunkVLANs[2] != 30 {
		t.Fatalf("expected trunk vlans [10,20,30], got %v", status.TrunkVLANs)
	}
	if status.NativeVLAN != 1 {
		t.Fatalf("expected native vlan 1, got %d", status.NativeVLAN)
	}
}

// TestParseSwitchportOutput_NativeVLAN reads a hypervisor-class trunk's
// native VLAN, and leaves it zero when the line is missing.
func TestParseSwitchportOutput_NativeVLAN(t *testing.T) {
	output := "Switchport: Enabled\nOperational Mode: trunk\nTrunking Native Mode VLAN: 405 (provisioning)\nTrunking VLANs Allowed: 401,403-408\n"
	status, err := parseSwitchportOutput("Eth1/25", output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.NativeVLAN != 405 {
		t.Fatalf("expected native vlan 405, got %d", status.NativeVLAN)
	}
	status, err = parseSwitchportOutput("Eth1/41", "Switchport: Enabled\nOperational Mode: static access\nAccess Mode VLAN: 402 (management)\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.NativeVLAN != 0 {
		t.Fatalf("an access port has no native vlan, got %d", status.NativeVLAN)
	}
}

func TestParseSwitchportOutput_DisabledPort(t *testing.T) {
	output := `Name: Eth1/3
Switchport: Disabled
Administrative Mode: static access
Operational Mode: down
Access Mode VLAN: 200 (mgmt)
`
	status, err := parseSwitchportOutput("Eth1/3", output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Enabled {
		t.Fatal("expected port to be disabled")
	}
	if status.AccessVLAN != 200 {
		t.Fatalf("expected access vlan 200, got %d", status.AccessVLAN)
	}
}

// --- parseInterfaceStatusTable tests ---

func TestParseInterfaceStatusTable(t *testing.T) {
	output := `Port      Name               Status       Vlan       Duplex  Speed   Type
Eth1/1    uplink             connected    trunk      full    1000    10/100/1000
Eth1/2    server-01          connected    100        full    1000    10/100/1000
Eth1/3    --                 disabled     200        auto    auto    10/100/1000
`
	ports, err := parseInterfaceStatusTable(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}

	// Port 1: trunk, connected
	if ports[0].Port != "Eth1/1" {
		t.Fatalf("expected port Eth1/1, got %s", ports[0].Port)
	}
	if ports[0].Mode != switchwire.PortModeTrunk {
		t.Fatalf("expected trunk mode, got %s", ports[0].Mode)
	}
	if !ports[0].Enabled {
		t.Fatal("expected port 1 to be enabled")
	}
	if !ports[0].LinkUp {
		t.Fatal("expected port 1 link up")
	}
	if ports[0].Description != "uplink" {
		t.Fatalf("expected description 'uplink', got %q", ports[0].Description)
	}

	// Port 2: access vlan 100, connected
	if ports[1].Mode != switchwire.PortModeAccess {
		t.Fatalf("expected access mode, got %s", ports[1].Mode)
	}
	if ports[1].AccessVLAN != 100 {
		t.Fatalf("expected vlan 100, got %d", ports[1].AccessVLAN)
	}
	if ports[1].Description != "server-01" {
		t.Fatalf("expected description 'server-01', got %q", ports[1].Description)
	}

	// Port 3: disabled
	if ports[2].Enabled {
		t.Fatal("expected port 3 to be disabled")
	}
	if ports[2].LinkUp {
		t.Fatal("expected port 3 link down")
	}
	if ports[2].AccessVLAN != 200 {
		t.Fatalf("expected vlan 200, got %d", ports[2].AccessVLAN)
	}
}

func TestParseInterfaceStatusTable_SinglePort(t *testing.T) {
	output := `Port      Name               Status       Vlan       Duplex  Speed   Type
Eth1/1    server-01          connected    10         full    1000    10/100/1000
`
	ports, err := parseInterfaceStatusTable(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(ports))
	}
	if ports[0].Port != "Eth1/1" {
		t.Fatalf("expected port Eth1/1, got %s", ports[0].Port)
	}
	if ports[0].AccessVLAN != 10 {
		t.Fatalf("expected vlan 10, got %d", ports[0].AccessVLAN)
	}
}

func TestParseInterfaceStatusTable_NotConnected(t *testing.T) {
	output := `Port      Name               Status       Vlan       Duplex  Speed   Type
Eth1/1    server-01          notconnect   100        auto    auto    10/100/1000
`
	ports, err := parseInterfaceStatusTable(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(ports))
	}
	if !ports[0].Enabled {
		t.Fatal("expected port to be enabled (admin up)")
	}
	if ports[0].LinkUp {
		t.Fatal("expected link to be down")
	}
}

func TestParseInterfaceStatusTable_NoHeader(t *testing.T) {
	output := `some random text
without a header line
`
	_, err := parseInterfaceStatusTable(output)
	if err == nil {
		t.Fatal("expected error for missing header")
	}
}

func TestParseInterfaceStatusTable_EmptyOutput(t *testing.T) {
	_, err := parseInterfaceStatusTable("")
	if err == nil {
		t.Fatal("expected error for empty output")
	}
}

// --- parseTrunkVLANList tests ---

func TestParseTrunkVLANList(t *testing.T) {
	vlans := parseTrunkVLANList("10,20,30")
	if len(vlans) != 3 {
		t.Fatalf("expected 3 vlans, got %d", len(vlans))
	}
	if vlans[0] != 10 || vlans[1] != 20 || vlans[2] != 30 {
		t.Fatalf("unexpected vlans: %v", vlans)
	}
}

func TestParseTrunkVLANList_Empty(t *testing.T) {
	vlans := parseTrunkVLANList("")
	if len(vlans) != 0 {
		t.Fatalf("expected 0 vlans for empty string, got %d", len(vlans))
	}
}

func TestParseTrunkVLANList_Invalid(t *testing.T) {
	vlans := parseTrunkVLANList("abc,def")
	if len(vlans) != 0 {
		t.Fatalf("expected 0 vlans for invalid input, got %d", len(vlans))
	}
}

func TestParseTrunkVLANList_WithSpaces(t *testing.T) {
	vlans := parseTrunkVLANList("10, 20, 30")
	if len(vlans) != 3 {
		t.Fatalf("expected 3 vlans, got %d", len(vlans))
	}
}

// --- SetPortVLAN tests ---

func TestSSHManager_SetPortVLAN(t *testing.T) {
	mock := newMockSSHExecutor()
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	err := mgr.SetPortVLAN(ctx, "Eth1/3", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.commands) != 5 {
		t.Fatalf("expected 5 commands, got %d: %v", len(mock.commands), mock.commands)
	}
	if mock.commands[0] != "configure terminal" {
		t.Fatalf("expected 'configure terminal', got %q", mock.commands[0])
	}
	if mock.commands[1] != "interface Eth1/3" {
		t.Fatalf("expected 'interface Eth1/3', got %q", mock.commands[1])
	}
	if mock.commands[2] != "switchport mode access" {
		t.Fatalf("expected 'switchport mode access', got %q", mock.commands[2])
	}
	if mock.commands[3] != "switchport access vlan 100" {
		t.Fatalf("expected 'switchport access vlan 100', got %q", mock.commands[3])
	}
	if mock.commands[4] != "end" {
		t.Fatalf("expected 'end', got %q", mock.commands[4])
	}
}

func TestSSHManager_SetPortVLAN_ExecuteError(t *testing.T) {
	mock := newMockSSHExecutor()
	mock.err = errors.New("connection lost")
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	err := mgr.SetPortVLAN(ctx, "Eth1/3", 100)
	if err == nil {
		t.Fatal("expected error for execute failure")
	}
	var vlanErr ErrPortVLANSetFailed
	if !errors.As(err, &vlanErr) {
		t.Fatalf("expected ErrPortVLANSetFailed, got %T: %v", err, err)
	}
}

func TestSSHManager_SetPortVLAN_OutputError(t *testing.T) {
	mock := newMockSSHExecutor()
	mock.outputs["switchport access vlan 100"] = "% Invalid command"
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	err := mgr.SetPortVLAN(ctx, "Eth1/3", 100)
	if err == nil {
		t.Fatal("expected error for error in output")
	}
}

// --- GetPortVLAN tests ---

func TestSSHManager_GetPortVLAN(t *testing.T) {
	switchportOutput := `Name: Eth1/3
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Access Mode VLAN: 100 (provisioning)
Trunking Native Mode VLAN: 1 (default)
`
	mock := newMockSSHExecutor()
	mock.outputs["show interfaces Eth1/3 switchport"] = switchportOutput
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	vlan, err := mgr.GetPortVLAN(ctx, "Eth1/3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vlan != 100 {
		t.Fatalf("expected vlan 100, got %d", vlan)
	}
	if len(mock.commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(mock.commands))
	}
	if mock.commands[0] != "show interfaces Eth1/3 switchport" {
		t.Fatalf("expected show command, got %q", mock.commands[0])
	}
}

func TestSSHManager_GetPortVLAN_ExecuteError(t *testing.T) {
	mock := newMockSSHExecutor()
	mock.err = errors.New("connection refused")
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	_, err := mgr.GetPortVLAN(ctx, "Eth1/3")
	if err == nil {
		t.Fatal("expected error for execute failure")
	}
}

func TestSSHManager_GetPortVLAN_ParseError(t *testing.T) {
	mock := newMockSSHExecutor()
	mock.outputs["show interfaces Eth1/3 switchport"] = "garbage output\nno vlan info here\n"
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	_, err := mgr.GetPortVLAN(ctx, "Eth1/3")
	if err == nil {
		t.Fatal("expected error for unparseable output")
	}
	var parseErr ErrSSHParseOutputFailed
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected ErrSSHParseOutputFailed, got %T: %v", err, err)
	}
}

// --- GetPortStatus tests ---

func TestSSHManager_GetPortStatus(t *testing.T) {
	switchportOutput := `Name: Eth1/3
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Access Mode VLAN: 100 (provisioning)
Trunking Native Mode VLAN: 1 (default)
`
	mock := newMockSSHExecutor()
	mock.outputs["show interfaces Eth1/3 switchport"] = switchportOutput
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	status, err := mgr.GetPortStatus(ctx, "Eth1/3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Port != "Eth1/3" {
		t.Fatalf("expected port Eth1/3, got %s", status.Port)
	}
	if status.Mode != switchwire.PortModeAccess {
		t.Fatalf("expected access mode, got %s", status.Mode)
	}
	if status.AccessVLAN != 100 {
		t.Fatalf("expected vlan 100, got %d", status.AccessVLAN)
	}
}

func TestSSHManager_GetPortStatus_ExecuteError(t *testing.T) {
	mock := newMockSSHExecutor()
	mock.err = errors.New("timeout")
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	_, err := mgr.GetPortStatus(ctx, "Eth1/3")
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- ListPorts tests ---

func TestSSHManager_ListPorts(t *testing.T) {
	listOutput := `Port      Name               Status       Vlan       Duplex  Speed   Type
Eth1/1    uplink             connected    trunk      full    1000    10/100/1000
Eth1/2    server-01          connected    100        full    1000    10/100/1000
Eth1/3    --                 disabled     200        auto    auto    10/100/1000
`
	mock := newMockSSHExecutor()
	mock.outputs["show interfaces status"] = listOutput
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	ports, err := mgr.ListPorts(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
	if mock.commands[0] != "show interfaces status" {
		t.Fatalf("expected 'show interfaces status', got %q", mock.commands[0])
	}
}

func TestSSHManager_ListPorts_ExecuteError(t *testing.T) {
	mock := newMockSSHExecutor()
	mock.err = errors.New("connection closed")
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	_, err := mgr.ListPorts(ctx)
	if err == nil {
		t.Fatal("expected error for execute failure")
	}
}

func TestSSHManager_ListPorts_ParseError(t *testing.T) {
	mock := newMockSSHExecutor()
	mock.outputs["show interfaces status"] = "no table here\njust random text\n"
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	_, err := mgr.ListPorts(ctx)
	if err == nil {
		t.Fatal("expected error for unparseable output")
	}
}

// --- EnablePort tests ---

func TestSSHManager_EnablePort(t *testing.T) {
	mock := newMockSSHExecutor()
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	err := mgr.EnablePort(ctx, "Eth1/5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.commands) != 4 {
		t.Fatalf("expected 4 commands, got %d: %v", len(mock.commands), mock.commands)
	}

	found := false
	for _, cmd := range mock.commands {
		if cmd == "no shutdown" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected 'no shutdown' command")
	}
}

func TestSSHManager_EnablePort_Error(t *testing.T) {
	mock := newMockSSHExecutor()
	mock.outputs["no shutdown"] = "% Error: cannot enable"
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	err := mgr.EnablePort(ctx, "Eth1/5")
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- DisablePort tests ---

func TestSSHManager_DisablePort(t *testing.T) {
	mock := newMockSSHExecutor()
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	err := mgr.DisablePort(ctx, "Eth1/5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, cmd := range mock.commands {
		if cmd == "shutdown" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected 'shutdown' command")
	}

	// Ensure "no shutdown" is NOT present.
	for _, cmd := range mock.commands {
		if cmd == "no shutdown" {
			t.Fatal("disable should not contain 'no shutdown'")
		}
	}
}

func TestSSHManager_DisablePort_OutputError(t *testing.T) {
	mock := newMockSSHExecutor()
	mock.outputs["shutdown"] = "% Error: port cannot be disabled"
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
	ctx := context.Background()

	err := mgr.DisablePort(ctx, "Eth1/5")
	if err == nil {
		t.Fatal("expected error for error output")
	}
}

// --- Close tests ---

func TestSSHManager_Close(t *testing.T) {
	mock := newMockSSHExecutor()
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)

	err := mgr.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.closed {
		t.Fatal("expected executor to be closed")
	}
}

func TestSSHManager_Close_NilExecutor(t *testing.T) {
	mgr := &sshManager{config: testSSHConfig(), logger: testSSHLogger()}
	err := mgr.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- validateSSHManagerConfig tests ---

func TestValidateSSHManagerConfig_Valid(t *testing.T) {
	config := &Config{
		Host:   "10.0.0.1",
		User:   "admin",
		SSHKey: "/path/to/key",
	}
	if err := validateSSHManagerConfig(config); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSSHManagerConfig_ValidWithPassword(t *testing.T) {
	config := &Config{
		Host:     "10.0.0.1",
		User:     "admin",
		Password: "secret",
	}
	if err := validateSSHManagerConfig(config); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSSHManagerConfig_Nil(t *testing.T) {
	err := validateSSHManagerConfig(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	var nilCfg ErrNilConfig
	if !errors.As(err, &nilCfg) {
		t.Fatalf("expected ErrNilConfig, got %T", err)
	}
}

func TestValidateSSHManagerConfig_MissingHost(t *testing.T) {
	config := &Config{User: "admin", SSHKey: "/path/to/key"}
	err := validateSSHManagerConfig(config)
	if err == nil {
		t.Fatal("expected error for missing host")
	}
	var invalidCfg ErrInvalidConfig
	if !errors.As(err, &invalidCfg) {
		t.Fatalf("expected ErrInvalidConfig, got %T", err)
	}
}

func TestValidateSSHManagerConfig_MissingUser(t *testing.T) {
	config := &Config{Host: "10.0.0.1", SSHKey: "/path/to/key"}
	err := validateSSHManagerConfig(config)
	if err == nil {
		t.Fatal("expected error for missing user")
	}
}

func TestValidateSSHManagerConfig_MissingAuth(t *testing.T) {
	config := &Config{Host: "10.0.0.1", User: "admin"}
	err := validateSSHManagerConfig(config)
	if err == nil {
		t.Fatal("expected error for missing ssh_key and password")
	}
	var invalidCfg ErrInvalidConfig
	if !errors.As(err, &invalidCfg) {
		t.Fatalf("expected ErrInvalidConfig, got %T", err)
	}
	if invalidCfg.Field != "ssh_key" {
		t.Fatalf("expected field 'ssh_key', got %q", invalidCfg.Field)
	}
}
