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

package nexus

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
)

// mockExecutor provides controllable SSH command responses for testing.
type mockExecutor struct {
	responses map[string]mockResponse
	executed  []string
	batchErr  error
}

type mockResponse struct {
	stdout string
	stderr string
	err    error
}

func (m *mockExecutor) Execute(_ context.Context, command string) (string, string, error) {
	m.executed = append(m.executed, command)
	if resp, ok := m.responses[command]; ok {
		return resp.stdout, resp.stderr, resp.err
	}
	// Default: commands that don't match return empty success (configure terminal, etc).
	return "", "", nil
}

func (m *mockExecutor) ExecuteBatch(_ context.Context, commands []string) ([]Result, error) {
	if m.batchErr != nil {
		return nil, m.batchErr
	}
	results := make([]Result, 0, len(commands))
	for _, cmd := range commands {
		m.executed = append(m.executed, cmd)
		resp, ok := m.responses[cmd]
		if !ok {
			results = append(results, Result{Command: cmd})
			continue
		}
		results = append(results, Result{
			Command: cmd,
			Stdout:  resp.stdout,
			Stderr:  resp.stderr,
			Err:     resp.err,
		})
	}
	return results, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func testSwitchConfig() fabric.SwitchConfig {
	return fabric.SwitchConfig{
		ID:     "nexus-01",
		Vendor: vendorName,
		MgmtIP: "10.0.0.1",
	}
}

func TestNewDriver_Valid(t *testing.T) {
	cfg := testSwitchConfig()
	drv, err := NewDriver(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewDriver: %s", err)
	}
	if drv == nil {
		t.Fatal("expected non-nil driver")
	}
}

func TestNewDriver_MissingMgmtIP(t *testing.T) {
	cfg := fabric.SwitchConfig{ID: "sw-01", Vendor: vendorName}
	_, err := NewDriver(cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for missing mgmt-ip")
	}
	var invErr ErrInvalidConfig
	if !errors.As(err, &invErr) {
		t.Fatalf("expected ErrInvalidConfig, got %T: %s", err, err)
	}
}

func TestConnect_WithExecutor(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{responses: map[string]mockResponse{}}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}
}

func TestPing_Success(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show version | head 1": {stdout: "Cisco Nexus Operating System (NX-OS) Software"},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}
	if err := drv.Ping(ctx); err != nil {
		t.Fatalf("Ping: %s", err)
	}
}

func TestPing_NotConnected(t *testing.T) {
	cfg := testSwitchConfig()
	drv, err := NewDriver(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewDriver: %s", err)
	}

	ctx := context.Background()
	err = drv.Ping(ctx)
	if err == nil {
		t.Fatal("expected error when not connected")
	}
	var notConn ErrNotConnected
	if !errors.As(err, &notConn) {
		t.Fatalf("expected ErrNotConnected, got %T: %s", err, err)
	}
}

func TestEnsureVLAN_AlreadyExists(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show vlan id 200": {
				stdout: "VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------\n200  production                       active    Eth1/1\n",
			},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	if err := drv.EnsureVLAN(ctx, 200, "production"); err != nil {
		t.Fatalf("EnsureVLAN: %s", err)
	}

	// Should not have executed configure terminal since VLAN exists.
	for _, cmd := range exec.executed {
		if strings.HasPrefix(cmd, "configure terminal") {
			t.Fatal("should not configure VLAN that already exists")
		}
	}
}

func TestEnsureVLAN_Creates(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show vlan id 200": {stdout: "VLAN 200 not found"},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	if err := drv.EnsureVLAN(ctx, 200, "production"); err != nil {
		t.Fatalf("EnsureVLAN: %s", err)
	}

	// Should have executed batch with configure terminal.
	found := false
	for _, cmd := range exec.executed {
		if cmd == "configure terminal" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected configure terminal command for VLAN creation")
	}
}

func TestEnsureVLAN_NotConnected(t *testing.T) {
	cfg := testSwitchConfig()
	drv, err := NewDriver(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewDriver: %s", err)
	}

	ctx := context.Background()
	err = drv.EnsureVLAN(ctx, 200, "test")
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestEnsureVNI_AlreadyExists(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show nve vni": {
				stdout: "Interface VNI      Multicast-group State\nnve1      100200   225.1.1.1       Up\n",
			},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	if err := drv.EnsureVNI(ctx, 100200, 200); err != nil {
		t.Fatalf("EnsureVNI: %s", err)
	}
}

func TestEnsureVNI_Creates(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show nve vni": {stdout: ""},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	if err := drv.EnsureVNI(ctx, 100200, 200); err != nil {
		t.Fatalf("EnsureVNI: %s", err)
	}

	found := false
	for _, cmd := range exec.executed {
		if cmd == "interface nve1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected interface nve1 command for VNI creation")
	}
}

func TestEnsureLAG_AlreadyExists(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show port-channel summary": {
				stdout: "10    Po10(SU)    Eth    LACP    Eth1/1(P)    Eth1/2(P)\n",
			},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	lag := fabric.LAGConfig{
		ID:            "lag-01",
		PortChannelID: 10,
		Members: []fabric.PortRef{
			{SwitchID: "nexus-01", Port: "Eth1/1"},
		},
	}
	if err := drv.EnsureLAG(ctx, lag); err != nil {
		t.Fatalf("EnsureLAG: %s", err)
	}
}

func TestEnsureLAG_Creates(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show port-channel summary": {stdout: ""},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	lag := fabric.LAGConfig{
		ID:            "lag-01",
		PortChannelID: 10,
		LACPMode:      "active",
		MCLAG:         true,
		Members: []fabric.PortRef{
			{SwitchID: "nexus-01", Port: "Eth1/1"},
			{SwitchID: "nexus-01", Port: "Eth1/2"},
		},
	}
	if err := drv.EnsureLAG(ctx, lag); err != nil {
		t.Fatalf("EnsureLAG: %s", err)
	}

	foundPC := false
	for _, cmd := range exec.executed {
		if strings.Contains(cmd, "port-channel10") {
			foundPC = true
			break
		}
	}
	if !foundPC {
		t.Fatal("expected port-channel interface command for LAG creation")
	}
}

func TestSetPortAccess_Idempotent(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show running-config interface Eth1/5": {
				stdout: "interface Ethernet1/5\n  switchport\n  switchport mode access\n  switchport access vlan 200\n  no shutdown\n",
			},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	port := fabric.PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}
	if err := drv.SetPortAccess(ctx, port, 200); err != nil {
		t.Fatalf("SetPortAccess: %s", err)
	}

	// Should not have executed configure terminal since already configured.
	for _, cmd := range exec.executed {
		if cmd == "configure terminal" {
			t.Fatal("should not reconfigure port that is already in correct state")
		}
	}
}

func TestSetPortAccess_Configures(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show running-config interface Eth1/5": {
				stdout: "interface Ethernet1/5\n  switchport\n  switchport mode access\n  switchport access vlan 100\n",
			},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	port := fabric.PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}
	if err := drv.SetPortAccess(ctx, port, 200); err != nil {
		t.Fatalf("SetPortAccess: %s", err)
	}

	found := false
	for _, cmd := range exec.executed {
		if strings.Contains(cmd, "switchport access vlan 200") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected switchport access vlan command")
	}
}

func TestSetPortTrunk_Success(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{responses: map[string]mockResponse{}}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	port := fabric.PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}
	if err := drv.SetPortTrunk(ctx, port, []uint16{200, 201, 203}, 200); err != nil {
		t.Fatalf("SetPortTrunk: %s", err)
	}

	foundTrunk := false
	foundAllowed := false
	foundNative := false
	for _, cmd := range exec.executed {
		if strings.Contains(cmd, "switchport mode trunk") {
			foundTrunk = true
		}
		if strings.Contains(cmd, "switchport trunk allowed vlan 200,201,203") {
			foundAllowed = true
		}
		if strings.Contains(cmd, "switchport trunk native vlan 200") {
			foundNative = true
		}
	}
	if !foundTrunk {
		t.Fatal("expected switchport mode trunk command")
	}
	if !foundAllowed {
		t.Fatal("expected switchport trunk allowed vlan command")
	}
	if !foundNative {
		t.Fatal("expected switchport trunk native vlan command")
	}
}

func TestSetPortTrunk_NotConnected(t *testing.T) {
	cfg := testSwitchConfig()
	drv, err := NewDriver(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewDriver: %s", err)
	}

	ctx := context.Background()
	port := fabric.PortRef{SwitchID: "nexus-01", Port: "Eth1/5"}
	err = drv.SetPortTrunk(ctx, port, []uint16{200}, 200)
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestExecuteBatch_CommandError(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		responses: map[string]mockResponse{
			"show vlan id 200": {stdout: "VLAN 200 not found"},
			"vlan 200": {
				err: errors.New("permission denied"),
			},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	err := drv.EnsureVLAN(ctx, 200, "test")
	if err == nil {
		t.Fatal("expected error for command failure")
	}
	var cmdErr ErrCommandExec
	if !errors.As(err, &cmdErr) {
		t.Fatalf("expected ErrCommandExec, got %T: %s", err, err)
	}
}

func TestExecuteBatch_BatchError(t *testing.T) {
	cfg := testSwitchConfig()
	exec := &mockExecutor{
		batchErr: errors.New("batch failed"),
		responses: map[string]mockResponse{
			"show vlan id 200": {stdout: "VLAN 200 not found"},
		},
	}
	drv := NewDriverWithExecutor(cfg, testLogger(), exec)

	ctx := context.Background()
	if err := drv.Connect(ctx); err != nil {
		t.Fatalf("Connect: %s", err)
	}

	err := drv.EnsureVLAN(ctx, 200, "test")
	if err == nil {
		t.Fatal("expected error for batch failure")
	}
}

func TestDriverRegistration(t *testing.T) {
	// The init() function should have registered the cisco-nexus driver.
	cfg := fabric.SwitchConfig{
		ID:     "test-sw",
		Vendor: vendorName,
		MgmtIP: "10.0.0.1",
	}
	drv, err := fabric.DriverFor(cfg, testLogger())
	if err != nil {
		t.Fatalf("DriverFor: %s", err)
	}
	if drv == nil {
		t.Fatal("expected non-nil driver from registry")
	}
}

func TestDriverRegistration_UnknownVendor(t *testing.T) {
	cfg := fabric.SwitchConfig{
		ID:     "test-sw",
		Vendor: "unknown-vendor",
		MgmtIP: "10.0.0.1",
	}
	_, err := fabric.DriverFor(cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for unknown vendor")
	}
	var notFound fabric.ErrDriverNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrDriverNotFound, got %T: %s", err, err)
	}
}
