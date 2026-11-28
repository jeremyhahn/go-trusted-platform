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
	"strings"
	"testing"
)

const statusTableHeader = "Port      Name               Status       Vlan       Duplex  Speed   Type\n"

// failingThenWorkingDialer returns a dialer whose first connection fails
// every command and whose later connections answer the switchport show.
func failingThenWorkingDialer() (dial func(context.Context, *Config) (SSHExecutor, error), dials *int, mocks *[]*mockSSHExecutor) {
	var n int
	var made []*mockSSHExecutor
	dial = func(context.Context, *Config) (SSHExecutor, error) {
		n++
		mock := newSwitchportMock()
		if n == 1 {
			mock.err = errors.New("connection lost")
		}
		made = append(made, mock)
		return mock, nil
	}
	return dial, &n, &made
}

// TestSSHManager_ExecuteErrorDropsConnection pins that a failed command
// closes and drops the connection, so the next call dials again.
func TestSSHManager_ExecuteErrorDropsConnection(t *testing.T) {
	dial, dials, mocks := failingThenWorkingDialer()
	mgr := newSSHManagerWithDialer(testSSHConfig(), testSSHLogger(), dial)
	ctx := context.Background()

	if _, err := mgr.GetPortVLAN(ctx, "Eth1/3"); err == nil {
		t.Fatal("first GetPortVLAN: expected an error from the failing connection")
	}
	if !(*mocks)[0].closed {
		t.Fatal("the failed connection was not closed")
	}
	vlan, err := mgr.GetPortVLAN(ctx, "Eth1/3")
	if err != nil {
		t.Fatalf("GetPortVLAN after a failed command: %v", err)
	}
	if vlan != 100 {
		t.Fatalf("vlan = %d, want 100", vlan)
	}
	if *dials != 2 {
		t.Fatalf("dials = %d, want 2 (a failed command redials)", *dials)
	}
}

// TestSSHManager_FailedMutationIsNotReplayed pins that a failed SetPortVLAN
// is not sent again on the new connection.
func TestSSHManager_FailedMutationIsNotReplayed(t *testing.T) {
	dial, dials, mocks := failingThenWorkingDialer()
	mgr := newSSHManagerWithDialer(testSSHConfig(), testSSHLogger(), dial)
	ctx := context.Background()

	if err := mgr.SetPortVLAN(ctx, "Eth1/3", 200); err == nil {
		t.Fatal("SetPortVLAN: expected an error from the failing connection")
	}
	if _, err := mgr.GetPortVLAN(ctx, "Eth1/3"); err != nil {
		t.Fatalf("GetPortVLAN after a failed mutation: %v", err)
	}
	if *dials != 2 {
		t.Fatalf("dials = %d, want 2", *dials)
	}
	second := (*mocks)[1]
	if len(second.commands) != 1 || second.commands[0] != "show interfaces Eth1/3 switchport" {
		t.Fatalf("second connection commands = %v, want only the switchport show", second.commands)
	}
	for _, cmd := range second.commands {
		if strings.Contains(cmd, "switchport access vlan 200") {
			t.Fatalf("the failed mutation was replayed: %q", cmd)
		}
	}
}

// TestSSHManager_RunConfigErrorDropsConnection pins the same drop-and-redial
// for the configuration path (EnablePort goes through runConfig).
func TestSSHManager_RunConfigErrorDropsConnection(t *testing.T) {
	dial, dials, mocks := failingThenWorkingDialer()
	mgr := newSSHManagerWithDialer(testSSHConfig(), testSSHLogger(), dial)
	ctx := context.Background()

	if err := mgr.EnablePort(ctx, "Eth1/3"); err == nil {
		t.Fatal("EnablePort: expected an error from the failing connection")
	}
	if !(*mocks)[0].closed {
		t.Fatal("the failed connection was not closed")
	}
	vlan, err := mgr.GetPortVLAN(ctx, "Eth1/3")
	if err != nil {
		t.Fatalf("GetPortVLAN after a failed EnablePort: %v", err)
	}
	if vlan != 100 {
		t.Fatalf("vlan = %d, want 100", vlan)
	}
	if *dials != 2 {
		t.Fatalf("dials = %d, want 2", *dials)
	}
}

// TestSSHManager_GetPortStatus_AdminAndLinkFromInterfaceStatus pins that
// Enabled and LinkUp come from the interface status row, not from the
// "Switchport: Enabled" line (Layer 2 switching).
func TestSSHManager_GetPortStatus_AdminAndLinkFromInterfaceStatus(t *testing.T) {
	cases := []struct {
		state       string
		wantEnabled bool
		wantLinkUp  bool
	}{
		{state: "disabled", wantEnabled: false, wantLinkUp: false},
		{state: "connected", wantEnabled: true, wantLinkUp: true},
		{state: "notconnect", wantEnabled: true, wantLinkUp: false},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			mock := newSwitchportMock()
			row := "Eth1/3    --                 " + padRight(tc.state, 13) + "100        auto    auto    10/100/1000\n"
			mock.outputs["show interfaces Eth1/3 status"] = statusTableHeader + row
			mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)

			status, err := mgr.GetPortStatus(context.Background(), "Eth1/3")
			if err != nil {
				t.Fatalf("GetPortStatus: %v", err)
			}
			if status.Enabled != tc.wantEnabled {
				t.Errorf("Enabled = %v, want %v", status.Enabled, tc.wantEnabled)
			}
			if status.LinkUp != tc.wantLinkUp {
				t.Errorf("LinkUp = %v, want %v", status.LinkUp, tc.wantLinkUp)
			}
			if status.AccessVLAN != 100 {
				t.Errorf("AccessVLAN = %d, want 100", status.AccessVLAN)
			}
		})
	}
}

// TestSSHManager_GetPortStatus_NoStatusRowRefuses pins that a port missing
// from the interface status table is a parse error, not a Down answer.
func TestSSHManager_GetPortStatus_NoStatusRowRefuses(t *testing.T) {
	mock := newSwitchportMock()
	mock.outputs["show interfaces Eth1/3 status"] = statusTableHeader
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)

	status, err := mgr.GetPortStatus(context.Background(), "Eth1/3")
	if err == nil {
		t.Fatalf("GetPortStatus = %+v, want a parse error", status)
	}
	var parseErr ErrSSHParseOutputFailed
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected ErrSSHParseOutputFailed, got %T: %v", err, err)
	}
	if parseErr.Command != "show interfaces Eth1/3 status" {
		t.Fatalf("parse error command = %q, want the status command", parseErr.Command)
	}
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s + " "
	}
	return s + strings.Repeat(" ", n-len(s))
}
