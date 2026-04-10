//go:build integration

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

package sdn

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

const (
	// ovsCheckTimeout is the timeout for checking OVS availability
	ovsCheckTimeout = 2 * time.Second
)

// skipIfNoOVS skips the test if Open vSwitch (OVS) is not available.
// OVS is required for bridge, port, flow, and OpenFlow tests.
func skipIfNoOVS(t *testing.T) {
	t.Helper()

	// Check if ovs-vsctl command exists
	if _, err := exec.LookPath("ovs-vsctl"); err != nil {
		t.Skip("Skipping test: ovs-vsctl not found in PATH. Install Open vSwitch to run this test.")
	}

	// Check if OVS daemon is running by trying to list bridges
	ctx, cancel := context.WithTimeout(context.Background(), ovsCheckTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "list-br")
	if err := cmd.Run(); err != nil {
		t.Skip("Skipping test: OVS daemon (ovs-vswitchd) is not running. Start OVS service to run this test.")
	}
}

// skipIfNoOVSDB skips the test if OVSDB server is not available.
// OVSDB is required for tests that connect to the OVSDB server directly.
func skipIfNoOVSDB(t *testing.T) {
	t.Helper()

	// Check if the OVSDB socket exists
	socketPaths := []string{
		"/var/run/openvswitch/db.sock",
		"/run/openvswitch/db.sock",
	}

	socketFound := false
	for _, path := range socketPaths {
		if _, err := os.Stat(path); err == nil {
			socketFound = true
			break
		}
	}

	if !socketFound {
		t.Skip("Skipping test: OVSDB socket not found. Ensure OVS is running with OVSDB accessible.")
	}

	// Also verify OVS is running
	skipIfNoOVS(t)
}

// skipIfNoOVSCtl skips the test if ovs-vsctl command is not available.
// This is a lighter check than skipIfNoOVS - it only checks for the command.
func skipIfNoOVSCtl(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("ovs-vsctl"); err != nil {
		t.Skip("Skipping test: ovs-vsctl not found in PATH.")
	}
}

// skipIfNoOVSOfctl skips the test if ovs-ofctl command is not available.
// This is required for OpenFlow flow manipulation tests.
func skipIfNoOVSOfctl(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("ovs-ofctl"); err != nil {
		t.Skip("Skipping test: ovs-ofctl not found in PATH.")
	}

	// Also need OVS running
	skipIfNoOVS(t)
}

// skipIfNotRoot skips the test if not running with root privileges.
// Many OVS and network interface tests require root.
func skipIfNotRoot(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("Skipping test: requires root privileges.")
	}
}

// skipIfNoNetworkAccess skips the test if basic network access is unavailable.
// Tests that need to ping or access network resources should use this.
func skipIfNoNetworkAccess(t *testing.T) {
	t.Helper()

	// Try to find ip command
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("Skipping test: 'ip' command not found.")
	}

	// Try to get default gateway - if this fails, network access is likely unavailable
	ctx, cancel := context.WithTimeout(context.Background(), ovsCheckTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", "route", "show", "default")
	if err := cmd.Run(); err != nil {
		t.Skip("Skipping test: no network access (no default route).")
	}
}

// skipIfOVSDBConnectFails skips the test if we cannot connect to the OVSDB server
// at the specified address.
func skipIfOVSDBConnectFails(t *testing.T, address string) {
	t.Helper()

	// For TCP connections, try to connect
	if len(address) > 4 && address[:4] == "tcp:" {
		// Extract host:port from "tcp:host:port"
		hostPort := address[4:]
		ctx, cancel := context.WithTimeout(context.Background(), ovsCheckTimeout)
		defer cancel()

		// Try ovs-vsctl to verify OVSDB is reachable
		cmd := exec.CommandContext(ctx, "ovs-vsctl", "--db="+address, "list-br")
		if err := cmd.Run(); err != nil {
			t.Skipf("Skipping test: cannot connect to OVSDB at %s.", hostPort)
		}
	} else {
		// For socket connections, check file exists
		skipIfNoOVSDB(t)
	}
}

// skipIfNoIPCommand skips the test if the 'ip' command is not available.
func skipIfNoIPCommand(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("Skipping test: 'ip' command not found in PATH.")
	}
}

// skipIfNoPingCommand skips the test if the 'ping' command is not available.
func skipIfNoPingCommand(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("Skipping test: 'ping' command not found in PATH.")
	}
}

// requireOVSForTest combines common skip checks for OVS-dependent tests.
// This is a convenience function that checks for OVS, root, and network access.
func requireOVSForTest(t *testing.T) {
	t.Helper()

	skipIfNotRoot(t)
	skipIfNoOVS(t)
}

// requireOVSDBForTest combines common skip checks for OVSDB-dependent tests.
func requireOVSDBForTest(t *testing.T) {
	t.Helper()

	skipIfNotRoot(t)
	skipIfNoOVSDB(t)
}
