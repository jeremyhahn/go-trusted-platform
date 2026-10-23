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

//go:build integration && linux
// +build integration,linux

// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package ovs

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

const testSocketPath = "/var/run/openvswitch/db.sock"

// ovsPrerequisiteError is a typed error reported when the host cannot run
// these tests. Per the platform testing policy they never call t.Skip: a
// missing prerequisite is a loud failure that names it, not a silent green.
type ovsPrerequisiteError struct {
	// Missing names the prerequisite that is absent.
	Missing string

	// Cause is the underlying error, if any.
	Cause error
}

func (e *ovsPrerequisiteError) Error() string {
	msg := fmt.Sprintf("OVS integration test prerequisite missing: %s; run it in the devcontainer, whose entrypoint starts ovsdb-server and ovs-vswitchd", e.Missing)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *ovsPrerequisiteError) Unwrap() error { return e.Cause }

// requireOVSSocket fails the test when no OVSDB socket is listening at
// testSocketPath.
func requireOVSSocket(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(testSocketPath); err != nil {
		t.Fatalf("%v", &ovsPrerequisiteError{Missing: "OVSDB socket at " + testSocketPath, Cause: err})
	}
}

// TestOVSIntegration tests the complete OVS client workflow
// This test requires OVS to be installed and running
func TestOVSIntegration(t *testing.T) {
	requireOVSSocket(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create client
	client, err := NewClient(testSocketPath)
	if err != nil {
		t.Fatalf("Failed to create OVS client: %v", err)
	}

	// Connect
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect to OVSDB: %v", err)
	}
	defer client.Disconnect()

	// Verify connected
	if !client.IsConnected() {
		t.Fatal("Client should be connected")
	}

	bridgeName := "test-ovs-br0"

	// Clean up any existing test bridge
	existing, _ := client.GetBridge(ctx, bridgeName)
	if existing != nil {
		if err := client.DeleteBridge(ctx, bridgeName); err != nil {
			t.Logf("Warning: failed to delete existing test bridge: %v", err)
		}
	}

	// Create bridge
	bridge, err := client.CreateBridge(ctx, bridgeName)
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}
	defer client.DeleteBridge(ctx, bridgeName)

	if bridge.Name != bridgeName {
		t.Errorf("Expected bridge name %s, got %s", bridgeName, bridge.Name)
	}

	// List bridges
	bridges, err := client.ListBridges(ctx)
	if err != nil {
		t.Fatalf("Failed to list bridges: %v", err)
	}

	found := false
	for _, br := range bridges {
		if br.Name == bridgeName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Created bridge %s not found in bridge list", bridgeName)
	}

	// Get bridge
	retrievedBridge, err := client.GetBridge(ctx, bridgeName)
	if err != nil {
		t.Fatalf("Failed to get bridge: %v", err)
	}
	if retrievedBridge.Name != bridgeName {
		t.Errorf("Expected bridge name %s, got %s", bridgeName, retrievedBridge.Name)
	}

	// Note: Port tests require real network interfaces, see TestOVSWithRealPorts
	t.Log("Skipping port tests as they require real network interfaces")

	// Test SetBridgeProtocols (OVSDB operation)
	if err := client.SetBridgeProtocols(ctx, bridgeName, []string{"OpenFlow13"}); err != nil {
		t.Fatalf("Failed to set bridge protocols: %v", err)
	}

	// Test SetBridgeFailMode
	if err := client.SetBridgeFailMode(ctx, bridgeName, "standalone"); err != nil {
		t.Fatalf("Failed to set bridge fail mode: %v", err)
	}

	// Delete bridge
	if err := client.DeleteBridge(ctx, bridgeName); err != nil {
		t.Fatalf("Failed to delete bridge: %v", err)
	}

	// Verify bridge deleted
	_, err = client.GetBridge(ctx, bridgeName)
	if err != ErrBridgeNotFound {
		t.Errorf("Expected ErrBridgeNotFound, got %v", err)
	}

	// Disconnect
	if err := client.Disconnect(); err != nil {
		t.Fatalf("Failed to disconnect: %v", err)
	}

	if client.IsConnected() {
		t.Error("Client should be disconnected")
	}
}

// TestOVSWithRealPorts tests port operations with actual TAP devices
// This is more comprehensive but requires root/CAP_NET_ADMIN
func TestOVSWithRealPorts(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatalf("%v", &ovsPrerequisiteError{Missing: "root (CAP_NET_ADMIN) to create OVS internal ports"})
	}
	requireOVSSocket(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create client
	client, err := NewClient(testSocketPath)
	if err != nil {
		t.Fatalf("Failed to create OVS client: %v", err)
	}

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect to OVSDB: %v", err)
	}
	defer client.Disconnect()

	bridgeName := "test-ovs-br1"
	portName := "test-internal0"

	// Clean up
	existing, _ := client.GetBridge(ctx, bridgeName)
	if existing != nil {
		client.DeleteBridge(ctx, bridgeName)
	}

	// Create bridge
	_, err = client.CreateBridge(ctx, bridgeName)
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}
	defer client.DeleteBridge(ctx, bridgeName)

	// Add internal port (OVS can create these without external interfaces)
	port, err := client.AddPort(ctx, bridgeName, portName)
	if err != nil {
		t.Fatalf("Failed to add port: %v", err)
	}
	defer client.DeletePort(ctx, bridgeName, portName)

	if port.Name != portName {
		t.Errorf("Expected port name %s, got %s", portName, port.Name)
	}

	// List ports
	ports, err := client.ListPorts(ctx, bridgeName)
	if err != nil {
		t.Fatalf("Failed to list ports: %v", err)
	}

	foundPort := false
	for _, p := range ports {
		if p.Name == portName {
			foundPort = true
			break
		}
	}
	if !foundPort {
		t.Errorf("Created port %s not found in port list", portName)
	}

	// Get port
	retrievedPort, err := client.GetPort(ctx, portName)
	if err != nil {
		t.Fatalf("Failed to get port: %v", err)
	}
	if retrievedPort.Name != portName {
		t.Errorf("Expected port name %s, got %s", portName, retrievedPort.Name)
	}

	// Set VLAN tag
	vlanTag := int64(100)
	if err := client.SetPortVLAN(ctx, portName, vlanTag); err != nil {
		t.Fatalf("Failed to set port VLAN: %v", err)
	}

	// Get port again and verify VLAN
	retrievedPort, err = client.GetPort(ctx, portName)
	if err != nil {
		t.Fatalf("Failed to get port after VLAN set: %v", err)
	}
	if retrievedPort.Tag != vlanTag {
		t.Errorf("Expected VLAN tag %d, got %d", vlanTag, retrievedPort.Tag)
	}

	// Set trunk VLANs
	trunks := []int64{200, 300, 400}
	if err := client.SetPortTrunks(ctx, portName, trunks); err != nil {
		t.Fatalf("Failed to set port trunks: %v", err)
	}

	// Delete port
	if err := client.DeletePort(ctx, bridgeName, portName); err != nil {
		t.Fatalf("Failed to delete port: %v", err)
	}

	// Verify port deleted
	_, err = client.GetPort(ctx, portName)
	if err != ErrPortNotFound {
		t.Errorf("Expected ErrPortNotFound, got %v", err)
	}
}
