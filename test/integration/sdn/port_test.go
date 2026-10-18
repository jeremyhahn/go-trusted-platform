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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/boundedexec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPortCreation tests creating a port on a bridge
func TestPortCreation(t *testing.T) {
	requireOVSForTest(t)

	bridgeName := "test-br-port-0"
	portName := "test-port-0"

	defer cleanupBridge(t, bridgeName)

	// Create bridge first
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Add port to bridge
	err = addPort(bridgeName, portName)
	require.NoError(t, err, "Failed to add port")

	// Verify port exists
	exists, err := portExists(bridgeName, portName)
	require.NoError(t, err)
	assert.True(t, exists, "Port should exist after creation")

	// List ports
	ports, err := listPorts(bridgeName)
	require.NoError(t, err)
	assert.Contains(t, ports, portName, "Port list should contain the created port")
}

// TestPortDeletion tests removing a port from a bridge
func TestPortDeletion(t *testing.T) {
	requireOVSForTest(t)

	bridgeName := "test-br-port-1"
	portName := "test-port-1"

	defer cleanupBridge(t, bridgeName)

	// Create bridge and add port
	err := createBridge(bridgeName)
	require.NoError(t, err)

	err = addPort(bridgeName, portName)
	require.NoError(t, err)

	// Verify port exists
	exists, err := portExists(bridgeName, portName)
	require.NoError(t, err)
	require.True(t, exists)

	// Remove port
	err = deletePort(bridgeName, portName)
	require.NoError(t, err, "Failed to delete port")

	// Verify port is gone
	exists, err = portExists(bridgeName, portName)
	require.NoError(t, err)
	assert.False(t, exists, "Port should not exist after deletion")
}

// TestPortConfiguration tests configuring port properties
func TestPortConfiguration(t *testing.T) {
	requireOVSForTest(t)

	bridgeName := "test-br-port-2"
	portName := "test-port-2"

	defer cleanupBridge(t, bridgeName)

	// Create bridge and add port
	err := createBridge(bridgeName)
	require.NoError(t, err)

	err = addPort(bridgeName, portName)
	require.NoError(t, err)

	// Set VLAN tag
	vlanTag := 100
	err = setPortVLAN(bridgeName, portName, vlanTag)
	require.NoError(t, err, "Failed to set VLAN tag")

	// Set VLAN trunks
	trunks := []int{10, 20, 30}
	err = setPortVLANTrunks(bridgeName, portName, trunks)
	require.NoError(t, err, "Failed to set VLAN trunks")

	// Get port info
	info, err := getPortInfo(portName)
	require.NoError(t, err)
	t.Logf("Port configuration: %s", info)
}

// TestPortExternalIDs tests setting external IDs on a port
func TestPortExternalIDs(t *testing.T) {
	requireOVSForTest(t)

	bridgeName := "test-br-port-3"
	portName := "test-port-3"

	defer cleanupBridge(t, bridgeName)

	// Create bridge and add port
	err := createBridge(bridgeName)
	require.NoError(t, err)

	err = addPort(bridgeName, portName)
	require.NoError(t, err)

	// Set external IDs
	externalIDs := map[string]string{
		"network-id": "net-001",
		"vm-id":      "vm-12345",
		"iface-id":   "if-67890",
	}

	for key, value := range externalIDs {
		err = setPortExternalID(portName, key, value)
		require.NoError(t, err, "Failed to set external ID %s=%s", key, value)
	}

	// Verify external IDs
	for key, expectedValue := range externalIDs {
		value, err := getPortExternalID(portName, key)
		require.NoError(t, err)
		assert.Equal(t, expectedValue, value, "External ID mismatch for key %s", key)
	}
}

// TestMultiplePorts tests creating multiple ports on a bridge
func TestMultiplePorts(t *testing.T) {
	requireOVSForTest(t)

	bridgeName := "test-br-port-multi"
	portNames := []string{"port-0", "port-1", "port-2"}

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Add all ports
	for _, portName := range portNames {
		err = addPort(bridgeName, portName)
		require.NoError(t, err, "Failed to add port %s", portName)
	}

	// Verify all ports exist
	for _, portName := range portNames {
		exists, err := portExists(bridgeName, portName)
		require.NoError(t, err)
		assert.True(t, exists, "Port %s should exist", portName)
	}

	// List all ports
	ports, err := listPorts(bridgeName)
	require.NoError(t, err)

	for _, portName := range portNames {
		assert.Contains(t, ports, portName, "Port list should contain %s", portName)
	}
}

// TestPortBonding tests link aggregation (bonding)
func TestPortBonding(t *testing.T) {
	requireOVSForTest(t)

	bridgeName := "test-br-bond"
	bondName := "bond0"
	interfaces := []string{"eth0-test", "eth1-test"}

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Create bond port (note: interfaces don't need to exist for test)
	err = addBondPort(bridgeName, bondName, interfaces)
	require.NoError(t, err, "Failed to create bond port")

	// Verify bond exists
	exists, err := portExists(bridgeName, bondName)
	require.NoError(t, err)
	assert.True(t, exists, "Bond port should exist")

	// Set bond mode
	err = setBondMode(bondName, "balance-slb")
	require.NoError(t, err, "Failed to set bond mode")

	// Get port info
	info, err := getPortInfo(bondName)
	require.NoError(t, err)
	t.Logf("Bond configuration: %s", info)
}

// Helper functions

func addPort(bridge, port string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "add-port", bridge, port)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add port: %v, output: %s", err, output)
	}
	return nil
}

func deletePort(bridge, port string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "del-port", bridge, port)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete port: %v, output: %s", err, output)
	}
	return nil
}

func portExists(bridge, port string) (bool, error) {
	ports, err := listPorts(bridge)
	if err != nil {
		return false, err
	}

	for _, p := range ports {
		if p == port {
			return true, nil
		}
	}
	return false, nil
}

func listPorts(bridge string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "list-ports", bridge)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list ports: %v, output: %s", err, output)
	}

	ports := []string{}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line != "" {
			ports = append(ports, line)
		}
	}
	return ports, nil
}

func getPortInfo(port string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "list", "port", port)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get port info: %v, output: %s", err, output)
	}
	return string(output), nil
}

func setPortVLAN(bridge, port string, tag int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "set", "port", port,
		fmt.Sprintf("tag=%d", tag))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set VLAN tag: %v, output: %s", err, output)
	}
	return nil
}

func setPortVLANTrunks(bridge, port string, trunks []int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	trunkStr := ""
	for i, trunk := range trunks {
		if i > 0 {
			trunkStr += ","
		}
		trunkStr += fmt.Sprintf("%d", trunk)
	}

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "set", "port", port,
		fmt.Sprintf("trunks=[%s]", trunkStr))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set VLAN trunks: %v, output: %s", err, output)
	}
	return nil
}

func setPortExternalID(port, key, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "set", "port", port,
		fmt.Sprintf("external-ids:%s=%s", key, value))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set external ID: %v, output: %s", err, output)
	}
	return nil
}

func getPortExternalID(port, key string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "get", "port", port,
		fmt.Sprintf("external-ids:%s", key))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get external ID: %v, output: %s", err, output)
	}
	return strings.TrimSpace(strings.Trim(string(output), "\"")), nil
}

func addBondPort(bridge, bond string, interfaces []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args := []string{"add-bond", bridge, bond}
	args = append(args, interfaces...)

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add bond port: %v, output: %s", err, output)
	}
	return nil
}

func setBondMode(bond, mode string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "set", "port", bond,
		fmt.Sprintf("bond_mode=%s", mode))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set bond mode: %v, output: %s", err, output)
	}
	return nil
}
