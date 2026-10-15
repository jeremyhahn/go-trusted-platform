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
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTAPDeviceCreation tests creating TAP devices
func TestTAPDeviceCreation(t *testing.T) {
	requireRoot(t)
	requireOVS(t)
	requireCommand(t, "ip")

	bridgeName := "test-br-tap-0"
	portName := "tap-test-0"

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Add TAP port
	err = addTAPPort(bridgeName, portName)
	require.NoError(t, err, "Failed to add TAP port")

	// Verify port exists
	exists, err := portExists(bridgeName, portName)
	require.NoError(t, err)
	assert.True(t, exists, "TAP port should exist after creation")

	// Verify TAP device exists in system
	deviceExists, err := tapDeviceExists(portName)
	require.NoError(t, err)
	assert.True(t, deviceExists, "TAP device should exist in system")
}

// TestTAPDeviceConfiguration tests configuring TAP device properties
func TestTAPDeviceConfiguration(t *testing.T) {
	requireRoot(t)
	requireOVS(t)
	requireCommand(t, "ip")

	bridgeName := "test-br-tap-1"
	portName := "tap-test-1"

	defer cleanupBridge(t, bridgeName)

	// Create bridge and add TAP port
	err := createBridge(bridgeName)
	require.NoError(t, err)

	err = addTAPPort(bridgeName, portName)
	require.NoError(t, err)

	// Bring interface up
	err = setInterfaceUp(portName)
	require.NoError(t, err, "Failed to bring interface up")

	// Set MTU
	mtu := 1500
	err = setInterfaceMTU(portName, mtu)
	require.NoError(t, err, "Failed to set MTU")

	// Get interface info
	info, err := getInterfaceInfo(portName)
	require.NoError(t, err)
	t.Logf("TAP interface info: %s", info)
}

// TestInternalPort tests creating internal ports
func TestInternalPort(t *testing.T) {
	requireRoot(t)
	requireOVS(t)
	requireCommand(t, "ip")

	bridgeName := "test-br-internal"
	portName := "internal-test"

	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Add internal port
	err = addInternalPort(bridgeName, portName)
	require.NoError(t, err, "Failed to add internal port")

	// Verify port exists
	exists, err := portExists(bridgeName, portName)
	require.NoError(t, err)
	assert.True(t, exists, "Internal port should exist after creation")

	// Assign IP address
	ipAddr := "192.168.100.1/24"
	err = setInterfaceIP(portName, ipAddr)
	require.NoError(t, err, "Failed to set IP address")

	// Bring interface up
	err = setInterfaceUp(portName)
	require.NoError(t, err, "Failed to bring interface up")

	// Verify IP is set
	hasIP, err := interfaceHasIP(portName, "192.168.100.1")
	require.NoError(t, err)
	assert.True(t, hasIP, "Interface should have assigned IP")
}

// TestVETHPair tests creating virtual ethernet pairs
func TestVETHPair(t *testing.T) {
	requireRoot(t)
	requireOVS(t)
	requireCommand(t, "ip")

	bridgeName := "test-br-veth"
	vethName := "veth-test-0"
	peerName := "veth-test-1"

	defer cleanupBridge(t, bridgeName)
	defer cleanupVETH(t, vethName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Create VETH pair
	err = createVETHPair(vethName, peerName)
	require.NoError(t, err, "Failed to create VETH pair")

	// Add one end to bridge
	err = addPort(bridgeName, vethName)
	require.NoError(t, err, "Failed to add VETH to bridge")

	// Bring both ends up
	err = setInterfaceUp(vethName)
	require.NoError(t, err)

	err = setInterfaceUp(peerName)
	require.NoError(t, err)

	// Verify both interfaces exist
	exists, err := interfaceExists(vethName)
	require.NoError(t, err)
	assert.True(t, exists, "VETH interface should exist")

	exists, err = interfaceExists(peerName)
	require.NoError(t, err)
	assert.True(t, exists, "VETH peer interface should exist")
}

// TestPatchPort tests creating patch ports for connecting bridges
func TestPatchPort(t *testing.T) {
	requireOVSForTest(t)

	bridge1 := "test-br-patch-1"
	bridge2 := "test-br-patch-2"
	patch1 := "patch-1-2"
	patch2 := "patch-2-1"

	defer cleanupBridge(t, bridge1)
	defer cleanupBridge(t, bridge2)

	// Create both bridges
	err := createBridge(bridge1)
	require.NoError(t, err)

	err = createBridge(bridge2)
	require.NoError(t, err)

	// Create patch ports connecting the bridges
	err = addPatchPort(bridge1, patch1, patch2)
	require.NoError(t, err, "Failed to add patch port on bridge1")

	err = addPatchPort(bridge2, patch2, patch1)
	require.NoError(t, err, "Failed to add patch port on bridge2")

	// Verify both patch ports exist
	exists, err := portExists(bridge1, patch1)
	require.NoError(t, err)
	assert.True(t, exists, "Patch port 1 should exist")

	exists, err = portExists(bridge2, patch2)
	require.NoError(t, err)
	assert.True(t, exists, "Patch port 2 should exist")
}

// Helper functions

func addTAPPort(bridge, port string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "add-port", bridge, port,
		"--", "set", "interface", port, "type=tap")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add TAP port: %v, output: %s", err, output)
	}
	return nil
}

func addInternalPort(bridge, port string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "add-port", bridge, port,
		"--", "set", "interface", port, "type=internal")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add internal port: %v, output: %s", err, output)
	}

	// Wait for OVS to create the internal port interface in the kernel and bring it up
	output, linkUpErr := bringInternalPortUp(ctx, port)
	if linkUpErr != nil {
		return fmt.Errorf("failed to bring up interface %s after retries: %v, output: %s", port, linkUpErr, output)
	}
	return nil
}

func addPatchPort(bridge, port, peer string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "add-port", bridge, port,
		"--", "set", "interface", port, "type=patch",
		fmt.Sprintf("options:peer=%s", peer))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add patch port: %v, output: %s", err, output)
	}
	return nil
}

func tapDeviceExists(name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", "link", "show", name)
	err := cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() == 1 {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

func interfaceExists(name string) (bool, error) {
	return tapDeviceExists(name)
}

func setInterfaceUp(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", "link", "set", name, "up")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to bring interface up: %v, output: %s", err, output)
	}
	return nil
}

func setInterfaceMTU(name string, mtu int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", "link", "set", name, "mtu", fmt.Sprintf("%d", mtu))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set MTU: %v, output: %s", err, output)
	}
	return nil
}

func setInterfaceIP(name, ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", "addr", "add", ip, "dev", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set IP: %v, output: %s", err, output)
	}
	return nil
}

func interfaceHasIP(name, ip string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", "addr", "show", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to show interface: %v, output: %s", err, output)
	}

	return containsString(string(output), ip), nil
}

func getInterfaceInfo(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", "link", "show", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get interface info: %v, output: %s", err, output)
	}
	return string(output), nil
}

func createVETHPair(name, peer string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", "link", "add", name, "type", "veth", "peer", "name", peer)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create VETH pair: %v, output: %s", err, output)
	}
	return nil
}

func cleanupVETH(t *testing.T, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", "link", "del", name)
	if err := cmd.Run(); err != nil {
		t.Logf("Warning: failed to cleanup VETH %s: %v", name, err)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			len(s) > len(substr) && strings.Contains(s, substr))))
}
