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
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/boundedexec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBridgeCreation tests creating an OVS bridge
func TestBridgeCreation(t *testing.T) {
	requireOVSForTest(t)

	bridgeName := "test-br0"
	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err, "Failed to create bridge")

	// Verify bridge exists
	exists, err := bridgeExists(bridgeName)
	require.NoError(t, err)
	assert.True(t, exists, "Bridge should exist after creation")

	// Get bridge info
	info, err := getBridgeInfo(bridgeName)
	require.NoError(t, err)
	assert.Contains(t, info, bridgeName, "Bridge info should contain bridge name")
}

// TestBridgeDeletion tests deleting an OVS bridge
func TestBridgeDeletion(t *testing.T) {
	requireOVSForTest(t)

	bridgeName := "test-br1"

	// Create bridge first
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Verify it exists
	exists, err := bridgeExists(bridgeName)
	require.NoError(t, err)
	require.True(t, exists)

	// Delete bridge
	err = deleteBridge(bridgeName)
	require.NoError(t, err, "Failed to delete bridge")

	// Verify it's gone
	exists, err = bridgeExists(bridgeName)
	require.NoError(t, err)
	assert.False(t, exists, "Bridge should not exist after deletion")
}

// TestBridgeConfiguration tests configuring bridge properties
func TestBridgeConfiguration(t *testing.T) {
	requireOVSForTest(t)

	bridgeName := "test-br2"
	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Set STP (Spanning Tree Protocol)
	err = setBridgeSTP(bridgeName, true)
	require.NoError(t, err, "Failed to enable STP")

	// Set RSTP (Rapid Spanning Tree Protocol)
	err = setBridgeRSTP(bridgeName, false)
	require.NoError(t, err, "Failed to disable RSTP")

	// Set fail mode
	err = setBridgeFailMode(bridgeName, "standalone")
	require.NoError(t, err, "Failed to set fail mode")

	// Get and verify configuration
	info, err := getBridgeInfo(bridgeName)
	require.NoError(t, err)
	t.Logf("Bridge configuration: %s", info)
}

// TestBridgeExternalIDs tests setting external IDs on a bridge
func TestBridgeExternalIDs(t *testing.T) {
	requireOVSForTest(t)

	bridgeName := "test-br3"
	defer cleanupBridge(t, bridgeName)

	// Create bridge
	err := createBridge(bridgeName)
	require.NoError(t, err)

	// Set external IDs
	externalIDs := map[string]string{
		"environment": "test",
		"purpose":     "integration-testing",
		"created-by":  "go-trusted-platform",
	}

	for key, value := range externalIDs {
		err = setBridgeExternalID(bridgeName, key, value)
		require.NoError(t, err, "Failed to set external ID %s=%s", key, value)
	}

	// Verify external IDs
	for key, expectedValue := range externalIDs {
		value, err := getBridgeExternalID(bridgeName, key)
		require.NoError(t, err)
		assert.Equal(t, expectedValue, value, "External ID mismatch for key %s", key)
	}
}

// TestMultipleBridges tests creating and managing multiple bridges
func TestMultipleBridges(t *testing.T) {
	requireOVSForTest(t)

	bridgeNames := []string{"test-br-multi-0", "test-br-multi-1", "test-br-multi-2"}

	// Cleanup all bridges on exit
	defer func() {
		for _, name := range bridgeNames {
			cleanupBridge(t, name)
		}
	}()

	// Create all bridges
	for _, name := range bridgeNames {
		err := createBridge(name)
		require.NoError(t, err, "Failed to create bridge %s", name)
	}

	// Verify all bridges exist
	for _, name := range bridgeNames {
		exists, err := bridgeExists(name)
		require.NoError(t, err)
		assert.True(t, exists, "Bridge %s should exist", name)
	}

	// List all bridges
	bridges, err := listBridges()
	require.NoError(t, err)

	for _, name := range bridgeNames {
		assert.Contains(t, bridges, name, "Bridge list should contain %s", name)
	}
}

// Helper functions

func createBridge(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "add-br", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create bridge: %v, output: %s", err, output)
	}
	return nil
}

func deleteBridge(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "del-br", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete bridge: %v, output: %s", err, output)
	}
	return nil
}

func bridgeExists(name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "br-exists", name)
	err := cmd.Run()
	if err != nil {
		// Exit code 2 means bridge doesn't exist
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			if exitError.ExitCode() == 2 {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

func getBridgeInfo(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "list", "bridge", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get bridge info: %v, output: %s", err, output)
	}
	return string(output), nil
}

func setBridgeSTP(name string, enable bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	value := "false"
	if enable {
		value = "true"
	}

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "set", "bridge", name, fmt.Sprintf("stp_enable=%s", value))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set STP: %v, output: %s", err, output)
	}
	return nil
}

func setBridgeRSTP(name string, enable bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	value := "false"
	if enable {
		value = "true"
	}

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "set", "bridge", name, fmt.Sprintf("rstp_enable=%s", value))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set RSTP: %v, output: %s", err, output)
	}
	return nil
}

func setBridgeFailMode(name string, mode string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "set-fail-mode", name, mode)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set fail mode: %v, output: %s", err, output)
	}
	return nil
}

func setBridgeExternalID(name, key, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "set", "bridge", name,
		fmt.Sprintf("external-ids:%s=%s", key, value))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set external ID: %v, output: %s", err, output)
	}
	return nil
}

func getBridgeExternalID(name, key string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "get", "bridge", name,
		fmt.Sprintf("external-ids:%s", key))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get external ID: %v, output: %s", err, output)
	}
	return strings.TrimSpace(strings.Trim(string(output), "\"")), nil
}

func listBridges() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := boundedexec.CommandContext(ctx, "ovs-vsctl", "list-br")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list bridges: %v, output: %s", err, output)
	}

	bridges := []string{}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line != "" {
			bridges = append(bridges, line)
		}
	}
	return bridges, nil
}

func cleanupBridge(t *testing.T, name string) {
	exists, err := bridgeExists(name)
	if err != nil {
		t.Logf("Warning: failed to check if bridge exists during cleanup: %v", err)
		return
	}
	if exists {
		if err := deleteBridge(name); err != nil {
			t.Logf("Warning: failed to cleanup bridge %s: %v", name, err)
		}
	}
}
