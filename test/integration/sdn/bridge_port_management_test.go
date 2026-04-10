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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// TestBridgeManagement tests OVS bridge creation, configuration, and deletion
func TestBridgeManagement(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to OVSDB: %v", err)
	}

	t.Run("CreateProvisioningBridge", func(t *testing.T) {
		bridgeName := "br-prov-test"
		defer client.DeleteBridge(ctx, bridgeName)

		bridge, err := client.CreateBridge(ctx, bridgeName)
		require.NoError(t, err)
		assert.Equal(t, bridgeName, bridge.Name)
		assert.NotEmpty(t, bridge.UUID)

		// Verify bridge exists
		retrieved, err := client.GetBridge(ctx, bridgeName)
		require.NoError(t, err)
		assert.Equal(t, bridge.UUID, retrieved.UUID)
		assert.Equal(t, bridge.Name, retrieved.Name)
	})

	t.Run("CreateProductionBridge", func(t *testing.T) {
		bridgeName := "br-prod-test"
		defer client.DeleteBridge(ctx, bridgeName)

		bridge, err := client.CreateBridge(ctx, bridgeName)
		require.NoError(t, err)
		assert.Equal(t, bridgeName, bridge.Name)

		// Configure for production use
		err = client.SetBridgeProtocols(ctx, bridgeName, []string{"OpenFlow13"})
		require.NoError(t, err)

		err = client.SetBridgeFailMode(ctx, bridgeName, "secure")
		require.NoError(t, err)

		// Verify configuration
		retrieved, err := client.GetBridge(ctx, bridgeName)
		require.NoError(t, err)
		assert.Equal(t, "secure", retrieved.FailMode)
		assert.Contains(t, retrieved.FlowProtocols, "OpenFlow13")
	})

	t.Run("ListBridges", func(t *testing.T) {
		// Create multiple bridges
		bridge1 := "br-list-test-1"
		bridge2 := "br-list-test-2"

		_, err := client.CreateBridge(ctx, bridge1)
		require.NoError(t, err)
		defer client.DeleteBridge(ctx, bridge1)

		_, err = client.CreateBridge(ctx, bridge2)
		require.NoError(t, err)
		defer client.DeleteBridge(ctx, bridge2)

		// List all bridges
		bridges, err := client.ListBridges(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, bridges)

		// Verify our bridges are in the list
		foundBridge1 := false
		foundBridge2 := false
		for _, br := range bridges {
			if br.Name == bridge1 {
				foundBridge1 = true
			}
			if br.Name == bridge2 {
				foundBridge2 = true
			}
		}

		assert.True(t, foundBridge1, "Bridge 1 should be in list")
		assert.True(t, foundBridge2, "Bridge 2 should be in list")
	})

	t.Run("DeleteBridge", func(t *testing.T) {
		bridgeName := "br-delete-test"

		_, err := client.CreateBridge(ctx, bridgeName)
		require.NoError(t, err)

		// Verify it exists
		_, err = client.GetBridge(ctx, bridgeName)
		require.NoError(t, err)

		// Delete it
		err = client.DeleteBridge(ctx, bridgeName)
		require.NoError(t, err)

		// Verify it's gone
		_, err = client.GetBridge(ctx, bridgeName)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ovs.ErrBridgeNotFound)
	})
}

// TestPortManagement tests port creation, configuration, and VLAN tagging
func TestPortManagement(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to OVSDB: %v", err)
	}

	// Setup test bridge
	bridgeName := "br-port-test"
	defer client.DeleteBridge(ctx, bridgeName)

	_, err = client.CreateBridge(ctx, bridgeName)
	require.NoError(t, err)

	t.Run("AddPort", func(t *testing.T) {
		portName := "test-port-1"

		port, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		assert.Equal(t, portName, port.Name)
		assert.NotEmpty(t, port.UUID)
		assert.NotEmpty(t, port.Interfaces)

		// Verify port exists
		retrieved, err := client.GetPort(ctx, portName)
		require.NoError(t, err)
		assert.Equal(t, port.UUID, retrieved.UUID)
	})

	t.Run("SetPortVLAN", func(t *testing.T) {
		portName := "test-port-vlan"
		vlanTag := int64(100)

		port, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		// Initially no VLAN tag
		assert.Equal(t, int64(0), port.Tag)

		// Set VLAN tag
		err = client.SetPortVLAN(ctx, portName, vlanTag)
		require.NoError(t, err)

		// Verify VLAN tag was set
		updated, err := client.GetPort(ctx, portName)
		require.NoError(t, err)
		assert.Equal(t, vlanTag, updated.Tag)
	})

	t.Run("SetPortVLANMultipleTimes", func(t *testing.T) {
		portName := "pt-vlan-multi" // Max 15 chars for Linux interface names

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		// Test multiple VLAN changes
		vlans := []int64{100, 200, 300}
		for _, vlan := range vlans {
			err = client.SetPortVLAN(ctx, portName, vlan)
			require.NoError(t, err)

			port, err := client.GetPort(ctx, portName)
			require.NoError(t, err)
			assert.Equal(t, vlan, port.Tag)
		}
	})

	t.Run("SetPortTrunks", func(t *testing.T) {
		portName := "test-port-trunk"

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		// Set trunk VLANs
		trunks := []int64{100, 200, 300}
		err = client.SetPortTrunks(ctx, portName, trunks)
		require.NoError(t, err)

		// Verify trunks were set
		port, err := client.GetPort(ctx, portName)
		require.NoError(t, err)
		assert.ElementsMatch(t, trunks, port.Trunks)
	})

	t.Run("ListPorts", func(t *testing.T) {
		// Create multiple ports
		port1 := "test-port-list-1"
		port2 := "test-port-list-2"

		_, err := client.AddPort(ctx, bridgeName, port1)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, port1)

		_, err = client.AddPort(ctx, bridgeName, port2)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, port2)

		// List ports
		ports, err := client.ListPorts(ctx, bridgeName)
		require.NoError(t, err)
		assert.NotEmpty(t, ports)

		// Verify our ports are in the list
		foundPort1 := false
		foundPort2 := false
		for _, p := range ports {
			if p.Name == port1 {
				foundPort1 = true
			}
			if p.Name == port2 {
				foundPort2 = true
			}
		}

		assert.True(t, foundPort1, "Port 1 should be in list")
		assert.True(t, foundPort2, "Port 2 should be in list")
	})

	t.Run("DeletePort", func(t *testing.T) {
		portName := "pt-delete" // Max 15 chars for Linux interface names

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)

		// Verify it exists
		_, err = client.GetPort(ctx, portName)
		require.NoError(t, err)

		// Delete it
		err = client.DeletePort(ctx, bridgeName, portName)
		require.NoError(t, err)

		// Verify it's gone
		_, err = client.GetPort(ctx, portName)
		assert.Error(t, err)
	})
}

// TestPortStateManagement tests port state transitions
func TestPortStateManagement(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to OVSDB: %v", err)
	}

	bridgeName := "br-state-test"
	defer client.DeleteBridge(ctx, bridgeName)

	_, err = client.CreateBridge(ctx, bridgeName)
	require.NoError(t, err)

	t.Run("SetPortStateUp", func(t *testing.T) {
		portName := "test-port-up"

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		// Set state to up
		err = client.SetPortState(ctx, portName, ovs.PortStateUp)
		require.NoError(t, err)

		// Verify interface state
		iface, err := client.GetInterface(ctx, portName)
		require.NoError(t, err)
		assert.Equal(t, "up", iface.AdminState)
	})

	t.Run("SetPortStateDown", func(t *testing.T) {
		portName := "test-port-down"

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		// Set state to down
		err = client.SetPortState(ctx, portName, ovs.PortStateDown)
		require.NoError(t, err)

		// Verify interface state
		iface, err := client.GetInterface(ctx, portName)
		require.NoError(t, err)
		assert.Equal(t, "down", iface.AdminState)
	})

	t.Run("TogglePortState", func(t *testing.T) {
		portName := "pt-toggle" // Max 15 chars for Linux interface names

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		// Test state transitions
		states := []ovs.PortState{ovs.PortStateUp, ovs.PortStateDown, ovs.PortStateUp}
		expectedStates := []string{"up", "down", "up"}

		for i, state := range states {
			err = client.SetPortState(ctx, portName, state)
			require.NoError(t, err)

			iface, err := client.GetInterface(ctx, portName)
			require.NoError(t, err)
			assert.Equal(t, expectedStates[i], iface.AdminState)
		}
	})
}

// TestVLANConfiguration tests VLAN configuration scenarios
func TestVLANConfiguration(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to OVSDB: %v", err)
	}

	bridgeName := "br-vlan-test"
	defer client.DeleteBridge(ctx, bridgeName)

	_, err = client.CreateBridge(ctx, bridgeName)
	require.NoError(t, err)

	t.Run("ProvisioningVLAN", func(t *testing.T) {
		portName := "test-prov-vlan"
		provisioningVLAN := int64(100)

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		err = client.SetPortVLAN(ctx, portName, provisioningVLAN)
		require.NoError(t, err)

		port, err := client.GetPort(ctx, portName)
		require.NoError(t, err)
		assert.Equal(t, provisioningVLAN, port.Tag)
	})

	t.Run("ProductionVLAN", func(t *testing.T) {
		portName := "test-prod-vlan"
		productionVLAN := int64(200)

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		err = client.SetPortVLAN(ctx, portName, productionVLAN)
		require.NoError(t, err)

		port, err := client.GetPort(ctx, portName)
		require.NoError(t, err)
		assert.Equal(t, productionVLAN, port.Tag)
	})

	t.Run("QuarantineVLAN", func(t *testing.T) {
		portName := "test-quar-vlan"
		quarantineVLAN := int64(999)

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		err = client.SetPortVLAN(ctx, portName, quarantineVLAN)
		require.NoError(t, err)

		port, err := client.GetPort(ctx, portName)
		require.NoError(t, err)
		assert.Equal(t, quarantineVLAN, port.Tag)
	})

	t.Run("VLANTransitionScenario", func(t *testing.T) {
		portName := "pt-vlan-trans" // Max 15 chars for Linux interface names

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		// Simulate device lifecycle VLAN transitions
		phases := []struct {
			name string
			vlan int64
		}{
			{"provisioning", 100},
			{"production", 200},
			{"quarantine", 999},
			{"production-restored", 200},
		}

		for _, phase := range phases {
			t.Run(phase.name, func(t *testing.T) {
				err = client.SetPortVLAN(ctx, portName, phase.vlan)
				require.NoError(t, err)

				port, err := client.GetPort(ctx, portName)
				require.NoError(t, err)
				assert.Equal(t, phase.vlan, port.Tag)
			})
		}
	})

	t.Run("InvalidVLANRange", func(t *testing.T) {
		portName := "pt-inv-vlan" // Max 15 chars for Linux interface names

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		// Test invalid VLAN IDs
		invalidVLANs := []int64{-1, 4096, 5000}
		for _, vlan := range invalidVLANs {
			err = client.SetPortVLAN(ctx, portName, vlan)
			assert.Error(t, err, "VLAN %d should be invalid", vlan)
		}
	})

	t.Run("ClearVLAN", func(t *testing.T) {
		portName := "test-clear-vlan"

		_, err := client.AddPort(ctx, bridgeName, portName)
		require.NoError(t, err)
		defer client.DeletePort(ctx, bridgeName, portName)

		// Set VLAN
		err = client.SetPortVLAN(ctx, portName, 100)
		require.NoError(t, err)

		// Clear VLAN (set to 0)
		err = client.SetPortVLAN(ctx, portName, 0)
		require.NoError(t, err)

		port, err := client.GetPort(ctx, portName)
		require.NoError(t, err)
		assert.Equal(t, int64(0), port.Tag)
	})
}
