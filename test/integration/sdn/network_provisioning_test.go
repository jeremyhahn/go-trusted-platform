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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

const (
	ovsSocketDir       = "/var/run/openvswitch"
	socketWaitTimeout  = 10 * time.Second
	socketCheckTimeout = 500 * time.Millisecond
)

// TestNetworkProvisioningFlow tests the complete network provisioning flow
// from device enrollment through production network access
func TestNetworkProvisioningFlow(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create OVS client
	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Fatal(missing("a connection to OVSDB", err))
	}

	// Create test bridges
	provBridge := "br-prov"
	prodBridge := "br-prod"

	// Cleanup before test
	cleanupBridges(t, ctx, client, provBridge, prodBridge)
	defer cleanupBridges(t, ctx, client, provBridge, prodBridge)

	// Create device profile with network phases
	profile := createTestDeviceProfile()

	t.Run("CreateProvisioningBridge", func(t *testing.T) {
		// Create bridge via ovs-vsctl which properly creates management socket
		createBridgeViaOVS(t, provBridge)

		// Verify bridge exists via our Go client
		bridge, err := client.GetBridge(ctx, provBridge)
		require.NoError(t, err)
		assert.Equal(t, provBridge, bridge.Name)

		// Configure bridge for OpenFlow 1.3
		configureBridgeForOpenFlow(t, provBridge, "OpenFlow13", "secure")
	})

	t.Run("CreateProductionBridge", func(t *testing.T) {
		// Create bridge via ovs-vsctl which properly creates management socket
		createBridgeViaOVS(t, prodBridge)

		// Verify bridge exists via our Go client
		bridge, err := client.GetBridge(ctx, prodBridge)
		require.NoError(t, err)
		assert.Equal(t, prodBridge, bridge.Name)

		// Configure bridge for OpenFlow 1.3
		configureBridgeForOpenFlow(t, prodBridge, "OpenFlow13", "secure")
	})

	portName := "test-port1"
	var portOFPort int32

	t.Run("CreatePortOnProvisioningBridge", func(t *testing.T) {
		// Use ovs-vsctl for port operations (more reliable than OVSDB)
		addPortViaOVS(t, provBridge, portName)

		// Get the OpenFlow port number
		portOFPort = getOFPortViaOVS(t, portName)

		// Set VLAN for provisioning phase
		if profile.Networks[entities.DefaultEnrollmentNetwork] != nil {
			setPortVLANViaOVS(t, portName, profile.Networks[entities.DefaultEnrollmentNetwork].VLAN)

			// Verify VLAN was set
			tag := getPortVLANViaOVS(t, portName)
			assert.Equal(t, int64(profile.Networks[entities.DefaultEnrollmentNetwork].VLAN), tag)
		}
	})

	t.Run("ApplyProvisioningPhaseFlows", func(t *testing.T) {
		// Install OpenFlow rules for provisioning phase
		// Allow DHCP, DNS, and enrollment traffic only
		portStr := fmt.Sprintf("%d", portOFPort)
		flows := []struct {
			priority int
			match    string
			actions  string
		}{
			{
				priority: 1000,
				match:    "in_port=" + portStr + ",dl_type=0x0800,nw_proto=17,tp_dst=67",
				actions:  "NORMAL",
			},
			{
				priority: 1000,
				match:    "in_port=" + portStr + ",dl_type=0x0800,nw_proto=17,tp_dst=68",
				actions:  "NORMAL",
			},
			{
				priority: 1000,
				match:    "in_port=" + portStr + ",dl_type=0x0800,nw_proto=17,tp_dst=53",
				actions:  "NORMAL",
			},
			{
				priority: 1000,
				match:    "in_port=" + portStr + ",dl_type=0x0800,nw_proto=6,tp_dst=443",
				actions:  "NORMAL",
			},
			{
				priority: 100,
				match:    "in_port=" + portStr,
				actions:  "drop",
			},
		}

		for _, flow := range flows {
			flowMod := &ovs.FlowMod{
				Table:    0,
				Priority: flow.priority,
				Match:    flow.match,
				Actions:  flow.actions,
			}

			err := client.AddFlow(ctx, provBridge, flowMod)
			require.NoError(t, err)
		}

		// Verify flows were installed
		installedFlows, err := client.ListFlows(ctx, provBridge)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(installedFlows), len(flows))
	})

	t.Run("TransitionToProductionNetwork", func(t *testing.T) {
		// Remove port from provisioning bridge
		deletePortViaOVS(t, provBridge, portName)

		// Add port to production bridge
		addPortViaOVS(t, prodBridge, portName)

		// Set production VLAN
		if profile.Networks[entities.DefaultPostEnrollmentNetwork] != nil {
			setPortVLANViaOVS(t, portName, profile.Networks[entities.DefaultPostEnrollmentNetwork].VLAN)

			// Verify VLAN was changed
			tag := getPortVLANViaOVS(t, portName)
			assert.Equal(t, int64(profile.Networks[entities.DefaultPostEnrollmentNetwork].VLAN), tag)
		}
	})

	t.Run("ApplyProductionPhaseACLs", func(t *testing.T) {
		if profile.Networks[entities.DefaultPostEnrollmentNetwork] == nil || len(profile.Networks[entities.DefaultPostEnrollmentNetwork].ACLs) == 0 {
			t.Fatal("the createTestDeviceProfile fixture defines no post-enrollment ACLs")
		}

		// Get the new OpenFlow port number (may have changed after moving to production bridge)
		prodPortOFPort := getOFPortViaOVS(t, portName)

		for _, acl := range profile.Networks[entities.DefaultPostEnrollmentNetwork].ACLs {
			flowMod := convertACLToFlowMod(prodPortOFPort, acl)
			err := client.AddFlow(ctx, prodBridge, flowMod)
			require.NoError(t, err)
		}

		// Verify ACL flows were installed
		installedFlows, err := client.ListFlows(ctx, prodBridge)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(installedFlows), len(profile.Networks[entities.DefaultPostEnrollmentNetwork].ACLs))
	})

	t.Run("TransitionToQuarantineOnFailure", func(t *testing.T) {
		// Simulate policy violation - transition to quarantine
		deletePortViaOVS(t, prodBridge, portName)

		addPortViaOVS(t, provBridge, portName)

		// Get the new OpenFlow port number
		quarantinePortOFPort := getOFPortViaOVS(t, portName)

		// Set quarantine VLAN
		if profile.Networks[entities.DefaultFailureNetwork] != nil {
			setPortVLANViaOVS(t, portName, profile.Networks[entities.DefaultFailureNetwork].VLAN)

			// Verify quarantine VLAN
			tag := getPortVLANViaOVS(t, portName)
			assert.Equal(t, int64(profile.Networks[entities.DefaultFailureNetwork].VLAN), tag)
		}

		// Apply quarantine flows - very restrictive
		flowMod := &ovs.FlowMod{
			Table:    0,
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%d", quarantinePortOFPort),
			Actions:  "drop",
		}

		err := client.AddFlow(ctx, provBridge, flowMod)
		require.NoError(t, err)
	})
}

// TestDeviceProfileToNetworkConfig tests the translation of device profiles
// to network configurations and OpenFlow rules
func TestDeviceProfileToNetworkConfig(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Fatal(missing("a connection to OVSDB", err))
	}

	bridgeName := "br-test-profile"
	cleanupBridges(t, ctx, client, bridgeName)
	defer cleanupBridges(t, ctx, client, bridgeName)

	// Create test bridge via ovs-vsctl which properly creates management socket
	createBridgeViaOVS(t, bridgeName)

	// Configure bridge for OpenFlow 1.3
	configureBridgeForOpenFlow(t, bridgeName, "OpenFlow13", "secure")

	profile := createTestDeviceProfile()

	t.Run("TranslateProvisioningNetworkConfig", func(t *testing.T) {
		if profile.Networks[entities.DefaultEnrollmentNetwork] == nil {
			t.Fatal("the createTestDeviceProfile fixture defines no enrollment network")
		}

		config := profile.Networks[entities.DefaultEnrollmentNetwork]
		assert.NotZero(t, config.VLAN)
		assert.Equal(t, entities.AuthMethodNone, config.AuthMethod)

		// Verify ACLs are present
		assert.NotEmpty(t, config.ACLs)

		// Verify ACLs are valid
		for _, acl := range config.ACLs {
			assert.True(t, acl.IsValid(), "ACL should be valid")
			assert.NotEmpty(t, acl.Protocol)
			assert.NotEmpty(t, acl.Action)
		}
	})

	t.Run("TranslateProductionNetworkConfig", func(t *testing.T) {
		if profile.Networks[entities.DefaultPostEnrollmentNetwork] == nil {
			t.Fatal("the createTestDeviceProfile fixture defines no post-enrollment network")
		}

		config := profile.Networks[entities.DefaultPostEnrollmentNetwork]
		assert.NotZero(t, config.VLAN)

		// Production should have more permissive ACLs
		assert.NotEmpty(t, config.ACLs)

		// Verify DHCP pool if configured
		if config.DHCPPool != nil {
			assert.NotEmpty(t, config.DHCPPool.Network)
			assert.NotEmpty(t, config.DHCPPool.RangeStart)
			assert.NotEmpty(t, config.DHCPPool.RangeEnd)
			assert.Greater(t, config.DHCPPool.LeaseTime, 0)
		}
	})

	t.Run("ApplyACLRulesAsOpenFlowEntries", func(t *testing.T) {
		if profile.Networks[entities.DefaultPostEnrollmentNetwork] == nil {
			t.Fatal("the createTestDeviceProfile fixture defines no post-enrollment network")
		}

		portName := "test-acl-port"
		addPortViaOVS(t, bridgeName, portName)
		defer deletePortViaOVS(t, bridgeName, portName)

		// Get the OpenFlow port number
		ofport := getOFPortViaOVS(t, portName)

		// Apply each ACL as an OpenFlow rule
		for i, acl := range profile.Networks[entities.DefaultPostEnrollmentNetwork].ACLs {
			flowMod := convertACLToFlowMod(ofport, acl)
			if i > 0 {
				flowMod.Cookie = fmt.Sprintf("0x%x", 0x1000+i)
			}

			err := client.AddFlow(ctx, bridgeName, flowMod)
			require.NoError(t, err)
		}

		// Verify flows were installed
		flows, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(flows), len(profile.Networks[entities.DefaultPostEnrollmentNetwork].ACLs))
	})

	t.Run("VLANAssignmentPerPhase", func(t *testing.T) {
		portName := "test-vlan-port"
		addPortViaOVS(t, bridgeName, portName)
		defer deletePortViaOVS(t, bridgeName, portName)

		// Test each phase's VLAN
		phases := []struct {
			name   string
			config *entities.NetworkPhaseConfig
		}{
			{"provisioning", profile.Networks[entities.DefaultEnrollmentNetwork]},
			{"production", profile.Networks[entities.DefaultPostEnrollmentNetwork]},
			{"quarantine", profile.Networks[entities.DefaultFailureNetwork]},
		}

		for _, phase := range phases {
			if phase.config == nil {
				continue
			}

			t.Run(phase.name, func(t *testing.T) {
				// Set VLAN
				setPortVLANViaOVS(t, portName, phase.config.VLAN)

				// Verify VLAN
				tag := getPortVLANViaOVS(t, portName)
				assert.Equal(t, int64(phase.config.VLAN), tag,
					"VLAN mismatch for %s phase", phase.name)
			})
		}
	})
}

// Helper functions

func cleanupBridges(t *testing.T, ctx context.Context, client *ovs.Client, bridges ...string) {
	for _, bridge := range bridges {
		// Use ovs-vsctl for reliable cleanup
		exec.CommandContext(ctx, "ovs-vsctl", "--if-exists", "del-br", bridge).Run()
	}
}

// createBridgeViaOVS creates a bridge using ovs-vsctl which properly waits for
// ovs-vswitchd to create the management socket. This is necessary because pure
// OVSDB transactions don't trigger socket creation reliably.
func createBridgeViaOVS(t *testing.T, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "add-br", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to create bridge %s via ovs-vsctl: %v, output: %s", name, err, output)
	}
}

// configureBridgeForOpenFlow sets OpenFlow protocol and fail_mode on a bridge
func configureBridgeForOpenFlow(t *testing.T, bridgeName string, protocol string, failMode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Set protocols
	cmd := exec.CommandContext(ctx, "ovs-vsctl", "set", "bridge", bridgeName,
		fmt.Sprintf("protocols=%s", protocol))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to set protocols on bridge %s: %v, output: %s", bridgeName, err, output)
	}

	// Set fail_mode
	cmd = exec.CommandContext(ctx, "ovs-vsctl", "set", "bridge", bridgeName,
		fmt.Sprintf("fail_mode=%s", failMode))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to set fail_mode on bridge %s: %v, output: %s", bridgeName, err, output)
	}
}

func createTestDeviceProfile() *entities.DeviceProfile {
	return &entities.DeviceProfile{
		ID:    1,
		Name:  "test-server-profile",
		Model: "test-model",
		Role:  entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:       100,
				AuthMethod: entities.AuthMethodNone,
				Gateway:    "10.0.100.1",
				DNS:        []string{"10.0.100.1"},
				ACLs: []entities.ACLConfig{
					{
						Priority: 1000,
						Protocol: "udp",
						SrcIP:    "any",
						DstIP:    "any",
						DstPort:  67, // DHCP
						Action:   "allow",
					},
					{
						Priority: 1000,
						Protocol: "udp",
						SrcIP:    "any",
						DstIP:    "any",
						DstPort:  68, // DHCP
						Action:   "allow",
					},
					{
						Priority: 1000,
						Protocol: "udp",
						SrcIP:    "any",
						DstIP:    "any",
						DstPort:  53, // DNS
						Action:   "allow",
					},
					{
						Priority: 1000,
						Protocol: "tcp",
						SrcIP:    "any",
						DstIP:    "any",
						DstPort:  443, // HTTPS for enrollment
						Action:   "allow",
					},
					{
						Priority: 100,
						Protocol: "any",
						SrcIP:    "any",
						DstIP:    "any",
						Action:   "deny",
					},
				},
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:       200,
				AuthMethod: entities.AuthMethod802_1X,
				Gateway:    "10.0.200.1",
				DNS:        []string{"10.0.200.1", "8.8.8.8"},
				DHCPPool: &entities.DHCPPoolConfig{
					Network:    "10.0.200.0/24",
					RangeStart: "10.0.200.100",
					RangeEnd:   "10.0.200.200",
					LeaseTime:  3600,
				},
				ACLs: []entities.ACLConfig{
					{
						Priority: 1000,
						Protocol: "tcp",
						SrcIP:    "any",
						DstIP:    "any",
						DstPort:  80,
						Action:   "allow",
					},
					{
						Priority: 1000,
						Protocol: "tcp",
						SrcIP:    "any",
						DstIP:    "any",
						DstPort:  443,
						Action:   "allow",
					},
					{
						Priority: 900,
						Protocol: "tcp",
						SrcIP:    "any",
						DstIP:    "10.0.200.0/24",
						DstPort:  22,
						Action:   "allow",
					},
					{
						Priority: 500,
						Protocol: "any",
						SrcIP:    "any",
						DstIP:    "any",
						Action:   "allow",
					},
				},
			},
			entities.DefaultFailureNetwork: {
				VLAN:       999,
				AuthMethod: entities.AuthMethodNone,
				Gateway:    "10.0.999.1",
				DNS:        []string{"10.0.999.1"},
				ACLs: []entities.ACLConfig{
					{
						Priority: 1000,
						Protocol: "any",
						SrcIP:    "any",
						DstIP:    "any",
						Action:   "deny",
					},
				},
			},
		},
	}
}

// waitForBridgeSocket waits for the OpenFlow management socket to become available.
// This is needed because OVS takes time to create the .mgmt socket after bridge creation.
func waitForBridgeSocket(t *testing.T, bridgeName string) {
	t.Helper()

	socketPath := filepath.Join(ovsSocketDir, bridgeName+".mgmt")
	available := func() bool {
		if _, err := os.Stat(socketPath); err != nil {
			return false
		}
		return checkOpenFlowAvailable(bridgeName)
	}
	condition := "OpenFlow socket for bridge " + bridgeName
	if err := testenv.WaitUntil(t.Context(), socketWaitTimeout, condition, available); err != nil {
		t.Fatalf("%v", err)
	}
}

// checkOpenFlowAvailable checks if we can actually connect to the OpenFlow socket
func checkOpenFlowAvailable(bridgeName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), socketCheckTimeout)
	defer cancel()

	client, err := openflow.NewClient(
		bridgeName,
		openflow.WithSocketDir(ovsSocketDir),
		openflow.WithTimeout(socketCheckTimeout),
	)
	if err != nil {
		return false
	}

	err = client.Connect(ctx)
	if err != nil {
		return false
	}

	// Successfully connected, clean up
	client.Disconnect()
	return true
}

// addPortViaOVS adds a port to a bridge using ovs-vsctl (more reliable than OVSDB for internal ports)
func addPortViaOVS(t *testing.T, bridgeName, portName string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "add-port", bridgeName, portName, "--", "set", "interface", portName, "type=internal")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to add port %s to %s: %s", portName, bridgeName, output)

	// Wait for OVS to create the internal port interface in the kernel and bring it up
	output, linkUpErr := bringInternalPortUp(ctx, portName)
	require.NoError(t, linkUpErr, "Failed to bring up interface %s after retries: %s", portName, output)
}

// deletePortViaOVS removes a port from a bridge using ovs-vsctl
func deletePortViaOVS(t *testing.T, bridgeName, portName string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "--if-exists", "del-port", bridgeName, portName)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to delete port %s from %s: %s", portName, bridgeName, output)
}

// getOFPortViaOVS gets the OpenFlow port number for a port using ovs-vsctl
func getOFPortViaOVS(t *testing.T, portName string) int32 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Wait for OVS to assign the ofport
	var ofport int32
	assigned := func() bool {
		cmd := exec.CommandContext(ctx, "ovs-vsctl", "get", "interface", portName, "ofport")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to get ofport for %s: %s", portName, output)

		_, err = fmt.Sscanf(string(output), "%d", &ofport)
		require.NoError(t, err, "Failed to parse ofport from: %s", output)

		return ofport > 0
	}
	if err := testenv.WaitUntil(ctx, ofportTimeout, "ofport for "+portName, assigned); err != nil {
		t.Logf("%v", err)
	}
	require.Greater(t, ofport, int32(0), "OpenFlow port number should be positive")

	return ofport
}

// setPortVLANViaOVS sets the VLAN tag on a port using ovs-vsctl
func setPortVLANViaOVS(t *testing.T, portName string, vlan uint16) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "set", "port", portName, fmt.Sprintf("tag=%d", vlan))
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to set VLAN %d on port %s: %s", vlan, portName, output)
}

// getPortVLANViaOVS gets the VLAN tag on a port using ovs-vsctl
func getPortVLANViaOVS(t *testing.T, portName string) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ovs-vsctl", "get", "port", portName, "tag")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to get VLAN for %s: %s", portName, output)

	var tag int64
	_, err = fmt.Sscanf(string(output), "%d", &tag)
	if err != nil {
		// VLAN not set (empty set [])
		return 0
	}
	return tag
}

func convertACLToFlowMod(ofport int32, acl entities.ACLConfig) *ovs.FlowMod {
	matchParts := []string{fmt.Sprintf("in_port=%d", ofport)}

	// Build match based on ACL
	if acl.Protocol != "any" {
		switch acl.Protocol {
		case "tcp":
			matchParts = append(matchParts, "dl_type=0x0800", "nw_proto=6")
		case "udp":
			matchParts = append(matchParts, "dl_type=0x0800", "nw_proto=17")
		case "icmp":
			matchParts = append(matchParts, "dl_type=0x0800", "nw_proto=1")
		}
	}

	if acl.SrcIP != "" && acl.SrcIP != "any" {
		matchParts = append(matchParts, "nw_src="+acl.SrcIP)
	}

	if acl.DstIP != "" && acl.DstIP != "any" {
		matchParts = append(matchParts, "nw_dst="+acl.DstIP)
	}

	if acl.DstPort > 0 {
		matchParts = append(matchParts, "tp_dst="+strconv.Itoa(int(acl.DstPort)))
	}

	if acl.SrcPort > 0 {
		matchParts = append(matchParts, "tp_src="+strconv.Itoa(int(acl.SrcPort)))
	}

	// Build actions based on ACL action
	actions := "drop"
	if acl.Action == "allow" {
		actions = "NORMAL"
	}

	match := ""
	for i, part := range matchParts {
		if i > 0 {
			match += ","
		}
		match += part
	}

	return &ovs.FlowMod{
		Table:    0,
		Priority: acl.Priority,
		Match:    match,
		Actions:  actions,
	}
}
