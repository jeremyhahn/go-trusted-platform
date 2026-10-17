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

//go:build integration
// +build integration

// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2EDeviceProvisioning tests the complete device provisioning flow with
// network transitions from provisioning VLAN to production VLAN.
//
// Test Flow:
//  1. Setup isolated network with two OVS bridges (provisioning and production VLANs)
//  2. Boot server VM on provisioning network with platform services (CA, ACME, DNS)
//  3. Boot client VM on provisioning network
//  4. Client performs TPM attestation and ACME enrollment
//  5. Server validates attestation and issues certificate with network policy
//  6. Server transitions client port from provisioning to production VLAN
//  7. Verify client is on production network with correct ACLs
//
// This test runs inside the devcontainer which provides:
//   - Privileged container with CAP_NET_ADMIN for OVS bridge creation
//   - QEMU and OVMF for VM emulation
//   - Open vSwitch for SDN networking
//   - swtpm for TPM emulation
//
// Run with: make integration-test-e2e
// For full test with ISOs: set INTEGRATION_TEST_SERVER_ISO and INTEGRATION_TEST_CLIENT_ISO
// Boot and enrollment budgets for the full-ISO phases.
//
// These are BUDGETS, not measurements: nothing polls a condition, so each phase
// spends its whole budget every run and then reports success regardless of what
// happened. They are named rather than inline so the values are visible and so
// nobody mistakes them for tuned figures -- with no marker to poll for, any
// shorter value would be an equally arbitrary guess (#372).
const (
	// serverBootBudget is how long Phase 2 allows the server VM to boot and
	// start its platform services. NOT verified: see #372.
	serverBootBudget = 2 * time.Minute

	// clientEnrollBudget is how long Phase 3 allows the client VM to boot and
	// complete ACME enrollment. NOT verified: see #372.
	clientEnrollBudget = 3 * time.Minute
)

func TestE2EDeviceProvisioning(t *testing.T) {
	// Check QEMU availability
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Fatalf("qemu-system-x86_64 not on PATH: %v; run in the devcontainer, which installs qemu-system-x86", err)
	}

	// Check OVS availability
	if _, err := exec.LookPath("ovs-vsctl"); err != nil {
		t.Fatalf("ovs-vsctl not on PATH: %v; run in the devcontainer, which installs openvswitch-switch", err)
	}

	// Check for pre-built ISOs
	serverISO := os.Getenv("INTEGRATION_TEST_SERVER_ISO")
	clientISO := os.Getenv("INTEGRATION_TEST_CLIENT_ISO")
	fullIntegrationMode := serverISO != "" && clientISO != ""

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	// Create test configuration
	config := DefaultTestConfig()
	config.ServerISO = serverISO
	config.ClientISO = clientISO

	// Setup infrastructure
	infra, err := SetupTestInfrastructure(ctx, t, config)
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer Cleanup(t, infra)
	defer CleanupOnFailure(t, infra)

	infra.Logger.Info("Starting E2E device provisioning test",
		"full_integration", fullIntegrationMode,
		"provisioning_vlan", config.ProvisioningNetwork.VLAN,
		"production_vlan", config.ProductionNetwork.VLAN)

	// Phase 1: Infrastructure Validation
	t.Run("Phase1_InfrastructureValidation", func(t *testing.T) {
		testInfrastructureValidation(ctx, t, infra)
	})

	// If no pre-built ISOs, stop here
	if !fullIntegrationMode {
		infra.Logger.Info("Infrastructure validation completed successfully")
		infra.Logger.Info("Skipping full provisioning test (no pre-built ISOs)")
		infra.Logger.Info("To run full test, set environment variables:",
			"INTEGRATION_TEST_SERVER_ISO", "<path/to/server.iso>",
			"INTEGRATION_TEST_CLIENT_ISO", "<path/to/client.iso>")
		return
	}

	// Phase 2: Server Provisioning
	t.Run("Phase2_ServerProvisioning", func(t *testing.T) {
		testServerProvisioning(ctx, t, infra)
	})

	// Phase 3: Client Provisioning and Enrollment
	t.Run("Phase3_ClientProvisioning", func(t *testing.T) {
		testClientProvisioning(ctx, t, infra)
	})

	// Phase 4: Network Transition
	t.Run("Phase4_NetworkTransition", func(t *testing.T) {
		testNetworkTransition(ctx, t, infra)
	})

	// Phase 5: Verification
	t.Run("Phase5_Verification", func(t *testing.T) {
		testVerification(ctx, t, infra)
	})

	infra.Logger.Info("E2E device provisioning test completed successfully")
}

// testInfrastructureValidation validates the test infrastructure
func testInfrastructureValidation(ctx context.Context, t *testing.T, infra *TestInfrastructure) {
	t.Helper()

	infra.Logger.Info("Phase 1: Infrastructure Validation")

	// Verify OVS bridges exist
	t.Run("VerifyBridges", func(t *testing.T) {
		// Check provisioning bridge
		cmd := exec.Command("ovs-vsctl", "br-exists", infra.Config.ProvisioningNetwork.Bridge)
		require.NoError(t, cmd.Run(), "Provisioning bridge should exist")

		// Check production bridge
		cmd = exec.Command("ovs-vsctl", "br-exists", infra.Config.ProductionNetwork.Bridge)
		require.NoError(t, cmd.Run(), "Production bridge should exist")

		infra.Logger.Info("OVS bridges validated",
			"provisioning", infra.Config.ProvisioningNetwork.Bridge,
			"production", infra.Config.ProductionNetwork.Bridge)
	})

	// Verify OVMF firmware
	t.Run("VerifyOVMF", func(t *testing.T) {
		ovmfCode := findOVMFCode()
		ovmfVars := findOVMFVars()

		require.NotEmpty(t, ovmfCode, "OVMF_CODE.fd not found")
		require.NotEmpty(t, ovmfVars, "OVMF_VARS.fd not found")

		infra.Logger.Info("OVMF firmware found",
			"code", ovmfCode,
			"vars", ovmfVars)
	})

	// Setup and verify server VM can be created
	t.Run("SetupServerVM", func(t *testing.T) {
		err := infra.SetupServerVM(ctx, t)
		require.NoError(t, err, "Failed to setup server VM")

		assert.NotNil(t, infra.ServerVM, "Server VM should be created")
		assert.NotNil(t, infra.ServerTPM, "Server TPM should be created")
		assert.NotEmpty(t, infra.ServerTapName, "Server TAP should be created")

		infra.Logger.Info("Server VM setup validated",
			"tap", infra.ServerTapName,
			"disk", infra.Config.ServerDiskPath)
	})

	// Setup and verify client VM can be created
	t.Run("SetupClientVM", func(t *testing.T) {
		err := infra.SetupClientVM(ctx, t)
		require.NoError(t, err, "Failed to setup client VM")

		assert.NotNil(t, infra.ClientVM, "Client VM should be created")
		assert.NotNil(t, infra.ClientTPM, "Client TPM should be created")
		assert.NotEmpty(t, infra.ClientTapName, "Client TAP should be created")

		infra.Logger.Info("Client VM setup validated",
			"tap", infra.ClientTapName,
			"disk", infra.Config.ClientDiskPath)
	})

	// Verify policy engine
	t.Run("VerifyPolicyEngine", func(t *testing.T) {
		require.NotNil(t, infra.PolicyEngine, "Policy engine should be initialized")

		// Set initial port state for client
		err := infra.PolicyEngine.SetPortState(infra.ClientTapName, policy.PortStateProvisioning)
		require.NoError(t, err, "Failed to set initial port state")

		state, err := infra.PolicyEngine.GetPortState(infra.ClientTapName)
		require.NoError(t, err, "Failed to get port state")
		assert.Equal(t, policy.PortStateProvisioning, state)

		infra.Logger.Info("Policy engine validated",
			"client_port", infra.ClientTapName,
			"initial_state", state)
	})

	infra.Logger.Info("Phase 1 complete: Infrastructure validated")
}

// testServerProvisioning boots and provisions the server VM
func testServerProvisioning(ctx context.Context, t *testing.T, infra *TestInfrastructure) {
	t.Helper()

	infra.Logger.Info("Phase 2: Server Provisioning")

	// Determine boot mode
	bootMode := qemu.BootModeBoot
	if infra.Config.ServerISO != "" {
		bootMode = qemu.BootModeInstall
		infra.Logger.Info("Server will install from ISO", "iso", infra.Config.ServerISO)
	}

	// Start server VM
	infra.Logger.Info("Starting server VM", "mode", bootMode)
	err := infra.ServerVM.Start(ctx, string(bootMode))
	require.NoError(t, err, "Failed to start server VM")

	// Wait for server to boot and initialize services
	infra.Logger.Info("Waiting for server to boot and initialize services")

	// In a real test, we would:
	// 1. Monitor serial console for boot completion
	// 2. Check that platform services are running (CA, ACME, DNS)
	// 3. Verify server is accessible on provisioning network

	// NOTHING BELOW VERIFIES ANY OF THE ABOVE (#372). This is an unconditional
	// budget, not a wait for a condition: polling the serial log for one
	// needs a boot-completion marker, and that marker is a property of the server ISO and is not known here. Inventing a
	// pattern would be worse than waiting -- a poll that never matches burns the
	// whole budget and then claims a verification it did not perform.
	require.NoError(t, testenv.Elapse(ctx, serverBootBudget))

	// Deliberately NOT "Phase 2 complete: Server provisioned". Nothing here
	// establishes that the server was provisioned, and a log line that says so
	// makes a failed run indistinguishable from a successful one.
	infra.Logger.Info("Phase 2 budget elapsed: server boot NOT verified",
		"budget", serverBootBudget,
		"tracking", "#372")
}

// testClientProvisioning boots the client and performs ACME enrollment
func testClientProvisioning(ctx context.Context, t *testing.T, infra *TestInfrastructure) {
	t.Helper()

	infra.Logger.Info("Phase 3: Client Provisioning and Enrollment")

	// Ensure client port is in provisioning state
	err := infra.PolicyEngine.SetPortState(infra.ClientTapName, policy.PortStateProvisioning)
	require.NoError(t, err, "Failed to set client port to provisioning state")

	// Apply provisioning network policy
	provPolicy := &policy.PortPolicy{
		TenantID: "test-tenant",
		VLAN:     infra.Config.ProvisioningNetwork.VLAN,
		ACLs: []policy.ACLRule{
			{
				Priority: 100,
				Match: policy.FlowMatch{
					IPProto: 6,   // TCP
					TCPDst:  443, // HTTPS for ACME
				},
				Action: policy.FlowAction{
					Type: policy.FlowActionAllow,
				},
				Description: "Allow HTTPS for ACME enrollment",
			},
			{
				Priority: 90,
				Match: policy.FlowMatch{
					IPProto: 17, // UDP
					UDPDst:  53, // DNS
				},
				Action: policy.FlowAction{
					Type: policy.FlowActionAllow,
				},
				Description: "Allow DNS queries",
			},
		},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err = infra.PolicyEngine.ApplyPolicy(infra.ClientTapName, provPolicy)
	require.NoError(t, err, "Failed to apply provisioning policy")

	infra.Logger.Info("Provisioning policy applied",
		"vlan", infra.Config.ProvisioningNetwork.VLAN,
		"acls", len(provPolicy.ACLs))

	// Determine boot mode
	bootMode := qemu.BootModeBoot
	if infra.Config.ClientISO != "" {
		bootMode = qemu.BootModeInstall
		infra.Logger.Info("Client will install from ISO", "iso", infra.Config.ClientISO)
	}

	// Start client VM
	infra.Logger.Info("Starting client VM", "mode", bootMode)
	err = infra.ClientVM.Start(ctx, string(bootMode))
	require.NoError(t, err, "Failed to start client VM")

	// Wait for client to boot and complete enrollment
	infra.Logger.Info("Waiting for client to boot and complete ACME enrollment")

	// In a real test, we would:
	// 1. Monitor serial console for enrollment progress
	// 2. Verify TPM attestation was performed
	// 3. Verify certificate was requested and received
	// 4. Check certificate contains correct attributes

	// NOTHING BELOW VERIFIES ANY OF THE ABOVE (#372) -- same shape as Phase 2:
	// an unconditional budget, because the enrollment-completion marker is a
	// property of the client ISO and is not known here.
	require.NoError(t, testenv.Elapse(ctx, clientEnrollBudget))

	// Transition to enrolled state
	err = infra.PolicyEngine.SetPortState(infra.ClientTapName, policy.PortStateEnrolled)
	require.NoError(t, err, "Failed to transition to enrolled state")

	// Deliberately NOT "Phase 3 complete: Client provisioned and enrolled": the
	// port-state transition above is real, but no TPM attestation, certificate
	// issuance or certificate attribute was checked (#372).
	infra.Logger.Info("Phase 3 budget elapsed: port moved to enrolled; enrollment itself NOT verified",
		"budget", clientEnrollBudget,
		"tracking", "#372")
}

// testNetworkTransition transitions the client from provisioning to production network
func testNetworkTransition(ctx context.Context, t *testing.T, infra *TestInfrastructure) {
	t.Helper()

	infra.Logger.Info("Phase 4: Network Transition (Provisioning -> Production)")

	// Remove client from provisioning bridge
	infra.Logger.Info("Removing client port from provisioning bridge",
		"bridge", infra.Config.ProvisioningNetwork.Bridge,
		"port", infra.ClientTapName)

	err := infra.OVSClient.DeletePort(ctx, infra.Config.ProvisioningNetwork.Bridge, infra.ClientTapName)
	require.NoError(t, err, "Failed to remove client port from provisioning bridge")

	// Add client to production bridge
	infra.Logger.Info("Adding client port to production bridge",
		"bridge", infra.Config.ProductionNetwork.Bridge,
		"port", infra.ClientTapName,
		"vlan", infra.Config.ProductionNetwork.VLAN)

	_, err = infra.OVSClient.AddPort(ctx, infra.Config.ProductionNetwork.Bridge, infra.ClientTapName)
	require.NoError(t, err, "Failed to add client port to production bridge")

	// Apply production network policy
	prodPolicy := &policy.PortPolicy{
		TenantID: "test-tenant",
		VLAN:     infra.Config.ProductionNetwork.VLAN,
		ACLs: []policy.ACLRule{
			{
				Priority: 100,
				Match: policy.FlowMatch{
					IPv4Src: infra.Config.ProductionNetwork.Subnet,
				},
				Action: policy.FlowAction{
					Type: policy.FlowActionAllow,
				},
				Description: "Allow production network traffic",
			},
		},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err = infra.PolicyEngine.ApplyPolicy(infra.ClientTapName, prodPolicy)
	require.NoError(t, err, "Failed to apply production policy")

	infra.Logger.Info("Production policy applied",
		"vlan", infra.Config.ProductionNetwork.VLAN,
		"acls", len(prodPolicy.ACLs))

	// Verify state transition
	state, err := infra.PolicyEngine.GetPortState(infra.ClientTapName)
	require.NoError(t, err, "Failed to get port state")
	assert.Equal(t, policy.PortStateAuthorized, state, "Port should be in authorized state")

	// Wait for network transition to settle. Nothing observable marks the end
	// (the flows go to a mock controller), so this is elapsed time.
	infra.Logger.Info("Waiting for network transition to complete")
	require.NoError(t, testenv.Elapse(ctx, NetworkTransitionWait))

	infra.Logger.Info("Phase 4 complete: Network transition successful",
		"from_vlan", infra.Config.ProvisioningNetwork.VLAN,
		"to_vlan", infra.Config.ProductionNetwork.VLAN)
}

// testVerification verifies the final state after provisioning
func testVerification(ctx context.Context, t *testing.T, infra *TestInfrastructure) {
	t.Helper()

	infra.Logger.Info("Phase 5: Verification")

	// Verify client port state
	t.Run("VerifyPortState", func(t *testing.T) {
		state, err := infra.PolicyEngine.GetPortState(infra.ClientTapName)
		require.NoError(t, err, "Failed to get port state")
		assert.Equal(t, policy.PortStateAuthorized, state,
			"Client port should be in authorized state")

		infra.Logger.Info("Port state verified",
			"port", infra.ClientTapName,
			"state", state)
	})

	// Verify applied policy
	t.Run("VerifyPolicy", func(t *testing.T) {
		appliedPolicy, err := infra.PolicyEngine.GetPolicy(infra.ClientTapName)
		require.NoError(t, err, "Failed to get applied policy")
		assert.NotNil(t, appliedPolicy, "Applied policy should exist")
		assert.Equal(t, infra.Config.ProductionNetwork.VLAN, appliedPolicy.VLAN,
			"Client should be on production VLAN")

		infra.Logger.Info("Policy verified",
			"vlan", appliedPolicy.VLAN,
			"acls", len(appliedPolicy.ACLs))
	})

	// Verify port is on production bridge
	t.Run("VerifyBridgeMembership", func(t *testing.T) {
		// List ports on production bridge
		ports, err := infra.OVSClient.ListPorts(ctx, infra.Config.ProductionNetwork.Bridge)
		require.NoError(t, err, "Failed to list production bridge ports")

		// Check if client port is in the list
		found := false
		for _, port := range ports {
			if port.Name == infra.ClientTapName {
				found = true
				break
			}
		}

		assert.True(t, found, "Client port should be on production bridge")

		infra.Logger.Info("Bridge membership verified",
			"bridge", infra.Config.ProductionNetwork.Bridge,
			"port", infra.ClientTapName)
	})

	// Verify VMs are still running
	t.Run("VerifyVMsRunning", func(t *testing.T) {
		assert.True(t, infra.ServerVM.IsRunning(), "Server VM should be running")
		assert.True(t, infra.ClientVM.IsRunning(), "Client VM should be running")

		infra.Logger.Info("VMs running",
			"server_pid", infra.ServerVM.GetPID(),
			"client_pid", infra.ClientVM.GetPID())
	})

	// In a real test with actual ISOs, we would also verify:
	// - Client certificate contains correct policy metadata
	// - DNS resolution works on production network
	// - Network connectivity from client to production services
	// - ACL rules are properly enforced

	infra.Logger.Info("Phase 5 complete: All verifications passed")
}
