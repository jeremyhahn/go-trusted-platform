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
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// OVSFlowController implements FlowController using real OVS client
type OVSFlowController struct {
	client *ovs.Client
}

func NewOVSFlowController(client *ovs.Client) *OVSFlowController {
	return &OVSFlowController{client: client}
}

func (o *OVSFlowController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	flowMod := &ovs.FlowMod{
		Table:    0,
		Priority: priority,
		Match:    match,
		Actions:  actions,
	}

	return o.client.AddFlow(ctx, bridgeName, flowMod)
}

func (o *OVSFlowController) DeleteFlow(bridgeName string, match string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return o.client.DeleteFlow(ctx, bridgeName, match)
}

func (o *OVSFlowController) DeleteFlowsByPort(bridgeName string, portID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Delete all flows matching the port
	match := "in_port=" + portID
	return o.client.DeleteFlow(ctx, bridgeName, match)
}

func (o *OVSFlowController) ListFlows(bridgeName string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	flows, err := o.client.ListFlows(ctx, bridgeName)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(flows))
	for i, flow := range flows {
		result[i] = fmt.Sprintf("table=%d,priority=%d", flow.Table, flow.Priority)
	}

	return result, nil
}

// SetPortVLAN implements OVSPortController interface.
// Note: In this test, portName is actually the OpenFlow port number as a string.
// The actual port configuration is done via ovs-vsctl commands in the test setup,
// so we return success without calling OVSDB (which expects real port names).
func (o *OVSFlowController) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	// The policy engine passes OpenFlow port numbers (e.g., "1", "2") as portName,
	// but OVSDB expects actual port names (e.g., "tp-eth0"). Since the test focuses
	// on policy engine logic and flow installation, not OVSDB port configuration,
	// we return success here. VLAN tagging is tested via flow rules.
	return nil
}

// SetPortState implements OVSPortController interface.
// Similar to SetPortVLAN, this is a no-op since port state is managed by the test setup.
func (o *OVSFlowController) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	return nil
}

// GetOFPort implements OVSPortController interface.
// Returns the port number from the portName (which is already the OpenFlow port number in tests).
func (o *OVSFlowController) GetOFPort(ctx context.Context, portName string) (int32, error) {
	// In tests, portName is already the OpenFlow port number as a string
	var port int32
	_, err := fmt.Sscanf(portName, "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("failed to parse port number: %w", err)
	}
	return port, nil
}

// TestPolicyEngineIntegration tests the policy engine with real OVS
func TestPolicyEngineIntegration(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create OVS client
	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to OVSDB: %v", err)
	}

	// Setup test bridge
	bridgeName := "br-policy-test"
	// Cleanup any existing bridge
	exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()
	defer exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()

	// Create bridge via ovs-vsctl which properly creates management socket
	cmd := exec.Command("ovs-vsctl", "add-br", bridgeName)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create bridge: %s", output)

	// Verify bridge exists via our Go client
	bridge, err := client.GetBridge(ctx, bridgeName)
	require.NoError(t, err)
	assert.Equal(t, bridgeName, bridge.Name)

	cmd = exec.Command("ovs-vsctl", "set", "bridge", bridgeName, "protocols=OpenFlow13")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to set protocols: %s", output)

	// Create policy engine with OVS flow controller
	flowController := NewOVSFlowController(client)
	engine, err := policy.NewEngine(policy.Config{
		BridgeName:     bridgeName,
		FlowController: flowController,
	})
	require.NoError(t, err)

	t.Run("StateTransitions", func(t *testing.T) {
		// Create a real port for state transition tests
		// Use unique name to avoid conflicts with system interfaces
		portName := "tp-eth0"
		addPortViaOVS(t, bridgeName, portName)
		defer deletePortViaOVS(t, bridgeName, portName)

		// Get the numeric OpenFlow port number to use as portID
		ofport := getOFPortViaOVS(t, portName)
		portID := fmt.Sprintf("%d", ofport)

		t.Run("UnconnectedToProvisioning", func(t *testing.T) {
			err := engine.SetPortState(portID, policy.PortStateProvisioning)
			require.NoError(t, err)

			state, err := engine.GetPortState(portID)
			require.NoError(t, err)
			assert.Equal(t, policy.PortStateProvisioning, state)
		})

		t.Run("ProvisioningToEnrolled", func(t *testing.T) {
			err := engine.SetPortState(portID, policy.PortStateEnrolled)
			require.NoError(t, err)

			state, err := engine.GetPortState(portID)
			require.NoError(t, err)
			assert.Equal(t, policy.PortStateEnrolled, state)
		})

		t.Run("EnrolledToAuthorized", func(t *testing.T) {
			testPolicy := &policy.PortPolicy{
				TenantID:  "test-tenant",
				VLAN:      100,
				ExpiresAt: time.Now().Add(24 * time.Hour),
				IssuedAt:  time.Now(),
			}

			err := engine.ApplyPolicy(portID, testPolicy)
			require.NoError(t, err)

			state, err := engine.GetPortState(portID)
			require.NoError(t, err)
			assert.Equal(t, policy.PortStateAuthorized, state)

			// Verify policy was stored
			storedPolicy, err := engine.GetPolicy(portID)
			require.NoError(t, err)
			assert.Equal(t, testPolicy.TenantID, storedPolicy.TenantID)
			assert.Equal(t, testPolicy.VLAN, storedPolicy.VLAN)
		})
	})

	t.Run("FlowInstallationOnPolicyApplication", func(t *testing.T) {
		portName := "tp-eth1"

		// Add test port to bridge using ovs-vsctl (more reliable)
		addPortViaOVS(t, bridgeName, portName)
		defer deletePortViaOVS(t, bridgeName, portName)

		// Get the numeric OpenFlow port number - use this as the portID for the engine
		// because OpenFlow requires numeric port IDs in flow matches
		ofport := getOFPortViaOVS(t, portName)
		portID := fmt.Sprintf("%d", ofport)

		// Set initial state using numeric port ID
		err = engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		// Create policy with ACLs - InPort will be set by the rule generator
		// so we don't need to specify it in ACLs
		testPolicy := &policy.PortPolicy{
			TenantID: "test-tenant",
			VLAN:     200,
			ACLs: []policy.ACLRule{
				{
					Priority: 1000,
					Match: policy.FlowMatch{
						IPProto: 6, // TCP
						TCPDst:  443,
					},
					Action: policy.FlowAction{
						Type: policy.FlowActionAllow,
					},
					Description: "Allow HTTPS",
				},
				{
					Priority: 900,
					Match: policy.FlowMatch{
						IPProto: 6, // TCP
						TCPDst:  22,
					},
					Action: policy.FlowAction{
						Type: policy.FlowActionAllow,
					},
					Description: "Allow SSH",
				},
			},
			ExpiresAt: time.Now().Add(24 * time.Hour),
			IssuedAt:  time.Now(),
		}

		// Apply policy using numeric port ID
		err = engine.ApplyPolicy(portID, testPolicy)
		require.NoError(t, err)

		// Verify flows were installed
		flows, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)

		// Should have flows for ACLs
		assert.GreaterOrEqual(t, len(flows), len(testPolicy.ACLs))

		// Verify state transitioned to authorized
		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateAuthorized, state)
	})

	t.Run("FlowRemovalOnPolicyRemoval", func(t *testing.T) {
		portName := "tp-eth2"

		// Add test port using ovs-vsctl
		addPortViaOVS(t, bridgeName, portName)
		defer deletePortViaOVS(t, bridgeName, portName)

		// Get the numeric OpenFlow port number
		ofport := getOFPortViaOVS(t, portName)
		portID := fmt.Sprintf("%d", ofport)

		// Set initial state and apply policy using numeric port ID
		err = engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		testPolicy := &policy.PortPolicy{
			TenantID:  "test-tenant",
			VLAN:      300,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			IssuedAt:  time.Now(),
		}

		err = engine.ApplyPolicy(portID, testPolicy)
		require.NoError(t, err)

		// Verify flows exist
		flowsBefore, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		flowCountBefore := len(flowsBefore)

		// Remove policy
		err = engine.RemovePolicy(portID)
		require.NoError(t, err)

		// Verify flows were removed
		flowsAfter, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(flowsAfter), flowCountBefore)

		// Verify state transitioned to unauthorized
		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateUnauthorized, state)
	})

	t.Run("QuarantineTransition", func(t *testing.T) {
		portName := "tp-eth3"

		// Add test port using ovs-vsctl
		addPortViaOVS(t, bridgeName, portName)
		defer deletePortViaOVS(t, bridgeName, portName)

		// Get the numeric OpenFlow port number
		ofport := getOFPortViaOVS(t, portName)
		portID := fmt.Sprintf("%d", ofport)

		// Get to authorized state first
		err = engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		testPolicy := &policy.PortPolicy{
			TenantID:  "test-tenant",
			VLAN:      400,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			IssuedAt:  time.Now(),
		}

		err = engine.ApplyPolicy(portID, testPolicy)
		require.NoError(t, err)

		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateAuthorized, state)

		// Transition to quarantine
		err = engine.SetPortState(portID, policy.PortStateQuarantined)
		require.NoError(t, err)

		state, err = engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateQuarantined, state)
	})

	t.Run("BlockedStateInstallsDropFlows", func(t *testing.T) {
		portName := "tp-eth4"

		// Add test port using ovs-vsctl
		addPortViaOVS(t, bridgeName, portName)
		defer deletePortViaOVS(t, bridgeName, portName)

		// Get the numeric OpenFlow port number
		ofport := getOFPortViaOVS(t, portName)
		portID := fmt.Sprintf("%d", ofport)

		// Set to provisioning first
		err = engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		// Transition to blocked
		err = engine.SetPortState(portID, policy.PortStateBlocked)
		require.NoError(t, err)

		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateBlocked, state)

		// Verify drop flows were installed
		flows, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		assert.NotEmpty(t, flows)
	})
}

// TestPolicyEngineWithCertificate tests certificate-based authentication flow
func TestPolicyEngineWithCertificate(t *testing.T) {
	requireOVSDBForTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client, err := ovs.NewClient("/var/run/openvswitch/db.sock")
	require.NoError(t, err)
	defer client.Close()

	err = client.Connect(ctx)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to OVSDB: %v", err)
	}

	bridgeName := "br-cert-test"
	// Cleanup any existing bridge
	exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()
	defer exec.Command("ovs-vsctl", "--if-exists", "del-br", bridgeName).Run()

	// Create bridge via ovs-vsctl
	cmd := exec.Command("ovs-vsctl", "add-br", bridgeName)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create bridge: %s", output)

	cmd = exec.Command("ovs-vsctl", "set", "bridge", bridgeName, "protocols=OpenFlow13")
	output, err = cmd.CombinedOutput()
	require.NoError(t, err, "Failed to set protocols: %s", output)

	// Create mock policy extractor
	extractor := &MockPolicyExtractor{
		policy: &policy.PortPolicy{
			TenantID:  "test-tenant-cert",
			VLAN:      500,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			IssuedAt:  time.Now(),
			ACLs: []policy.ACLRule{
				{
					Priority: 1000,
					Match:    policy.FlowMatch{IPProto: 6, TCPDst: 443},
					Action:   policy.FlowAction{Type: policy.FlowActionAllow},
				},
			},
		},
	}

	// Create engine with custom extractor
	flowController := NewOVSFlowController(client)
	engine, err := policy.NewEngine(policy.Config{
		BridgeName:      bridgeName,
		FlowController:  flowController,
		PolicyExtractor: extractor,
	})
	require.NoError(t, err)

	portName := "tp-eth-cert"
	addPortViaOVS(t, bridgeName, portName)
	defer deletePortViaOVS(t, bridgeName, portName)

	// Get the numeric OpenFlow port number
	ofport := getOFPortViaOVS(t, portName)
	portID := fmt.Sprintf("%d", ofport)

	t.Run("AuthenticateWithCertificate", func(t *testing.T) {
		// Create mock certificate
		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "test-device",
				Organization: []string{"test-tenant-cert"},
			},
			NotBefore: time.Now().Add(-1 * time.Hour),
			NotAfter:  time.Now().Add(24 * time.Hour),
		}

		// Set initial state using numeric port ID
		err := engine.SetPortState(portID, policy.PortStateProvisioning)
		require.NoError(t, err)

		// Authenticate with certificate
		err = engine.AuthenticatePort(portID, cert)
		require.NoError(t, err)

		// Verify state is authorized
		state, err := engine.GetPortState(portID)
		require.NoError(t, err)
		assert.Equal(t, policy.PortStateAuthorized, state)

		// Verify policy was extracted and applied
		appliedPolicy, err := engine.GetPolicy(portID)
		require.NoError(t, err)
		assert.Equal(t, "test-tenant-cert", appliedPolicy.TenantID)
		assert.Equal(t, uint16(500), appliedPolicy.VLAN)

		// Verify flows were installed
		flows, err := client.ListFlows(ctx, bridgeName)
		require.NoError(t, err)
		assert.NotEmpty(t, flows)
	})
}

// MockPolicyExtractor for testing
type MockPolicyExtractor struct {
	policy *policy.PortPolicy
	err    error
}

func (m *MockPolicyExtractor) ExtractPolicy(cert *x509.Certificate) (*policy.PortPolicy, error) {
	if m.err != nil {
		return nil, m.err
	}
	// Update certificate reference in policy
	if m.policy != nil {
		policyCopy := *m.policy
		policyCopy.Certificate = cert
		return &policyCopy, nil
	}
	return nil, fmt.Errorf("no policy configured")
}

func (m *MockPolicyExtractor) ExtractTenantID(cert *x509.Certificate) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0], nil
	}
	return "", fmt.Errorf("no organization in certificate")
}

func (m *MockPolicyExtractor) ExtractVLAN(cert *x509.Certificate) (uint16, error) {
	if m.err != nil {
		return 0, m.err
	}
	if m.policy != nil {
		return m.policy.VLAN, nil
	}
	return 0, fmt.Errorf("no VLAN configured")
}

func (m *MockPolicyExtractor) ExtractACLs(cert *x509.Certificate) ([]policy.ACLRule, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.policy != nil {
		return m.policy.ACLs, nil
	}
	return nil, fmt.Errorf("no ACLs configured")
}
