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

package policy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestSDNEnrollmentHook_PolicyEngineGetter tests the PolicyEngine getter method
func TestSDNEnrollmentHook_PolicyEngineGetter(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Test that PolicyEngine getter returns the correct engine
	engine := hook.PolicyEngine()
	assert.NotNil(t, engine)
	assert.Equal(t, mockEngine, engine)
}

// TestSDNEnrollmentHook_PeekPendingActivation tests the PeekPendingActivation method
func TestSDNEnrollmentHook_PeekPendingActivation(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Store a pending activation
	profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
	cert := createEnrollmentCertificate(t, "TestOrg")
	pending := &PendingActivation{
		PortID:      "port1",
		Profile:     profile,
		Certificate: cert,
		EnrolledAt:  time.Now(),
	}
	hook.pendingActivations.Store("SRV-12345", pending)

	t.Run("peek existing activation", func(t *testing.T) {
		retrieved, found := hook.PeekPendingActivation("SRV-12345")
		assert.True(t, found)
		assert.NotNil(t, retrieved)
		assert.Equal(t, "port1", retrieved.PortID)
		assert.Equal(t, profile.Name, retrieved.Profile.Name)
		assert.Equal(t, cert, retrieved.Certificate)

		// Verify the activation is still present (not deleted)
		retrieved2, found2 := hook.PeekPendingActivation("SRV-12345")
		assert.True(t, found2)
		assert.NotNil(t, retrieved2)
	})

	t.Run("peek non-existent activation", func(t *testing.T) {
		retrieved, found := hook.PeekPendingActivation("UNKNOWN-12345")
		assert.False(t, found)
		assert.Nil(t, retrieved)
	})
}

// TestSDNEnrollmentHook_BuildPortPolicy_DenyAction tests deny action conversion
func TestSDNEnrollmentHook_BuildPortPolicy_DenyAction(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	cert := createEnrollmentCertificate(t, "TestOrg")

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "Test Profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
				ACLs: []entities.ACLConfig{
					{
						Priority: 100,
						Protocol: "tcp",
						SrcIP:    "10.0.0.0/8",
						DstIP:    "any",
						DstPort:  22,
						Action:   "deny", // Test deny action
					},
				},
			},
		},
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}

	policy := hook.buildPortPolicy(profile, cert)
	require.NotNil(t, policy)
	require.Len(t, policy.ACLs, 1)
	assert.Equal(t, FlowActionDeny, policy.ACLs[0].Action.Type)
}

// TestSDNEnrollmentHook_BuildPortPolicy_NoOrganization tests default tenant ID
func TestSDNEnrollmentHook_BuildPortPolicy_NoOrganization(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Create a certificate without an Organization field
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-device",
			// No Organization field
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	profile := createTestDeviceProfile(1, "Test Profile", "52:54:00", "", 100)

	policy := hook.buildPortPolicy(profile, cert)
	require.NotNil(t, policy)
	// Verify default tenant ID is used when Organization is empty
	assert.Equal(t, "default", policy.TenantID)
}

// TestSDNEnrollmentHook_ActivateDevice_NilPolicyBuild tests activation with nil policy build
func TestSDNEnrollmentHook_ActivateDevice_NilPolicyBuild(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Store a pending activation with a profile that has no production network
	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "Incomplete Profile",
	}
	cert := createEnrollmentCertificate(t, "TestOrg")
	pending := &PendingActivation{
		PortID:      "port1",
		Profile:     profile,
		Certificate: cert,
		EnrolledAt:  time.Now(),
	}
	hook.pendingActivations.Store("SRV-NIL-POLICY", pending)

	err = hook.ActivateDevice("SRV-NIL-POLICY")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to build port policy from profile")

	// Verify the pending activation was restored
	_, ok := hook.pendingActivations.Load("SRV-NIL-POLICY")
	assert.True(t, ok, "pending activation should be restored on policy build failure")
}

// TestVLANFlowManager_NewWithCustomConfigs tests VLAN flow manager with custom configs
func TestVLANFlowManager_NewWithCustomConfigs(t *testing.T) {
	t.Run("with custom provisioning config that has VLAN set", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		// Note: The manager uses config.ProvisioningVLAN for manager.provisioningVLAN
		// but ProvisioningConfig.ProvisioningVLAN is used when generating flows
		provConfig := &ProvisioningFlowConfig{
			ProvisioningVLAN: 999,
			ACMEServerIPs:    []net.IP{net.ParseIP("192.168.1.100")},
		}

		config := VLANFlowManagerConfig{
			BridgeName:         "br0",
			FlowController:     mockController,
			ProvisioningVLAN:   999, // This is used for manager.provisioningVLAN
			ProvisioningConfig: provConfig,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, uint16(999), manager.provisioningVLAN)
	})

	t.Run("with custom quarantine config that has VLAN set", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		quarConfig := &QuarantineFlowConfig{
			QuarantineVLAN:       777,
			RemediationServerIPs: []net.IP{net.ParseIP("192.168.1.200")},
		}

		config := VLANFlowManagerConfig{
			BridgeName:       "br0",
			FlowController:   mockController,
			QuarantineVLAN:   777, // This is used for manager.quarantineVLAN
			QuarantineConfig: quarConfig,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, uint16(777), manager.quarantineVLAN)
	})

	t.Run("with provisioning config but zero vlan", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		provConfig := &ProvisioningFlowConfig{
			ProvisioningVLAN: 0, // Zero VLAN, should use default
		}

		config := VLANFlowManagerConfig{
			BridgeName:         "br0",
			FlowController:     mockController,
			ProvisioningConfig: provConfig,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, DefaultProvisioningVLAN, manager.provisioningVLAN)
	})

	t.Run("with quarantine config but zero vlan", func(t *testing.T) {
		mockController := newVLANMockFlowController()
		quarConfig := &QuarantineFlowConfig{
			QuarantineVLAN: 0, // Zero VLAN, should use default
		}

		config := VLANFlowManagerConfig{
			BridgeName:       "br0",
			FlowController:   mockController,
			QuarantineConfig: quarConfig,
		}

		manager, err := NewVLANFlowManager(config)
		require.NoError(t, err)
		require.NotNil(t, manager)
		assert.Equal(t, DefaultQuarantineVLAN, manager.quarantineVLAN)
	})
}

// TestVLANFlowManager_ConvertACLConfig_DefaultAction tests default deny action
func TestVLANFlowManager_ConvertACLConfig_DefaultAction(t *testing.T) {
	mockController := newVLANMockFlowController()
	config := VLANFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: mockController,
	}

	manager, err := NewVLANFlowManager(config)
	require.NoError(t, err)

	// Test with unknown action (should default to deny)
	acl := entities.ACLConfig{
		Priority: 100,
		Protocol: "tcp",
		Action:   "unknown", // Unknown action, should default to deny
	}

	rule := manager.convertACLConfig(acl)
	assert.Equal(t, FlowActionDeny, rule.Action.Type)
}

// TestVLANFlowManager_ConvertACLConfig_UDP tests UDP rule with source port
func TestVLANFlowManager_ConvertACLConfig_UDP_SourcePort(t *testing.T) {
	mockController := newVLANMockFlowController()
	config := VLANFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: mockController,
	}

	manager, err := NewVLANFlowManager(config)
	require.NoError(t, err)

	acl := entities.ACLConfig{
		Priority: 100,
		Protocol: "udp",
		SrcPort:  12345, // Source port for UDP
		DstPort:  53,
		Action:   "allow",
	}

	rule := manager.convertACLConfig(acl)
	assert.Equal(t, ProtoUDP, rule.Match.IPProto)
	assert.Equal(t, uint16(12345), rule.Match.UDPSrc)
	assert.Equal(t, uint16(53), rule.Match.UDPDst)
}

// TestSDNEnrollmentHook_OnEnrollmentComplete_ProfileNotFoundBySerial tests fallback to MAC lookup
func TestSDNEnrollmentHook_OnEnrollmentComplete_ProfileNotFoundBySerial(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Test MAC extractor that returns a valid MAC
	hook.macExtractor = testMACExtractor("52:54:00:12:34:56")
	hook.RegisterPort("52:54:00:12:34:56", "port1")

	// Create a profile that matches by MAC prefix
	profile := createTestDeviceProfile(1, "MAC Profile", "52:54:00", "", 100)

	// Setup mock to fail serial lookup but succeed on MAC lookup
	serialCallCount := 0
	mockDAO.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
			serialCallCount++
			if serialCallCount == 1 {
				// First call (serial lookup) - return empty
				_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{}})
			} else {
				// Second call (MAC lookup) - return the profile
				_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{profile}})
			}
		}).
		Return(nil).Twice()

	mockEngine.On("GetPortState", "port1").Return(PortStateProvisioning, nil).Once()
	mockEngine.On("SetPortState", "port1", PortStateEnrolled).Return(nil).Once()

	event := &EnrollmentEvent{
		Context:       context.Background(),
		Certificate:   createEnrollmentCertificate(t, "TestOrg"),
		ClientIP:      "192.168.1.100",
		ProductSerial: "UNKNOWN-12345", // Serial that won't match
	}

	err = hook.OnEnrollmentComplete(event)
	assert.NoError(t, err)

	mockEngine.AssertExpectations(t)
	mockDAO.AssertExpectations(t)
}

// TestSDNEnrollmentHook_OnEnrollmentComplete_NoProfileBySerialOrMAC tests error when profile not found
func TestSDNEnrollmentHook_OnEnrollmentComplete_NoProfileBySerialOrMAC(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Test MAC extractor that returns a valid MAC
	hook.macExtractor = testMACExtractor("52:54:00:12:34:56")

	// Setup mock to fail both serial and MAC lookup
	mockDAO.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
			_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{}})
		}).
		Return(nil).Twice()

	event := &EnrollmentEvent{
		Context:       context.Background(),
		Certificate:   createEnrollmentCertificate(t, "TestOrg"),
		ClientIP:      "192.168.1.100",
		ProductSerial: "UNKNOWN-12345",
	}

	err = hook.OnEnrollmentComplete(event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "device profile not found")

	mockDAO.AssertExpectations(t)
}

// TestSDNEnrollmentHook_OnEnrollmentComplete_PortNotRegistered tests error when port not registered
func TestSDNEnrollmentHook_OnEnrollmentComplete_PortNotRegistered(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Test MAC extractor that returns a valid MAC (but port not registered)
	hook.macExtractor = testMACExtractor("52:54:00:12:34:56")
	// Note: Not calling hook.RegisterPort()

	profile := createTestDeviceProfile(1, "Server Profile", "", "SRV-", 100)
	mockDAO.On("ForEachPage", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.DeviceProfile])
			_ = fn(datastore.PageResult[*entities.DeviceProfile]{Entities: []*entities.DeviceProfile{profile}})
		}).
		Return(fmt.Errorf("found")).Once()

	event := &EnrollmentEvent{
		Context:       context.Background(),
		Certificate:   createEnrollmentCertificate(t, "TestOrg"),
		ClientIP:      "192.168.1.100",
		ProductSerial: "SRV-12345",
	}

	err = hook.OnEnrollmentComplete(event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port not found for MAC address")

	mockDAO.AssertExpectations(t)
}

// TestSDNEnrollmentHook_OnEnrollmentComplete_NilProfile tests when profile is nil after lookup
func TestSDNEnrollmentHook_OnEnrollmentComplete_NilProfile(t *testing.T) {
	mockEngine := &MockPolicyEngine{}
	mockDAO := &MockDeviceProfileDAO{}

	hook, err := NewSDNEnrollmentHook(SDNEnrollmentHookConfig{
		Logger:       slog.Default(),
		PolicyEngine: mockEngine,
		ProfileDAO:   mockDAO,
	})
	require.NoError(t, err)

	// Use an empty MAC extractor to skip MAC lookup branch
	hook.macExtractor = testMACExtractor("")

	// No serial provided, empty MAC extractor
	event := &EnrollmentEvent{
		Context:       context.Background(),
		Certificate:   createEnrollmentCertificate(t, "TestOrg"),
		ClientIP:      "192.168.1.100",
		ProductSerial: "", // No serial
	}

	err = hook.OnEnrollmentComplete(event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to identify device")
}

// TestEngine_RemovePolicyFromEnrolled tests removing policy from enrolled state
func TestEngine_RemovePolicyFromEnrolled(t *testing.T) {
	controller := newMockFlowController()
	config := Config{
		BridgeName:     "br0",
		FlowController: controller,
	}

	engine, err := NewEngine(config)
	require.NoError(t, err)

	// Apply policy first
	policy := &PortPolicy{
		TenantID: "tenant-1",
		VLAN:     100,
	}
	require.NoError(t, engine.ApplyPolicy("port1", policy))

	// Verify state is authorized
	state, err := engine.GetPortState("port1")
	require.NoError(t, err)
	assert.Equal(t, PortStateAuthorized, state)

	// Remove policy
	err = engine.RemovePolicy("port1")
	require.NoError(t, err)

	// Verify state is unauthorized
	state, err = engine.GetPortState("port1")
	require.NoError(t, err)
	assert.Equal(t, PortStateUnauthorized, state)

	// Verify policy is removed
	_, err = engine.GetPolicy("port1")
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

// TestEngine_AuthenticatePort_FromUnauthorized tests authentication from unauthorized state
func TestEngine_AuthenticatePort_FromUnauthorized(t *testing.T) {
	controller := newMockFlowController()
	config := Config{
		BridgeName:     "br0",
		FlowController: controller,
	}

	engine, err := NewEngine(config)
	require.NoError(t, err)

	// First set to provisioning, then unauthorized
	require.NoError(t, engine.SetPortState("port1", PortStateProvisioning))
	require.NoError(t, engine.SetPortState("port1", PortStateUnauthorized))

	// Authenticate from unauthorized
	cert := createTestCertificate(t, x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"tenant-1"},
			OrganizationalUnit: []string{"vlan=100"},
		},
	})

	err = engine.AuthenticatePort("port1", cert)
	assert.NoError(t, err)

	// Verify authorized
	state, err := engine.GetPortState("port1")
	require.NoError(t, err)
	assert.Equal(t, PortStateAuthorized, state)
}

// TestEngine_AuthenticatePort_FromProvisioning tests authentication from provisioning state
func TestEngine_AuthenticatePort_FromProvisioning(t *testing.T) {
	controller := newMockFlowController()
	config := Config{
		BridgeName:     "br0",
		FlowController: controller,
	}

	engine, err := NewEngine(config)
	require.NoError(t, err)

	// Set to provisioning
	require.NoError(t, engine.SetPortState("port1", PortStateProvisioning))

	// Authenticate from provisioning
	cert := createTestCertificate(t, x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"tenant-1"},
			OrganizationalUnit: []string{"vlan=100"},
		},
	})

	err = engine.AuthenticatePort("port1", cert)
	assert.NoError(t, err)

	// Verify authorized
	state, err := engine.GetPortState("port1")
	require.NoError(t, err)
	assert.Equal(t, PortStateAuthorized, state)
}

// TestEngine_ApplyPolicy_FromEnrolledState tests applying policy from enrolled state
func TestEngine_ApplyPolicy_FromEnrolledState(t *testing.T) {
	controller := newMockFlowController()
	config := Config{
		BridgeName:     "br0",
		FlowController: controller,
	}

	engine, err := NewEngine(config)
	require.NoError(t, err)

	// Set to provisioning, then enrolled (simulating successful enrollment)
	require.NoError(t, engine.SetPortState("port1", PortStateProvisioning))
	require.NoError(t, engine.SetPortState("port1", PortStateEnrolled))

	// Verify enrolled
	state, err := engine.GetPortState("port1")
	require.NoError(t, err)
	assert.Equal(t, PortStateEnrolled, state)

	// Apply policy - this should transition from Enrolled to Authorized directly
	policy := &PortPolicy{
		TenantID: "tenant-1",
		VLAN:     100,
	}
	err = engine.ApplyPolicy("port1", policy)
	assert.NoError(t, err)

	// Verify authorized
	state, err = engine.GetPortState("port1")
	require.NoError(t, err)
	assert.Equal(t, PortStateAuthorized, state)
}
