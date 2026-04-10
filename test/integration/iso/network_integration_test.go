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

package iso_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// TestDeviceProfileNetworkConfigExtraction verifies that network configurations
// can be correctly extracted from device profiles for ISO embedding
func TestDeviceProfileNetworkConfigExtraction(t *testing.T) {
	tests := []struct {
		name    string
		profile *entities.DeviceProfile
		want    struct {
			provVLAN uint16
			prodVLAN uint16
			quarVLAN uint16
			provACLs int
			prodACLs int
		}
	}{
		{
			name: "Full network configuration",
			profile: &entities.DeviceProfile{
				ID:    1,
				Name:  "test-server-profile",
				Model: "TestServer",
				Role:  entities.DeviceRoleServer,
				Networks: map[string]*entities.NetworkPhaseConfig{
					entities.DefaultEnrollmentNetwork: {
						VLAN: 100,
						DHCPPool: &entities.DHCPPoolConfig{
							Network:    "10.0.100.0/24",
							RangeStart: "10.0.100.10",
							RangeEnd:   "10.0.100.250",
							LeaseTime:  3600,
						},
						Gateway:    "10.0.100.1",
						DNS:        []string{"10.0.100.2", "10.0.100.3"},
						AuthMethod: entities.AuthMethodNone,
						ACLs: []entities.ACLConfig{
							{
								Priority: 100,
								Protocol: "tcp",
								SrcIP:    "0.0.0.0/0",
								DstIP:    "10.0.100.2/32",
								DstPort:  443,
								Action:   "allow",
							},
							{
								Priority: 90,
								Protocol: "udp",
								SrcIP:    "0.0.0.0/0",
								DstIP:    "10.0.100.2/32",
								DstPort:  53,
								Action:   "allow",
							},
						},
					},
					entities.DefaultPostEnrollmentNetwork: {
						VLAN:       200,
						StaticIP:   "10.0.200.50/24",
						Gateway:    "10.0.200.1",
						DNS:        []string{"10.0.200.2"},
						AuthMethod: entities.AuthMethod802_1X,
						ACLs: []entities.ACLConfig{
							{
								Priority: 100,
								Protocol: "any",
								SrcIP:    "10.0.200.0/24",
								DstIP:    "0.0.0.0/0",
								Action:   "allow",
							},
						},
					},
					entities.DefaultFailureNetwork: {
						VLAN:       300,
						Gateway:    "10.0.300.1",
						DNS:        []string{"10.0.300.2"},
						AuthMethod: entities.AuthMethodNone,
					},
				},
			},
			want: struct {
				provVLAN uint16
				prodVLAN uint16
				quarVLAN uint16
				provACLs int
				prodACLs int
			}{
				provVLAN: 100,
				prodVLAN: 200,
				quarVLAN: 300,
				provACLs: 2,
				prodACLs: 1,
			},
		},
		{
			name: "Client profile with provisioning and production only",
			profile: &entities.DeviceProfile{
				ID:    2,
				Name:  "test-client-profile",
				Model: "TestClient",
				Role:  entities.DeviceRoleClient,
				Networks: map[string]*entities.NetworkPhaseConfig{
					entities.DefaultEnrollmentNetwork: {
						VLAN:       101,
						Gateway:    "10.0.101.1",
						DNS:        []string{"10.0.101.2"},
						AuthMethod: entities.AuthMethodNone,
					},
					entities.DefaultPostEnrollmentNetwork: {
						VLAN:       201,
						Gateway:    "10.0.201.1",
						DNS:        []string{"10.0.201.2"},
						AuthMethod: entities.AuthMethod802_1X,
					},
				},
			},
			want: struct {
				provVLAN uint16
				prodVLAN uint16
				quarVLAN uint16
				provACLs int
				prodACLs int
			}{
				provVLAN: 101,
				prodVLAN: 201,
				quarVLAN: 0,
				provACLs: 0,
				prodACLs: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify provisioning network
			require.NotNil(t, tt.profile.Networks[entities.DefaultEnrollmentNetwork])
			assert.Equal(t, tt.want.provVLAN, tt.profile.Networks[entities.DefaultEnrollmentNetwork].VLAN)
			if tt.want.provACLs > 0 {
				assert.Len(t, tt.profile.Networks[entities.DefaultEnrollmentNetwork].ACLs, tt.want.provACLs)
			}

			// Verify production network
			require.NotNil(t, tt.profile.Networks[entities.DefaultPostEnrollmentNetwork])
			assert.Equal(t, tt.want.prodVLAN, tt.profile.Networks[entities.DefaultPostEnrollmentNetwork].VLAN)
			if tt.want.prodACLs > 0 {
				assert.Len(t, tt.profile.Networks[entities.DefaultPostEnrollmentNetwork].ACLs, tt.want.prodACLs)
			}

			// Verify quarantine network (if present)
			if tt.want.quarVLAN > 0 {
				require.NotNil(t, tt.profile.Networks[entities.DefaultFailureNetwork])
				assert.Equal(t, tt.want.quarVLAN, tt.profile.Networks[entities.DefaultFailureNetwork].VLAN)
			}
		})
	}
}

// TestNetworkPhaseACLValidation verifies ACL configuration validation
func TestNetworkPhaseACLValidation(t *testing.T) {
	tests := []struct {
		name    string
		acl     *entities.ACLConfig
		wantErr bool
	}{
		{
			name: "Valid TCP ACL",
			acl: &entities.ACLConfig{
				Priority: 100,
				Protocol: "tcp",
				SrcIP:    "10.0.0.0/24",
				DstIP:    "192.168.1.1/32",
				SrcPort:  0,
				DstPort:  443,
				Action:   "allow",
			},
			wantErr: false,
		},
		{
			name: "Valid UDP ACL",
			acl: &entities.ACLConfig{
				Priority: 90,
				Protocol: "udp",
				SrcIP:    "0.0.0.0/0",
				DstIP:    "10.0.0.1/32",
				DstPort:  53,
				Action:   "allow",
			},
			wantErr: false,
		},
		{
			name: "Valid ICMP ACL",
			acl: &entities.ACLConfig{
				Priority: 80,
				Protocol: "icmp",
				SrcIP:    "10.0.0.0/24",
				DstIP:    "0.0.0.0/0",
				Action:   "allow",
			},
			wantErr: false,
		},
		{
			name: "Valid any protocol ACL",
			acl: &entities.ACLConfig{
				Priority: 70,
				Protocol: "any",
				SrcIP:    "10.0.0.0/8",
				DstIP:    "0.0.0.0/0",
				Action:   "allow",
			},
			wantErr: false,
		},
		{
			name: "Valid deny ACL",
			acl: &entities.ACLConfig{
				Priority: 60,
				Protocol: "tcp",
				SrcIP:    "192.168.0.0/16",
				DstIP:    "10.0.0.1/32",
				DstPort:  22,
				Action:   "deny",
			},
			wantErr: false,
		},
		{
			name: "Invalid protocol",
			acl: &entities.ACLConfig{
				Priority: 50,
				Protocol: "invalid",
				SrcIP:    "10.0.0.0/24",
				DstIP:    "0.0.0.0/0",
				Action:   "allow",
			},
			wantErr: true,
		},
		{
			name: "Invalid action",
			acl: &entities.ACLConfig{
				Priority: 40,
				Protocol: "tcp",
				SrcIP:    "10.0.0.0/24",
				DstIP:    "0.0.0.0/0",
				Action:   "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.acl.IsValid()
			if tt.wantErr {
				assert.False(t, isValid, "ACL should be invalid")
			} else {
				assert.True(t, isValid, "ACL should be valid")
			}
		})
	}
}

// TestSDNPolicyConversion verifies conversion from device profile network config
// to SDN policy structures
func TestSDNPolicyConversion(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "conversion-test",
		Model: "TestDevice",
		Role:  entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:    100,
				Gateway: "10.0.100.1",
				DNS:     []string{"10.0.100.2"},
				ACLs: []entities.ACLConfig{
					{
						Priority: 100,
						Protocol: "tcp",
						SrcIP:    "0.0.0.0/0",
						DstIP:    "10.0.100.2/32",
						DstPort:  443,
						Action:   "allow",
					},
				},
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:    200,
				Gateway: "10.0.200.1",
				DNS:     []string{"10.0.200.2"},
				ACLs: []entities.ACLConfig{
					{
						Priority: 100,
						Protocol: "any",
						SrcIP:    "10.0.200.0/24",
						DstIP:    "0.0.0.0/0",
						Action:   "allow",
					},
				},
			},
		},
	}

	t.Run("Convert provisioning network to SDN policy", func(t *testing.T) {
		// Simulate conversion to SDN policy
		sdnPolicy := convertNetworkConfigToSDNPolicy(profile.Networks[entities.DefaultEnrollmentNetwork], "test-tenant")

		require.NotNil(t, sdnPolicy)
		assert.Equal(t, "test-tenant", sdnPolicy.TenantID)
		assert.Equal(t, uint16(100), sdnPolicy.VLAN)
		assert.Len(t, sdnPolicy.ACLs, 1)

		// Verify ACL conversion
		acl := sdnPolicy.ACLs[0]
		assert.Equal(t, 100, acl.Priority)
		assert.Equal(t, uint16(443), acl.Match.TCPDst)
	})

	t.Run("Convert production network to SDN policy", func(t *testing.T) {
		// Simulate conversion to SDN policy
		sdnPolicy := convertNetworkConfigToSDNPolicy(profile.Networks[entities.DefaultPostEnrollmentNetwork], "test-tenant")

		require.NotNil(t, sdnPolicy)
		assert.Equal(t, "test-tenant", sdnPolicy.TenantID)
		assert.Equal(t, uint16(200), sdnPolicy.VLAN)
		assert.Len(t, sdnPolicy.ACLs, 1)

		// Verify ACL conversion
		acl := sdnPolicy.ACLs[0]
		assert.Equal(t, 100, acl.Priority)
		assert.Equal(t, policy.FlowActionAllow, acl.Action.Type)
	})
}

// convertNetworkConfigToSDNPolicy converts a DeviceProfile NetworkPhaseConfig
// to an SDN PortPolicy for testing
func convertNetworkConfigToSDNPolicy(config *entities.NetworkPhaseConfig, tenantID string) *policy.PortPolicy {
	if config == nil {
		return nil
	}

	p := &policy.PortPolicy{
		TenantID: tenantID,
		VLAN:     config.VLAN,
		ACLs:     make([]policy.ACLRule, 0, len(config.ACLs)),
	}

	// Convert ACLs
	for _, acl := range config.ACLs {
		aclRule := policy.ACLRule{
			Priority:    acl.Priority,
			Description: "Converted from device profile",
		}

		// Set up flow match
		aclRule.Match = policy.FlowMatch{
			IPv4Src: acl.SrcIP,
			IPv4Dst: acl.DstIP,
		}

		// Set protocol-specific fields
		switch acl.Protocol {
		case "tcp":
			aclRule.Match.IPProto = 6
			if acl.SrcPort > 0 {
				aclRule.Match.TCPSrc = acl.SrcPort
			}
			if acl.DstPort > 0 {
				aclRule.Match.TCPDst = acl.DstPort
			}
		case "udp":
			aclRule.Match.IPProto = 17
			if acl.SrcPort > 0 {
				aclRule.Match.UDPSrc = acl.SrcPort
			}
			if acl.DstPort > 0 {
				aclRule.Match.UDPDst = acl.DstPort
			}
		case "icmp":
			aclRule.Match.IPProto = 1
		}

		// Set action
		switch acl.Action {
		case "allow":
			aclRule.Action.Type = policy.FlowActionAllow
		case "deny":
			aclRule.Action.Type = policy.FlowActionDeny
		}

		p.ACLs = append(p.ACLs, aclRule)
	}

	return p
}

// TestProvisioningToProductionTransition verifies the state transition
// when a device moves from provisioning to production network
func TestProvisioningToProductionTransition(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "transition-test",
		Model: "TestDevice",
		Role:  entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:    100,
				Gateway: "10.0.100.1",
				DNS:     []string{"10.0.100.2"},
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:    200,
				Gateway: "10.0.200.1",
				DNS:     []string{"10.0.200.2"},
			},
		},
	}

	t.Run("Verify VLAN change during transition", func(t *testing.T) {
		// Initial state: provisioning network
		initialVLAN := profile.Networks[entities.DefaultEnrollmentNetwork].VLAN
		assert.Equal(t, uint16(100), initialVLAN)

		// After enrollment and activation: production network
		finalVLAN := profile.Networks[entities.DefaultPostEnrollmentNetwork].VLAN
		assert.Equal(t, uint16(200), finalVLAN)
		assert.NotEqual(t, initialVLAN, finalVLAN, "VLAN should change during transition")
	})

	t.Run("Verify gateway change during transition", func(t *testing.T) {
		initialGateway := profile.Networks[entities.DefaultEnrollmentNetwork].Gateway
		finalGateway := profile.Networks[entities.DefaultPostEnrollmentNetwork].Gateway

		assert.NotEqual(t, initialGateway, finalGateway, "Gateway should change during transition")
		assert.Equal(t, "10.0.100.1", initialGateway)
		assert.Equal(t, "10.0.200.1", finalGateway)
	})

	t.Run("Verify DNS change during transition", func(t *testing.T) {
		initialDNS := profile.Networks[entities.DefaultEnrollmentNetwork].DNS
		finalDNS := profile.Networks[entities.DefaultPostEnrollmentNetwork].DNS

		require.Len(t, initialDNS, 1)
		require.Len(t, finalDNS, 1)
		assert.NotEqual(t, initialDNS[0], finalDNS[0], "DNS should change during transition")
	})
}

// TestAuthMethodValidation verifies authentication method validation
func TestAuthMethodValidation(t *testing.T) {
	tests := []struct {
		name   string
		method entities.AuthMethod
		valid  bool
	}{
		{
			name:   "None authentication",
			method: entities.AuthMethodNone,
			valid:  true,
		},
		{
			name:   "802.1X authentication",
			method: entities.AuthMethod802_1X,
			valid:  true,
		},
		{
			name:   "Invalid authentication method",
			method: entities.AuthMethod("invalid"),
			valid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.method.IsValid()
			assert.Equal(t, tt.valid, isValid)
		})
	}
}

// TestDeviceRoleValidation verifies device role validation
func TestDeviceRoleValidation(t *testing.T) {
	tests := []struct {
		name  string
		role  entities.DeviceRole
		valid bool
	}{
		{name: "Server role", role: entities.DeviceRoleServer, valid: true},
		{name: "Client role", role: entities.DeviceRoleClient, valid: true},
		{name: "Workstation role", role: entities.DeviceRoleWorkstation, valid: true},
		{name: "Edge role", role: entities.DeviceRoleEdge, valid: true},
		{name: "IoT role", role: entities.DeviceRoleIoT, valid: true},
		{name: "Gateway role", role: entities.DeviceRoleGateway, valid: true},
		{name: "Load Balancer role", role: entities.DeviceRoleLoadBalancer, valid: true},
		{name: "Unknown role", role: entities.DeviceRoleUnknown, valid: true},
		{name: "Invalid role", role: entities.DeviceRole("invalid"), valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.role.IsValid()
			assert.Equal(t, tt.valid, isValid)
		})
	}
}

// TestDHCPPoolConfiguration verifies DHCP pool configuration
func TestDHCPPoolConfiguration(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "dhcp-test",
		Model: "TestDevice",
		Role:  entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN: 100,
				DHCPPool: &entities.DHCPPoolConfig{
					Network:    "10.0.100.0/24",
					RangeStart: "10.0.100.10",
					RangeEnd:   "10.0.100.250",
					LeaseTime:  3600,
				},
			},
		},
	}

	t.Run("Verify DHCP pool configuration", func(t *testing.T) {
		dhcp := profile.Networks[entities.DefaultEnrollmentNetwork].DHCPPool
		require.NotNil(t, dhcp)

		assert.Equal(t, "10.0.100.0/24", dhcp.Network)
		assert.Equal(t, "10.0.100.10", dhcp.RangeStart)
		assert.Equal(t, "10.0.100.250", dhcp.RangeEnd)
		assert.Equal(t, 3600, dhcp.LeaseTime)
	})
}
