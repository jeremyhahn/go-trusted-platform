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

package iso

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

func TestNetworkConfigGenerator(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "test-server",
		Model: "TestServer",
		Role:  entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:    100,
				Zone:    "provisioning",
				Gateway: "10.0.100.1",
				DNS:     []string{"10.0.100.2", "10.0.100.3"},
				DHCPPool: &entities.DHCPPoolConfig{
					Network:    "10.0.100.0/24",
					RangeStart: "10.0.100.10",
					RangeEnd:   "10.0.100.250",
					LeaseTime:  3600,
				},
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
				},
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:       200,
				Zone:       "control-plane",
				StaticIP:   "10.0.200.50/24",
				Gateway:    "10.0.200.1",
				DNS:        []string{"10.0.200.2"},
				AuthMethod: entities.AuthMethod802_1X,
			},
			entities.DefaultFailureNetwork: {
				VLAN:    300,
				Zone:    "quarantine",
				Gateway: "10.0.300.1",
				DNS:     []string{"10.0.300.2"},
			},
		},
	}

	t.Run("Generate provisioning config", func(t *testing.T) {
		gen := NewNetworkConfigGenerator(profile)
		config := gen.GenerateProvisioningConfig()

		require.NotNil(t, config)
		assert.Equal(t, uint16(100), config.VLAN)
		assert.Equal(t, "provisioning", config.Zone)
		assert.Equal(t, "10.0.100.1", config.Gateway)
		assert.Len(t, config.DNS, 2)
		assert.Contains(t, config.DNS, "10.0.100.2")
		assert.Equal(t, entities.AuthMethodNone, config.AuthMethod)

		// Verify DHCP pool
		require.NotNil(t, config.DHCPPool)
		assert.Equal(t, "10.0.100.0/24", config.DHCPPool.Network)
		assert.Equal(t, "10.0.100.10", config.DHCPPool.RangeStart)
		assert.Equal(t, "10.0.100.250", config.DHCPPool.RangeEnd)
		assert.Equal(t, 3600, config.DHCPPool.LeaseTime)

		// Verify ACLs
		assert.Len(t, config.ACLs, 1)
		assert.Equal(t, 100, config.ACLs[0].Priority)
		assert.Equal(t, "tcp", config.ACLs[0].Protocol)
		assert.Equal(t, uint16(443), config.ACLs[0].DstPort)
	})

	t.Run("Generate admitted config", func(t *testing.T) {
		gen := NewNetworkConfigGenerator(profile)
		config := gen.GenerateAdmittedConfig()

		require.NotNil(t, config)
		assert.Equal(t, uint16(200), config.VLAN)
		assert.Equal(t, "control-plane", config.Zone)
		assert.Equal(t, "10.0.200.50/24", config.StaticIP)
		assert.Equal(t, "10.0.200.1", config.Gateway)
		assert.Len(t, config.DNS, 1)
		assert.Contains(t, config.DNS, "10.0.200.2")
		assert.Equal(t, entities.AuthMethod802_1X, config.AuthMethod)
	})

	t.Run("Generate quarantine config", func(t *testing.T) {
		gen := NewNetworkConfigGenerator(profile)
		config := gen.GenerateQuarantineConfig()

		require.NotNil(t, config)
		assert.Equal(t, uint16(300), config.VLAN)
		assert.Equal(t, "quarantine", config.Zone)
		assert.Equal(t, "10.0.300.1", config.Gateway)
		assert.Len(t, config.DNS, 1)
	})

	t.Run("Extract ACLs", func(t *testing.T) {
		gen := NewNetworkConfigGenerator(profile)
		acls := gen.ExtractACLs(profile.GetEnrollmentNetworkConfig())

		require.Len(t, acls, 1)
		assert.Equal(t, 100, acls[0].Priority)
		assert.Equal(t, "tcp", acls[0].Protocol)
		assert.Equal(t, "allow", acls[0].Action)
	})

	t.Run("Nil profile returns nil configs", func(t *testing.T) {
		gen := NewNetworkConfigGenerator(nil)

		assert.Nil(t, gen.GenerateProvisioningConfig())
		assert.Nil(t, gen.GenerateAdmittedConfig())
		assert.Nil(t, gen.GenerateQuarantineConfig())
	})

	t.Run("Nil network config returns nil", func(t *testing.T) {
		emptyProfile := &entities.DeviceProfile{
			ID:   2,
			Name: "empty",
		}
		gen := NewNetworkConfigGenerator(emptyProfile)

		assert.Nil(t, gen.GenerateProvisioningConfig())
		assert.Nil(t, gen.GenerateAdmittedConfig())
		assert.Nil(t, gen.GenerateQuarantineConfig())
	})
}

func TestSystemdNetworkdConfigGenerator(t *testing.T) {
	t.Run("Generate static IP config with zone comment", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			VLAN:     200,
			Zone:     "control-plane",
			StaticIP: "10.0.200.50/24",
			Gateway:  "10.0.200.1",
			DNS:      []string{"10.0.200.2", "10.0.200.3"},
		}

		gen := NewSystemdNetworkdConfigGenerator("eth0")
		output := gen.Generate(config)

		assert.NotEmpty(t, output)
		// Zone comment must appear before Match section.
		assert.Contains(t, output, "# trusted-platform-zone: control-plane")
		assert.Contains(t, output, "[Match]")
		assert.Contains(t, output, "Name=eth0")
		assert.Contains(t, output, "[Network]")
		assert.Contains(t, output, "Address=10.0.200.50/24")
		assert.Contains(t, output, "Gateway=10.0.200.1")
		assert.Contains(t, output, "DNS=10.0.200.2")
		assert.Contains(t, output, "DNS=10.0.200.3")
		assert.Contains(t, output, "[VLAN]")
		assert.Contains(t, output, "Id=200")
	})

	t.Run("Generate config without zone emits no comment", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			VLAN:     200,
			StaticIP: "10.0.200.50/24",
			Gateway:  "10.0.200.1",
		}

		gen := NewSystemdNetworkdConfigGenerator("eth0")
		output := gen.Generate(config)

		assert.NotContains(t, output, "trusted-platform-zone")
		assert.Contains(t, output, "[Match]")
	})

	t.Run("Generate DHCP config", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			DHCP:    true,
			Gateway: "10.0.100.1",
			DNS:     []string{"10.0.100.2"},
		}

		gen := NewSystemdNetworkdConfigGenerator("eth0")
		output := gen.Generate(config)

		assert.NotEmpty(t, output)
		assert.Contains(t, output, "DHCP=yes")
		assert.Contains(t, output, "Gateway=10.0.100.1")
		assert.Contains(t, output, "DNS=10.0.100.2")
	})

	t.Run("Generate config with legacy DNSServers field", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			StaticIP:   "10.0.100.10/24",
			Gateway:    "10.0.100.1",
			DNSServers: []string{"8.8.8.8", "8.8.4.4"},
		}

		gen := NewSystemdNetworkdConfigGenerator("eth1")
		output := gen.Generate(config)

		assert.Contains(t, output, "DNS=8.8.8.8")
		assert.Contains(t, output, "DNS=8.8.4.4")
	})

	t.Run("DNS field takes precedence over DNSServers", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			StaticIP:   "10.0.100.10/24",
			DNS:        []string{"10.0.100.2"},
			DNSServers: []string{"8.8.8.8"}, // Should be ignored
		}

		gen := NewSystemdNetworkdConfigGenerator("eth0")
		output := gen.Generate(config)

		assert.Contains(t, output, "DNS=10.0.100.2")
		assert.NotContains(t, output, "DNS=8.8.8.8")
	})

	t.Run("Generate filename", func(t *testing.T) {
		gen := NewSystemdNetworkdConfigGenerator("eth0")

		filename := gen.GenerateFilename("provisioning")
		assert.Equal(t, "10-eth0-provisioning.network", filename)

		filename = gen.GenerateFilename("admitted")
		assert.Equal(t, "10-eth0-admitted.network", filename)
	})

	t.Run("Nil config returns empty string", func(t *testing.T) {
		gen := NewSystemdNetworkdConfigGenerator("eth0")
		output := gen.Generate(nil)
		assert.Empty(t, output)
	})

	t.Run("Config without VLAN", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			StaticIP: "192.168.1.10/24",
			Gateway:  "192.168.1.1",
		}

		gen := NewSystemdNetworkdConfigGenerator("eth0")
		output := gen.Generate(config)

		assert.Contains(t, output, "Address=192.168.1.10/24")
		assert.NotContains(t, output, "[VLAN]")
	})
}

func TestDnsmasqConfigGenerator(t *testing.T) {
	t.Run("Generate DHCP server config", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			VLAN: 100,
			DHCPPool: &entities.DHCPPoolConfig{
				Network:    "10.0.100.0/24",
				RangeStart: "10.0.100.10",
				RangeEnd:   "10.0.100.250",
				LeaseTime:  3600,
			},
			Gateway: "10.0.100.1",
			DNS:     []string{"10.0.100.2", "10.0.100.3"},
		}

		gen := NewDnsmasqConfigGenerator("eth0")
		output := gen.Generate(config)

		assert.NotEmpty(t, output)
		assert.Contains(t, output, "interface=eth0")
		assert.Contains(t, output, "bind-interfaces")
		assert.Contains(t, output, "dhcp-range=10.0.100.10,10.0.100.250,3600")
		assert.Contains(t, output, "dhcp-option=option:router,10.0.100.1")
		assert.Contains(t, output, "dhcp-option=option:dns-server,10.0.100.2")
		assert.Contains(t, output, "dhcp-option=option:dns-server,10.0.100.3")
	})

	t.Run("Generate config without gateway", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			DHCPPool: &entities.DHCPPoolConfig{
				Network:    "10.0.100.0/24",
				RangeStart: "10.0.100.10",
				RangeEnd:   "10.0.100.250",
				LeaseTime:  7200,
			},
			DNS: []string{"8.8.8.8"},
		}

		gen := NewDnsmasqConfigGenerator("eth0")
		output := gen.Generate(config)

		assert.Contains(t, output, "dhcp-range=10.0.100.10,10.0.100.250,7200")
		assert.NotContains(t, output, "option:router")
		assert.Contains(t, output, "dhcp-option=option:dns-server,8.8.8.8")
	})

	t.Run("Generate config without DNS", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			DHCPPool: &entities.DHCPPoolConfig{
				Network:    "10.0.100.0/24",
				RangeStart: "10.0.100.10",
				RangeEnd:   "10.0.100.250",
				LeaseTime:  3600,
			},
			Gateway: "10.0.100.1",
		}

		gen := NewDnsmasqConfigGenerator("eth0")
		output := gen.Generate(config)

		assert.Contains(t, output, "dhcp-option=option:router,10.0.100.1")
		assert.NotContains(t, output, "option:dns-server")
	})

	t.Run("Generate filename", func(t *testing.T) {
		gen := NewDnsmasqConfigGenerator("eth0")

		filename := gen.GenerateFilename("provisioning")
		assert.Equal(t, "dnsmasq-provisioning.conf", filename)
	})

	t.Run("Nil config returns empty string", func(t *testing.T) {
		gen := NewDnsmasqConfigGenerator("eth0")
		output := gen.Generate(nil)
		assert.Empty(t, output)
	})

	t.Run("Config without DHCP pool returns empty string", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			StaticIP: "10.0.100.10/24",
			Gateway:  "10.0.100.1",
		}

		gen := NewDnsmasqConfigGenerator("eth0")
		output := gen.Generate(config)
		assert.Empty(t, output)
	})

	t.Run("Use legacy DNSServers field", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			DHCPPool: &entities.DHCPPoolConfig{
				Network:    "10.0.100.0/24",
				RangeStart: "10.0.100.10",
				RangeEnd:   "10.0.100.250",
				LeaseTime:  3600,
			},
			DNSServers: []string{"8.8.8.8", "8.8.4.4"},
		}

		gen := NewDnsmasqConfigGenerator("eth0")
		output := gen.Generate(config)

		assert.Contains(t, output, "dhcp-option=option:dns-server,8.8.8.8")
		assert.Contains(t, output, "dhcp-option=option:dns-server,8.8.4.4")
	})
}

func TestNetworkConfigWriter(t *testing.T) {
	tmpDir := t.TempDir()

	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "test-device",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:    100,
				Zone:    "provisioning",
				Gateway: "10.0.100.1",
				DNS:     []string{"10.0.100.2"},
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:     200,
				Zone:     "control-plane",
				StaticIP: "10.0.200.50/24",
				Gateway:  "10.0.200.1",
				DNS:      []string{"10.0.200.2"},
			},
			entities.DefaultFailureNetwork: {
				VLAN:    300,
				Zone:    "quarantine",
				Gateway: "10.0.300.1",
			},
		},
	}

	t.Run("Get directory paths", func(t *testing.T) {
		writer := NewNetworkConfigWriter(tmpDir, profile)

		netConfigDir := writer.GetNetworkConfigDir()
		assert.Equal(t, filepath.Join(tmpDir, "etc", "platformd", "network"), netConfigDir)

		systemdDir := writer.GetSystemdNetworkdDir()
		assert.Equal(t, filepath.Join(tmpDir, "etc", "systemd", "network"), systemdDir)

		dnsmasqDir := writer.GetDnsmasqConfigDir()
		assert.Equal(t, filepath.Join(tmpDir, "etc", "dnsmasq.d"), dnsmasqDir)
	})

	t.Run("Get config file paths", func(t *testing.T) {
		writer := NewNetworkConfigWriter(tmpDir, profile)

		provPath := writer.GetProvisioningConfigPath()
		assert.Equal(t, filepath.Join(tmpDir, "etc", "platformd", "network", "provisioning.yaml"), provPath)

		prodPath := writer.GetAdmittedConfigPath()
		assert.Equal(t, filepath.Join(tmpDir, "etc", "platformd", "network", "admitted.yaml"), prodPath)

		quarPath := writer.GetQuarantineConfigPath()
		assert.Equal(t, filepath.Join(tmpDir, "etc", "platformd", "network", "quarantine.yaml"), quarPath)

		apiPath := writer.GetPlatformAPIConfigPath()
		assert.Equal(t, filepath.Join(tmpDir, "etc", "platformd", "network", "platform-api.yaml"), apiPath)

		envPath := writer.GetNetworkEnvPath()
		assert.Equal(t, filepath.Join(tmpDir, "etc", "platformd", "network", "network.env"), envPath)
	})

	t.Run("Writer with nil profile", func(t *testing.T) {
		writer := NewNetworkConfigWriter(tmpDir, nil)
		assert.NotNil(t, writer)
		assert.NotNil(t, writer.generator)

		// Should not panic when accessing methods
		assert.Nil(t, writer.generator.GenerateProvisioningConfig())
	})
}

func TestPlatformAPIConfig(t *testing.T) {
	t.Run("Create platform API config", func(t *testing.T) {
		config := &PlatformAPIConfig{
			Endpoint:   "https://platform.example.com/api/v1",
			ProfileID:  12345,
			TLSVerify:  true,
			CACertPath: "/etc/ssl/certs/ca-bundle.crt",
		}

		assert.Equal(t, "https://platform.example.com/api/v1", config.Endpoint)
		assert.Equal(t, uint64(12345), config.ProfileID)
		assert.True(t, config.TLSVerify)
		assert.Equal(t, "/etc/ssl/certs/ca-bundle.crt", config.CACertPath)
	})

	t.Run("Create platform API config with profile name", func(t *testing.T) {
		config := &PlatformAPIConfig{
			Endpoint:    "https://platform.example.com/api/v1",
			ProfileName: "default-server",
			TLSVerify:   false,
		}

		assert.Equal(t, "default-server", config.ProfileName)
		assert.Equal(t, uint64(0), config.ProfileID)
		assert.False(t, config.TLSVerify)
	})
}

// TestZoneNetworkSet verifies ZoneNetworkSet population from device profiles.
func TestZoneNetworkSet(t *testing.T) {
	t.Run("Explicit zones in all phases", func(t *testing.T) {
		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "full-zones",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork: {
					VLAN: 100,
					Zone: "provisioning",
				},
				entities.DefaultPostEnrollmentNetwork: {
					VLAN: 200,
					Zone: "control-plane",
				},
				entities.DefaultFailureNetwork: {
					VLAN: 300,
					Zone: "quarantine",
				},
			},
		}

		gen := NewNetworkConfigGenerator(profile)
		set := gen.ExtractZoneNetworks()

		assert.Equal(t, "provisioning", set.Provisioning.Zone)
		assert.Equal(t, "provisioning", set.Provisioning.Name)
		assert.Equal(t, uint16(100), set.Provisioning.VLAN)

		assert.Equal(t, "control-plane", set.Admitted.Zone)
		assert.Equal(t, "admitted", set.Admitted.Name)
		assert.Equal(t, uint16(200), set.Admitted.VLAN)

		assert.Equal(t, "quarantine", set.Quarantine.Zone)
		assert.Equal(t, "quarantine", set.Quarantine.Name)
		assert.Equal(t, uint16(300), set.Quarantine.VLAN)
	})

	t.Run("Profile-level zone fallback for admitted phase", func(t *testing.T) {
		// The profile.Zone field is the fallback when the per-network Zone is
		// empty. GetPostEnrollmentNetworkConfig applies this fallback.
		profile := &entities.DeviceProfile{
			ID:   2,
			Name: "profile-zone-fallback",
			Zone: "ops",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultPostEnrollmentNetwork: {
					VLAN: 200,
					// Zone intentionally empty — should inherit from profile.Zone
				},
			},
		}

		gen := NewNetworkConfigGenerator(profile)
		set := gen.ExtractZoneNetworks()

		assert.Equal(t, "ops", set.Admitted.Zone)
		assert.Equal(t, "admitted", set.Admitted.Name)
		assert.Equal(t, uint16(200), set.Admitted.VLAN)
	})

	t.Run("Missing zone yields empty string not an error", func(t *testing.T) {
		// No zone on the network config and no profile.Zone — consistent with
		// how missing VLANs yield zero (no error).
		profile := &entities.DeviceProfile{
			ID:   3,
			Name: "no-zones",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork:     {VLAN: 100},
				entities.DefaultPostEnrollmentNetwork: {VLAN: 200},
				entities.DefaultFailureNetwork:        {VLAN: 300},
			},
		}

		gen := NewNetworkConfigGenerator(profile)
		set := gen.ExtractZoneNetworks()

		assert.Empty(t, set.Provisioning.Zone)
		assert.Equal(t, uint16(100), set.Provisioning.VLAN)
		assert.Empty(t, set.Admitted.Zone)
		assert.Equal(t, uint16(200), set.Admitted.VLAN)
		assert.Empty(t, set.Quarantine.Zone)
		assert.Equal(t, uint16(300), set.Quarantine.VLAN)
	})

	t.Run("Custom enrollment and post-enrollment network names", func(t *testing.T) {
		profile := &entities.DeviceProfile{
			ID:                    4,
			Name:                  "custom-names",
			EnrollmentNetwork:     "onboarding",
			PostEnrollmentNetwork: "production",
			Networks: map[string]*entities.NetworkPhaseConfig{
				"onboarding": {VLAN: 101, Zone: "onboarding"},
				"production": {VLAN: 201, Zone: "production"},
			},
		}

		gen := NewNetworkConfigGenerator(profile)
		set := gen.ExtractZoneNetworks()

		assert.Equal(t, "onboarding", set.Provisioning.Name)
		assert.Equal(t, "onboarding", set.Provisioning.Zone)
		assert.Equal(t, uint16(101), set.Provisioning.VLAN)

		assert.Equal(t, "production", set.Admitted.Name)
		assert.Equal(t, "production", set.Admitted.Zone)
		assert.Equal(t, uint16(201), set.Admitted.VLAN)
	})

	t.Run("Nil profile returns empty ZoneNetworkSet", func(t *testing.T) {
		gen := NewNetworkConfigGenerator(nil)
		set := gen.ExtractZoneNetworks()

		assert.Empty(t, set.Provisioning.Zone)
		assert.Empty(t, set.Provisioning.Name)
		assert.Equal(t, uint16(0), set.Provisioning.VLAN)
		assert.Empty(t, set.Admitted.Zone)
		assert.Empty(t, set.Admitted.Name)
		assert.Equal(t, uint16(0), set.Admitted.VLAN)
		assert.Empty(t, set.Quarantine.Zone)
		assert.Empty(t, set.Quarantine.Name)
		assert.Equal(t, uint16(0), set.Quarantine.VLAN)
	})

	t.Run("Missing networks yields name-only ZoneNetwork entries", func(t *testing.T) {
		// Profile defined but no Networks entries — each ZoneNetwork should
		// carry the default name but zero VLAN and empty zone.
		profile := &entities.DeviceProfile{ID: 5, Name: "empty-networks"}

		gen := NewNetworkConfigGenerator(profile)
		set := gen.ExtractZoneNetworks()

		assert.Equal(t, entities.DefaultEnrollmentNetwork, set.Provisioning.Name)
		assert.Empty(t, set.Provisioning.Zone)
		assert.Equal(t, uint16(0), set.Provisioning.VLAN)

		assert.Equal(t, entities.DefaultPostEnrollmentNetwork, set.Admitted.Name)
		assert.Empty(t, set.Admitted.Zone)
		assert.Equal(t, uint16(0), set.Admitted.VLAN)

		assert.Equal(t, entities.DefaultFailureNetwork, set.Quarantine.Name)
		assert.Empty(t, set.Quarantine.Zone)
		assert.Equal(t, uint16(0), set.Quarantine.VLAN)
	})
}

// TestNetworkConfigDeepCopy verifies that copyNetworkConfig creates independent copies.
func TestNetworkConfigDeepCopy(t *testing.T) {
	original := &entities.NetworkPhaseConfig{
		VLAN:    100,
		Zone:    "provisioning",
		Gateway: "10.0.100.1",
		DNS:     []string{"10.0.100.2", "10.0.100.3"},
		DHCPPool: &entities.DHCPPoolConfig{
			Network:    "10.0.100.0/24",
			RangeStart: "10.0.100.10",
			RangeEnd:   "10.0.100.250",
			LeaseTime:  3600,
		},
		ACLs: []entities.ACLConfig{
			{Priority: 100, Protocol: "tcp", Action: "allow"},
		},
	}

	profile := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: original,
		},
	}

	gen := NewNetworkConfigGenerator(profile)
	copied := gen.GenerateProvisioningConfig()

	// Modify copy
	copied.VLAN = 999
	copied.Zone = "modified"
	copied.Gateway = "192.168.1.1"
	copied.DNS[0] = "8.8.8.8"
	copied.DHCPPool.LeaseTime = 7200
	copied.ACLs[0].Priority = 200

	// Verify original is unchanged
	assert.Equal(t, uint16(100), original.VLAN)
	assert.Equal(t, "provisioning", original.Zone)
	assert.Equal(t, "10.0.100.1", original.Gateway)
	assert.Equal(t, "10.0.100.2", original.DNS[0])
	assert.Equal(t, 3600, original.DHCPPool.LeaseTime)
	assert.Equal(t, 100, original.ACLs[0].Priority)
}

// TestACLExtraction verifies ACL extraction from network configs.
func TestACLExtraction(t *testing.T) {
	t.Run("Extract valid ACLs", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			VLAN: 100,
			ACLs: []entities.ACLConfig{
				{Priority: 100, Protocol: "tcp", SrcIP: "0.0.0.0/0", DstIP: "10.0.100.1/32", DstPort: 443, Action: "allow"},
				{Priority: 90, Protocol: "udp", SrcIP: "0.0.0.0/0", DstIP: "10.0.100.1/32", DstPort: 53, Action: "allow"},
				{Priority: 80, Protocol: "tcp", SrcIP: "192.168.0.0/16", DstIP: "10.0.100.1/32", DstPort: 22, Action: "deny"},
			},
		}

		profile := &entities.DeviceProfile{
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork: config,
			},
		}

		gen := NewNetworkConfigGenerator(profile)
		acls := gen.ExtractACLs(config)

		require.Len(t, acls, 3)

		assert.Equal(t, 100, acls[0].Priority)
		assert.Equal(t, "tcp", acls[0].Protocol)
		assert.Equal(t, uint16(443), acls[0].DstPort)
		assert.Equal(t, "allow", acls[0].Action)

		assert.Equal(t, 90, acls[1].Priority)
		assert.Equal(t, "udp", acls[1].Protocol)
		assert.Equal(t, uint16(53), acls[1].DstPort)

		assert.Equal(t, 80, acls[2].Priority)
		assert.Equal(t, "deny", acls[2].Action)
	})

	t.Run("Extract from nil config", func(t *testing.T) {
		gen := NewNetworkConfigGenerator(nil)
		acls := gen.ExtractACLs(nil)
		assert.Nil(t, acls)
	})

	t.Run("Extract from config with no ACLs", func(t *testing.T) {
		config := &entities.NetworkPhaseConfig{
			VLAN: 100,
		}

		gen := NewNetworkConfigGenerator(nil)
		acls := gen.ExtractACLs(config)
		assert.Nil(t, acls)
	})
}

// TestErrorHandling verifies error conditions are handled properly.
func TestErrorHandling(t *testing.T) {
	t.Run("Empty interface name for systemd-networkd", func(t *testing.T) {
		gen := NewSystemdNetworkdConfigGenerator("")
		config := &entities.NetworkPhaseConfig{
			StaticIP: "10.0.100.10/24",
		}

		output := gen.Generate(config)
		// Should still generate valid config, just with empty interface
		assert.Contains(t, output, "[Match]")
		assert.Contains(t, output, "Name=")
	})

	t.Run("Empty interface name for dnsmasq", func(t *testing.T) {
		gen := NewDnsmasqConfigGenerator("")
		config := &entities.NetworkPhaseConfig{
			DHCPPool: &entities.DHCPPoolConfig{
				Network:    "10.0.100.0/24",
				RangeStart: "10.0.100.10",
				RangeEnd:   "10.0.100.250",
				LeaseTime:  3600,
			},
		}

		output := gen.Generate(config)
		assert.Contains(t, output, "interface=")
	})
}
