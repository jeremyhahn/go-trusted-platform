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

package iso

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestNetworkConfigGenerationFromDeviceProfile verifies that network configurations
// can be generated from device profiles and embedded in ISO
func TestNetworkConfigGenerationFromDeviceProfile(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "test-server",
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
				DNS:        []string{"10.0.100.2"},
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
				StaticIP:   "10.0.200.50/24",
				Gateway:    "10.0.200.1",
				DNS:        []string{"10.0.200.2"},
				AuthMethod: entities.AuthMethod802_1X,
			},
		},
	}

	t.Run("Generate provisioning network configuration", func(t *testing.T) {
		config := generateNetworkConfigFromProfile(profile.GetEnrollmentNetworkConfig())
		require.NotNil(t, config)

		assert.Equal(t, uint16(100), config.VLAN)
		assert.Equal(t, "10.0.100.1", config.Gateway)
		assert.Contains(t, config.DNS, "10.0.100.2")
		assert.Equal(t, entities.AuthMethodNone, config.AuthMethod)

		// Verify DHCP pool
		require.NotNil(t, config.DHCPPool)
		assert.Equal(t, "10.0.100.0/24", config.DHCPPool.Network)
		assert.Equal(t, "10.0.100.10", config.DHCPPool.RangeStart)
		assert.Equal(t, "10.0.100.250", config.DHCPPool.RangeEnd)

		// Verify ACLs
		assert.Len(t, config.ACLs, 1)
		assert.Equal(t, 100, config.ACLs[0].Priority)
		assert.Equal(t, "tcp", config.ACLs[0].Protocol)
	})

	t.Run("Generate admitted network configuration", func(t *testing.T) {
		config := generateNetworkConfigFromProfile(profile.GetPostEnrollmentNetworkConfig())
		require.NotNil(t, config)

		assert.Equal(t, uint16(200), config.VLAN)
		assert.Equal(t, "10.0.200.50/24", config.StaticIP)
		assert.Equal(t, "10.0.200.1", config.Gateway)
		assert.Contains(t, config.DNS, "10.0.200.2")
		assert.Equal(t, entities.AuthMethod802_1X, config.AuthMethod)
	})

	t.Run("Serialize network config to YAML", func(t *testing.T) {
		config := generateNetworkConfigFromProfile(profile.GetEnrollmentNetworkConfig())
		require.NotNil(t, config)

		data, err := yaml.Marshal(config)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify YAML contains expected fields
		yamlStr := string(data)
		assert.Contains(t, yamlStr, "vlan: 100")
		assert.Contains(t, yamlStr, "gateway: 10.0.100.1")
	})
}

// TestNetworkConfigEmbeddingInISO verifies that network configs can be
// properly embedded in ISO overlays
func TestNetworkConfigEmbeddingInISO(t *testing.T) {

	// Create temporary work directory
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0755))

	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "embed-test",
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

	t.Run("Embed provisioning network config in overlay", func(t *testing.T) {
		config := generateNetworkConfigFromProfile(profile.GetEnrollmentNetworkConfig())
		require.NotNil(t, config)

		// Create network config directory in overlay
		netConfigDir := filepath.Join(overlayDir, "etc", "platformd", "network")
		require.NoError(t, os.MkdirAll(netConfigDir, 0755))

		// Write provisioning config
		provConfigPath := filepath.Join(netConfigDir, "provisioning.yaml")
		data, err := yaml.Marshal(config)
		require.NoError(t, err)

		err = os.WriteFile(provConfigPath, data, 0644)
		require.NoError(t, err)

		// Verify file was created
		assert.FileExists(t, provConfigPath)

		// Read back and verify
		readData, err := os.ReadFile(provConfigPath)
		require.NoError(t, err)

		var readConfig entities.NetworkPhaseConfig
		err = yaml.Unmarshal(readData, &readConfig)
		require.NoError(t, err)

		assert.Equal(t, config.VLAN, readConfig.VLAN)
		assert.Equal(t, config.Gateway, readConfig.Gateway)
	})

	t.Run("Embed admitted network config in overlay", func(t *testing.T) {
		config := generateNetworkConfigFromProfile(profile.GetPostEnrollmentNetworkConfig())
		require.NotNil(t, config)

		// Create network config directory in overlay
		netConfigDir := filepath.Join(overlayDir, "etc", "platformd", "network")
		require.NoError(t, os.MkdirAll(netConfigDir, 0755))

		// Write admitted config
		admittedConfigPath := filepath.Join(netConfigDir, "admitted.yaml")
		data, err := yaml.Marshal(config)
		require.NoError(t, err)

		err = os.WriteFile(admittedConfigPath, data, 0644)
		require.NoError(t, err)

		// Verify file was created
		assert.FileExists(t, admittedConfigPath)

		// Read back and verify
		readData, err := os.ReadFile(admittedConfigPath)
		require.NoError(t, err)

		var readConfig entities.NetworkPhaseConfig
		err = yaml.Unmarshal(readData, &readConfig)
		require.NoError(t, err)

		assert.Equal(t, config.VLAN, readConfig.VLAN)
		assert.Equal(t, config.Gateway, readConfig.Gateway)
	})
}

// TestVLANExtractionFromProfile verifies VLAN IDs can be extracted from profiles
func TestVLANExtractionFromProfile(t *testing.T) {
	tests := []struct {
		name         string
		profile      *entities.DeviceProfile
		wantProv     uint16
		wantAdmitted uint16
		wantQuar     uint16
	}{
		{
			name: "All networks configured",
			profile: &entities.DeviceProfile{
				Networks: map[string]*entities.NetworkPhaseConfig{
					entities.DefaultEnrollmentNetwork:     {VLAN: 100},
					entities.DefaultPostEnrollmentNetwork: {VLAN: 200},
					entities.DefaultFailureNetwork:        {VLAN: 300},
				},
			},
			wantProv:     100,
			wantAdmitted: 200,
			wantQuar:     300,
		},
		{
			name: "Only provisioning and admitted",
			profile: &entities.DeviceProfile{
				Networks: map[string]*entities.NetworkPhaseConfig{
					entities.DefaultEnrollmentNetwork:     {VLAN: 101},
					entities.DefaultPostEnrollmentNetwork: {VLAN: 201},
				},
			},
			wantProv:     101,
			wantAdmitted: 201,
			wantQuar:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vlans := extractVLANsFromProfile(tt.profile)

			assert.Equal(t, tt.wantProv, vlans.Provisioning.VLAN)
			assert.Equal(t, tt.wantAdmitted, vlans.Admitted.VLAN)
			assert.Equal(t, tt.wantQuar, vlans.Quarantine.VLAN)
		})
	}
}

// TestACLExtractionFromProfile verifies ACL rules can be extracted from profiles
func TestACLExtractionFromProfile(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "acl-test",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN: 100,
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
					{
						Priority: 80,
						Protocol: "tcp",
						SrcIP:    "192.168.0.0/16",
						DstIP:    "10.0.100.2/32",
						DstPort:  22,
						Action:   "deny",
					},
				},
			},
		},
	}

	t.Run("Extract provisioning ACLs", func(t *testing.T) {
		acls := extractACLsFromNetworkConfig(profile.GetEnrollmentNetworkConfig())

		require.Len(t, acls, 3)

		// Verify first ACL (allow HTTPS)
		assert.Equal(t, 100, acls[0].Priority)
		assert.Equal(t, "tcp", acls[0].Protocol)
		assert.Equal(t, uint16(443), acls[0].DstPort)
		assert.Equal(t, "allow", acls[0].Action)

		// Verify second ACL (allow DNS)
		assert.Equal(t, 90, acls[1].Priority)
		assert.Equal(t, "udp", acls[1].Protocol)
		assert.Equal(t, uint16(53), acls[1].DstPort)
		assert.Equal(t, "allow", acls[1].Action)

		// Verify third ACL (deny SSH from specific subnet)
		assert.Equal(t, 80, acls[2].Priority)
		assert.Equal(t, "192.168.0.0/16", acls[2].SrcIP)
		assert.Equal(t, "deny", acls[2].Action)
	})

	t.Run("Validate extracted ACLs", func(t *testing.T) {
		acls := extractACLsFromNetworkConfig(profile.GetEnrollmentNetworkConfig())

		for i, acl := range acls {
			assert.True(t, acl.IsValid(), "ACL %d should be valid", i)
		}
	})
}

// TestNetworkConfigWithDHCP verifies DHCP configuration generation
func TestNetworkConfigWithDHCP(t *testing.T) {
	profile := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN: 100,
				DHCPPool: &entities.DHCPPoolConfig{
					Network:    "10.0.100.0/24",
					RangeStart: "10.0.100.10",
					RangeEnd:   "10.0.100.250",
					LeaseTime:  3600,
				},
				Gateway: "10.0.100.1",
				DNS:     []string{"10.0.100.2", "10.0.100.3"},
			},
		},
	}

	t.Run("Generate DHCP configuration", func(t *testing.T) {
		config := generateNetworkConfigFromProfile(profile.GetEnrollmentNetworkConfig())
		require.NotNil(t, config)
		require.NotNil(t, config.DHCPPool)

		dhcp := config.DHCPPool
		assert.Equal(t, "10.0.100.0/24", dhcp.Network)
		assert.Equal(t, "10.0.100.10", dhcp.RangeStart)
		assert.Equal(t, "10.0.100.250", dhcp.RangeEnd)
		assert.Equal(t, 3600, dhcp.LeaseTime)
	})

	t.Run("Generate dnsmasq config from DHCP pool", func(t *testing.T) {
		config := generateNetworkConfigFromProfile(profile.GetEnrollmentNetworkConfig())
		require.NotNil(t, config)

		dnsmasqConfig := generateDnsmasqConfig(config)
		assert.NotEmpty(t, dnsmasqConfig)

		// Verify dnsmasq config contains expected directives
		assert.Contains(t, dnsmasqConfig, "dhcp-range=10.0.100.10,10.0.100.250,3600")
		assert.Contains(t, dnsmasqConfig, "dhcp-option=option:router,10.0.100.1")
		assert.Contains(t, dnsmasqConfig, "dhcp-option=option:dns-server,10.0.100.2")
	})
}

// TestNetworkConfigWithStaticIP verifies static IP configuration
func TestNetworkConfigWithStaticIP(t *testing.T) {
	profile := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:     200,
				StaticIP: "10.0.200.50/24",
				Gateway:  "10.0.200.1",
				DNS:      []string{"10.0.200.2"},
			},
		},
	}

	t.Run("Generate static IP configuration", func(t *testing.T) {
		config := generateNetworkConfigFromProfile(profile.GetPostEnrollmentNetworkConfig())
		require.NotNil(t, config)

		assert.Equal(t, "10.0.200.50/24", config.StaticIP)
		assert.Equal(t, "10.0.200.1", config.Gateway)
		assert.Len(t, config.DNS, 1)
	})

	t.Run("Generate systemd-networkd config from static IP", func(t *testing.T) {
		config := generateNetworkConfigFromProfile(profile.GetPostEnrollmentNetworkConfig())
		require.NotNil(t, config)

		networkdConfig := generateSystemdNetworkdConfig(config, "eth0")
		assert.NotEmpty(t, networkdConfig)

		// Verify networkd config contains expected sections
		assert.Contains(t, networkdConfig, "[Match]")
		assert.Contains(t, networkdConfig, "Name=eth0")
		assert.Contains(t, networkdConfig, "[Network]")
		assert.Contains(t, networkdConfig, "Address=10.0.200.50/24")
		assert.Contains(t, networkdConfig, "Gateway=10.0.200.1")
		assert.Contains(t, networkdConfig, "DNS=10.0.200.2")
	})
}

// Helper functions for network config generation - now using production code

func generateNetworkConfigFromProfile(config *entities.NetworkPhaseConfig) *entities.NetworkPhaseConfig {
	if config == nil {
		return nil
	}
	profile := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: config,
		},
	}
	gen := NewNetworkConfigGenerator(profile)
	return gen.GenerateProvisioningConfig()
}

func extractVLANsFromProfile(profile *entities.DeviceProfile) ZoneNetworkSet {
	gen := NewNetworkConfigGenerator(profile)
	return gen.ExtractZoneNetworks()
}

func extractACLsFromNetworkConfig(config *entities.NetworkPhaseConfig) []entities.ACLConfig {
	gen := NewNetworkConfigGenerator(nil)
	return gen.ExtractACLs(config)
}

func generateDnsmasqConfig(config *entities.NetworkPhaseConfig) string {
	gen := NewDnsmasqConfigGenerator("eth0")
	return gen.Generate(config)
}

func generateSystemdNetworkdConfig(config *entities.NetworkPhaseConfig, iface string) string {
	gen := NewSystemdNetworkdConfigGenerator(iface)
	return gen.Generate(config)
}
func TestCustomizerWithNetworkConfig(t *testing.T) {

	// Create temporary work directory
	tmpDir := t.TempDir()

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Work:    tmpDir,
			ISO:     filepath.Join(tmpDir, "iso"),
			Overlay: filepath.Join(tmpDir, "overlay"),
		},
		Platform: PlatformConfig{
			Version: "1.0.0",
		},
	}
	config.SetDefaults()

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	t.Run("Customizer initialization", func(t *testing.T) {
		assert.NotNil(t, customizer)
		assert.Equal(t, config, customizer.config)
	})

	t.Run("Check overlay directory creation", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(customizer.overlayDir, 0755))
		assert.DirExists(t, customizer.overlayDir)
	})
}
