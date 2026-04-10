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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestCustomizer_EmbedDeviceProfileNetworkConfig(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")

	profile := &entities.DeviceProfile{
		ID:    1,
		Name:  "test-server",
		Model: "TestServer",
		Role:  entities.DeviceRoleServer,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:    100,
				Gateway: "10.0.100.1",
				DNS:     []string{"10.0.100.2", "10.0.100.3"},
				DHCPPool: &entities.DHCPPoolConfig{
					Network:    "10.0.100.0/24",
					RangeStart: "10.0.100.10",
					RangeEnd:   "10.0.100.250",
					LeaseTime:  3600,
				},
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:     200,
				StaticIP: "10.0.200.50/24",
				Gateway:  "10.0.200.1",
				DNS:      []string{"10.0.200.2"},
			},
			entities.DefaultFailureNetwork: {
				VLAN:    300,
				Gateway: "10.0.300.1",
				DNS:     []string{"10.0.300.2"},
			},
		},
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay: overlayDir,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	ctx := context.Background()

	t.Run("Embed all network phase configs", func(t *testing.T) {
		err := customizer.EmbedDeviceProfileNetworkConfig(ctx, profile)
		require.NoError(t, err)

		// Verify provisioning config was created
		provConfigPath := filepath.Join(overlayDir, "etc", "platformd", "network", "provisioning.yaml")
		assert.FileExists(t, provConfigPath)

		// Verify production config was created
		prodConfigPath := filepath.Join(overlayDir, "etc", "platformd", "network", "production.yaml")
		assert.FileExists(t, prodConfigPath)

		// Verify quarantine config was created
		quarConfigPath := filepath.Join(overlayDir, "etc", "platformd", "network", "quarantine.yaml")
		assert.FileExists(t, quarConfigPath)
	})

	t.Run("Verify provisioning config content", func(t *testing.T) {
		provConfigPath := filepath.Join(overlayDir, "etc", "platformd", "network", "provisioning.yaml")
		data, err := os.ReadFile(provConfigPath)
		require.NoError(t, err)

		var config entities.NetworkPhaseConfig
		err = yaml.Unmarshal(data, &config)
		require.NoError(t, err)

		assert.Equal(t, uint16(100), config.VLAN)
		assert.Equal(t, "10.0.100.1", config.Gateway)
		assert.Len(t, config.DNS, 2)
		require.NotNil(t, config.DHCPPool)
		assert.Equal(t, "10.0.100.0/24", config.DHCPPool.Network)
	})

	t.Run("Verify systemd-networkd configs created", func(t *testing.T) {
		systemdDir := filepath.Join(overlayDir, "etc", "systemd", "network")

		provNetworkdPath := filepath.Join(systemdDir, "10-eth0-provisioning.network")
		assert.FileExists(t, provNetworkdPath)

		prodNetworkdPath := filepath.Join(systemdDir, "10-eth0-production.network")
		assert.FileExists(t, prodNetworkdPath)

		quarNetworkdPath := filepath.Join(systemdDir, "10-eth0-quarantine.network")
		assert.FileExists(t, quarNetworkdPath)
	})

	t.Run("Verify dnsmasq config created for provisioning", func(t *testing.T) {
		dnsmasqDir := filepath.Join(overlayDir, "etc", "dnsmasq.d")
		dnsmasqPath := filepath.Join(dnsmasqDir, "dnsmasq-provisioning.conf")

		assert.FileExists(t, dnsmasqPath)

		content, err := os.ReadFile(dnsmasqPath)
		require.NoError(t, err)

		assert.Contains(t, string(content), "dhcp-range=10.0.100.10,10.0.100.250,3600")
	})

	t.Run("Nil profile does not error", func(t *testing.T) {
		err := customizer.EmbedDeviceProfileNetworkConfig(ctx, nil)
		require.NoError(t, err)
	})
}

func TestCustomizer_EmbedNetworkPhaseConfig(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")

	profile := &entities.DeviceProfile{
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:     100,
				StaticIP: "10.0.100.10/24",
				Gateway:  "10.0.100.1",
				DNS:      []string{"10.0.100.2"},
			},
		},
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay: overlayDir,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	writer := NewNetworkConfigWriter(overlayDir, profile)
	gen := NewNetworkConfigGenerator(profile)

	t.Run("Embed provisioning phase config", func(t *testing.T) {
		// Create network config directory
		require.NoError(t, os.MkdirAll(writer.GetNetworkConfigDir(), 0755))

		err := customizer.embedNetworkPhaseConfig(
			writer,
			gen,
			"provisioning",
			gen.GenerateProvisioningConfig(),
		)
		require.NoError(t, err)

		// Verify config file was created
		configPath := writer.GetProvisioningConfigPath()
		assert.FileExists(t, configPath)

		// Verify content
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)

		var config entities.NetworkPhaseConfig
		err = yaml.Unmarshal(data, &config)
		require.NoError(t, err)

		assert.Equal(t, uint16(100), config.VLAN)
		assert.Equal(t, "10.0.100.10/24", config.StaticIP)
	})

	t.Run("Nil config does not error", func(t *testing.T) {
		err := customizer.embedNetworkPhaseConfig(writer, gen, "production", nil)
		require.NoError(t, err)
	})

	t.Run("Unknown phase returns error", func(t *testing.T) {
		err := customizer.embedNetworkPhaseConfig(
			writer,
			gen,
			"unknown-phase",
			gen.GenerateProvisioningConfig(),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown network phase")
	})
}

func TestCustomizer_EmbedSystemdNetworkdConfig(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")

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

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay: overlayDir,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	writer := NewNetworkConfigWriter(overlayDir, profile)

	t.Run("Generate systemd-networkd config", func(t *testing.T) {
		err := customizer.embedSystemdNetworkdConfig(
			writer,
			profile.GetPostEnrollmentNetworkConfig(),
			"production",
		)
		require.NoError(t, err)

		// Verify config file was created
		systemdDir := writer.GetSystemdNetworkdDir()
		configPath := filepath.Join(systemdDir, "10-eth0-production.network")
		assert.FileExists(t, configPath)

		// Verify content
		content, err := os.ReadFile(configPath)
		require.NoError(t, err)

		assert.Contains(t, string(content), "[Match]")
		assert.Contains(t, string(content), "Name=eth0")
		assert.Contains(t, string(content), "Address=10.0.200.50/24")
		assert.Contains(t, string(content), "Gateway=10.0.200.1")
		assert.Contains(t, string(content), "DNS=10.0.200.2")
		assert.Contains(t, string(content), "Id=200")
	})

	t.Run("Empty config does not create file", func(t *testing.T) {
		emptyConfig := &entities.NetworkPhaseConfig{}
		err := customizer.embedSystemdNetworkdConfig(writer, emptyConfig, "test")
		require.NoError(t, err)
	})
}

func TestCustomizer_EmbedDnsmasqConfig(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")

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

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay: overlayDir,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	writer := NewNetworkConfigWriter(overlayDir, profile)

	t.Run("Generate dnsmasq config", func(t *testing.T) {
		err := customizer.embedDnsmasqConfig(
			writer,
			profile.GetEnrollmentNetworkConfig(),
			"provisioning",
		)
		require.NoError(t, err)

		// Verify config file was created
		dnsmasqDir := writer.GetDnsmasqConfigDir()
		configPath := filepath.Join(dnsmasqDir, "dnsmasq-provisioning.conf")
		assert.FileExists(t, configPath)

		// Verify content
		content, err := os.ReadFile(configPath)
		require.NoError(t, err)

		contentStr := string(content)
		assert.Contains(t, contentStr, "interface=eth0")
		assert.Contains(t, contentStr, "dhcp-range=10.0.100.10,10.0.100.250,3600")
		assert.Contains(t, contentStr, "dhcp-option=option:router,10.0.100.1")
		assert.Contains(t, contentStr, "dhcp-option=option:dns-server,10.0.100.2")
	})

	t.Run("Config without DHCP pool does not create file", func(t *testing.T) {
		configNoDHCP := &entities.NetworkPhaseConfig{
			VLAN:    200,
			Gateway: "10.0.200.1",
		}
		err := customizer.embedDnsmasqConfig(writer, configNoDHCP, "production")
		require.NoError(t, err)
	})
}

func TestCustomizer_EmbedPlatformAPIConfig(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay: overlayDir,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	ctx := context.Background()

	t.Run("Embed platform API config with profile ID", func(t *testing.T) {
		apiConfig := &PlatformAPIConfig{
			Endpoint:   "https://platform.example.com/api/v1",
			ProfileID:  12345,
			TLSVerify:  true,
			CACertPath: "/etc/ssl/certs/ca-bundle.crt",
		}

		err := customizer.EmbedPlatformAPIConfig(ctx, apiConfig)
		require.NoError(t, err)

		// Verify config file was created
		configPath := filepath.Join(overlayDir, "etc", "platformd", "network", "platform-api.yaml")
		assert.FileExists(t, configPath)

		// Verify content
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)

		var loaded PlatformAPIConfig
		err = yaml.Unmarshal(data, &loaded)
		require.NoError(t, err)

		assert.Equal(t, "https://platform.example.com/api/v1", loaded.Endpoint)
		assert.Equal(t, uint64(12345), loaded.ProfileID)
		assert.True(t, loaded.TLSVerify)
		assert.Equal(t, "/etc/ssl/certs/ca-bundle.crt", loaded.CACertPath)
	})

	t.Run("Embed platform API config with profile name", func(t *testing.T) {
		apiConfig := &PlatformAPIConfig{
			Endpoint:    "https://platform.example.com/api/v1",
			ProfileName: "default-server",
			TLSVerify:   false,
		}

		err := customizer.EmbedPlatformAPIConfig(ctx, apiConfig)
		require.NoError(t, err)

		// Verify config file was created
		configPath := filepath.Join(overlayDir, "etc", "platformd", "network", "platform-api.yaml")
		assert.FileExists(t, configPath)

		// Verify content
		data, err := os.ReadFile(configPath)
		require.NoError(t, err)

		var loaded PlatformAPIConfig
		err = yaml.Unmarshal(data, &loaded)
		require.NoError(t, err)

		assert.Equal(t, "default-server", loaded.ProfileName)
		assert.False(t, loaded.TLSVerify)
	})

	t.Run("Nil API config does not error", func(t *testing.T) {
		err := customizer.EmbedPlatformAPIConfig(ctx, nil)
		require.NoError(t, err)
	})

	t.Run("Empty endpoint does not error", func(t *testing.T) {
		apiConfig := &PlatformAPIConfig{
			ProfileID: 123,
		}
		err := customizer.EmbedPlatformAPIConfig(ctx, apiConfig)
		require.NoError(t, err)
	})
}

func TestCustomizer_MultiPhaseNetworkConfig(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")

	// Profile with different configs for each phase
	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "multi-phase-test",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN: 100,
				DHCP: true,
				DHCPPool: &entities.DHCPPoolConfig{
					Network:    "10.0.100.0/24",
					RangeStart: "10.0.100.10",
					RangeEnd:   "10.0.100.250",
					LeaseTime:  3600,
				},
				Gateway: "10.0.100.1",
				DNS:     []string{"10.0.100.2"},
			},
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:     200,
				StaticIP: "10.0.200.50/24",
				Gateway:  "10.0.200.1",
				DNS:      []string{"10.0.200.2", "10.0.200.3"},
			},
			entities.DefaultFailureNetwork: {
				VLAN:    300,
				DHCP:    true,
				Gateway: "10.0.300.1",
				DNS:     []string{"10.0.300.2"},
			},
		},
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay: overlayDir,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	ctx := context.Background()

	t.Run("Embed all phases with different configs", func(t *testing.T) {
		err := customizer.EmbedDeviceProfileNetworkConfig(ctx, profile)
		require.NoError(t, err)

		// Verify all YAML configs created
		netConfigDir := filepath.Join(overlayDir, "etc", "platformd", "network")
		assert.FileExists(t, filepath.Join(netConfigDir, "provisioning.yaml"))
		assert.FileExists(t, filepath.Join(netConfigDir, "production.yaml"))
		assert.FileExists(t, filepath.Join(netConfigDir, "quarantine.yaml"))

		// Verify all systemd-networkd configs created
		systemdDir := filepath.Join(overlayDir, "etc", "systemd", "network")
		assert.FileExists(t, filepath.Join(systemdDir, "10-eth0-provisioning.network"))
		assert.FileExists(t, filepath.Join(systemdDir, "10-eth0-production.network"))
		assert.FileExists(t, filepath.Join(systemdDir, "10-eth0-quarantine.network"))

		// Verify dnsmasq only created for provisioning (has DHCP pool)
		dnsmasqDir := filepath.Join(overlayDir, "etc", "dnsmasq.d")
		assert.FileExists(t, filepath.Join(dnsmasqDir, "dnsmasq-provisioning.conf"))
		// Production and quarantine should not have dnsmasq configs
		assert.NoFileExists(t, filepath.Join(dnsmasqDir, "dnsmasq-production.conf"))
		assert.NoFileExists(t, filepath.Join(dnsmasqDir, "dnsmasq-quarantine.conf"))
	})
}

func TestCustomizer_PartialProfileConfig(t *testing.T) {
	tmpDir := t.TempDir()
	overlayDir := filepath.Join(tmpDir, "overlay")

	// Profile with only provisioning network
	profile := &entities.DeviceProfile{
		ID:   1,
		Name: "partial-profile",
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultEnrollmentNetwork: {
				VLAN:    100,
				Gateway: "10.0.100.1",
				DNS:     []string{"10.0.100.2"},
			},
		},
		// No production or quarantine networks
	}

	config := &PlatformISOConfig{
		Directories: DirectoryConfig{
			Overlay: overlayDir,
		},
	}

	logger := logging.DefaultLogger()
	customizer := NewCustomizer(config, logger)

	ctx := context.Background()

	t.Run("Embed only configured phases", func(t *testing.T) {
		err := customizer.EmbedDeviceProfileNetworkConfig(ctx, profile)
		require.NoError(t, err)

		// Only provisioning should be created
		netConfigDir := filepath.Join(overlayDir, "etc", "platformd", "network")
		assert.FileExists(t, filepath.Join(netConfigDir, "provisioning.yaml"))

		// Production and quarantine should not be created
		assert.NoFileExists(t, filepath.Join(netConfigDir, "production.yaml"))
		assert.NoFileExists(t, filepath.Join(netConfigDir, "quarantine.yaml"))
	})
}
