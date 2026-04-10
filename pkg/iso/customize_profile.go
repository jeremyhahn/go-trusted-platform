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
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// EmbedDeviceProfileNetworkConfig embeds device profile network configurations into the ISO overlay
func (c *Customizer) EmbedDeviceProfileNetworkConfig(ctx context.Context, profile *entities.DeviceProfile) error {
	if profile == nil {
		c.logger.Debug("No device profile provided, skipping network config embedding")
		return nil
	}

	c.logger.Info("Embedding device profile network configurations")

	// Create network config writer
	writer := NewNetworkConfigWriter(c.overlayDir, profile)

	// Create network config directory
	netConfigDir := writer.GetNetworkConfigDir()
	if err := os.MkdirAll(netConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create network config directory: %w", err)
	}

	// Generate network config generator
	gen := NewNetworkConfigGenerator(profile)

	// Embed provisioning network config
	if err := c.embedNetworkPhaseConfig(writer, gen, "provisioning", gen.GenerateProvisioningConfig()); err != nil {
		return fmt.Errorf("failed to embed provisioning network config: %w", err)
	}

	// Embed production network config
	if err := c.embedNetworkPhaseConfig(writer, gen, "production", gen.GenerateProductionConfig()); err != nil {
		return fmt.Errorf("failed to embed production network config: %w", err)
	}

	// Embed quarantine network config
	if err := c.embedNetworkPhaseConfig(writer, gen, "quarantine", gen.GenerateQuarantineConfig()); err != nil {
		return fmt.Errorf("failed to embed quarantine network config: %w", err)
	}

	c.logger.Info("Successfully embedded device profile network configurations")
	return nil
}

// embedNetworkPhaseConfig embeds a single network phase configuration
func (c *Customizer) embedNetworkPhaseConfig(
	writer *NetworkConfigWriter,
	gen *NetworkConfigGenerator,
	phase string,
	config *entities.NetworkPhaseConfig,
) error {
	if config == nil {
		c.logger.Debug("No network configuration for phase, skipping", "phase", phase)
		return nil
	}

	c.logger.Debug("Embedding network configuration", "phase", phase, "vlan", config.VLAN)

	// Write YAML config for platformd to read
	var configPath string
	switch phase {
	case "provisioning":
		configPath = writer.GetProvisioningConfigPath()
	case "production":
		configPath = writer.GetProductionConfigPath()
	case "quarantine":
		configPath = writer.GetQuarantineConfigPath()
	default:
		return fmt.Errorf("unknown network phase: %s", phase)
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal %s network config: %w", phase, err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write %s network config: %w", phase, err)
	}

	c.logger.Debug("Wrote network config", "phase", phase, "path", configPath)

	// Generate systemd-networkd config if we have network settings
	if err := c.embedSystemdNetworkdConfig(writer, config, phase); err != nil {
		c.logger.Warn("Failed to generate systemd-networkd config",
			"phase", phase, "error", err)
		// Don't fail on systemd-networkd errors - it's optional
	}

	// Generate dnsmasq config if DHCP pool is configured
	if config.DHCPPool != nil {
		if err := c.embedDnsmasqConfig(writer, config, phase); err != nil {
			c.logger.Warn("Failed to generate dnsmasq config",
				"phase", phase, "error", err)
			// Don't fail on dnsmasq errors - it's optional
		}
	}

	return nil
}

// embedSystemdNetworkdConfig generates and embeds systemd-networkd configuration
func (c *Customizer) embedSystemdNetworkdConfig(
	writer *NetworkConfigWriter,
	config *entities.NetworkPhaseConfig,
	phase string,
) error {
	// Create systemd-networkd directory
	systemdDir := writer.GetSystemdNetworkdDir()
	if err := os.MkdirAll(systemdDir, 0755); err != nil {
		return fmt.Errorf("failed to create systemd-networkd directory: %w", err)
	}

	// Generate networkd config for eth0 (default interface)
	gen := NewSystemdNetworkdConfigGenerator("eth0")
	networkdConfig := gen.Generate(config)

	if networkdConfig == "" {
		c.logger.Debug("No systemd-networkd config to generate", "phase", phase)
		return nil
	}

	// Write networkd config file
	filename := gen.GenerateFilename(phase)
	configPath := filepath.Join(systemdDir, filename)

	if err := os.WriteFile(configPath, []byte(networkdConfig), 0644); err != nil {
		return fmt.Errorf("failed to write systemd-networkd config: %w", err)
	}

	c.logger.Debug("Wrote systemd-networkd config", "phase", phase, "path", configPath)
	return nil
}

// embedDnsmasqConfig generates and embeds dnsmasq DHCP server configuration
func (c *Customizer) embedDnsmasqConfig(
	writer *NetworkConfigWriter,
	config *entities.NetworkPhaseConfig,
	phase string,
) error {
	// Create dnsmasq config directory
	dnsmasqDir := writer.GetDnsmasqConfigDir()
	if err := os.MkdirAll(dnsmasqDir, 0755); err != nil {
		return fmt.Errorf("failed to create dnsmasq config directory: %w", err)
	}

	// Generate dnsmasq config
	gen := NewDnsmasqConfigGenerator("eth0")
	dnsmasqConfig := gen.Generate(config)

	if dnsmasqConfig == "" {
		c.logger.Debug("No dnsmasq config to generate", "phase", phase)
		return nil
	}

	// Write dnsmasq config file
	filename := gen.GenerateFilename(phase)
	configPath := filepath.Join(dnsmasqDir, filename)

	if err := os.WriteFile(configPath, []byte(dnsmasqConfig), 0644); err != nil {
		return fmt.Errorf("failed to write dnsmasq config: %w", err)
	}

	c.logger.Debug("Wrote dnsmasq config", "phase", phase, "path", configPath)
	return nil
}

// EmbedPlatformAPIConfig embeds platform API endpoint configuration for profile fetching
func (c *Customizer) EmbedPlatformAPIConfig(ctx context.Context, apiConfig *PlatformAPIConfig) error {
	if apiConfig == nil || apiConfig.Endpoint == "" {
		c.logger.Debug("No platform API endpoint configured, skipping")
		return nil
	}

	c.logger.Info("Embedding platform API configuration", "endpoint", apiConfig.Endpoint)

	// Create network config directory
	netConfigDir := filepath.Join(c.overlayDir, "etc", "platformd", "network")
	if err := os.MkdirAll(netConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create network config directory: %w", err)
	}

	// Write platform API config
	configPath := filepath.Join(netConfigDir, "platform-api.yaml")
	data, err := yaml.Marshal(apiConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal platform API config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write platform API config: %w", err)
	}

	c.logger.Info("Successfully embedded platform API configuration", "path", configPath)
	return nil
}
