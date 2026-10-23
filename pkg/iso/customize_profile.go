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
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// GetNetworkEnvPath returns the path for the baked network environment file
// within the ISO overlay. The file carries zone env vars (e.g.
// TP_NETWORK_ZONE) for consumption by firstboot scripts and services.
func (w *NetworkConfigWriter) GetNetworkEnvPath() string {
	return filepath.Join(w.GetNetworkConfigDir(), "network.env")
}

// EmbedDeviceProfileNetworkConfig embeds device profile network configurations
// into the ISO overlay. For each configured phase it writes:
//   - a per-phase YAML artifact (e.g. admitted.yaml) that includes the zone field,
//   - a systemd-networkd stub (with a # trusted-platform-zone: header comment),
//   - a dnsmasq DHCP config when DHCPPool is set.
//
// After all phases are processed, a network.env file is written with
// TP_NETWORK_ZONE set to the admitted phase's zone name (the zone the device
// operates in after successful enrollment). Its one reader, the
// trusted-platform-network script, was removed with #149: platformd's
// post-enrollment activation applies the admitted network.
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
		return &WrappedError{Msg: "failed to create network config directory", Err: err}
	}

	// Generate network config generator
	gen := NewNetworkConfigGenerator(profile)

	// Embed provisioning network config
	if err := c.embedNetworkPhaseConfig(writer, gen, "provisioning", gen.GenerateProvisioningConfig()); err != nil {
		return &WrappedError{Msg: "failed to embed provisioning network config", Err: err}
	}

	// Embed admitted network config (post-enrollment operational phase)
	if err := c.embedNetworkPhaseConfig(writer, gen, "admitted", gen.GenerateAdmittedConfig()); err != nil {
		return &WrappedError{Msg: "failed to embed admitted network config", Err: err}
	}

	// Embed quarantine network config
	if err := c.embedNetworkPhaseConfig(writer, gen, "quarantine", gen.GenerateQuarantineConfig()); err != nil {
		return &WrappedError{Msg: "failed to embed quarantine network config", Err: err}
	}

	// Bake zone env vars into the overlay so firstboot services and scripts
	// can export TP_NETWORK_ZONE without having to parse the YAML.
	if err := c.embedNetworkEnv(writer, gen); err != nil {
		return &WrappedError{Msg: "failed to embed network env", Err: err}
	}

	c.logger.Info("Successfully embedded device profile network configurations")
	return nil
}

// embedNetworkPhaseConfig embeds a single network phase configuration.
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

	c.logger.Debug("Embedding network configuration", "phase", phase, "vlan", config.VLAN, "zone", config.Zone)

	// Write YAML config for platformd to read. NetworkPhaseConfig.Zone is
	// marshalled by yaml.Marshal when non-empty (yaml:"zone,omitempty").
	var configPath string
	switch phase {
	case "provisioning":
		configPath = writer.GetProvisioningConfigPath()
	case "admitted":
		configPath = writer.GetAdmittedConfigPath()
	case "quarantine":
		configPath = writer.GetQuarantineConfigPath()
	default:
		return &MessageError{Msg: fmt.Sprintf("unknown network phase: %s", phase)}
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to marshal %s network config", phase), Err: err}
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("failed to write %s network config", phase), Err: err}
	}

	c.logger.Debug("Wrote network config", "phase", phase, "path", configPath)

	// Generate systemd-networkd config if we have network settings.
	// The generator prepends a "# trusted-platform-zone: <zone>" comment
	// when config.Zone is non-empty.
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

// embedNetworkEnv writes a shell-sourceable env file to the ISO overlay.
// TP_NETWORK_ZONE is set to the admitted phase's zone name so that firstboot
// scripts and systemd services can export the zone without parsing YAML.
// When that zone is empty the var is written as an empty assignment
// (consistent with how missing VLANs are emitted as zero rather than an error).
func (c *Customizer) embedNetworkEnv(writer *NetworkConfigWriter, gen *NetworkConfigGenerator) error {
	zones := gen.ExtractZoneNetworks()

	var sb strings.Builder
	sb.WriteString("# Trusted Platform – network zone environment\n")
	sb.WriteString("# Generated by platformctl iso create; do not edit manually.\n")
	sb.WriteString("# For scripts that need the admitted zone without parsing the YAML.\n\n")

	fmt.Fprintf(&sb, "TP_NETWORK_ZONE=%q\n", zones.Admitted.Zone)

	envPath := writer.GetNetworkEnvPath()
	if err := os.WriteFile(envPath, []byte(sb.String()), 0644); err != nil {
		return &WrappedError{Msg: "failed to write network env file", Err: err}
	}

	c.logger.Debug("Wrote network env file", "path", envPath, "zone", zones.Admitted.Zone)
	return nil
}

// embedSystemdNetworkdConfig generates and embeds systemd-networkd configuration.
func (c *Customizer) embedSystemdNetworkdConfig(
	writer *NetworkConfigWriter,
	config *entities.NetworkPhaseConfig,
	phase string,
) error {
	// Create systemd-networkd directory
	systemdDir := writer.GetSystemdNetworkdDir()
	if err := os.MkdirAll(systemdDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create systemd-networkd directory", Err: err}
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
		return &WrappedError{Msg: "failed to write systemd-networkd config", Err: err}
	}

	c.logger.Debug("Wrote systemd-networkd config", "phase", phase, "path", configPath)
	return nil
}

// embedDnsmasqConfig generates and embeds dnsmasq DHCP server configuration.
func (c *Customizer) embedDnsmasqConfig(
	writer *NetworkConfigWriter,
	config *entities.NetworkPhaseConfig,
	phase string,
) error {
	// Create dnsmasq config directory
	dnsmasqDir := writer.GetDnsmasqConfigDir()
	if err := os.MkdirAll(dnsmasqDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create dnsmasq config directory", Err: err}
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
		return &WrappedError{Msg: "failed to write dnsmasq config", Err: err}
	}

	c.logger.Debug("Wrote dnsmasq config", "phase", phase, "path", configPath)
	return nil
}

// EmbedPlatformAPIConfig embeds platform API endpoint configuration for profile fetching.
func (c *Customizer) EmbedPlatformAPIConfig(ctx context.Context, apiConfig *PlatformAPIConfig) error {
	if apiConfig == nil || apiConfig.Endpoint == "" {
		c.logger.Debug("No platform API endpoint configured, skipping")
		return nil
	}

	c.logger.Info("Embedding platform API configuration", "endpoint", apiConfig.Endpoint)

	// Create network config directory
	netConfigDir := filepath.Join(c.overlayDir, "etc", "platformd", "network")
	if err := os.MkdirAll(netConfigDir, 0755); err != nil {
		return &WrappedError{Msg: "failed to create network config directory", Err: err}
	}

	// Write platform API config
	configPath := filepath.Join(netConfigDir, "platform-api.yaml")
	data, err := yaml.Marshal(apiConfig)
	if err != nil {
		return &WrappedError{Msg: "failed to marshal platform API config", Err: err}
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return &WrappedError{Msg: "failed to write platform API config", Err: err}
	}

	c.logger.Info("Successfully embedded platform API configuration", "path", configPath)
	return nil
}
