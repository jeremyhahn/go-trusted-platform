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

package container

import "time"

const (
	// DefaultHTTPPort is the default HTTP server port.
	DefaultHTTPPort = 8080

	// DefaultTFTPPort is the default TFTP server port.
	DefaultTFTPPort = 69

	// DefaultDHCPLeaseTime is the default DHCP lease duration.
	DefaultDHCPLeaseTime = 1 * time.Hour
)

// ServerConfig holds all configuration for the bootstrap container server.
type ServerConfig struct {
	// Interface is the network interface to bind to.
	Interface string

	// HTTPPort is the HTTP server port (default: 8080).
	HTTPPort int

	// TFTPPort is the TFTP server port (default: 69).
	TFTPPort int

	// DHCPConfig holds DHCP server settings.
	DHCPConfig DHCPConfig

	// ManifestPath is the path to the YAML manifest file.
	ManifestPath string

	// ConfigDir is the directory containing per-device config files.
	ConfigDir string

	// KernelPath is the path to the vmlinuz kernel image.
	KernelPath string

	// InitrdPath is the path to the initramfs image.
	InitrdPath string
}

// DHCPConfig holds DHCP server settings for the bootstrap container.
type DHCPConfig struct {
	ServerIP   string        `yaml:"server_ip" json:"server_ip"`
	RangeStart string        `yaml:"range_start" json:"range_start"`
	RangeEnd   string        `yaml:"range_end" json:"range_end"`
	SubnetMask string        `yaml:"subnet_mask" json:"subnet_mask"`
	Gateway    string        `yaml:"gateway" json:"gateway"`
	DNS        []string      `yaml:"dns" json:"dns"`
	LeaseTime  time.Duration `yaml:"lease_time" json:"lease_time"`
}

// Validate checks the server configuration for required fields and valid values.
func (c *ServerConfig) Validate() error {
	if c.ManifestPath == "" {
		return ErrInvalidServerConfig{Field: "manifest_path", Reason: "must not be empty"}
	}
	if c.KernelPath == "" {
		return ErrInvalidServerConfig{Field: "kernel_path", Reason: "must not be empty"}
	}
	if c.InitrdPath == "" {
		return ErrInvalidServerConfig{Field: "initrd_path", Reason: "must not be empty"}
	}
	if c.DHCPConfig.ServerIP == "" {
		return ErrInvalidServerConfig{Field: "dhcp_config.server_ip", Reason: "must not be empty"}
	}
	if c.DHCPConfig.RangeStart == "" {
		return ErrInvalidServerConfig{Field: "dhcp_config.range_start", Reason: "must not be empty"}
	}
	if c.DHCPConfig.RangeEnd == "" {
		return ErrInvalidServerConfig{Field: "dhcp_config.range_end", Reason: "must not be empty"}
	}
	if c.DHCPConfig.SubnetMask == "" {
		return ErrInvalidServerConfig{Field: "dhcp_config.subnet_mask", Reason: "must not be empty"}
	}
	if c.HTTPPort < 0 || c.HTTPPort > 65535 {
		return ErrInvalidServerConfig{Field: "http_port", Reason: "must be between 0 and 65535"}
	}
	if c.TFTPPort < 0 || c.TFTPPort > 65535 {
		return ErrInvalidServerConfig{Field: "tftp_port", Reason: "must be between 0 and 65535"}
	}
	return nil
}

// ApplyDefaults fills in zero-valued fields with sensible defaults.
func (c *ServerConfig) ApplyDefaults() {
	if c.HTTPPort == 0 {
		c.HTTPPort = DefaultHTTPPort
	}
	if c.TFTPPort == 0 {
		c.TFTPPort = DefaultTFTPPort
	}
	if c.DHCPConfig.LeaseTime == 0 {
		c.DHCPConfig.LeaseTime = DefaultDHCPLeaseTime
	}
	if c.DHCPConfig.SubnetMask == "" {
		c.DHCPConfig.SubnetMask = "255.255.255.0"
	}
}
