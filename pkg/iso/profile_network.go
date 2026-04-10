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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// NetworkConfigGenerator generates network configuration files from device profiles
type NetworkConfigGenerator struct {
	profile *entities.DeviceProfile
}

// NewNetworkConfigGenerator creates a new network configuration generator
func NewNetworkConfigGenerator(profile *entities.DeviceProfile) *NetworkConfigGenerator {
	return &NetworkConfigGenerator{
		profile: profile,
	}
}

// GenerateProvisioningConfig generates provisioning network configuration
func (g *NetworkConfigGenerator) GenerateProvisioningConfig() *entities.NetworkPhaseConfig {
	if g.profile == nil {
		return nil
	}
	provNet := g.profile.GetEnrollmentNetworkConfig()
	if provNet == nil {
		return nil
	}
	return g.copyNetworkConfig(provNet)
}

// GenerateProductionConfig generates production network configuration
func (g *NetworkConfigGenerator) GenerateProductionConfig() *entities.NetworkPhaseConfig {
	if g.profile == nil {
		return nil
	}
	prodNet := g.profile.GetPostEnrollmentNetworkConfig()
	if prodNet == nil {
		return nil
	}
	return g.copyNetworkConfig(prodNet)
}

// GenerateQuarantineConfig generates quarantine network configuration
func (g *NetworkConfigGenerator) GenerateQuarantineConfig() *entities.NetworkPhaseConfig {
	if g.profile == nil {
		return nil
	}
	quarNet := g.profile.GetFailureNetworkConfig()
	if quarNet == nil {
		return nil
	}
	return g.copyNetworkConfig(quarNet)
}

// copyNetworkConfig creates a deep copy of network configuration
func (g *NetworkConfigGenerator) copyNetworkConfig(config *entities.NetworkPhaseConfig) *entities.NetworkPhaseConfig {
	if config == nil {
		return nil
	}

	copy := &entities.NetworkPhaseConfig{
		VLAN:         config.VLAN,
		StaticIP:     config.StaticIP,
		Gateway:      config.Gateway,
		DNS:          make([]string, len(config.DNS)),
		AuthMethod:   config.AuthMethod,
		Subnet:       config.Subnet,
		DNSServers:   make([]string, len(config.DNSServers)),
		DHCP:         config.DHCP,
		FirewallZone: config.FirewallZone,
	}

	// Deep copy DNS slices
	for i, dns := range config.DNS {
		copy.DNS[i] = dns
	}
	for i, dns := range config.DNSServers {
		copy.DNSServers[i] = dns
	}

	// Deep copy DHCP pool if present
	if config.DHCPPool != nil {
		copy.DHCPPool = &entities.DHCPPoolConfig{
			Network:    config.DHCPPool.Network,
			RangeStart: config.DHCPPool.RangeStart,
			RangeEnd:   config.DHCPPool.RangeEnd,
			LeaseTime:  config.DHCPPool.LeaseTime,
		}
	}

	// Deep copy ACLs
	if len(config.ACLs) > 0 {
		copy.ACLs = make([]entities.ACLConfig, len(config.ACLs))
		for i, acl := range config.ACLs {
			copy.ACLs[i] = acl
		}
	}

	return copy
}

// ExtractVLANs extracts VLAN IDs from the device profile
func (g *NetworkConfigGenerator) ExtractVLANs() VLANSet {
	vlans := VLANSet{}

	if g.profile != nil {
		if provNet := g.profile.GetEnrollmentNetworkConfig(); provNet != nil {
			vlans.Provisioning = provNet.VLAN
		}
		if prodNet := g.profile.GetPostEnrollmentNetworkConfig(); prodNet != nil {
			vlans.Production = prodNet.VLAN
		}
		if quarNet := g.profile.GetFailureNetworkConfig(); quarNet != nil {
			vlans.Quarantine = quarNet.VLAN
		}
	}

	return vlans
}

// ExtractACLs extracts ACL rules from a network configuration
func (g *NetworkConfigGenerator) ExtractACLs(config *entities.NetworkPhaseConfig) []entities.ACLConfig {
	if config == nil || len(config.ACLs) == 0 {
		return nil
	}

	acls := make([]entities.ACLConfig, len(config.ACLs))
	copy(acls, config.ACLs)
	return acls
}

// VLANSet represents VLAN IDs for all network phases
type VLANSet struct {
	Provisioning uint16
	Production   uint16
	Quarantine   uint16
}

// SystemdNetworkdConfigGenerator generates systemd-networkd configuration files
type SystemdNetworkdConfigGenerator struct {
	interfaceName string
}

// NewSystemdNetworkdConfigGenerator creates a new systemd-networkd config generator
func NewSystemdNetworkdConfigGenerator(interfaceName string) *SystemdNetworkdConfigGenerator {
	return &SystemdNetworkdConfigGenerator{
		interfaceName: interfaceName,
	}
}

// Generate creates systemd-networkd configuration from network phase config
func (s *SystemdNetworkdConfigGenerator) Generate(config *entities.NetworkPhaseConfig) string {
	if config == nil {
		return ""
	}

	var builder strings.Builder

	// Match section
	builder.WriteString("[Match]\n")
	fmt.Fprintf(&builder, "Name=%s\n", s.interfaceName)
	builder.WriteString("\n")

	// Network section
	builder.WriteString("[Network]\n")

	// Static IP configuration
	if config.StaticIP != "" {
		fmt.Fprintf(&builder, "Address=%s\n", config.StaticIP)
	}

	// Gateway configuration
	if config.Gateway != "" {
		fmt.Fprintf(&builder, "Gateway=%s\n", config.Gateway)
	}

	// DNS configuration (prefer DNS over DNSServers)
	dnsServers := config.DNS
	if len(dnsServers) == 0 {
		dnsServers = config.DNSServers
	}
	for _, dns := range dnsServers {
		fmt.Fprintf(&builder, "DNS=%s\n", dns)
	}

	// DHCP configuration (legacy field)
	if config.DHCP {
		builder.WriteString("DHCP=yes\n")
	}

	// VLAN configuration
	if config.VLAN > 0 {
		builder.WriteString("\n[VLAN]\n")
		fmt.Fprintf(&builder, "Id=%d\n", config.VLAN)
	}

	return builder.String()
}

// GenerateFilename generates the appropriate filename for the network config
func (s *SystemdNetworkdConfigGenerator) GenerateFilename(phase string) string {
	// systemd-networkd filenames use priority prefix (e.g., 10-eth0.network)
	return fmt.Sprintf("10-%s-%s.network", s.interfaceName, phase)
}

// DnsmasqConfigGenerator generates dnsmasq DHCP server configuration files
type DnsmasqConfigGenerator struct {
	interfaceName string
}

// NewDnsmasqConfigGenerator creates a new dnsmasq config generator
func NewDnsmasqConfigGenerator(interfaceName string) *DnsmasqConfigGenerator {
	return &DnsmasqConfigGenerator{
		interfaceName: interfaceName,
	}
}

// Generate creates dnsmasq configuration from network phase config
func (d *DnsmasqConfigGenerator) Generate(config *entities.NetworkPhaseConfig) string {
	if config == nil || config.DHCPPool == nil {
		return ""
	}

	var builder strings.Builder

	builder.WriteString("# Auto-generated dnsmasq configuration\n")
	fmt.Fprintf(&builder, "interface=%s\n", d.interfaceName)
	builder.WriteString("bind-interfaces\n")
	builder.WriteString("\n")

	// DHCP range configuration
	builder.WriteString("# DHCP range\n")
	fmt.Fprintf(&builder, "dhcp-range=%s,%s,%d\n",
		config.DHCPPool.RangeStart,
		config.DHCPPool.RangeEnd,
		config.DHCPPool.LeaseTime)
	builder.WriteString("\n")

	// Gateway (router) option
	if config.Gateway != "" {
		builder.WriteString("# Gateway\n")
		fmt.Fprintf(&builder, "dhcp-option=option:router,%s\n", config.Gateway)
		builder.WriteString("\n")
	}

	// DNS servers (prefer DNS over DNSServers)
	dnsServers := config.DNS
	if len(dnsServers) == 0 {
		dnsServers = config.DNSServers
	}
	if len(dnsServers) > 0 {
		builder.WriteString("# DNS servers\n")
		for _, dns := range dnsServers {
			fmt.Fprintf(&builder, "dhcp-option=option:dns-server,%s\n", dns)
		}
		builder.WriteString("\n")
	}

	return builder.String()
}

// GenerateFilename generates the appropriate filename for the dnsmasq config
func (d *DnsmasqConfigGenerator) GenerateFilename(phase string) string {
	return fmt.Sprintf("dnsmasq-%s.conf", phase)
}

// NetworkConfigWriter handles writing network configuration files to ISO overlay
type NetworkConfigWriter struct {
	overlayDir string
	generator  *NetworkConfigGenerator
}

// NewNetworkConfigWriter creates a new network config writer
func NewNetworkConfigWriter(overlayDir string, profile *entities.DeviceProfile) *NetworkConfigWriter {
	return &NetworkConfigWriter{
		overlayDir: overlayDir,
		generator:  NewNetworkConfigGenerator(profile),
	}
}

// GetNetworkConfigDir returns the directory path for network configs in the overlay
func (w *NetworkConfigWriter) GetNetworkConfigDir() string {
	return filepath.Join(w.overlayDir, "etc", "platformd", "network")
}

// GetSystemdNetworkdDir returns the directory path for systemd-networkd configs
func (w *NetworkConfigWriter) GetSystemdNetworkdDir() string {
	return filepath.Join(w.overlayDir, "etc", "systemd", "network")
}

// GetDnsmasqConfigDir returns the directory path for dnsmasq configs
func (w *NetworkConfigWriter) GetDnsmasqConfigDir() string {
	return filepath.Join(w.overlayDir, "etc", "dnsmasq.d")
}

// GetProvisioningConfigPath returns the path for provisioning network config
func (w *NetworkConfigWriter) GetProvisioningConfigPath() string {
	return filepath.Join(w.GetNetworkConfigDir(), "provisioning.yaml")
}

// GetProductionConfigPath returns the path for production network config
func (w *NetworkConfigWriter) GetProductionConfigPath() string {
	return filepath.Join(w.GetNetworkConfigDir(), "production.yaml")
}

// GetQuarantineConfigPath returns the path for quarantine network config
func (w *NetworkConfigWriter) GetQuarantineConfigPath() string {
	return filepath.Join(w.GetNetworkConfigDir(), "quarantine.yaml")
}

// PlatformAPIConfig represents platform API endpoint configuration for provisioning
type PlatformAPIConfig struct {
	// Endpoint is the platform API URL
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// ProfileID is the device profile ID to fetch
	ProfileID uint64 `yaml:"profile_id,omitempty" json:"profile_id,omitempty"`

	// ProfileName is the device profile name to fetch (alternative to ID)
	ProfileName string `yaml:"profile_name,omitempty" json:"profile_name,omitempty"`

	// TLSVerify controls TLS certificate verification
	TLSVerify bool `yaml:"tls_verify" json:"tls_verify"`

	// CACertPath is the path to the CA certificate bundle
	CACertPath string `yaml:"ca_cert_path,omitempty" json:"ca_cert_path,omitempty"`
}

// GetPlatformAPIConfigPath returns the path for platform API config
func (w *NetworkConfigWriter) GetPlatformAPIConfigPath() string {
	return filepath.Join(w.GetNetworkConfigDir(), "platform-api.yaml")
}
