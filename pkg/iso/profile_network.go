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

// ZoneNetwork holds the zone identity, logical network name, and VLAN ID for
// a single network phase. Zone is the SDN zone name (e.g. "control-plane");
// Name is the key used to look the network up in the profile's Networks map
// (e.g. "admitted"); VLAN is the 802.1Q VLAN ID.
type ZoneNetwork struct {
	// Zone is the SDN zone name for this network phase (e.g. "provisioning",
	// "control-plane", "quarantine"). Empty when neither the NetworkPhaseConfig nor
	// the profile-level Zone field carries a value.
	Zone string
	// Name is the logical network name from the device profile's Networks map
	// (e.g. "provisioning", "admitted", "quarantine").
	Name string
	// VLAN is the 802.1Q VLAN ID. Zero means no VLAN is configured.
	VLAN uint16
}

// ZoneNetworkSet carries the zone identity, network name, and VLAN ID for all
// three network phases recognised by the platform: provisioning (enrollment),
// admitted (post-enrollment operational), and quarantine (failure isolation).
type ZoneNetworkSet struct {
	Provisioning ZoneNetwork
	Admitted     ZoneNetwork
	Quarantine   ZoneNetwork
}

// NetworkConfigGenerator generates network configuration files from device profiles.
type NetworkConfigGenerator struct {
	profile *entities.DeviceProfile
}

// NewNetworkConfigGenerator creates a new network configuration generator.
func NewNetworkConfigGenerator(profile *entities.DeviceProfile) *NetworkConfigGenerator {
	return &NetworkConfigGenerator{
		profile: profile,
	}
}

// GenerateProvisioningConfig generates provisioning network configuration.
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

// GenerateAdmittedConfig generates the admitted (post-enrollment) network
// configuration.
func (g *NetworkConfigGenerator) GenerateAdmittedConfig() *entities.NetworkPhaseConfig {
	if g.profile == nil {
		return nil
	}
	admittedNet := g.profile.GetPostEnrollmentNetworkConfig()
	if admittedNet == nil {
		return nil
	}
	return g.copyNetworkConfig(admittedNet)
}

// GenerateQuarantineConfig generates quarantine network configuration.
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

// copyNetworkConfig creates a deep copy of network configuration.
func (g *NetworkConfigGenerator) copyNetworkConfig(config *entities.NetworkPhaseConfig) *entities.NetworkPhaseConfig {
	if config == nil {
		return nil
	}

	cp := &entities.NetworkPhaseConfig{
		VLAN:       config.VLAN,
		StaticIP:   config.StaticIP,
		Gateway:    config.Gateway,
		DNS:        make([]string, len(config.DNS)),
		AuthMethod: config.AuthMethod,
		Subnet:     config.Subnet,
		DNSServers: make([]string, len(config.DNSServers)),
		DHCP:       config.DHCP,
		Zone:       config.Zone,
	}

	// Deep copy DNS slices
	copy(cp.DNS, config.DNS)
	copy(cp.DNSServers, config.DNSServers)

	// Deep copy DHCP pool if present
	if config.DHCPPool != nil {
		cp.DHCPPool = &entities.DHCPPoolConfig{
			Network:    config.DHCPPool.Network,
			RangeStart: config.DHCPPool.RangeStart,
			RangeEnd:   config.DHCPPool.RangeEnd,
			LeaseTime:  config.DHCPPool.LeaseTime,
		}
	}

	// Deep copy ACLs
	if len(config.ACLs) > 0 {
		cp.ACLs = make([]entities.ACLConfig, len(config.ACLs))
		copy(cp.ACLs, config.ACLs)
	}

	return cp
}

// networkName returns the resolved logical network name for the given phase
// accessor and its default name when the profile's override field is empty.
func networkName(override, defaultName string) string {
	if override != "" {
		return override
	}
	return defaultName
}

// ExtractZoneNetworks extracts the zone identity, network name, and VLAN ID
// for all three network phases from the device profile. Missing zone values
// are left as empty strings (consistent with how missing VLANs are left as
// zero — no error is returned for absent data).
func (g *NetworkConfigGenerator) ExtractZoneNetworks() ZoneNetworkSet {
	if g.profile == nil {
		return ZoneNetworkSet{}
	}

	set := ZoneNetworkSet{}

	// Provisioning (enrollment) phase
	provName := networkName(g.profile.EnrollmentNetwork, entities.DefaultEnrollmentNetwork)
	if provNet := g.profile.GetEnrollmentNetworkConfig(); provNet != nil {
		set.Provisioning = ZoneNetwork{
			Zone: provNet.Zone,
			Name: provName,
			VLAN: provNet.VLAN,
		}
	} else {
		set.Provisioning = ZoneNetwork{Name: provName}
	}

	// Admitted (post-enrollment) phase — GetPostEnrollmentNetworkConfig already
	// applies the profile-level Zone fallback when the per-network Zone is empty.
	admittedName := networkName(g.profile.PostEnrollmentNetwork, entities.DefaultPostEnrollmentNetwork)
	if admittedNet := g.profile.GetPostEnrollmentNetworkConfig(); admittedNet != nil {
		set.Admitted = ZoneNetwork{
			Zone: admittedNet.Zone,
			Name: admittedName,
			VLAN: admittedNet.VLAN,
		}
	} else {
		set.Admitted = ZoneNetwork{Name: admittedName}
	}

	// Quarantine (failure) phase
	quarName := networkName(g.profile.FailureNetwork, entities.DefaultFailureNetwork)
	if quarNet := g.profile.GetFailureNetworkConfig(); quarNet != nil {
		set.Quarantine = ZoneNetwork{
			Zone: quarNet.Zone,
			Name: quarName,
			VLAN: quarNet.VLAN,
		}
	} else {
		set.Quarantine = ZoneNetwork{Name: quarName}
	}

	return set
}

// ExtractACLs extracts ACL rules from a network configuration.
func (g *NetworkConfigGenerator) ExtractACLs(config *entities.NetworkPhaseConfig) []entities.ACLConfig {
	if config == nil || len(config.ACLs) == 0 {
		return nil
	}

	acls := make([]entities.ACLConfig, len(config.ACLs))
	copy(acls, config.ACLs)
	return acls
}

// SystemdNetworkdConfigGenerator generates systemd-networkd configuration files.
type SystemdNetworkdConfigGenerator struct {
	interfaceName string
}

// NewSystemdNetworkdConfigGenerator creates a new systemd-networkd config generator.
func NewSystemdNetworkdConfigGenerator(interfaceName string) *SystemdNetworkdConfigGenerator {
	return &SystemdNetworkdConfigGenerator{
		interfaceName: interfaceName,
	}
}

// Generate creates systemd-networkd configuration from network phase config.
// When config.Zone is non-empty a comment header
// "# trusted-platform-zone: <zone>" is prepended so the installed OS can
// identify which SDN zone this interface belongs to (systemd-networkd has no
// native zone concept).
func (s *SystemdNetworkdConfigGenerator) Generate(config *entities.NetworkPhaseConfig) string {
	if config == nil {
		return ""
	}

	var builder strings.Builder

	// Emit zone metadata comment when zone is known. systemd-networkd has no
	// zone concept; a comment header is the correct vehicle.
	if config.Zone != "" {
		fmt.Fprintf(&builder, "# trusted-platform-zone: %s\n", config.Zone)
	}

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

// GenerateFilename generates the appropriate filename for the network config.
func (s *SystemdNetworkdConfigGenerator) GenerateFilename(phase string) string {
	// systemd-networkd filenames use priority prefix (e.g., 10-eth0.network)
	return fmt.Sprintf("10-%s-%s.network", s.interfaceName, phase)
}

// DnsmasqConfigGenerator generates dnsmasq DHCP server configuration files.
type DnsmasqConfigGenerator struct {
	interfaceName string
}

// NewDnsmasqConfigGenerator creates a new dnsmasq config generator.
func NewDnsmasqConfigGenerator(interfaceName string) *DnsmasqConfigGenerator {
	return &DnsmasqConfigGenerator{
		interfaceName: interfaceName,
	}
}

// Generate creates dnsmasq configuration from network phase config.
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

// GenerateFilename generates the appropriate filename for the dnsmasq config.
func (d *DnsmasqConfigGenerator) GenerateFilename(phase string) string {
	return fmt.Sprintf("dnsmasq-%s.conf", phase)
}

// NetworkConfigWriter handles writing network configuration files to ISO overlay.
type NetworkConfigWriter struct {
	overlayDir string
	generator  *NetworkConfigGenerator
}

// NewNetworkConfigWriter creates a new network config writer.
func NewNetworkConfigWriter(overlayDir string, profile *entities.DeviceProfile) *NetworkConfigWriter {
	return &NetworkConfigWriter{
		overlayDir: overlayDir,
		generator:  NewNetworkConfigGenerator(profile),
	}
}

// GetNetworkConfigDir returns the directory path for network configs in the overlay.
func (w *NetworkConfigWriter) GetNetworkConfigDir() string {
	return filepath.Join(w.overlayDir, "etc", "platformd", "network")
}

// GetSystemdNetworkdDir returns the directory path for systemd-networkd configs.
func (w *NetworkConfigWriter) GetSystemdNetworkdDir() string {
	return filepath.Join(w.overlayDir, "etc", "systemd", "network")
}

// GetDnsmasqConfigDir returns the directory path for dnsmasq configs.
func (w *NetworkConfigWriter) GetDnsmasqConfigDir() string {
	return filepath.Join(w.overlayDir, "etc", "dnsmasq.d")
}

// GetProvisioningConfigPath returns the path for provisioning network config.
func (w *NetworkConfigWriter) GetProvisioningConfigPath() string {
	return filepath.Join(w.GetNetworkConfigDir(), "provisioning.yaml")
}

// GetAdmittedConfigPath returns the path for the admitted (post-enrollment)
// network config.
func (w *NetworkConfigWriter) GetAdmittedConfigPath() string {
	return filepath.Join(w.GetNetworkConfigDir(), "admitted.yaml")
}

// GetQuarantineConfigPath returns the path for quarantine network config.
func (w *NetworkConfigWriter) GetQuarantineConfigPath() string {
	return filepath.Join(w.GetNetworkConfigDir(), "quarantine.yaml")
}

// PlatformAPIConfig represents platform API endpoint configuration for provisioning.
type PlatformAPIConfig struct {
	// Endpoint is the platform API URL.
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// ProfileID is the device profile ID to fetch.
	ProfileID uint64 `yaml:"profile_id,omitempty" json:"profile_id,omitempty"`

	// ProfileName is the device profile name to fetch (alternative to ID).
	ProfileName string `yaml:"profile_name,omitempty" json:"profile_name,omitempty"`

	// TLSVerify controls TLS certificate verification.
	TLSVerify bool `yaml:"tls_verify" json:"tls_verify"`

	// CACertPath is the path to the CA certificate bundle.
	CACertPath string `yaml:"ca_cert_path,omitempty" json:"ca_cert_path,omitempty"`
}

// GetPlatformAPIConfigPath returns the path for platform API config.
func (w *NetworkConfigWriter) GetPlatformAPIConfigPath() string {
	return filepath.Join(w.GetNetworkConfigDir(), "platform-api.yaml")
}
