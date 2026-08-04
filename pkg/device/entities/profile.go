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

package entities

import "time"

// DeviceRole represents the role or function of a device in the system
type DeviceRole string

const (
	DeviceRoleUnknown      DeviceRole = "unknown"
	DeviceRoleServer       DeviceRole = "server"
	DeviceRoleClient       DeviceRole = "client"
	DeviceRoleWorkstation  DeviceRole = "workstation"
	DeviceRoleEdge         DeviceRole = "edge"
	DeviceRoleIoT          DeviceRole = "iot"
	DeviceRoleGateway      DeviceRole = "gateway"
	DeviceRoleLoadBalancer DeviceRole = "load-balancer"
)

// String returns the string representation of DeviceRole
func (r DeviceRole) String() string {
	return string(r)
}

// IsValid checks if the DeviceRole is valid
func (r DeviceRole) IsValid() bool {
	switch r {
	case DeviceRoleUnknown, DeviceRoleServer, DeviceRoleClient,
		DeviceRoleWorkstation, DeviceRoleEdge, DeviceRoleIoT,
		DeviceRoleGateway, DeviceRoleLoadBalancer:
		return true
	default:
		return false
	}
}

// AuthMethod represents the authentication method for network access
type AuthMethod string

const (
	// AuthMethodNone represents no authentication
	AuthMethodNone AuthMethod = "none"
	// AuthMethod802_1X represents 802.1X authentication
	AuthMethod802_1X AuthMethod = "802.1x"
)

// String returns the string representation of AuthMethod
func (a AuthMethod) String() string {
	return string(a)
}

// IsValid checks if the AuthMethod is valid
func (a AuthMethod) IsValid() bool {
	switch a {
	case AuthMethodNone, AuthMethod802_1X:
		return true
	default:
		return false
	}
}

// DHCPPoolConfig defines DHCP pool configuration for a network phase
type DHCPPoolConfig struct {
	// Network is the CIDR notation of the network
	Network string `json:"network" yaml:"network"`
	// RangeStart is the starting IP address of the DHCP pool
	RangeStart string `json:"range_start" yaml:"range_start"`
	// RangeEnd is the ending IP address of the DHCP pool
	RangeEnd string `json:"range_end" yaml:"range_end"`
	// LeaseTime is the DHCP lease time in seconds
	LeaseTime int `json:"lease_time" yaml:"lease_time"`
}

// ACLConfig defines access control list configuration
type ACLConfig struct {
	// Priority determines the order of ACL evaluation (lower number = higher priority)
	Priority int `json:"priority" yaml:"priority"`
	// Protocol is the network protocol (tcp, udp, icmp, any)
	Protocol string `json:"protocol" yaml:"protocol"`
	// SrcIP is the source IP address or CIDR
	SrcIP string `json:"src_ip" yaml:"src_ip"`
	// DstIP is the destination IP address or CIDR
	DstIP string `json:"dst_ip" yaml:"dst_ip"`
	// SrcPort is the source port (0 for any)
	SrcPort uint16 `json:"src_port,omitempty" yaml:"src_port,omitempty"`
	// DstPort is the destination port (0 for any)
	DstPort uint16 `json:"dst_port,omitempty" yaml:"dst_port,omitempty"`
	// Action is the action to take (allow, deny)
	Action string `json:"action" yaml:"action"`
}

// IsValid checks if the ACLConfig is valid
func (a *ACLConfig) IsValid() bool {
	if a == nil {
		return false
	}
	// Validate protocol
	switch a.Protocol {
	case "tcp", "udp", "icmp", "any":
		// valid
	default:
		return false
	}
	// Validate action
	switch a.Action {
	case "allow", "deny":
		// valid
	default:
		return false
	}
	return true
}

// NetworkPhaseConfig defines network configuration for a specific provisioning phase
type NetworkPhaseConfig struct {
	// VLAN is the VLAN ID for this network phase
	VLAN uint16 `json:"vlan" yaml:"vlan"`
	// DHCPPool is the DHCP pool configuration (optional)
	DHCPPool *DHCPPoolConfig `json:"dhcp_pool,omitempty" yaml:"dhcp_pool,omitempty"`
	// StaticIP is the static IP address for this device (optional)
	StaticIP string `json:"static_ip,omitempty" yaml:"static_ip,omitempty"`
	// Gateway is the default gateway for this network
	Gateway string `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	// DNS is the list of DNS servers
	DNS []string `json:"dns,omitempty" yaml:"dns,omitempty"`
	// AuthMethod is the authentication method for this network
	AuthMethod AuthMethod `json:"auth_method" yaml:"auth_method"`
	// ACLs is the list of access control rules
	ACLs []ACLConfig `json:"acls,omitempty" yaml:"acls,omitempty"`
	// Zone is the SDN zone name assigned to this network phase (e.g. "trusted",
	// "provisioning", "quarantine"). When empty the SDN engine derives the zone
	// from the profile-level Zone field.
	Zone string `json:"zone,omitempty" yaml:"zone,omitempty"`

	// Legacy fields retained for YAML/JSON unmarshalling of existing configs.
	Subnet     string   `json:"subnet,omitempty" yaml:"subnet,omitempty"`
	DNSServers []string `json:"dns_servers,omitempty" yaml:"dns_servers,omitempty"`
	DHCP       bool     `json:"dhcp" yaml:"dhcp"`
}

// PlatformdConfigRef represents a reference to platformd configuration
// which can be either inline or a reference to an external file
type PlatformdConfigRef struct {
	// ConfigType indicates whether the config is inline or a reference
	ConfigType string `json:"config_type" yaml:"config_type"`
	// Inline contains the inline configuration (typically app.App structure)
	Inline interface{} `json:"inline,omitempty" yaml:"inline,omitempty"`
	// Reference is the path to an external configuration file
	Reference string `json:"reference,omitempty" yaml:"reference,omitempty"`

	// Legacy fields for backward compatibility
	ConfigName string `json:"config_name,omitempty" yaml:"config_name,omitempty"`
	ConfigPath string `json:"config_path,omitempty" yaml:"config_path,omitempty"`
	Version    string `json:"version,omitempty" yaml:"version,omitempty"`
}

// IsValid checks if the PlatformdConfigRef is valid
func (p *PlatformdConfigRef) IsValid() bool {
	if p == nil {
		return false
	}
	switch p.ConfigType {
	case "inline":
		return p.Inline != nil
	case "reference":
		return p.Reference != ""
	case "": // Legacy format
		return p.ConfigName != "" || p.ConfigPath != ""
	default:
		return false
	}
}

// ProfileMatchRules defines rules for matching devices to profiles
type ProfileMatchRules struct {
	// MACPrefix is the MAC address prefix to match (e.g., "52:54:00")
	MACPrefix string `json:"mac_prefix,omitempty" yaml:"mac_prefix,omitempty"`
	// SerialPrefix is the serial number prefix to match
	SerialPrefix string `json:"serial_prefix,omitempty" yaml:"serial_prefix,omitempty"`
	// Model is the device model to match
	Model string `json:"model,omitempty" yaml:"model,omitempty"`

	// Legacy fields for backward compatibility
	ModelPattern      string            `json:"model_pattern,omitempty" yaml:"model_pattern,omitempty"`
	SerialPattern     string            `json:"serial_pattern,omitempty" yaml:"serial_pattern,omitempty"`
	ManufacturerMatch string            `json:"manufacturer_match,omitempty" yaml:"manufacturer_match,omitempty"`
	TPMVendor         string            `json:"tpm_vendor,omitempty" yaml:"tpm_vendor,omitempty"`
	CustomAttributes  map[string]string `json:"custom_attributes,omitempty" yaml:"custom_attributes,omitempty"`
}

// IsEmpty checks if all match rules are empty
func (p *ProfileMatchRules) IsEmpty() bool {
	if p == nil {
		return true
	}
	return p.MACPrefix == "" && p.SerialPrefix == "" && p.Model == "" &&
		p.ModelPattern == "" && p.SerialPattern == "" && p.ManufacturerMatch == "" &&
		p.TPMVendor == "" && len(p.CustomAttributes) == 0
}

// Matches checks if the given device properties match these rules
// Returns true if at least one non-empty rule matches
func (p *ProfileMatchRules) Matches(macAddr, serial, model string) bool {
	if p.IsEmpty() {
		return false
	}

	matched := false

	// Check new-style rules
	if p.MACPrefix != "" {
		if len(macAddr) >= len(p.MACPrefix) && macAddr[:len(p.MACPrefix)] == p.MACPrefix {
			matched = true
		}
	}

	if p.SerialPrefix != "" {
		if len(serial) >= len(p.SerialPrefix) && serial[:len(p.SerialPrefix)] == p.SerialPrefix {
			matched = true
		}
	}

	if p.Model != "" {
		if model == p.Model {
			matched = true
		}
	}

	// Check legacy-style rules for backward compatibility
	if p.ModelPattern != "" {
		if model == p.ModelPattern {
			matched = true
		}
	}

	if p.SerialPattern != "" {
		if len(serial) >= len(p.SerialPattern) && serial[:len(p.SerialPattern)] == p.SerialPattern {
			matched = true
		}
	}

	return matched
}

// Default network transition names used when the enrollment, post-enrollment,
// or failure network fields are not explicitly configured.
const (
	DefaultEnrollmentNetwork     = "provisioning"
	DefaultPostEnrollmentNetwork = "trusted"
	DefaultFailureNetwork        = "quarantine"
)

// DeviceProfile represents a device profile with configuration, identity metadata,
// and match rules for automatic device provisioning.
type DeviceProfile struct {
	ID       uint64     `yaml:"id" json:"id"`
	TenantID string     `yaml:"tenant_id" json:"tenant_id"`
	Name     string     `yaml:"name" json:"name"`
	Model    string     `yaml:"model" json:"model"`
	Role     DeviceRole `yaml:"role" json:"role"`
	EventLog []byte     `yaml:"eventLog" json:"eventLog"`

	// Zone declares the default SDN zone for this device profile. Individual
	// network phase configs may override this with their own Zone field.
	Zone string `yaml:"zone,omitempty" json:"zone,omitempty"`

	// Networks is a map of named network phase configurations keyed by
	// logical network name (e.g., "provisioning", "trusted", "quarantine").
	Networks map[string]*NetworkPhaseConfig `yaml:"networks,omitempty" json:"networks,omitempty"`

	// EnrollmentNetwork is the name of the network used during device enrollment.
	// Defaults to "provisioning" when empty.
	EnrollmentNetwork string `yaml:"enrollment-network,omitempty" json:"enrollment_network,omitempty"`

	// PostEnrollmentNetwork is the name of the network the device transitions to
	// after successful enrollment. Defaults to "trusted" when empty.
	PostEnrollmentNetwork string `yaml:"post-enrollment-network,omitempty" json:"post_enrollment_network,omitempty"`

	// FailureNetwork is the name of the network the device is moved to when
	// enrollment or attestation fails. Defaults to "quarantine" when empty.
	FailureNetwork string `yaml:"failure-network,omitempty" json:"failure_network,omitempty"`

	// Platformd configuration reference
	PlatformdConfig *PlatformdConfigRef `yaml:"platformd,omitempty" json:"platformd,omitempty"`

	// Match rules for auto-assignment
	MatchRules *ProfileMatchRules `yaml:"match-rules,omitempty" json:"match_rules,omitempty"`

	// BMC is the baseboard management controller configuration for bare metal provisioning.
	// Credentials are encrypted at rest via barrier storage.
	BMC *BMCConfig `yaml:"bmc,omitempty" json:"bmc,omitempty"`

	// WorkloadPCR is the PCR index used for workload attestation (containers, VMs).
	// If 0, the platform default (14) is used. Valid range: 0-23.
	WorkloadPCR int `yaml:"workload-pcr,omitempty" json:"workload_pcr,omitempty"`

	// Config is the full platform config for this device (from template or custom).
	// Typed as any to avoid import cycles; callers should type-assert to *app.App.
	Config any `yaml:"config,omitempty" json:"config,omitempty"`

	// EKSerial is the exact TPM Endorsement Key certificate serial number
	// used for device identity resolution at boot time.
	EKSerial string `yaml:"ek-serial,omitempty" json:"ek_serial,omitempty"`

	// EKCert is the PEM-encoded TPM Endorsement Key certificate prestaged for
	// this device. When set, pre-enrollment config delivery (paradigm B)
	// cryptographically binds the delivered config to the hardware EK by
	// comparing the public key of this certificate against the EK certificate
	// the booting device presents. An empty value means no EK certificate was
	// prestaged and the resolver falls back to EK-serial/MAC matching unless
	// EK matching is explicitly required.
	EKCert string `yaml:"ek-cert,omitempty" json:"ek_cert,omitempty"`

	// MACAddress is the exact MAC address for non-TPM device identification.
	MACAddress string `yaml:"mac-address,omitempty" json:"mac_address,omitempty"`

	// Assigned indicates whether this profile has been bound to a specific device.
	Assigned bool `yaml:"assigned" json:"assigned"`

	// AssignedAt is the timestamp when the profile was assigned to a device.
	AssignedAt time.Time `yaml:"assigned_at,omitempty" json:"assigned_at,omitempty"`
}

// DefaultWorkloadPCR is the default PCR index for workload attestation.
const DefaultWorkloadPCR = 14

// EntityID returns the profile's unique identifier.
func (dp *DeviceProfile) EntityID() uint64 {
	return dp.ID
}

// SetEntityID sets the profile's unique identifier.
func (dp *DeviceProfile) SetEntityID(id uint64) {
	dp.ID = id
}

// GetWorkloadPCR returns the effective WorkloadPCR index for this profile.
// If not configured (0), returns the platform default (14).
func (dp *DeviceProfile) GetWorkloadPCR() int {
	if dp == nil || dp.WorkloadPCR == 0 {
		return DefaultWorkloadPCR
	}
	return dp.WorkloadPCR
}

// GetNetwork returns the NetworkPhaseConfig for the given network name.
// Returns nil if no configuration exists for the given name.
func (dp *DeviceProfile) GetNetwork(name string) *NetworkPhaseConfig {
	if dp == nil || dp.Networks == nil {
		return nil
	}
	cfg, ok := dp.Networks[name]
	if !ok {
		return nil
	}
	return cfg
}

// GetEnrollmentNetworkConfig returns the network configuration used during
// device enrollment. If EnrollmentNetwork is empty, it defaults to
// "provisioning".
func (dp *DeviceProfile) GetEnrollmentNetworkConfig() *NetworkPhaseConfig {
	if dp == nil {
		return nil
	}
	name := dp.EnrollmentNetwork
	if name == "" {
		name = DefaultEnrollmentNetwork
	}
	return dp.GetNetwork(name)
}

// GetPostEnrollmentNetworkConfig returns the network configuration the device
// transitions to after successful enrollment. If PostEnrollmentNetwork is
// empty, it defaults to "trusted". When the resolved config has no Zone set,
// the profile-level Zone is applied.
func (dp *DeviceProfile) GetPostEnrollmentNetworkConfig() *NetworkPhaseConfig {
	if dp == nil {
		return nil
	}
	name := dp.PostEnrollmentNetwork
	if name == "" {
		name = DefaultPostEnrollmentNetwork
	}
	cfg := dp.GetNetwork(name)
	if cfg != nil && cfg.Zone == "" && dp.Zone != "" {
		// Return a copy with the profile Zone applied so the original map entry
		// is not mutated.
		copy := *cfg
		copy.Zone = dp.Zone
		return &copy
	}
	return cfg
}

// GetFailureNetworkConfig returns the network configuration for devices that
// fail enrollment or attestation. If FailureNetwork is empty, it defaults
// to "quarantine".
func (dp *DeviceProfile) GetFailureNetworkConfig() *NetworkPhaseConfig {
	if dp == nil {
		return nil
	}
	name := dp.FailureNetwork
	if name == "" {
		name = DefaultFailureNetwork
	}
	return dp.GetNetwork(name)
}
