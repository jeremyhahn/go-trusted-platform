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

package fabric

// FabricConfig is the top-level configuration for the physical switch fabric.
type FabricConfig struct {
	// Mode selects VLAN-only or EVPN-VXLAN fabric operation.
	Mode FabricMode `yaml:"mode" json:"mode" mapstructure:"mode"`

	// EVPN holds EVPN-specific parameters. Required when Mode is "evpn".
	EVPN *EVPNConfig `yaml:"evpn,omitempty" json:"evpn,omitempty" mapstructure:"evpn"`

	// Switches lists the physical switches in the fabric.
	Switches []SwitchConfig `yaml:"switches" json:"switches" mapstructure:"switches"`

	// Peers defines MC-LAG or vPC peer relationships between switches.
	Peers []PeerConfig `yaml:"peers,omitempty" json:"peers,omitempty" mapstructure:"peers"`

	// LAGs defines link aggregation groups across the fabric.
	LAGs []LAGConfig `yaml:"lags,omitempty" json:"lags,omitempty" mapstructure:"lags"`

	// Segments defines the network segments provisioned on the fabric.
	Segments []SegmentConfig `yaml:"segments" json:"segments" mapstructure:"segments"`
}

// Validate checks the fabric configuration for internal consistency.
func (c *FabricConfig) Validate() error {
	if c == nil {
		return ErrNilConfig{}
	}

	if c.Mode == "" {
		c.Mode = ModeVLAN
	}

	if c.Mode != ModeVLAN && c.Mode != ModeEVPN {
		return ErrInvalidFabricConfig{Reason: "mode must be 'vlan' or 'evpn'"}
	}

	if c.Mode == ModeEVPN && c.EVPN == nil {
		return ErrInvalidFabricConfig{Reason: "evpn config required when mode is 'evpn'"}
	}

	if len(c.Switches) == 0 {
		return ErrInvalidFabricConfig{Reason: "at least one switch is required"}
	}

	switchIDs := make(map[string]struct{}, len(c.Switches))
	for i := range c.Switches {
		if err := c.Switches[i].Validate(); err != nil {
			return err
		}
		if _, exists := switchIDs[c.Switches[i].ID]; exists {
			return ErrInvalidFabricConfig{Reason: "duplicate switch id: " + c.Switches[i].ID}
		}
		switchIDs[c.Switches[i].ID] = struct{}{}
	}

	if len(c.Segments) == 0 {
		return ErrInvalidFabricConfig{Reason: "at least one segment is required"}
	}

	segNames := make(map[string]struct{}, len(c.Segments))
	vlanIDs := make(map[uint16]string, len(c.Segments))
	for i := range c.Segments {
		if err := c.Segments[i].Validate(); err != nil {
			return err
		}
		if _, exists := segNames[c.Segments[i].Name]; exists {
			return ErrInvalidFabricConfig{Reason: "duplicate segment name: " + c.Segments[i].Name}
		}
		segNames[c.Segments[i].Name] = struct{}{}

		if other, exists := vlanIDs[c.Segments[i].VLAN]; exists {
			return ErrDuplicateVLAN{
				VLAN:     c.Segments[i].VLAN,
				Segment1: other,
				Segment2: c.Segments[i].Name,
			}
		}
		vlanIDs[c.Segments[i].VLAN] = c.Segments[i].Name
	}

	for i := range c.Peers {
		if err := c.Peers[i].Validate(switchIDs); err != nil {
			return err
		}
	}

	for i := range c.LAGs {
		if err := c.LAGs[i].Validate(); err != nil {
			return err
		}
	}

	return nil
}

// EVPNConfig holds EVPN-VXLAN overlay parameters.
type EVPNConfig struct {
	// VNIBase is the starting VNI value. VNI = VNIBase + VLAN ID.
	VNIBase uint32 `yaml:"vni-base" json:"vni_base" mapstructure:"vni-base"`

	// AnycastGatewayMAC is the shared MAC for distributed anycast gateway.
	AnycastGatewayMAC string `yaml:"anycast-gateway-mac" json:"anycast_gateway_mac" mapstructure:"anycast-gateway-mac"`

	// ARPSuppression enables ARP suppression on VTEP interfaces.
	ARPSuppression bool `yaml:"arp-suppression" json:"arp_suppression" mapstructure:"arp-suppression"`

	// RTBase is the base route-target value for auto-derivation.
	RTBase string `yaml:"rt-base,omitempty" json:"rt_base,omitempty" mapstructure:"rt-base"`
}

// SwitchConfig describes a single physical switch in the fabric.
type SwitchConfig struct {
	// ID is the unique identifier for this switch.
	ID string `yaml:"id" json:"id" mapstructure:"id"`

	// Vendor identifies the switch vendor (e.g., "cisco-nexus").
	Vendor string `yaml:"vendor" json:"vendor" mapstructure:"vendor"`

	// Model is the switch hardware model.
	Model string `yaml:"model,omitempty" json:"model,omitempty" mapstructure:"model"`

	// MgmtIP is the management IP address used for SSH connections.
	MgmtIP string `yaml:"mgmt-ip" json:"mgmt_ip" mapstructure:"mgmt-ip"`

	// CredentialsRef is a reference to stored credentials (e.g., a secret name).
	CredentialsRef string `yaml:"credentials-ref" json:"credentials_ref" mapstructure:"credentials-ref"`

	// VTEPLoopback is the loopback address used for VXLAN VTEP (EVPN mode).
	VTEPLoopback string `yaml:"vtep-loopback,omitempty" json:"vtep_loopback,omitempty" mapstructure:"vtep-loopback"`

	// BGPASN is the BGP autonomous system number for the switch.
	BGPASN uint32 `yaml:"bgp-asn,omitempty" json:"bgp_asn,omitempty" mapstructure:"bgp-asn"`

	// SSHPort overrides the default SSH port (22).
	SSHPort int `yaml:"ssh-port,omitempty" json:"ssh_port,omitempty" mapstructure:"ssh-port"`

	// SSHUser is the SSH username for the switch.
	SSHUser string `yaml:"ssh-user,omitempty" json:"ssh_user,omitempty" mapstructure:"ssh-user"`

	// SSHPassword is the SSH password for the switch.
	SSHPassword string `yaml:"ssh-password,omitempty" json:"ssh_password,omitempty" mapstructure:"ssh-password" secret:"true"`

	// SSHKeyPath is the path to the SSH private key file.
	SSHKeyPath string `yaml:"ssh-key-path,omitempty" json:"ssh_key_path,omitempty" mapstructure:"ssh-key-path"`

	// KnownHostsPath is the path to the SSH known_hosts file.
	KnownHostsPath string `yaml:"known-hosts-path,omitempty" json:"known_hosts_path,omitempty" mapstructure:"known-hosts-path"`
}

// Validate checks the switch configuration for required fields.
func (c *SwitchConfig) Validate() error {
	if c.ID == "" {
		return ErrInvalidFabricConfig{Reason: "switch id is required"}
	}
	if c.Vendor == "" {
		return ErrInvalidFabricConfig{Reason: "switch vendor is required for switch " + c.ID}
	}
	if c.MgmtIP == "" {
		return ErrInvalidFabricConfig{Reason: "switch mgmt-ip is required for switch " + c.ID}
	}
	return nil
}

// PeerConfig defines a peering relationship between two switches for
// MC-LAG (vPC) or ESI-LAG.
type PeerConfig struct {
	// SwitchA is the ID of the first switch in the peer pair.
	SwitchA string `yaml:"switch-a" json:"switch_a" mapstructure:"switch-a"`

	// SwitchB is the ID of the second switch in the peer pair.
	SwitchB string `yaml:"switch-b" json:"switch_b" mapstructure:"switch-b"`

	// PeerLinkPorts lists the physical ports forming the peer link.
	PeerLinkPorts []string `yaml:"peer-link-ports" json:"peer_link_ports" mapstructure:"peer-link-ports"`

	// KeepaliveDest is the keepalive destination IP for vPC keepalive.
	KeepaliveDest string `yaml:"keepalive-dest,omitempty" json:"keepalive_dest,omitempty" mapstructure:"keepalive-dest"`
}

// Validate checks the peer configuration.
func (c *PeerConfig) Validate(switchIDs map[string]struct{}) error {
	if c.SwitchA == "" || c.SwitchB == "" {
		return ErrInvalidFabricConfig{Reason: "peer config requires switch-a and switch-b"}
	}
	if _, ok := switchIDs[c.SwitchA]; !ok {
		return ErrUnknownSwitch{ID: c.SwitchA}
	}
	if _, ok := switchIDs[c.SwitchB]; !ok {
		return ErrUnknownSwitch{ID: c.SwitchB}
	}
	if len(c.PeerLinkPorts) == 0 {
		return ErrInvalidFabricConfig{Reason: "peer config requires at least one peer-link port"}
	}
	return nil
}

// LAGConfig defines a link aggregation group.
type LAGConfig struct {
	// ID is the unique LAG identifier.
	ID string `yaml:"id" json:"id" mapstructure:"id"`

	// Members lists the switch ports in this LAG.
	Members []PortRef `yaml:"members" json:"members" mapstructure:"members"`

	// MCLAG indicates this is a multi-chassis LAG spanning two peer switches.
	MCLAG bool `yaml:"mclag,omitempty" json:"mclag,omitempty" mapstructure:"mclag"`

	// ESI is the Ethernet Segment Identifier for ESI-LAG on NX-OS 10.2+.
	ESI string `yaml:"esi,omitempty" json:"esi,omitempty" mapstructure:"esi"`

	// LACPMode is the LACP negotiation mode ("active" or "passive").
	LACPMode string `yaml:"lacp-mode,omitempty" json:"lacp_mode,omitempty" mapstructure:"lacp-mode"`

	// LACPRate is the LACP PDU rate ("fast" or "normal").
	LACPRate string `yaml:"lacp-rate,omitempty" json:"lacp_rate,omitempty" mapstructure:"lacp-rate"`

	// PortChannelID is the NX-OS port-channel number.
	PortChannelID uint16 `yaml:"port-channel-id" json:"port_channel_id" mapstructure:"port-channel-id"`
}

// Validate checks the LAG configuration for required fields.
func (c *LAGConfig) Validate() error {
	if c.ID == "" {
		return ErrInvalidFabricConfig{Reason: "lag id is required"}
	}
	if len(c.Members) == 0 {
		return ErrInvalidFabricConfig{Reason: "lag requires at least one member for lag " + c.ID}
	}
	if c.PortChannelID == 0 {
		return ErrInvalidFabricConfig{Reason: "lag port-channel-id is required for lag " + c.ID}
	}
	return nil
}

// SegmentConfig defines a network segment to be provisioned on the fabric.
type SegmentConfig struct {
	// Name is the unique segment name.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// VLAN is the IEEE 802.1Q VLAN identifier.
	VLAN uint16 `yaml:"vlan" json:"vlan" mapstructure:"vlan"`

	// CIDR is the IP network prefix (e.g., "10.200.0.0/24").
	CIDR string `yaml:"cidr" json:"cidr" mapstructure:"cidr"`

	// Gateway is the default gateway IP address.
	Gateway string `yaml:"gateway,omitempty" json:"gateway,omitempty" mapstructure:"gateway"`

	// DNS lists the DNS server addresses.
	DNS []string `yaml:"dns,omitempty" json:"dns,omitempty" mapstructure:"dns"`

	// DHCP enables DHCP serving on this segment.
	DHCP bool `yaml:"dhcp,omitempty" json:"dhcp,omitempty" mapstructure:"dhcp"`

	// Role classifies the segment for port lifecycle operations.
	Role SegmentRole `yaml:"role,omitempty" json:"role,omitempty" mapstructure:"role"`
}

// Validate checks the segment configuration.
func (c *SegmentConfig) Validate() error {
	if c.Name == "" {
		return ErrInvalidFabricConfig{Reason: "segment name is required"}
	}
	if c.VLAN < 1 || c.VLAN > 4094 {
		return ErrInvalidFabricConfig{Reason: "segment vlan must be between 1 and 4094 for segment " + c.Name}
	}
	if c.Role != RoleNone && c.Role != RoleProvisioning && c.Role != RoleQuarantine {
		return ErrInvalidFabricConfig{Reason: "segment role must be 'provisioning', 'quarantine', or empty for segment " + c.Name}
	}
	return nil
}
