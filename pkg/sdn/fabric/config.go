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

import (
	"slices"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// FabricConfig is the configuration of the physical switch fabric. The
// reference switch is pure L2 (docs/architecture/reference-network.md): it
// carries the environment's underlay VLANs, derived by the network plan, on
// the ports of each port class, and does no routing, SVIs or EVPN.
type FabricConfig struct {
	// Switches lists the physical switches in the fabric.
	Switches []SwitchConfig `yaml:"switches" json:"switches" mapstructure:"switches"`

	// Peers defines MC-LAG or vPC peer relationships between switches. The
	// peer-link ports carry the peer-link port class.
	Peers []PeerConfig `yaml:"peers,omitempty" json:"peers,omitempty" mapstructure:"peers"`

	// LAGs defines link aggregation groups across the fabric.
	LAGs []LAGConfig `yaml:"lags,omitempty" json:"lags,omitempty" mapstructure:"lags"`

	// Ports assigns a port class to each platform switch port. A port's
	// mode, allowed VLANs, native VLAN and MTU all follow from its class.
	Ports []PortAssignment `yaml:"ports,omitempty" json:"ports,omitempty" mapstructure:"ports"`
}

// PortAssignment gives one switch port (or port-channel) its port class.
type PortAssignment struct {
	// PortRef names the switch and port.
	PortRef `yaml:",inline" json:",inline" mapstructure:",squash"`

	// Class is the port class: gateway, hypervisor, bmc, mgmt-uplink or
	// peer-link.
	Class zone.PortClass `yaml:"class" json:"class" mapstructure:"class"`

	// Description is an optional interface description.
	Description string `yaml:"description,omitempty" json:"description,omitempty" mapstructure:"description"`
}

// Validate checks the fabric configuration: at least one switch with a
// unique ID, valid peers and LAGs, and every port assignment on a known
// switch, with a known class, assigned once.
func (c *FabricConfig) Validate() error {
	if c == nil {
		return ErrNilConfig{}
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

	seen := make(map[PortRef]struct{}, len(c.Ports))
	for _, pa := range c.Ports {
		if err := pa.Validate(); err != nil {
			return err
		}
		if _, ok := switchIDs[pa.SwitchID]; !ok {
			return ErrUnknownSwitch{ID: pa.SwitchID}
		}
		if !slices.Contains(netplan.PortClasses(), pa.Class) {
			return ErrUnknownPortClass{Class: pa.Class}
		}
		key := PortRef{SwitchID: pa.SwitchID, Port: pa.Port}
		if _, dup := seen[key]; dup {
			return ErrDuplicatePort{SwitchID: pa.SwitchID, Port: pa.Port}
		}
		seen[key] = struct{}{}
	}

	return nil
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
