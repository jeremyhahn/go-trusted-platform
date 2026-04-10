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

package ovs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
)

// VXLANInterfaceType is the OVSDB interface type for VXLAN tunnels
const VXLANInterfaceType = "vxlan"

// VXLANPortConfig holds VXLAN port configuration for OVS
type VXLANPortConfig struct {
	RemoteIP     netip.Addr // Remote VTEP IP (options:remote_ip)
	LocalIP      netip.Addr // Local VTEP IP (options:local_ip), optional
	Key          uint32     // VNI/Key (options:key), 0 means use flow-based
	DstPort      uint16     // UDP destination port (options:dst_port), default 4789
	TOS          uint8      // Type of Service (options:tos), optional
	TTL          uint8      // TTL (options:ttl), optional
	DF           bool       // Don't Fragment (options:df_default)
	Csum         bool       // Enable checksums (options:csum)
	ExtensionGBP bool       // Enable GBP extension (options:exts=gbp)
}

// VXLANPort represents an OVS VXLAN port with its configuration
type VXLANPort struct {
	Port                 // Embed base Port
	RemoteIP  netip.Addr // Remote VTEP IP
	LocalIP   netip.Addr // Local VTEP IP (may be invalid if not set)
	Key       uint32     // VNI, 0 if flow-based
	DstPort   uint16     // UDP destination port
	Options   map[string]string
	IsFlowKey bool // True if VNI is determined by OpenFlow rules
}

// DefaultVXLANPort is the standard VXLAN UDP port
const DefaultVXLANPort uint16 = 4789

// MaxVNI is the maximum valid VXLAN Network Identifier
const MaxVNI uint32 = 16777215 // 2^24 - 1

// Validate checks if the VXLAN configuration is valid
func (cfg *VXLANPortConfig) Validate() error {
	if !cfg.RemoteIP.IsValid() {
		return ErrInvalidRemoteIP
	}

	// RemoteIP must be either IPv4 or IPv6, not zero
	if cfg.RemoteIP.IsUnspecified() {
		return ErrInvalidRemoteIP
	}

	// LocalIP is optional, but if provided must be valid and same family as RemoteIP
	if cfg.LocalIP.IsValid() && !cfg.LocalIP.IsUnspecified() {
		if cfg.RemoteIP.Is4() != cfg.LocalIP.Is4() {
			return ErrIPFamilyMismatch
		}
	}

	// Key can be 0 (flow-based) or any value up to MaxVNI
	if cfg.Key > MaxVNI {
		return ErrInvalidVNI
	}

	// DstPort of 0 means use default (4789)
	// Any port value is technically valid

	return nil
}

// generateVXLANPortName generates a unique port name based on remote IP and key
// Format: vxlan-{hash8}-{key} where hash8 is first 8 chars of SHA256(remote_ip)
func generateVXLANPortName(remoteIP netip.Addr, key uint32) string {
	hash := sha256.Sum256([]byte(remoteIP.String()))
	hashStr := hex.EncodeToString(hash[:4]) // 8 hex chars

	if key == 0 {
		return fmt.Sprintf("vxlan-%s-flow", hashStr)
	}
	return fmt.Sprintf("vxlan-%s-%d", hashStr, key)
}

// buildVXLANOptions builds the OVSDB options map for a VXLAN interface
func buildVXLANOptions(cfg *VXLANPortConfig) map[string]string {
	options := make(map[string]string)

	// Required: remote_ip
	options["remote_ip"] = cfg.RemoteIP.String()

	// Optional: local_ip
	if cfg.LocalIP.IsValid() && !cfg.LocalIP.IsUnspecified() {
		options["local_ip"] = cfg.LocalIP.String()
	}

	// Key: 0 means flow-based, otherwise use the value
	if cfg.Key > 0 {
		options["key"] = strconv.FormatUint(uint64(cfg.Key), 10)
	} else {
		options["key"] = "flow"
	}

	// Optional: dst_port (only if not default 4789)
	if cfg.DstPort != 0 && cfg.DstPort != DefaultVXLANPort {
		options["dst_port"] = strconv.FormatUint(uint64(cfg.DstPort), 10)
	}

	// Optional: tos
	if cfg.TOS > 0 {
		options["tos"] = strconv.FormatUint(uint64(cfg.TOS), 10)
	}

	// Optional: ttl
	if cfg.TTL > 0 {
		options["ttl"] = strconv.FormatUint(uint64(cfg.TTL), 10)
	}

	// Optional: df_default
	if cfg.DF {
		options["df_default"] = "true"
	}

	// Optional: csum
	if cfg.Csum {
		options["csum"] = "true"
	}

	// Optional: GBP extension
	if cfg.ExtensionGBP {
		options["exts"] = "gbp"
	}

	return options
}

// AddVXLANPort creates a VXLAN tunnel port on a bridge.
// Port name will be auto-generated as vxlan-{remote_ip_hash}-{key}
func (c *Client) AddVXLANPort(ctx context.Context, bridgeName string, cfg *VXLANPortConfig) (*VXLANPort, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}
	if cfg == nil {
		return nil, ErrInvalidVXLANConfig
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Generate port name
	portName := generateVXLANPortName(cfg.RemoteIP, cfg.Key)

	return c.AddVXLANPortWithName(ctx, bridgeName, portName, cfg)
}

// AddVXLANPortWithName creates a VXLAN port with a specific name
func (c *Client) AddVXLANPortWithName(ctx context.Context, bridgeName, portName string, cfg *VXLANPortConfig) (*VXLANPort, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}
	if portName == "" {
		return nil, ErrInvalidPortName
	}
	if cfg == nil {
		return nil, ErrInvalidVXLANConfig
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Check if bridge exists
	bridge, err := c.GetBridge(ctx, bridgeName)
	if err != nil {
		return nil, err
	}

	// Check if port already exists
	existing, _ := c.GetPort(ctx, portName)
	if existing != nil {
		// Check if it's a VXLAN port
		iface, _ := c.GetInterface(ctx, portName)
		if iface != nil && iface.Type == VXLANInterfaceType {
			return nil, ErrVXLANPortExists
		}
		return nil, ErrPortExists
	}

	// Build interface options
	options := buildVXLANOptions(cfg)

	// Create interface row with type="vxlan" and options
	interfaceRow := map[string]interface{}{
		"name":    portName,
		"type":    VXLANInterfaceType,
		"options": MarshalMap(options),
	}
	interfaceInsert := NewInsertOperation(interfaceTable, interfaceRow, "new_vxlan_interface")

	// Create port row with interface reference
	portRow := map[string]interface{}{
		"name":       portName,
		"interfaces": NamedUUID{NamedUUID: "new_vxlan_interface"},
	}
	portInsert := NewInsertOperation(portTable, portRow, "new_vxlan_port")

	// Mutate bridge to add port reference
	bridgeMutate := NewMutateOperation(
		bridgeTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", bridge.UUID})},
		[]Mutation{NewMutation("ports", "insert", NamedUUID{NamedUUID: "new_vxlan_port"})},
	)

	// Execute transaction
	results, err := c.Transact(ctx, interfaceInsert, portInsert, bridgeMutate)
	if err != nil {
		return nil, fmt.Errorf("failed to add VXLAN port: %w", err)
	}

	if len(results) < 2 || results[1].UUID == nil {
		return nil, ErrTransactionFailed
	}

	// Retrieve and return the created VXLAN port
	return c.GetVXLANPort(ctx, bridgeName, portName)
}

// DeleteVXLANPort removes a VXLAN tunnel port from a bridge
func (c *Client) DeleteVXLANPort(ctx context.Context, bridgeName, portName string) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if portName == "" {
		return ErrInvalidPortName
	}

	// Verify it's a VXLAN port
	iface, err := c.GetInterface(ctx, portName)
	if err != nil {
		if err == ErrPortNotFound {
			return ErrVXLANPortNotFound
		}
		return err
	}

	if iface.Type != VXLANInterfaceType {
		return ErrVXLANPortNotFound
	}

	// Use the standard DeletePort method
	return c.DeletePort(ctx, bridgeName, portName)
}

// ListVXLANPorts returns all VXLAN ports on a bridge
func (c *Client) ListVXLANPorts(ctx context.Context, bridgeName string) ([]*VXLANPort, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}

	// Get all ports on the bridge
	ports, err := c.ListPorts(ctx, bridgeName)
	if err != nil {
		return nil, err
	}

	vxlanPorts := make([]*VXLANPort, 0)

	for _, port := range ports {
		// Get the interface for this port
		if len(port.Interfaces) == 0 {
			continue
		}

		// Get interface by name (port and interface typically share the same name)
		iface, err := c.GetInterface(ctx, port.Name)
		if err != nil {
			continue
		}

		// Check if it's a VXLAN interface
		if iface.Type != VXLANInterfaceType {
			continue
		}

		// Parse VXLAN-specific data
		vxlanPort := parseVXLANPort(port, iface)
		vxlanPorts = append(vxlanPorts, vxlanPort)
	}

	return vxlanPorts, nil
}

// GetVXLANPort returns a specific VXLAN port
func (c *Client) GetVXLANPort(ctx context.Context, bridgeName, portName string) (*VXLANPort, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}
	if portName == "" {
		return nil, ErrInvalidPortName
	}

	// Check bridge exists
	_, err := c.GetBridge(ctx, bridgeName)
	if err != nil {
		return nil, err
	}

	// Get the port
	port, err := c.GetPort(ctx, portName)
	if err != nil {
		if err == ErrPortNotFound {
			return nil, ErrVXLANPortNotFound
		}
		return nil, err
	}

	// Get the interface
	iface, err := c.GetInterface(ctx, portName)
	if err != nil {
		return nil, err
	}

	// Verify it's a VXLAN interface
	if iface.Type != VXLANInterfaceType {
		return nil, ErrVXLANPortNotFound
	}

	return parseVXLANPort(port, iface), nil
}

// parseVXLANPort parses a VXLAN port from port and interface data
func parseVXLANPort(port *Port, iface *Interface) *VXLANPort {
	vxlanPort := &VXLANPort{
		Port:    *port,
		Options: make(map[string]string),
		DstPort: DefaultVXLANPort, // Default value
	}

	// Copy options from interface OtherConfig if available
	// In OVSDB, interface options are stored separately
	// We need to query them from the raw interface data
	// For now, we'll use the OtherConfig as a fallback
	for k, v := range iface.OtherConfig {
		vxlanPort.Options[k] = v
	}

	// Parse remote_ip
	if remoteIPStr, ok := vxlanPort.Options["remote_ip"]; ok {
		if addr, err := netip.ParseAddr(remoteIPStr); err == nil {
			vxlanPort.RemoteIP = addr
		}
	}

	// Parse local_ip
	if localIPStr, ok := vxlanPort.Options["local_ip"]; ok {
		if addr, err := netip.ParseAddr(localIPStr); err == nil {
			vxlanPort.LocalIP = addr
		}
	}

	// Parse key
	if keyStr, ok := vxlanPort.Options["key"]; ok {
		if keyStr == "flow" {
			vxlanPort.Key = 0
			vxlanPort.IsFlowKey = true
		} else if key, err := strconv.ParseUint(keyStr, 10, 32); err == nil {
			vxlanPort.Key = uint32(key)
		}
	}

	// Parse dst_port
	if dstPortStr, ok := vxlanPort.Options["dst_port"]; ok {
		if dstPort, err := strconv.ParseUint(dstPortStr, 10, 16); err == nil {
			vxlanPort.DstPort = uint16(dstPort)
		}
	}

	return vxlanPort
}

// GetInterfaceOptions retrieves the options map from an interface by name.
// This is useful for getting VXLAN-specific options that are stored in the
// interface options column rather than other_config.
func (c *Client) GetInterfaceOptions(ctx context.Context, name string) (map[string]string, error) {
	if name == "" {
		return nil, ErrInvalidPortName
	}

	// Select the interface with its options column
	rows, err := c.Select(ctx, interfaceTable, []Condition{NewCondition("name", "==", name)}, []string{"_uuid", "name", "options"})
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, ErrPortNotFound
	}

	// Parse the options map
	options := parseMap(rows[0]["options"])
	return options, nil
}

// GetVXLANPortWithOptions returns a VXLAN port with its complete options.
// This method queries the interface options column directly for accurate VXLAN config.
func (c *Client) GetVXLANPortWithOptions(ctx context.Context, bridgeName, portName string) (*VXLANPort, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}
	if portName == "" {
		return nil, ErrInvalidPortName
	}

	// Get the base VXLAN port
	vxlanPort, err := c.GetVXLANPort(ctx, bridgeName, portName)
	if err != nil {
		return nil, err
	}

	// Get the interface options
	options, err := c.GetInterfaceOptions(ctx, portName)
	if err != nil {
		return vxlanPort, nil // Return port even if options query fails
	}

	// Update the VXLAN port with the actual options
	vxlanPort.Options = options

	// Re-parse the VXLAN-specific fields from options
	if remoteIPStr, ok := options["remote_ip"]; ok {
		if addr, err := netip.ParseAddr(remoteIPStr); err == nil {
			vxlanPort.RemoteIP = addr
		}
	}

	if localIPStr, ok := options["local_ip"]; ok {
		if addr, err := netip.ParseAddr(localIPStr); err == nil {
			vxlanPort.LocalIP = addr
		}
	}

	if keyStr, ok := options["key"]; ok {
		if keyStr == "flow" {
			vxlanPort.Key = 0
			vxlanPort.IsFlowKey = true
		} else if key, err := strconv.ParseUint(keyStr, 10, 32); err == nil {
			vxlanPort.Key = uint32(key)
			vxlanPort.IsFlowKey = false
		}
	}

	if dstPortStr, ok := options["dst_port"]; ok {
		if dstPort, err := strconv.ParseUint(dstPortStr, 10, 16); err == nil {
			vxlanPort.DstPort = uint16(dstPort)
		}
	}

	return vxlanPort, nil
}

// UpdateVXLANPort updates the configuration of an existing VXLAN port.
// Only non-zero values in the config will be updated.
func (c *Client) UpdateVXLANPort(ctx context.Context, bridgeName, portName string, cfg *VXLANPortConfig) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if portName == "" {
		return ErrInvalidPortName
	}
	if cfg == nil {
		return ErrInvalidVXLANConfig
	}

	// Verify the port exists and is a VXLAN port
	_, err := c.GetVXLANPort(ctx, bridgeName, portName)
	if err != nil {
		return err
	}

	// Validate the new configuration
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Build the new options map
	options := buildVXLANOptions(cfg)

	// Update the interface options
	updateOp := NewUpdateOperation(
		interfaceTable,
		[]Condition{NewCondition("name", "==", portName)},
		map[string]interface{}{
			"options": MarshalMap(options),
		},
	)

	_, err = c.Transact(ctx, updateOp)
	if err != nil {
		return fmt.Errorf("failed to update VXLAN port: %w", err)
	}

	return nil
}
