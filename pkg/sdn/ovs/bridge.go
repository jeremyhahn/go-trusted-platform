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
	"fmt"
	"strings"
)

const (
	bridgeTable = "Bridge"
	ovsTable    = "Open_vSwitch"
)

// CreateBridge creates a new OVS bridge
// This creates the bridge along with the required internal port and interface
// (same as ovs-vsctl add-br)
func (c *Client) CreateBridge(ctx context.Context, name string) (*Bridge, error) {
	if name == "" {
		return nil, ErrInvalidBridgeName
	}

	// Check if bridge already exists
	existing, err := c.GetBridge(ctx, name)
	if err == nil && existing != nil {
		return nil, ErrBridgeExists
	}

	// Get OVS UUID first
	ovsUUID, err := c.getOpenVSwitchUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Open_vSwitch UUID: %w", err)
	}

	// Create internal interface (required for bridge to work properly)
	interfaceRow := map[string]interface{}{
		"name": name,
		"type": "internal",
	}
	interfaceInsert := NewInsertOperation(interfaceTable, interfaceRow, "new_interface")

	// Create internal port referencing the interface
	portRow := map[string]interface{}{
		"name":       name,
		"interfaces": NamedUUID{NamedUUID: "new_interface"},
	}
	portInsert := NewInsertOperation(portTable, portRow, "new_port")

	// Create bridge row with reference to the port
	bridgeRow := map[string]interface{}{
		"name":          name,
		"datapath_type": "",
		"ports":         NamedUUID{NamedUUID: "new_port"},
	}
	bridgeInsert := NewInsertOperation(bridgeTable, bridgeRow, "new_bridge")

	// Mutate OVS table to add bridge reference
	ovsMutate := NewMutateOperation(
		ovsTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", ovsUUID})},
		[]Mutation{NewMutation("bridges", "insert", NamedUUID{NamedUUID: "new_bridge"})},
	)

	// Execute transaction: interface -> port -> bridge -> OVS mutation
	results, err := c.Transact(ctx, interfaceInsert, portInsert, bridgeInsert, ovsMutate)
	if err != nil {
		return nil, fmt.Errorf("failed to create bridge: %w", err)
	}

	if len(results) < 3 || results[2].UUID == nil {
		return nil, ErrTransactionFailed
	}

	// Retrieve the created bridge
	return c.GetBridge(ctx, name)
}

// DeleteBridge deletes an OVS bridge
func (c *Client) DeleteBridge(ctx context.Context, name string) error {
	if name == "" {
		return ErrInvalidBridgeName
	}

	// Get bridge to ensure it exists
	bridge, err := c.GetBridge(ctx, name)
	if err != nil {
		return err
	}
	if bridge == nil {
		return ErrBridgeNotFound
	}

	// Get OVS UUID
	ovsUUID, err := c.getOpenVSwitchUUID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Open_vSwitch UUID: %w", err)
	}

	// Remove bridge from OVS table
	ovsMutate := NewMutateOperation(
		ovsTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", ovsUUID})},
		[]Mutation{NewMutation("bridges", "delete", []interface{}{"uuid", bridge.UUID})},
	)

	// Delete bridge
	bridgeDelete := NewDeleteOperation(
		bridgeTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", bridge.UUID})},
	)

	// Execute transaction
	_, err = c.Transact(ctx, ovsMutate, bridgeDelete)
	if err != nil {
		return fmt.Errorf("failed to delete bridge: %w", err)
	}

	return nil
}

// GetBridge retrieves a bridge by name
func (c *Client) GetBridge(ctx context.Context, name string) (*Bridge, error) {
	if name == "" {
		return nil, ErrInvalidBridgeName
	}

	rows, err := c.Select(ctx, bridgeTable, []Condition{NewCondition("name", "==", name)}, nil)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, ErrBridgeNotFound
	}

	return parseBridge(rows[0])
}

// ListBridges returns all bridges
func (c *Client) ListBridges(ctx context.Context) ([]*Bridge, error) {
	rows, err := c.Select(ctx, bridgeTable, nil, nil)
	if err != nil {
		return nil, err
	}

	bridges := make([]*Bridge, 0, len(rows))
	for _, row := range rows {
		bridge, err := parseBridge(row)
		if err != nil {
			continue // Skip unparseable bridges
		}
		bridges = append(bridges, bridge)
	}

	return bridges, nil
}

// UpdateBridge updates bridge properties
func (c *Client) UpdateBridge(ctx context.Context, name string, updates map[string]interface{}) error {
	if name == "" {
		return ErrInvalidBridgeName
	}

	bridge, err := c.GetBridge(ctx, name)
	if err != nil {
		return err
	}

	updateOp := NewUpdateOperation(
		bridgeTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", bridge.UUID})},
		updates,
	)

	_, err = c.Transact(ctx, updateOp)
	if err != nil {
		return fmt.Errorf("failed to update bridge: %w", err)
	}

	return nil
}

// SetBridgeFailMode sets the fail mode for a bridge
func (c *Client) SetBridgeFailMode(ctx context.Context, name string, failMode string) error {
	if failMode != "standalone" && failMode != "secure" && failMode != "" {
		return fmt.Errorf("invalid fail mode: %s (must be 'standalone', 'secure', or empty)", failMode)
	}

	var value interface{}
	if failMode == "" {
		value = Set{Set: []interface{}{}}
	} else {
		value = failMode
	}

	return c.UpdateBridge(ctx, name, map[string]interface{}{
		"fail_mode": value,
	})
}

// SetBridgeProtocols sets the OpenFlow protocols for a bridge
func (c *Client) SetBridgeProtocols(ctx context.Context, name string, protocols []string) error {
	for _, proto := range protocols {
		if !isValidProtocol(proto) {
			return ErrInvalidProtocol
		}
	}

	value := Set{Set: make([]interface{}, len(protocols))}
	for i, p := range protocols {
		value.Set[i] = p
	}

	return c.UpdateBridge(ctx, name, map[string]interface{}{
		"protocols": value,
	})
}

// parseBridge parses a bridge row from OVSDB
func parseBridge(row map[string]interface{}) (*Bridge, error) {
	bridge := &Bridge{
		ExternalIDs: make(map[string]string),
		OtherConfig: make(map[string]string),
		Status:      make(map[string]string),
	}

	// Parse UUID
	if uuidVal, ok := row["_uuid"]; ok {
		if uuidArr, ok := uuidVal.([]interface{}); ok && len(uuidArr) == 2 {
			if uuidStr, ok := uuidArr[1].(string); ok {
				bridge.UUID = uuidStr
			}
		}
	}

	// Parse name
	if name, ok := row["name"].(string); ok {
		bridge.Name = name
	}

	// Parse datapath_type
	if dt, ok := row["datapath_type"].(string); ok {
		bridge.DatapathType = dt
	}

	// Parse fail_mode
	if fm, ok := row["fail_mode"].(string); ok {
		bridge.FailMode = fm
	} else if fmArr, ok := row["fail_mode"].([]interface{}); ok && len(fmArr) == 2 {
		if fmStr, ok := fmArr[1].(string); ok {
			bridge.FailMode = fmStr
		}
	}

	// Parse ports
	bridge.Ports = parseUUIDSet(row["ports"])

	// Parse protocols
	bridge.FlowProtocols = parseStringSet(row["protocols"])

	// Parse STP enable
	if stp, ok := row["stp_enable"].(bool); ok {
		bridge.STP = stp
	}

	// Parse RSTP enable
	if rstp, ok := row["rstp_enable"].(bool); ok {
		bridge.RSTP = rstp
	}

	// Parse mcast_snooping_enable
	if mcast, ok := row["mcast_snooping_enable"].(bool); ok {
		bridge.McastSnooping = mcast
	}

	// Parse external_ids
	bridge.ExternalIDs = parseMap(row["external_ids"])

	// Parse other_config
	bridge.OtherConfig = parseMap(row["other_config"])

	// Parse status
	bridge.Status = parseMap(row["status"])

	return bridge, nil
}

// parseUUIDSet parses an OVSDB set of UUIDs
func parseUUIDSet(val interface{}) []string {
	if val == nil {
		return nil
	}

	// Handle set format: ["set", [["uuid", "xxx"], ["uuid", "yyy"]]]
	if arr, ok := val.([]interface{}); ok {
		if len(arr) == 2 && arr[0] == "set" {
			if items, ok := arr[1].([]interface{}); ok {
				result := make([]string, 0, len(items))
				for _, item := range items {
					if uuidArr, ok := item.([]interface{}); ok && len(uuidArr) == 2 {
						if uuidStr, ok := uuidArr[1].(string); ok {
							result = append(result, uuidStr)
						}
					}
				}
				return result
			}
		}
		// Handle single UUID: ["uuid", "xxx"]
		if len(arr) == 2 && arr[0] == "uuid" {
			if uuidStr, ok := arr[1].(string); ok {
				return []string{uuidStr}
			}
		}
	}

	return nil
}

// parseStringSet parses an OVSDB set of strings
func parseStringSet(val interface{}) []string {
	if val == nil {
		return nil
	}

	// Handle set format: ["set", ["str1", "str2"]]
	if arr, ok := val.([]interface{}); ok {
		if len(arr) == 2 && arr[0] == "set" {
			if items, ok := arr[1].([]interface{}); ok {
				result := make([]string, 0, len(items))
				for _, item := range items {
					if s, ok := item.(string); ok {
						result = append(result, s)
					}
				}
				return result
			}
		}
	}

	// Handle single string
	if s, ok := val.(string); ok {
		return []string{s}
	}

	return nil
}

// parseMap parses an OVSDB map
func parseMap(val interface{}) map[string]string {
	result := make(map[string]string)

	if val == nil {
		return result
	}

	// Handle map format: ["map", [["key1", "val1"], ["key2", "val2"]]]
	if arr, ok := val.([]interface{}); ok && len(arr) == 2 && arr[0] == "map" {
		if items, ok := arr[1].([]interface{}); ok {
			for _, item := range items {
				if pair, ok := item.([]interface{}); ok && len(pair) == 2 {
					if key, ok := pair[0].(string); ok {
						if value, ok := pair[1].(string); ok {
							result[key] = value
						}
					}
				}
			}
		}
	}

	return result
}

// isValidProtocol checks if an OpenFlow protocol version is valid
func isValidProtocol(protocol string) bool {
	validProtocols := []string{
		"OpenFlow10", "OpenFlow11", "OpenFlow12",
		"OpenFlow13", "OpenFlow14", "OpenFlow15",
	}

	for _, valid := range validProtocols {
		if strings.EqualFold(protocol, valid) {
			return true
		}
	}

	return false
}
