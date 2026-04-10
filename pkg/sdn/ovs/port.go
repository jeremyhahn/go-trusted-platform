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
)

const (
	portTable      = "Port"
	interfaceTable = "Interface"
)

// AddPort adds a port to a bridge
func (c *Client) AddPort(ctx context.Context, bridgeName, portName string) (*Port, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}
	if portName == "" {
		return nil, ErrInvalidPortName
	}

	// Check if bridge exists
	bridge, err := c.GetBridge(ctx, bridgeName)
	if err != nil {
		return nil, err
	}

	// Check if port already exists
	existing, _ := c.GetPort(ctx, portName)
	if existing != nil {
		return nil, ErrPortExists
	}

	// Create interface row
	interfaceRow := map[string]interface{}{
		"name": portName,
		"type": "",
	}
	interfaceInsert := NewInsertOperation(interfaceTable, interfaceRow, "new_interface")

	// Create port row with interface reference
	portRow := map[string]interface{}{
		"name":       portName,
		"interfaces": NamedUUID{NamedUUID: "new_interface"},
	}
	portInsert := NewInsertOperation(portTable, portRow, "new_port")

	// Mutate bridge to add port reference
	bridgeMutate := NewMutateOperation(
		bridgeTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", bridge.UUID})},
		[]Mutation{NewMutation("ports", "insert", NamedUUID{NamedUUID: "new_port"})},
	)

	// Execute transaction
	results, err := c.Transact(ctx, interfaceInsert, portInsert, bridgeMutate)
	if err != nil {
		return nil, fmt.Errorf("failed to add port: %w", err)
	}

	if len(results) < 2 || results[1].UUID == nil {
		return nil, ErrTransactionFailed
	}

	// Retrieve the created port
	return c.GetPort(ctx, portName)
}

// DeletePort removes a port from a bridge
func (c *Client) DeletePort(ctx context.Context, bridgeName, portName string) error {
	if bridgeName == "" {
		return ErrInvalidBridgeName
	}
	if portName == "" {
		return ErrInvalidPortName
	}

	// Check if bridge exists
	bridge, err := c.GetBridge(ctx, bridgeName)
	if err != nil {
		return err
	}

	// Check if port exists
	port, err := c.GetPort(ctx, portName)
	if err != nil {
		return err
	}

	// Remove port from bridge
	bridgeMutate := NewMutateOperation(
		bridgeTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", bridge.UUID})},
		[]Mutation{NewMutation("ports", "delete", []interface{}{"uuid", port.UUID})},
	)

	// Delete port
	portDelete := NewDeleteOperation(
		portTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", port.UUID})},
	)

	// Delete associated interfaces
	var interfaceDeletes []Operation
	for _, ifaceUUID := range port.Interfaces {
		interfaceDeletes = append(interfaceDeletes, NewDeleteOperation(
			interfaceTable,
			[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", ifaceUUID})},
		))
	}

	// Execute transaction
	ops := []Operation{bridgeMutate, portDelete}
	ops = append(ops, interfaceDeletes...)
	_, err = c.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("failed to delete port: %w", err)
	}

	return nil
}

// GetPort retrieves a port by name
func (c *Client) GetPort(ctx context.Context, name string) (*Port, error) {
	if name == "" {
		return nil, ErrInvalidPortName
	}

	rows, err := c.Select(ctx, portTable, []Condition{NewCondition("name", "==", name)}, nil)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, ErrPortNotFound
	}

	return parsePort(rows[0])
}

// ListPorts returns all ports on a bridge
func (c *Client) ListPorts(ctx context.Context, bridgeName string) ([]*Port, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}

	// Get bridge to verify it exists and get port UUIDs
	bridge, err := c.GetBridge(ctx, bridgeName)
	if err != nil {
		return nil, err
	}

	ports := make([]*Port, 0, len(bridge.Ports))
	for _, portUUID := range bridge.Ports {
		// Select port by UUID
		rows, err := c.Select(ctx, portTable, []Condition{NewCondition("_uuid", "==", []interface{}{"uuid", portUUID})}, nil)
		if err != nil || len(rows) == 0 {
			continue
		}
		port, err := parsePort(rows[0])
		if err != nil {
			continue
		}
		ports = append(ports, port)
	}

	return ports, nil
}

// UpdatePort updates port properties
func (c *Client) UpdatePort(ctx context.Context, name string, updates map[string]interface{}) error {
	if name == "" {
		return ErrInvalidPortName
	}

	port, err := c.GetPort(ctx, name)
	if err != nil {
		return err
	}

	updateOp := NewUpdateOperation(
		portTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", port.UUID})},
		updates,
	)

	_, err = c.Transact(ctx, updateOp)
	if err != nil {
		return fmt.Errorf("failed to update port: %w", err)
	}

	return nil
}

// SetPortVLAN sets the VLAN tag for a port
func (c *Client) SetPortVLAN(ctx context.Context, portName string, tag int64) error {
	if tag < 0 || tag > 4095 {
		return fmt.Errorf("invalid VLAN tag: %d (must be 0-4095)", tag)
	}

	var value interface{}
	if tag == 0 {
		value = Set{Set: []interface{}{}}
	} else {
		value = tag
	}

	return c.UpdatePort(ctx, portName, map[string]interface{}{
		"tag": value,
	})
}

// SetPortTrunks sets the trunk VLANs for a port
func (c *Client) SetPortTrunks(ctx context.Context, portName string, trunks []int64) error {
	for _, vlan := range trunks {
		if vlan < 0 || vlan > 4095 {
			return fmt.Errorf("invalid VLAN tag: %d (must be 0-4095)", vlan)
		}
	}

	value := Set{Set: make([]interface{}, len(trunks))}
	for i, vlan := range trunks {
		value.Set[i] = vlan
	}

	return c.UpdatePort(ctx, portName, map[string]interface{}{
		"trunks": value,
	})
}

// SetPortState sets the admin state of a port using OVSDB
// Note: admin_state is set on the Interface table, not Port table
func (c *Client) SetPortState(ctx context.Context, portName string, state PortState) error {
	if portName == "" {
		return ErrInvalidPortName
	}

	// Check if port exists
	_, err := c.GetPort(ctx, portName)
	if err != nil {
		return err
	}

	adminState := "up"
	if state == PortStateDown {
		adminState = "down"
	}

	// Set interface admin_state via OVSDB transaction
	updateOp := NewUpdateOperation(
		interfaceTable,
		[]Condition{NewCondition("name", "==", portName)},
		map[string]interface{}{
			"admin_state": adminState,
		},
	)

	_, err = c.Transact(ctx, updateOp)
	if err != nil {
		return fmt.Errorf("failed to set interface state: %w", err)
	}

	return nil
}

// GetInterface retrieves an interface by name
func (c *Client) GetInterface(ctx context.Context, name string) (*Interface, error) {
	if name == "" {
		return nil, ErrInvalidPortName
	}

	rows, err := c.Select(ctx, interfaceTable, []Condition{NewCondition("name", "==", name)}, nil)
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, ErrPortNotFound
	}

	return parseInterface(rows[0])
}

// GetOFPort retrieves the OpenFlow port number for an interface by name
func (c *Client) GetOFPort(ctx context.Context, portName string) (int32, error) {
	iface, err := c.GetInterface(ctx, portName)
	if err != nil {
		return 0, err
	}
	if iface.OFPort <= 0 {
		return 0, ErrPortNotFound
	}
	return iface.OFPort, nil
}

// parsePort parses a port row from OVSDB
func parsePort(row map[string]interface{}) (*Port, error) {
	port := &Port{
		ExternalIDs: make(map[string]string),
		OtherConfig: make(map[string]string),
		Statistics:  make(map[string]int64),
	}

	// Parse UUID
	if uuidVal, ok := row["_uuid"]; ok {
		if uuidArr, ok := uuidVal.([]interface{}); ok && len(uuidArr) == 2 {
			if uuidStr, ok := uuidArr[1].(string); ok {
				port.UUID = uuidStr
			}
		}
	}

	// Parse name
	if name, ok := row["name"].(string); ok {
		port.Name = name
	}

	// Parse tag
	if tagVal, ok := row["tag"]; ok {
		switch v := tagVal.(type) {
		case float64:
			port.Tag = int64(v)
		case int64:
			port.Tag = v
		case []interface{}:
			// Empty set: ["set", []]
			if len(v) == 2 && v[0] == "set" {
				port.Tag = 0
			}
		}
	}

	// Parse interfaces
	port.Interfaces = parseUUIDSet(row["interfaces"])

	// Parse trunks
	if trunksVal, ok := row["trunks"]; ok {
		if arr, ok := trunksVal.([]interface{}); ok && len(arr) == 2 && arr[0] == "set" {
			if items, ok := arr[1].([]interface{}); ok {
				for _, item := range items {
					if num, ok := item.(float64); ok {
						port.Trunks = append(port.Trunks, int64(num))
					}
				}
			}
		}
	}

	// Parse external_ids
	port.ExternalIDs = parseMap(row["external_ids"])

	// Parse other_config
	port.OtherConfig = parseMap(row["other_config"])

	return port, nil
}

// parseInterface parses an interface row from OVSDB
func parseInterface(row map[string]interface{}) (*Interface, error) {
	iface := &Interface{
		ExternalIDs: make(map[string]string),
		OtherConfig: make(map[string]string),
		Statistics:  make(map[string]int64),
	}

	// Parse UUID
	if uuidVal, ok := row["_uuid"]; ok {
		if uuidArr, ok := uuidVal.([]interface{}); ok && len(uuidArr) == 2 {
			if uuidStr, ok := uuidArr[1].(string); ok {
				iface.UUID = uuidStr
			}
		}
	}

	// Parse name
	if name, ok := row["name"].(string); ok {
		iface.Name = name
	}

	// Parse type
	if typ, ok := row["type"].(string); ok {
		iface.Type = typ
	}

	// Parse MAC
	if mac, ok := row["mac_in_use"].(string); ok {
		iface.MAC = mac
	}

	// Parse MTU
	if mtuVal, ok := row["mtu"]; ok {
		switch v := mtuVal.(type) {
		case float64:
			iface.MTU = int64(v)
		case int64:
			iface.MTU = v
		}
	}

	// Parse ofport (OpenFlow port number)
	if ofportVal, ok := row["ofport"]; ok {
		switch v := ofportVal.(type) {
		case float64:
			iface.OFPort = int32(v)
		case int64:
			iface.OFPort = int32(v)
		}
	}

	// Parse admin_state
	if state, ok := row["admin_state"].(string); ok {
		iface.AdminState = state
	}

	// Parse link_state
	if state, ok := row["link_state"].(string); ok {
		iface.LinkState = state
	}

	// Parse external_ids
	iface.ExternalIDs = parseMap(row["external_ids"])

	// Parse other_config
	iface.OtherConfig = parseMap(row["other_config"])

	return iface, nil
}

// getPortVLANTag retrieves the VLAN tag for a port using OVSDB
func (c *Client) getPortVLANTag(ctx context.Context, portName string) (int64, error) {
	port, err := c.GetPort(ctx, portName)
	if err != nil {
		return 0, err
	}
	return port.Tag, nil
}
