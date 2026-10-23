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
	return c.AddPortWithType(ctx, bridgeName, portName, "")
}

// interfaceTypes are the Interface table type values Open vSwitch implements
// (ovs-vswitchd.conf.db(5), Interface "type"). The empty type is "system": an
// existing kernel network device of the port's name.
var interfaceTypes = map[string]bool{
	"": true, "system": true, "internal": true, "tap": true, "patch": true,
	"geneve": true, "gre": true, "vxlan": true, "lisp": true, "stt": true,
	"erspan": true, "ip6erspan": true, "ip6gre": true, "gtpu": true,
	"bareudp": true, "srv6": true, "dpdk": true, "dpdkvhostuserclient": true,
	"afxdp": true, "afxdp-nonpmd": true,
}

// AddPortWithType adds a port to a bridge whose single interface has the
// given Open vSwitch type, written in the same transaction that creates it:
// an "internal" port never exists, even briefly, as a system interface that
// would attach a kernel device of the same name.
func (c *Client) AddPortWithType(ctx context.Context, bridgeName, portName, ifType string) (*Port, error) {
	if !interfaceTypes[ifType] {
		return nil, &ErrInvalidPortType{Type: ifType}
	}
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
		"type": ifType,
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
		return nil, &WrappedError{Msg: "failed to add port", Err: err}
	}

	if len(results) < 2 || results[1].UUID == nil {
		return nil, ErrTransactionFailed
	}

	// Retrieve the created port
	return c.GetPort(ctx, portName)
}

// AddBond creates a bonded port on a bridge: one Port row with N
// Interface rows, bond_mode set (and optionally lacp=active|passive).
// Members is the list of physical NIC names (e.g. {"eth6","eth7"}).
//
// The transaction inserts N interfaces, one port that references all
// of them, and mutates the bridge to include the new port — all in a
// single OVSDB Transact so the write is atomic. This is the same
// pattern `ovs-vsctl add-bond` uses internally, just without the fork
// overhead or the vsctl dependency on the target system.
//
// Modes: "active-backup", "balance-slb", "balance-tcp" (OVS port
// bond_mode values). LACP: "active", "passive", "off" — pass empty to
// leave the column unset (no LACP). Returns ErrPortExists when a port
// with this name already exists; callers who want idempotent semantics
// should GetPort first and treat ErrPortNotFound as "safe to create".
func (c *Client) AddBond(ctx context.Context, bridgeName, bondName string, members []string, mode string, lacp string) (*Port, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}
	if bondName == "" {
		return nil, ErrInvalidPortName
	}
	if len(members) < 2 {
		return nil, &MessageError{Msg: fmt.Sprintf("OVS bond needs at least 2 members (got %d)", len(members))}
	}

	bridge, err := c.GetBridge(ctx, bridgeName)
	if err != nil {
		return nil, err
	}
	if existing, _ := c.GetPort(ctx, bondName); existing != nil {
		return nil, ErrPortExists
	}

	// Build one Insert per member interface. Each gets a distinct
	// named-uuid so the Port insert can reference all of them.
	ops := make([]Operation, 0, len(members)+2)
	ifaceNamedUUIDs := make([]interface{}, 0, len(members))
	for i, member := range members {
		named := fmt.Sprintf("bond_iface_%d", i)
		ifaceRow := map[string]interface{}{
			"name": member,
			"type": "",
		}
		ops = append(ops, NewInsertOperation(interfaceTable, ifaceRow, named))
		ifaceNamedUUIDs = append(ifaceNamedUUIDs, NamedUUID{NamedUUID: named})
	}

	portRow := map[string]interface{}{
		"name":       bondName,
		"interfaces": MarshalSet(ifaceNamedUUIDs),
	}
	if mode != "" {
		portRow["bond_mode"] = mode
	}
	if lacp != "" {
		portRow["lacp"] = lacp
	}
	const portNamedUUID = "new_bond_port"
	ops = append(ops, NewInsertOperation(portTable, portRow, portNamedUUID))

	ops = append(ops, NewMutateOperation(
		bridgeTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", bridge.UUID})},
		[]Mutation{NewMutation("ports", "insert", NamedUUID{NamedUUID: portNamedUUID})},
	))

	if _, err := c.Transact(ctx, ops...); err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("failed to add OVS bond %q", bondName), Err: err}
	}

	return c.GetPort(ctx, bondName)
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
		return &WrappedError{Msg: "failed to delete port", Err: err}
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
		return &WrappedError{Msg: "failed to update port", Err: err}
	}

	return nil
}

// SetPortVLAN sets the VLAN tag for a port
func (c *Client) SetPortVLAN(ctx context.Context, portName string, tag int64) error {
	if tag < 0 || tag > 4095 {
		return &MessageError{Msg: fmt.Sprintf("invalid VLAN tag: %d (must be 0-4095)", tag)}
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
			return &MessageError{Msg: fmt.Sprintf("invalid VLAN tag: %d (must be 0-4095)", vlan)}
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
		return &WrappedError{Msg: "failed to set interface state", Err: err}
	}

	return nil
}

// SetIngressPolicing polices the named interface's ingress to rateBps with a
// burst of burstBits (see ValidateIngressPolicing). A rate of 0 disables
// policing; a burst of 0 lets Open vSwitch pick its default. An unknown
// interface is ErrInterfaceNotFound.
func (c *Client) SetIngressPolicing(ctx context.Context, name string, rateBps, burstBits uint64) error {
	if name == "" {
		return ErrInvalidPortName
	}
	if err := ValidateIngressPolicing(rateBps, burstBits); err != nil {
		return err
	}

	// bps / 1000 is at most 1.8e16, so the kbps value always fits the
	// signed OVSDB integer column.
	updateOp := NewUpdateOperation(
		interfaceTable,
		[]Condition{NewCondition("name", "==", name)},
		map[string]interface{}{
			"ingress_policing_rate":  int64(rateBps / 1000),
			"ingress_policing_burst": int64(burstBits / 1000),
		},
	)

	results, err := c.Transact(ctx, updateOp)
	if err != nil {
		return &WrappedError{Msg: "failed to set interface ingress policing", Err: err}
	}
	if len(results) == 0 || results[0].Count == nil || *results[0].Count == 0 {
		return ErrInterfaceNotFound
	}

	return nil
}

// ValidateIngressPolicing checks an ingress policing rate (bps) and burst
// (bits) before anything is applied. Open vSwitch polices in kbps and kb, so
// each must be 0 or a whole multiple of 1000; a burst without a rate has
// nothing to shape. An invalid pair is *ErrInvalidPolicing.
func ValidateIngressPolicing(rateBps, burstBits uint64) error {
	if rateBps%1000 != 0 || burstBits%1000 != 0 || (rateBps == 0 && burstBits != 0) {
		return &ErrInvalidPolicing{RateBps: rateBps, BurstBits: burstBits}
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
