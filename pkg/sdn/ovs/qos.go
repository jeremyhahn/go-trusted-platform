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
	"strconv"
)

const (
	qosTable   = "QoS"
	queueTable = "Queue"

	// egressShapingKey marks, in external_ids, the QoS and Queue rows
	// SetEgressShaping creates, so it only ever deletes rows it created.
	egressShapingKey = "tp-egress-shaping"
)

// SetEgressShaping shapes the traffic Open vSwitch sends out of the named
// port to rateBps with a burst of burstBits (see ValidateEgressShaping).
// Ingress policing limits what the port receives; this limits what it
// transmits. The port gets a linux-htb QoS whose queue 0, the queue
// unclassified traffic uses, carries the rate, so every packet is shaped.
//
// A rate of 0 removes the shaping; a burst of 0 lets Open vSwitch pick its
// default. Shaping set by an earlier call is replaced and its rows deleted. A
// QoS something else attached is detached but left in the database. An
// unknown port is ErrPortNotFound.
func (c *Client) SetEgressShaping(ctx context.Context, name string, rateBps, burstBits uint64) error {
	if name == "" {
		return ErrInvalidPortName
	}
	if err := ValidateEgressShaping(rateBps, burstBits); err != nil {
		return err
	}

	portUUID, attached, err := c.portQoS(ctx, name)
	if err != nil {
		return err
	}
	cleanup, err := c.ownQoSDeletes(ctx, attached)
	if err != nil {
		return err
	}

	ops := egressShapingOps(portUUID, rateBps, burstBits)
	portUpdate := len(ops) - 1
	results, err := c.Transact(ctx, append(ops, cleanup...)...)
	if err != nil {
		return &WrappedError{Msg: "failed to set port egress shaping", Err: err}
	}
	// The port can be deleted between the select and the transaction.
	if len(results) <= portUpdate || results[portUpdate].Count == nil || *results[portUpdate].Count == 0 {
		return ErrPortNotFound
	}
	return nil
}

// ValidateEgressShaping checks an egress shaping rate (bps) and burst (bits)
// before anything is applied. Open vSwitch shapes in bps and bits, so any
// value is accepted except a burst without a rate, which has nothing to
// shape. An invalid pair is *ErrInvalidShaping.
func ValidateEgressShaping(rateBps, burstBits uint64) error {
	if rateBps == 0 && burstBits != 0 {
		return &ErrInvalidShaping{RateBps: rateBps, BurstBits: burstBits}
	}
	return nil
}

// egressShapingOps points the port at a new shaping QoS, or at none when
// rateBps is 0.
func egressShapingOps(portUUID string, rateBps, burstBits uint64) []Operation {
	portWhere := []Condition{NewCondition("_uuid", "==", []interface{}{"uuid", portUUID})}
	if rateBps == 0 {
		return []Operation{
			NewUpdateOperation(portTable, portWhere, map[string]interface{}{"qos": Set{Set: []interface{}{}}}),
		}
	}

	owned := MarshalMap(map[string]string{egressShapingKey: "true"})
	rate := strconv.FormatUint(rateBps, 10)
	queueConfig := map[string]string{"max-rate": rate}
	if burstBits > 0 {
		queueConfig["burst"] = strconv.FormatUint(burstBits, 10)
	}

	return []Operation{
		NewInsertOperation(queueTable, map[string]interface{}{
			"other_config": MarshalMap(queueConfig),
			"external_ids": owned,
		}, "egress_queue"),
		NewInsertOperation(qosTable, map[string]interface{}{
			"type":         "linux-htb",
			"other_config": MarshalMap(map[string]string{"max-rate": rate}),
			"queues":       Map{Map: [][]interface{}{{0, NamedUUID{NamedUUID: "egress_queue"}}}},
			"external_ids": owned,
		}, "egress_qos"),
		NewUpdateOperation(portTable, portWhere, map[string]interface{}{"qos": NamedUUID{NamedUUID: "egress_qos"}}),
	}
}

// portQoS returns the named port's UUID and the QoS it has attached, if any.
func (c *Client) portQoS(ctx context.Context, name string) (string, []string, error) {
	rows, err := c.Select(ctx, portTable, []Condition{NewCondition("name", "==", name)}, []string{"_uuid", "qos"})
	if err != nil {
		return "", nil, err
	}
	if len(rows) == 0 {
		return "", nil, ErrPortNotFound
	}
	portUUID, err := UnmarshalUUID(rows[0]["_uuid"])
	if err != nil {
		return "", nil, err
	}
	return portUUID, parseUUIDSet(rows[0]["qos"]), nil
}

// ownQoSDeletes deletes each of qosUUIDs that SetEgressShaping created, with
// its queues. QoS and Queue rows are roots in the Open vSwitch schema, so a
// row nothing references any more stays until it is deleted.
func (c *Client) ownQoSDeletes(ctx context.Context, qosUUIDs []string) ([]Operation, error) {
	var ops []Operation
	for _, qosUUID := range qosUUIDs {
		where := []Condition{NewCondition("_uuid", "==", []interface{}{"uuid", qosUUID})}
		rows, err := c.Select(ctx, qosTable, where, []string{"external_ids", "queues"})
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 || parseMap(rows[0]["external_ids"])[egressShapingKey] != "true" {
			continue
		}
		ops = append(ops, NewDeleteOperation(qosTable, where))
		for _, queueUUID := range parseUUIDMapValues(rows[0]["queues"]) {
			ops = append(ops, NewDeleteOperation(queueTable,
				[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", queueUUID})}))
		}
	}
	return ops, nil
}

// parseUUIDMapValues returns the UUID values of an OVSDB map such as a QoS
// row's queues: ["map", [[key, ["uuid", "..."]], ...]].
func parseUUIDMapValues(val interface{}) []string {
	arr, ok := val.([]interface{})
	if !ok || len(arr) != 2 || arr[0] != "map" {
		return nil
	}
	pairs, ok := arr[1].([]interface{})
	if !ok {
		return nil
	}
	uuids := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		kv, ok := pair.([]interface{})
		if !ok || len(kv) != 2 {
			continue
		}
		if id, err := UnmarshalUUID(kv[1]); err == nil {
			uuids = append(uuids, id)
		}
	}
	return uuids
}
