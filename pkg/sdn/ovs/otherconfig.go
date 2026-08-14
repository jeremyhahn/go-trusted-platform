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
	"errors"
)

var (
	// ErrNoOpenVSwitchRow is returned when the root Open_vSwitch row does
	// not exist. The message intentionally matches the string produced by
	// getOpenVSwitchUUID so retry wrappers keyed on that substring treat
	// both as the same transient startup condition.
	ErrNoOpenVSwitchRow = errors.New("no Open_vSwitch row found")

	// ErrInterfaceNotFound is returned when an Interface row does not exist.
	ErrInterfaceNotFound = errors.New("interface not found")

	// ErrEmptyConfig is returned when a map-column mutation is requested
	// with no keys to apply or delete.
	ErrEmptyConfig = errors.New("at least one configuration key required")
)

// upsertMapMutations builds the delete+insert mutation pair required to
// upsert keys into an OVSDB map column. OVSDB map-column semantics: a naked
// "insert" fails with a constraint violation when a key already exists, so
// the keys are deleted first and re-inserted with their new values in the
// same transaction.
func upsertMapMutations(column string, config map[string]string) []Mutation {
	keys := make([]interface{}, 0, len(config))
	for k := range config {
		keys = append(keys, k)
	}
	return []Mutation{
		NewMutation(column, "delete", Set{Set: keys}),
		NewMutation(column, "insert", MarshalMap(config)),
	}
}

// mutateByName executes a single mutate operation against table rows matching
// name==name and maps a zero match count to notFound.
func (c *Client) mutateByName(ctx context.Context, table, name string, mutations []Mutation, notFound error) error {
	op := NewMutateOperation(
		table,
		[]Condition{NewCondition("name", "==", name)},
		mutations,
	)

	results, err := c.Transact(ctx, op)
	if err != nil {
		return &WrappedError{Msg: "failed to mutate " + table, Err: err}
	}

	if len(results) == 0 || results[0].Count == nil || *results[0].Count == 0 {
		return notFound
	}

	return nil
}

// SetOVSOtherConfig upserts the given keys into the other_config column of
// the global Open_vSwitch row. Existing keys are overwritten; keys not listed
// in config are left untouched.
func (c *Client) SetOVSOtherConfig(ctx context.Context, config map[string]string) error {
	if len(config) == 0 {
		return ErrEmptyConfig
	}

	ovsUUID, err := c.getOpenVSwitchUUID(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to get Open_vSwitch UUID", Err: err}
	}

	op := NewMutateOperation(
		ovsTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", ovsUUID})},
		upsertMapMutations("other_config", config),
	)

	results, err := c.Transact(ctx, op)
	if err != nil {
		return &WrappedError{Msg: "failed to set Open_vSwitch other_config", Err: err}
	}

	if len(results) == 0 || results[0].Count == nil || *results[0].Count == 0 {
		return ErrNoOpenVSwitchRow
	}

	return nil
}

// GetOVSOtherConfig returns the other_config column of the global
// Open_vSwitch row.
func (c *Client) GetOVSOtherConfig(ctx context.Context) (map[string]string, error) {
	rows, err := c.Select(ctx, ovsTable, nil, []string{"other_config"})
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, ErrNoOpenVSwitchRow
	}

	return parseMap(rows[0]["other_config"]), nil
}

// DeleteOVSOtherConfig removes the given keys from the other_config column
// of the global Open_vSwitch row. Keys that are not present are ignored
// (OVSDB map-delete semantics).
func (c *Client) DeleteOVSOtherConfig(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return ErrEmptyConfig
	}

	ovsUUID, err := c.getOpenVSwitchUUID(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to get Open_vSwitch UUID", Err: err}
	}

	keySet := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		keySet = append(keySet, k)
	}

	op := NewMutateOperation(
		ovsTable,
		[]Condition{NewCondition("_uuid", "==", []interface{}{"uuid", ovsUUID})},
		[]Mutation{NewMutation("other_config", "delete", Set{Set: keySet})},
	)

	results, err := c.Transact(ctx, op)
	if err != nil {
		return &WrappedError{Msg: "failed to delete Open_vSwitch other_config keys", Err: err}
	}

	if len(results) == 0 || results[0].Count == nil || *results[0].Count == 0 {
		return ErrNoOpenVSwitchRow
	}

	return nil
}

// SetBridgeDatapath sets the datapath_type column of a bridge. An empty
// datapathType selects the default kernel ("system") datapath; "netdev"
// selects the userspace/DPDK datapath. Changing the datapath type of a live
// bridge causes ovs-vswitchd to destroy and recreate the datapath.
func (c *Client) SetBridgeDatapath(ctx context.Context, name string, datapathType string) error {
	if name == "" {
		return ErrInvalidBridgeName
	}

	return c.UpdateBridge(ctx, name, map[string]interface{}{
		"datapath_type": datapathType,
	})
}

// SetBridgeOtherConfig upserts the given keys into the other_config column
// of the named bridge. Existing keys are overwritten; keys not listed in
// config are left untouched.
func (c *Client) SetBridgeOtherConfig(ctx context.Context, name string, config map[string]string) error {
	if name == "" {
		return ErrInvalidBridgeName
	}
	if len(config) == 0 {
		return ErrEmptyConfig
	}

	return c.mutateByName(ctx, bridgeTable, name, upsertMapMutations("other_config", config), ErrBridgeNotFound)
}

// SetInterfaceType sets the type column of the named interface (e.g.
// "internal", "dpdk", "vxlan"). An empty type selects the default system
// netdev type.
func (c *Client) SetInterfaceType(ctx context.Context, name, ifType string) error {
	if name == "" {
		return ErrInvalidPortName
	}

	op := NewUpdateOperation(
		interfaceTable,
		[]Condition{NewCondition("name", "==", name)},
		map[string]interface{}{"type": ifType},
	)

	results, err := c.Transact(ctx, op)
	if err != nil {
		return &WrappedError{Msg: "failed to set interface type", Err: err}
	}

	if len(results) == 0 || results[0].Count == nil || *results[0].Count == 0 {
		return ErrInterfaceNotFound
	}

	return nil
}

// SetInterfaceOptions upserts the given keys into the options column of the
// named interface. Existing keys are overwritten; keys not listed in options
// are left untouched.
func (c *Client) SetInterfaceOptions(ctx context.Context, name string, options map[string]string) error {
	if name == "" {
		return ErrInvalidPortName
	}
	if len(options) == 0 {
		return ErrEmptyConfig
	}

	return c.mutateByName(ctx, interfaceTable, name, upsertMapMutations("options", options), ErrInterfaceNotFound)
}

// SetInterfaceOtherConfig upserts the given keys into the other_config
// column of the named interface. Existing keys are overwritten; keys not
// listed in config are left untouched.
func (c *Client) SetInterfaceOtherConfig(ctx context.Context, name string, config map[string]string) error {
	if name == "" {
		return ErrInvalidPortName
	}
	if len(config) == 0 {
		return ErrEmptyConfig
	}

	return c.mutateByName(ctx, interfaceTable, name, upsertMapMutations("other_config", config), ErrInterfaceNotFound)
}

// SetBridgeExternalIDs upserts the given keys into the external_ids column
// of the named bridge. Existing keys are overwritten; keys not listed in ids
// are left untouched.
func (c *Client) SetBridgeExternalIDs(ctx context.Context, name string, ids map[string]string) error {
	if name == "" {
		return ErrInvalidBridgeName
	}
	if len(ids) == 0 {
		return ErrEmptyConfig
	}

	return c.mutateByName(ctx, bridgeTable, name, upsertMapMutations("external_ids", ids), ErrBridgeNotFound)
}

// GetBridgeExternalIDs returns the external_ids column of the named bridge.
func (c *Client) GetBridgeExternalIDs(ctx context.Context, name string) (map[string]string, error) {
	if name == "" {
		return nil, ErrInvalidBridgeName
	}

	rows, err := c.Select(ctx, bridgeTable, []Condition{NewCondition("name", "==", name)}, []string{"external_ids"})
	if err != nil {
		return nil, err
	}

	if len(rows) == 0 {
		return nil, ErrBridgeNotFound
	}

	return parseMap(rows[0]["external_ids"]), nil
}
