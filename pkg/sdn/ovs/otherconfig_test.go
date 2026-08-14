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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deleteOpenVSwitchRow removes the root Open_vSwitch row from the mock
// database to simulate the pre-initialisation startup window.
func deleteOpenVSwitchRow(server *mockOVSDBServer) {
	server.mu.RLock()
	db := server.databases[DefaultDatabase]
	server.mu.RUnlock()

	table := db.tables["Open_vSwitch"]
	table.mu.Lock()
	table.rows = make(map[string]map[string]interface{})
	table.mu.Unlock()
}

// lastMutateOp returns the most recent mutate operation recorded against the
// given table, failing the test when none exists.
func lastMutateOp(t *testing.T, server *mockOVSDBServer, table string) Operation {
	t.Helper()
	ops := server.TransactOps()
	for i := len(ops) - 1; i >= 0; i-- {
		if ops[i].Op == "mutate" && ops[i].Table == table {
			return ops[i]
		}
	}
	t.Fatalf("no mutate operation recorded for table %s", table)
	return Operation{}
}

// assertUpsertMutationPair asserts the wire-level delete+insert mutation pair
// that OVSDB map-column upserts require: mutation 0 deletes the keys as a
// set, mutation 1 inserts the new map in the same transaction.
func assertUpsertMutationPair(t *testing.T, op Operation, column string, config map[string]string) {
	t.Helper()
	require.Len(t, op.Mutations, 2)

	deleteMut := op.Mutations[0]
	require.Len(t, deleteMut, 3)
	assert.Equal(t, column, deleteMut[0])
	assert.Equal(t, "delete", deleteMut[1])
	deleteVal, ok := deleteMut[2].([]interface{})
	require.True(t, ok, "delete value must be an OVSDB set: %v", deleteMut[2])
	require.Len(t, deleteVal, 2)
	assert.Equal(t, "set", deleteVal[0])
	deletedKeys, ok := deleteVal[1].([]interface{})
	require.True(t, ok)
	assert.Len(t, deletedKeys, len(config))
	for _, key := range deletedKeys {
		_, present := config[key.(string)]
		assert.True(t, present, "deleted key %v not in config", key)
	}

	insertMut := op.Mutations[1]
	require.Len(t, insertMut, 3)
	assert.Equal(t, column, insertMut[0])
	assert.Equal(t, "insert", insertMut[1])
	insertVal, ok := insertMut[2].([]interface{})
	require.True(t, ok, "insert value must be an OVSDB map: %v", insertMut[2])
	require.Len(t, insertVal, 2)
	assert.Equal(t, "map", insertVal[0])
	insertedPairs, ok := insertVal[1].([]interface{})
	require.True(t, ok)
	assert.Len(t, insertedPairs, len(config))
	for _, item := range insertedPairs {
		pair, ok := item.([]interface{})
		require.True(t, ok)
		require.Len(t, pair, 2)
		assert.Equal(t, config[pair[0].(string)], pair[1])
	}
}

func TestClient_SetOVSOtherConfig(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("set new keys", func(t *testing.T) {
		config := map[string]string{
			"hw-offload": "true",
			"tc-policy":  "skip_sw",
		}
		err := client.SetOVSOtherConfig(ctx, config)
		require.NoError(t, err)

		current, err := client.GetOVSOtherConfig(ctx)
		require.NoError(t, err)
		assert.Equal(t, "true", current["hw-offload"])
		assert.Equal(t, "skip_sw", current["tc-policy"])

		assertUpsertMutationPair(t, lastMutateOp(t, server, "Open_vSwitch"), "other_config", config)
	})

	t.Run("upsert existing key", func(t *testing.T) {
		// A naked insert would fail with a constraint violation on the
		// existing key; the delete+insert pair must make this succeed.
		err := client.SetOVSOtherConfig(ctx, map[string]string{"tc-policy": "skip_hw"})
		require.NoError(t, err)

		current, err := client.GetOVSOtherConfig(ctx)
		require.NoError(t, err)
		assert.Equal(t, "skip_hw", current["tc-policy"])
		assert.Equal(t, "true", current["hw-offload"], "untouched key must survive upsert")
	})

	t.Run("empty config", func(t *testing.T) {
		err := client.SetOVSOtherConfig(ctx, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyConfig)
	})

	t.Run("missing root row", func(t *testing.T) {
		deleteOpenVSwitchRow(server)
		err := client.SetOVSOtherConfig(ctx, map[string]string{"hw-offload": "true"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no Open_vSwitch row found")
	})
}

func TestClient_GetOVSOtherConfig(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("empty initially", func(t *testing.T) {
		current, err := client.GetOVSOtherConfig(ctx)
		require.NoError(t, err)
		assert.Empty(t, current)
	})

	t.Run("returns set values", func(t *testing.T) {
		require.NoError(t, client.SetOVSOtherConfig(ctx, map[string]string{"dpdk-init": "true"}))

		current, err := client.GetOVSOtherConfig(ctx)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"dpdk-init": "true"}, current)
	})

	t.Run("missing root row", func(t *testing.T) {
		deleteOpenVSwitchRow(server)
		_, err := client.GetOVSOtherConfig(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoOpenVSwitchRow)
	})
}

func TestClient_DeleteOVSOtherConfig(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("delete existing key", func(t *testing.T) {
		require.NoError(t, client.SetOVSOtherConfig(ctx, map[string]string{
			"hw-offload": "true",
			"tc-policy":  "skip_sw",
		}))

		err := client.DeleteOVSOtherConfig(ctx, []string{"tc-policy"})
		require.NoError(t, err)

		current, err := client.GetOVSOtherConfig(ctx)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"hw-offload": "true"}, current)
	})

	t.Run("delete missing key is a no-op", func(t *testing.T) {
		err := client.DeleteOVSOtherConfig(ctx, []string{"does-not-exist"})
		require.NoError(t, err)
	})

	t.Run("empty keys", func(t *testing.T) {
		err := client.DeleteOVSOtherConfig(ctx, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyConfig)
	})

	t.Run("missing root row", func(t *testing.T) {
		deleteOpenVSwitchRow(server)
		err := client.DeleteOVSOtherConfig(ctx, []string{"hw-offload"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no Open_vSwitch row found")
	})
}

func TestClient_SetBridgeDatapath(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("set netdev datapath", func(t *testing.T) {
		_, err := client.CreateBridge(ctx, "br-dp")
		require.NoError(t, err)

		err = client.SetBridgeDatapath(ctx, "br-dp", "netdev")
		require.NoError(t, err)

		bridge, err := client.GetBridge(ctx, "br-dp")
		require.NoError(t, err)
		assert.Equal(t, "netdev", bridge.DatapathType)
	})

	t.Run("empty name", func(t *testing.T) {
		err := client.SetBridgeDatapath(ctx, "", "netdev")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("bridge not found", func(t *testing.T) {
		err := client.SetBridgeDatapath(ctx, "br-missing", "netdev")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})
}

func TestClient_SetBridgeOtherConfig(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("set and upsert", func(t *testing.T) {
		_, err := client.CreateBridge(ctx, "br-oc")
		require.NoError(t, err)

		config := map[string]string{"forward-bpdu": "true"}
		require.NoError(t, client.SetBridgeOtherConfig(ctx, "br-oc", config))
		assertUpsertMutationPair(t, lastMutateOp(t, server, "Bridge"), "other_config", config)

		// Overwrite the existing key: must not trip the map-insert
		// constraint violation.
		require.NoError(t, client.SetBridgeOtherConfig(ctx, "br-oc", map[string]string{"forward-bpdu": "false"}))

		bridge, err := client.GetBridge(ctx, "br-oc")
		require.NoError(t, err)
		assert.Equal(t, "false", bridge.OtherConfig["forward-bpdu"])
	})

	t.Run("empty name", func(t *testing.T) {
		err := client.SetBridgeOtherConfig(ctx, "", map[string]string{"k": "v"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("empty config", func(t *testing.T) {
		err := client.SetBridgeOtherConfig(ctx, "br-oc", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyConfig)
	})

	t.Run("bridge not found", func(t *testing.T) {
		err := client.SetBridgeOtherConfig(ctx, "br-missing", map[string]string{"k": "v"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})
}

func TestClient_SetInterfaceType(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("set dpdk type", func(t *testing.T) {
		// CreateBridge creates the internal interface row of the same name.
		_, err := client.CreateBridge(ctx, "br-if")
		require.NoError(t, err)

		err = client.SetInterfaceType(ctx, "br-if", "dpdk")
		require.NoError(t, err)

		rows, err := client.Select(ctx, interfaceTable, []Condition{NewCondition("name", "==", "br-if")}, []string{"type"})
		require.NoError(t, err)
		require.Len(t, rows, 1)
		assert.Equal(t, "dpdk", rows[0]["type"])
	})

	t.Run("empty name", func(t *testing.T) {
		err := client.SetInterfaceType(ctx, "", "dpdk")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("interface not found", func(t *testing.T) {
		err := client.SetInterfaceType(ctx, "if-missing", "dpdk")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInterfaceNotFound)
	})
}

func TestClient_SetInterfaceOptions(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("set and upsert", func(t *testing.T) {
		_, err := client.CreateBridge(ctx, "br-opt")
		require.NoError(t, err)

		options := map[string]string{"dpdk-devargs": "0000:03:00.0", "n_rxq": "2"}
		require.NoError(t, client.SetInterfaceOptions(ctx, "br-opt", options))
		assertUpsertMutationPair(t, lastMutateOp(t, server, "Interface"), "options", options)

		// Overwrite one key; the other must survive.
		require.NoError(t, client.SetInterfaceOptions(ctx, "br-opt", map[string]string{"n_rxq": "4"}))

		current, err := client.GetInterfaceOptions(ctx, "br-opt")
		require.NoError(t, err)
		assert.Equal(t, "4", current["n_rxq"])
		assert.Equal(t, "0000:03:00.0", current["dpdk-devargs"])
	})

	t.Run("empty name", func(t *testing.T) {
		err := client.SetInterfaceOptions(ctx, "", map[string]string{"k": "v"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("empty options", func(t *testing.T) {
		err := client.SetInterfaceOptions(ctx, "br-opt", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyConfig)
	})

	t.Run("interface not found", func(t *testing.T) {
		err := client.SetInterfaceOptions(ctx, "if-missing", map[string]string{"k": "v"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInterfaceNotFound)
	})
}

func TestClient_SetInterfaceOtherConfig(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("set and upsert", func(t *testing.T) {
		_, err := client.CreateBridge(ctx, "br-ioc")
		require.NoError(t, err)

		config := map[string]string{"pmd-rxq-affinity": "0:1"}
		require.NoError(t, client.SetInterfaceOtherConfig(ctx, "br-ioc", config))
		assertUpsertMutationPair(t, lastMutateOp(t, server, "Interface"), "other_config", config)

		require.NoError(t, client.SetInterfaceOtherConfig(ctx, "br-ioc", map[string]string{"pmd-rxq-affinity": "0:2"}))

		rows, err := client.Select(ctx, interfaceTable, []Condition{NewCondition("name", "==", "br-ioc")}, []string{"other_config"})
		require.NoError(t, err)
		require.Len(t, rows, 1)
		assert.Equal(t, "0:2", parseMap(rows[0]["other_config"])["pmd-rxq-affinity"])
	})

	t.Run("empty name", func(t *testing.T) {
		err := client.SetInterfaceOtherConfig(ctx, "", map[string]string{"k": "v"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("empty config", func(t *testing.T) {
		err := client.SetInterfaceOtherConfig(ctx, "br-ioc", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyConfig)
	})

	t.Run("interface not found", func(t *testing.T) {
		err := client.SetInterfaceOtherConfig(ctx, "if-missing", map[string]string{"k": "v"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInterfaceNotFound)
	})
}
