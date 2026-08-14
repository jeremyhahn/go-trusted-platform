//go:build integration

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

package sdn

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

const hwOffloadBridge = "tp-hwoffload"

// TestHWOffloadOtherConfig verifies that the hw-offload configuration
// mutators land in OVSDB, round-trip through GetOVSOtherConfig, and
// survive a client reconnect. No actual hardware offload is asserted —
// the devcontainer has no offload-capable NIC; the OVSDB state is the
// contract under test.
func TestHWOffloadOtherConfig(t *testing.T) {
	requireOVSDBForTest(t)

	client := newOVSDBClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Snapshot the pre-test values so cleanup restores the devcontainer's
	// OVS to its prior state.
	before, err := client.GetOVSOtherConfig(ctx)
	require.NoError(t, err, "read initial other_config")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		restore := map[string]string{}
		remove := []string{}
		for _, key := range []string{"hw-offload", "tc-policy"} {
			if prev, ok := before[key]; ok {
				restore[key] = prev
			} else {
				remove = append(remove, key)
			}
		}
		if len(restore) > 0 {
			if restoreErr := client.SetOVSOtherConfig(cleanupCtx, restore); restoreErr != nil {
				t.Logf("restore other_config: %v", restoreErr)
			}
		}
		if len(remove) > 0 {
			if removeErr := client.DeleteOVSOtherConfig(cleanupCtx, remove); removeErr != nil {
				t.Logf("remove other_config keys: %v", removeErr)
			}
		}
	})

	t.Run("SetLandsInOVSDB", func(t *testing.T) {
		require.NoError(t, client.SetOVSOtherConfig(ctx, map[string]string{
			"hw-offload": "true",
			"tc-policy":  "none",
		}), "set hw-offload other_config")

		config, getErr := client.GetOVSOtherConfig(ctx)
		require.NoError(t, getErr, "round-trip other_config")
		require.Equal(t, "true", config["hw-offload"])
		require.Equal(t, "none", config["tc-policy"])
	})

	t.Run("SurvivesClientReconnect", func(t *testing.T) {
		require.NoError(t, client.Disconnect(), "disconnect")

		fresh, newErr := ovs.NewClient("/var/run/openvswitch/db.sock")
		require.NoError(t, newErr, "create fresh client")
		t.Cleanup(func() { fresh.Close() })

		config, getErr := fresh.GetOVSOtherConfig(ctx)
		require.NoError(t, getErr, "read other_config after reconnect")
		require.Equal(t, "true", config["hw-offload"], "hw-offload persists in OVSDB")
		require.Equal(t, "none", config["tc-policy"], "tc-policy persists in OVSDB")
	})

	t.Run("DeleteRemovesKeys", func(t *testing.T) {
		require.NoError(t, client.SetOVSOtherConfig(ctx, map[string]string{
			"tp-hwoffload-test-key": "1",
		}))
		require.NoError(t, client.DeleteOVSOtherConfig(ctx, []string{"tp-hwoffload-test-key"}))

		config, getErr := client.GetOVSOtherConfig(ctx)
		require.NoError(t, getErr)
		_, present := config["tp-hwoffload-test-key"]
		require.False(t, present, "deleted key must be gone")
	})
}

// TestSetBridgeDatapathReconcile verifies the bridge datapath_type
// mutator: setting an explicit type lands in OVSDB and reconciling back
// to the kernel default clears the column.
func TestSetBridgeDatapathReconcile(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, hwOffloadBridge)
	client := newOVSDBClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("ExplicitSystemType", func(t *testing.T) {
		require.NoError(t, client.SetBridgeDatapath(ctx, bridge.name, "system"))

		row, getErr := client.GetBridge(ctx, bridge.name)
		require.NoError(t, getErr, "get bridge")
		require.Equal(t, "system", row.DatapathType)
	})

	t.Run("ReconcileToDefault", func(t *testing.T) {
		// Empty datapathType selects the kernel default; the column must
		// clear so ovs-vswitchd keeps the existing datapath.
		require.NoError(t, client.SetBridgeDatapath(ctx, bridge.name, ""))

		row, getErr := client.GetBridge(ctx, bridge.name)
		require.NoError(t, getErr, "get bridge")
		require.Equal(t, "", row.DatapathType, "datapath_type must reconcile to the default")
	})

	t.Run("UnknownBridge", func(t *testing.T) {
		err := client.SetBridgeDatapath(ctx, "tp-does-not-exist", "system")
		require.Error(t, err, "unknown bridge must be rejected")
	})
}
