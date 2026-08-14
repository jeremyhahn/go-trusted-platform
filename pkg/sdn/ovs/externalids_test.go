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

func TestClient_SetBridgeExternalIDs(t *testing.T) {
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

	_, err := client.CreateBridge(ctx, "br-ct")
	require.NoError(t, err)

	t.Run("upsert keys", func(t *testing.T) {
		ids := map[string]string{
			"trusted-platform-ct-zones": `{"firewall/trusted":42}`,
		}
		err := client.SetBridgeExternalIDs(ctx, "br-ct", ids)
		require.NoError(t, err)

		// Assert the wire-level delete+insert mutation pair OVSDB map
		// upserts require, against the external_ids column.
		op := lastMutateOp(t, server, "Bridge")
		assertUpsertMutationPair(t, op, "external_ids", ids)
	})

	t.Run("empty bridge name", func(t *testing.T) {
		err := client.SetBridgeExternalIDs(ctx, "", map[string]string{"k": "v"})
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("empty config", func(t *testing.T) {
		err := client.SetBridgeExternalIDs(ctx, "br-ct", nil)
		assert.ErrorIs(t, err, ErrEmptyConfig)
	})

	t.Run("bridge not found", func(t *testing.T) {
		err := client.SetBridgeExternalIDs(ctx, "br-ghost", map[string]string{"k": "v"})
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})
}

func TestClient_GetBridgeExternalIDs(t *testing.T) {
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

	_, err := client.CreateBridge(ctx, "br-ct")
	require.NoError(t, err)

	t.Run("round trip", func(t *testing.T) {
		want := map[string]string{
			"trusted-platform-ct-zones": `{"nat/default":7}`,
		}
		require.NoError(t, client.SetBridgeExternalIDs(ctx, "br-ct", want))

		got, err := client.GetBridgeExternalIDs(ctx, "br-ct")
		require.NoError(t, err)
		assert.Equal(t, want["trusted-platform-ct-zones"], got["trusted-platform-ct-zones"])
	})

	t.Run("empty bridge name", func(t *testing.T) {
		_, err := client.GetBridgeExternalIDs(ctx, "")
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("bridge not found", func(t *testing.T) {
		_, err := client.GetBridgeExternalIDs(ctx, "br-ghost")
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})
}
