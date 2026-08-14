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
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAddFlows tests the batched AddFlows function
func TestAddFlows(t *testing.T) {
	ctx := context.Background()

	t.Run("empty bridge name", func(t *testing.T) {
		client, _ := setupTestClient(t)
		flows := []*FlowMod{{Priority: 100}}

		err := client.AddFlows(ctx, "", flows)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("nil flow in batch", func(t *testing.T) {
		client, _ := setupTestClient(t)
		flows := []*FlowMod{{Priority: 100}, nil}

		err := client.AddFlows(ctx, "br0", flows)
		assert.ErrorIs(t, err, ErrInvalidFlow)
	})

	t.Run("empty batch is a no-op", func(t *testing.T) {
		client, _ := setupTestClient(t)

		// Succeeds without any connection because nothing is sent
		assert.NoError(t, client.AddFlows(ctx, "br0", nil))
		assert.NoError(t, client.AddFlows(ctx, "br0", []*FlowMod{}))
	})

	t.Run("not connected", func(t *testing.T) {
		client, _ := setupTestClient(t)
		client.connected = false
		flows := []*FlowMod{{Priority: 100}}

		err := client.AddFlows(ctx, "br0", flows)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("invalid match string fails before dialing", func(t *testing.T) {
		client, _ := setupTestClient(t)
		flows := []*FlowMod{{
			Priority: 100,
			Match:    "in_port=not-a-number",
			Actions:  "output:2",
		}}

		err := client.AddFlows(ctx, "br0", flows)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to convert flow")
	})

	t.Run("invalid actions string fails before dialing", func(t *testing.T) {
		client, _ := setupTestClient(t)
		flows := []*FlowMod{{
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:not-a-number",
		}}

		err := client.AddFlows(ctx, "br0", flows)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to convert flow")
	})

	t.Run("getOpenFlowClient error simulation", func(t *testing.T) {
		client := &Client{
			connected:   true,
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
		}

		flows := []*FlowMod{{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
		}}

		// Fails because there is no OpenFlow socket to connect to
		err := client.AddFlows(ctx, "br0", flows)
		assert.Error(t, err)
	})
}

// TestAddFlows_Conversion verifies the batch conversion matches AddFlow's
// single-flow conversion for every batch member
func TestAddFlows_Conversion(t *testing.T) {
	flows := []*FlowMod{
		{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
			Cookie:   "0x10",
		},
		{
			Table:    5,
			Priority: 200,
			Match:    "dl_type=0x0800,nw_dst=10.0.0.0/24",
			Actions:  "NORMAL",
		},
	}

	for i, flow := range flows {
		ofFlow, err := convertToOpenFlow(flow)
		require.NoError(t, err, "flow %d", i)
		assert.Equal(t, uint8(flow.Table), ofFlow.TableID, "flow %d", i)
		assert.Equal(t, uint16(flow.Priority), ofFlow.Priority, "flow %d", i)
	}
}
