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

package cluster

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newNodeStateManagers returns one state manager per cluster node, all over
// the same replicated store, as every node of a cluster shares one QuicBaaS
// state machine.
func newNodeStateManagers(t *testing.T, nodes int) []*QuicBaaSStateManager {
	t.Helper()
	store := quicbaas.NewMockStorage()
	require.NoError(t, store.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, store.Stop(context.Background())) })

	managers := make([]*QuicBaaSStateManager, nodes)
	for i := range managers {
		managers[i] = NewQuicBaaSStateManager(store, logging.DefaultLogger(), WithStateManagerTimeout(5*time.Second))
	}
	return managers
}

func TestStateManager_ConcurrentReadsAcrossNodesAgree(t *testing.T) {
	managers := newNodeStateManagers(t, 3)
	ctx := context.Background()
	require.NoError(t, managers[0].CreateBridge(ctx, &BridgeState{
		ID: "br-shared", Name: "shared", DatapathType: "netdev", STPEnabled: true,
	}))

	const readsPerNode = 20
	type read struct {
		bridge *BridgeState
		err    error
	}
	reads := make(chan read, len(managers)*readsPerNode)
	var wg sync.WaitGroup
	for _, sm := range managers {
		for range readsPerNode {
			wg.Add(1)
			go func() {
				defer wg.Done()
				bridge, err := sm.GetBridge(ctx, "br-shared")
				reads <- read{bridge, err}
			}()
		}
	}
	wg.Wait()
	close(reads)

	for r := range reads {
		require.NoError(t, r.err)
		assert.Equal(t, "br-shared", r.bridge.ID)
		assert.Equal(t, "shared", r.bridge.Name)
		assert.Equal(t, "netdev", r.bridge.DatapathType)
		assert.True(t, r.bridge.STPEnabled)
	}
}

func TestStateManager_StateOutlivesTheWritingNode(t *testing.T) {
	managers := newNodeStateManagers(t, 3)
	ctx := context.Background()
	oldLeader, newLeader, follower := managers[0], managers[1], managers[2]

	require.NoError(t, oldLeader.CreateBridge(ctx, &BridgeState{ID: "br-before", Name: "before"}))
	require.NoError(t, oldLeader.CreatePort(ctx, &PortState{ID: "port-before", Name: "eth0", BridgeID: "br-before", Tag: 100}))

	// The new leader reads what the old leader wrote, then writes on top of it.
	bridge, ports, err := newLeader.GetBridgeWithPorts(ctx, "br-before")
	require.NoError(t, err)
	assert.Equal(t, "before", bridge.Name)
	require.Len(t, ports, 1)
	assert.Equal(t, "port-before", ports[0].ID)
	assert.Equal(t, uint16(100), ports[0].Tag)

	require.NoError(t, newLeader.CreateBridge(ctx, &BridgeState{ID: "br-after", Name: "after"}))
	require.NoError(t, newLeader.CreatePort(ctx, &PortState{ID: "port-after", Name: "eth1", BridgeID: "br-before"}))

	bridges, err := follower.ListBridges(ctx)
	require.NoError(t, err)
	ids := make([]string, 0, len(bridges))
	for _, b := range bridges {
		ids = append(ids, b.ID)
	}
	assert.ElementsMatch(t, []string{"br-before", "br-after"}, ids)

	ports, err = follower.ListPorts(ctx, "br-before")
	require.NoError(t, err)
	assert.Len(t, ports, 2)
}
