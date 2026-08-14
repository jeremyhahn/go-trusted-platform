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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

const (
	flowBatchBridge = "tp-flowbatch"
	flowBatchTable  = 200
	flowBatchCount  = 500
)

// batchTestMAC derives a unique destination MAC for a batch flow index.
func batchTestMAC(i int) net.HardwareAddr {
	return net.HardwareAddr{0x0e, 0xba, 0x00, byte(i >> 16), byte(i >> 8), byte(i)}
}

// batchFlow builds one drop flow in the batch test table with a unique
// eth_dst match.
func batchFlow(i int) *openflow.FlowMod {
	flow := openflow.NewFlowMod(0)
	flow.TableID = flowBatchTable
	flow.Priority = 10
	flow.Match.AddEthDst(batchTestMAC(i))
	return flow
}

// TestFlowBatchInstall installs a 500-flow batch through SendFlowMods on
// a real bridge and verifies every flow landed.
func TestFlowBatchInstall(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, flowBatchBridge)
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	flows := make([]*openflow.FlowMod, 0, flowBatchCount)
	for i := 0; i < flowBatchCount; i++ {
		flows = append(flows, batchFlow(i))
	}

	require.NoError(t, client.SendFlowMods(ctx, flows), "batched install of %d flows", flowBatchCount)

	stats, err := client.GetFlowStats(ctx, nil)
	require.NoError(t, err, "flow stats")

	installed := 0
	for _, stat := range stats {
		if stat.TableID == flowBatchTable {
			installed++
		}
	}
	require.Equal(t, flowBatchCount, installed, "every batched flow must be present")
}

// TestFlowBatchPartialFailure injects one invalid flow (a reference to a
// nonexistent group) mid-batch and asserts ErrBatchPartialFailure
// identifies exactly that index while the valid flows install.
func TestFlowBatchPartialFailure(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, flowBatchBridge+"-pf")
	client := bridge.createClient(t)
	bridge.clearFlows(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const total = 50
	const badIndex = 25

	flows := make([]*openflow.FlowMod, 0, total)
	for i := 0; i < total; i++ {
		flow := batchFlow(i)
		if i == badIndex {
			// Reference a group that does not exist on the bridge; the
			// switch rejects this flow mod with OFPET_BAD_ACTION.
			flow.Instructions = []openflow.Instruction{
				openflow.NewInstructionApplyActions(openflow.NewActionGroup(0x0BAD0BAD)),
			}
		}
		flows = append(flows, flow)
	}

	err := client.SendFlowMods(ctx, flows)
	require.Error(t, err, "batch with a bad group reference must fail")

	var partial *openflow.ErrBatchPartialFailure
	require.ErrorAs(t, err, &partial, "error must be ErrBatchPartialFailure")
	require.Len(t, partial.Failed, 1, "exactly one flow must be rejected")
	require.Equal(t, badIndex, partial.Failed[0].Index, "the rejected flow index must be identified")

	// Every other flow must have installed.
	stats, statsErr := client.GetFlowStats(ctx, nil)
	require.NoError(t, statsErr, "flow stats")

	installed := 0
	for _, stat := range stats {
		if stat.TableID == flowBatchTable {
			installed++
		}
	}
	require.Equal(t, total-1, installed, "all valid flows must be present")
}
