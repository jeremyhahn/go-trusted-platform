// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// The snapshot payloads round-trip through the protocol codec, and the
// shared handler fixtures live in gateway_handlers_test.go under the same
// tag: without it the file cannot see them and an untagged lint typechecks
// a package that never builds this way.
//go:build codec_msgpack

package quic

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The QUIC gateway category carries the telemetry snapshot at sub-opcodes
// 0x15 and 0x16 (#594), so a QUIC client reads the same datapath picture as
// gRPC, REST and MCP.

func snapshotFixture(id string) *GatewaySnapshotInfo {
	return &GatewaySnapshotInfo{
		GatewayID:    id,
		Hostname:     "lab-node-1",
		HealthStatus: "healthy",
		BGP: &SnapshotBGPInfo{
			LocalAS: 401870, PeerCount: 1, EstablishedPeers: 1,
			Peers: []SnapshotBGPPeerInfo{{
				Address: "10.255.0.2", State: "Established", PrefixesAccepted: 118,
				BFD: &SnapshotBFDInfo{State: "up", DetectionMultiplier: 3},
			}},
		},
		Tunnels:  []SnapshotTunnelInfo{{Name: "gre-mia", Transport: "ipsec", State: "up", Uplink: "att", Bound: true}},
		Uplinks:  []SnapshotUplinkInfo{{Name: "att", Table: 101, RuleCount: 1, Tunnels: []string{"gre-mia"}}},
		Services: []SnapshotServiceInfo{{Name: "tunnels", Active: true, Healthy: true}},
		Pipeline: &SnapshotPipelineInfo{Installed: true, Bridge: "br-fabric", Terminal: "normal", FailMode: "secure"},
	}
}

func TestGatewayHandleSnapshot(t *testing.T) {
	ctx := context.Background()

	t.Run("returns the snapshot the service reports", func(t *testing.T) {
		handler, service := createTestGatewayHandler()
		service.snapshotResp = snapshotFixture("lab-node-1-gateway")

		payload, err := EncodePayload(&GatewaySnapshotRequest{GatewayID: "lab-node-1-gateway"})
		require.NoError(t, err)
		resp := handler.HandleRequest(ctx, &Request{Opcode: OpGatewaySnapshot, Payload: payload})
		require.Equal(t, StatusOK, resp.Status)

		var decoded GatewaySnapshotResponse
		require.NoError(t, DecodePayload(resp.Payload, &decoded))
		require.NotNil(t, decoded.Snapshot)
		assert.Equal(t, "lab-node-1-gateway", decoded.Snapshot.GatewayID)
		assert.Equal(t, "lab-node-1-gateway", service.lastSnapshotID, "the request's gateway id reaches the service")
		require.NotNil(t, decoded.Snapshot.BGP)
		require.Len(t, decoded.Snapshot.BGP.Peers, 1)
		assert.Equal(t, int64(118), decoded.Snapshot.BGP.Peers[0].PrefixesAccepted)
		require.NotNil(t, decoded.Snapshot.BGP.Peers[0].BFD)
		assert.Equal(t, "up", decoded.Snapshot.BGP.Peers[0].BFD.State)
		require.Len(t, decoded.Snapshot.Tunnels, 1)
		assert.True(t, decoded.Snapshot.Tunnels[0].Bound)
		require.Len(t, decoded.Snapshot.Uplinks, 1)
		assert.Equal(t, 101, decoded.Snapshot.Uplinks[0].Table)
		require.NotNil(t, decoded.Snapshot.Pipeline)
		assert.Equal(t, "secure", decoded.Snapshot.Pipeline.FailMode)
		assert.Positive(t, decoded.Timestamp)
	})

	t.Run("an empty payload reads this node's own gateway", func(t *testing.T) {
		handler, service := createTestGatewayHandler()
		service.snapshotResp = snapshotFixture("local")

		resp := handler.HandleRequest(ctx, &Request{Opcode: OpGatewaySnapshot})
		require.Equal(t, StatusOK, resp.Status)
		assert.Empty(t, service.lastSnapshotID)
	})

	t.Run("a service failure is not an empty snapshot", func(t *testing.T) {
		handler, service := createTestGatewayHandler()
		service.snapshotErr = errors.New("store unavailable")

		resp := handler.HandleRequest(ctx, &Request{Opcode: OpGatewaySnapshot})
		assert.NotEqual(t, StatusOK, resp.Status)
	})

	t.Run("an unconfigured gateway service is unavailable", func(t *testing.T) {
		handler := NewGatewayHandler(newGatewayTestLogger(), nil)
		resp := handler.HandleRequest(ctx, &Request{Opcode: OpGatewaySnapshot})
		assert.Equal(t, StatusUnavailable, resp.Status)
		resp = handler.HandleRequest(ctx, &Request{Opcode: OpGatewayListSnapshots})
		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("a malformed request payload is refused", func(t *testing.T) {
		handler, _ := createTestGatewayHandler()
		resp := handler.HandleRequest(ctx, &Request{Opcode: OpGatewaySnapshot, Payload: []byte{0xFF, 0xFE, 0xFD}})
		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})
}

func TestGatewayHandleListSnapshots(t *testing.T) {
	ctx := context.Background()

	handler, service := createTestGatewayHandler()
	service.snapshotsResp = []*GatewaySnapshotInfo{snapshotFixture("lab-node-1-gateway"), snapshotFixture("lab-node-2-gateway")}

	resp := handler.HandleRequest(ctx, &Request{Opcode: OpGatewayListSnapshots})
	require.Equal(t, StatusOK, resp.Status)

	var decoded GatewayListSnapshotsResponse
	require.NoError(t, DecodePayload(resp.Payload, &decoded))
	assert.Equal(t, int32(2), decoded.Count)
	require.Len(t, decoded.Snapshots, 2)
	assert.Equal(t, "lab-node-2-gateway", decoded.Snapshots[1].GatewayID)

	t.Run("a listing failure is reported", func(t *testing.T) {
		handler, service := createTestGatewayHandler()
		service.snapshotsErr = errors.New("store unavailable")
		resp := handler.HandleRequest(ctx, &Request{Opcode: OpGatewayListSnapshots})
		assert.NotEqual(t, StatusOK, resp.Status)
	})
}

func TestGatewaySnapshotOpcodesAreDistinct(t *testing.T) {
	seen := map[byte]string{
		OpGatewayStatus:            "status",
		OpGatewaySetMode:           "set-mode",
		OpGatewayBGPStatus:         "bgp-status",
		OpGatewayListNetworkZones:  "zones-list",
		OpGatewayDeleteNetworkZone: "zones-delete",
	}
	for op, name := range map[byte]string{OpGatewaySnapshot: "snapshot", OpGatewayListSnapshots: "snapshots"} {
		existing, clash := seen[op]
		assert.False(t, clash, "%s collides with %s", name, existing)
	}
	assert.Equal(t, byte(0x15), OpGatewaySnapshot)
	assert.Equal(t, byte(0x16), OpGatewayListSnapshots)
}
