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

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The snapshot RPCs answer from the control plane's telemetry store, or
// from the gateway a node runs itself (#594).

// memorySnapshotStore is an in-memory gwstate.Store.
type memorySnapshotStore struct {
	snaps   map[string]*gwstate.Snapshot
	listErr error
}

func (m *memorySnapshotStore) Put(snap *gwstate.Snapshot) error {
	if m.snaps == nil {
		m.snaps = map[string]*gwstate.Snapshot{}
	}
	m.snaps[snap.GatewayID] = snap
	return nil
}

func (m *memorySnapshotStore) Get(id string) (*gwstate.Snapshot, error) {
	snap, ok := m.snaps[id]
	if !ok {
		return nil, gwstate.ErrSnapshotNotFound{GatewayID: id}
	}
	return snap, nil
}

func (m *memorySnapshotStore) List() ([]*gwstate.Snapshot, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	out := make([]*gwstate.Snapshot, 0, len(m.snaps))
	for _, snap := range m.snaps {
		out = append(out, snap)
	}
	return out, nil
}

func (m *memorySnapshotStore) Delete(id string) error {
	delete(m.snaps, id)
	return nil
}

// localSnapshotSource is a node's own gateway.
type localSnapshotSource struct{ snap *gwstate.Snapshot }

func (l localSnapshotSource) Snapshot() *gwstate.Snapshot { return l.snap }

func reportedSnapshot(id string) *gwstate.Snapshot {
	return &gwstate.Snapshot{
		GatewayID:  id,
		Hostname:   "node-01",
		Mode:       "nat,transit,tunnels",
		ReportedAt: time.Date(2026, 9, 8, 22, 0, 0, 0, time.UTC),
		Health:     gwstate.HealthState{Status: "healthy", Components: map[string]string{"transit": "healthy"}},
		BGP: gwstate.BGPState{
			LocalASN: 64512, RouterID: "203.0.113.4", PeerCount: 1, EstablishedPeers: 1, ReceivedPrefixes: 118,
			Peers: []gwstate.BGPPeerState{{
				Address: "10.255.0.2", ASN: 64512, State: "Established",
				PrefixesReceived: 120, PrefixesAccepted: 118, PrefixesSent: 2,
				Families: []string{"ipv4-unicast"},
				BFD: &gwstate.BFDState{
					State: "up", RemoteState: "up", FailureTransitions: 1,
					LastFailure:  time.Date(2026, 9, 8, 20, 0, 0, 0, time.UTC),
					TxIntervalMS: 300, RxIntervalMS: 300, DetectionMultiplier: 3,
				},
			}},
		},
		Services: []gwstate.ServiceState{{Name: "dhcp", RefusedReason: "no allocator"}},
		Tunnels: []gwstate.TunnelState{{
			Name: "gre-pri", Transport: "ipsec", Type: "gre", State: "up", Uplink: "isp-a", Bound: true,
			RekeySeconds: 28800, LastRekey: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
		}},
		Uplinks:      []gwstate.UplinkState{{Name: "isp-a", Table: 101, RuleCount: 1, Tunnels: []string{"gre-pri"}}},
		HostFirewall: &gwstate.HostFirewallState{Active: true, Installed: true, Fingerprint: "sha256:abc", RuleCount: 10},
		Firewall:     &gwstate.FirewallState{Active: true, FlowCount: 26, CTZones: map[string]uint16{"control-plane": 26567}},
		NAT: &gwstate.NATState{Active: true, SNATEnabled: true, DNATRules: 2, CTZone: 23974,
			Uplinks: []gwstate.NATUplinkState{{Name: "isp-a", Default: true, PoolAddresses: 8, Ports: 64512, Static: 1}}},
		Pipeline: &gwstate.PipelineState{Installed: true, Bridge: "br-fabric", Owner: "node-01-gateway", Terminal: "normal", FailMode: "secure"},
	}
}

func reportedOverlaySnapshot(id string) *gwstate.Snapshot {
	snap := reportedSnapshot(id)
	snap.Overlay = &gwstate.OverlayState{
		Running:                  true,
		LocalVTEP:                "192.0.2.10",
		VNICount:                 1,
		RemoteVTEPCount:          1,
		LocalMACCount:            2,
		RemoteMACCount:           1,
		PrefixCount:              1,
		RefusedBindings:          3,
		L3VNI:                    50100,
		ARPSuppressionEnabled:    true,
		AnycastGatewayConfigured: true,
		StartedAt:                time.Date(2026, 9, 8, 21, 0, 0, 0, time.UTC),
		Uptime:                   5 * time.Minute,
		NDCounters: gwstate.OverlayNDCounterState{
			Punted:       11,
			Answered:     7,
			MeterDropped: 2,
			QueueDropped: 1,
			FellThrough:  3,
		},
		AdmittedVTEPs: []gwstate.AdmittedVTEPState{{
			VTEP:           "198.51.100.10",
			DeviceID:       42,
			HostID:         "host-42",
			Serial:         "SERIAL42",
			Hostname:       "edge-42",
			AllocationID:   "alloc-42",
			BaselineSource: "golden",
			ProfileID:      9,
			VerdictAt:      time.Date(2026, 9, 8, 20, 55, 0, 0, time.UTC),
		}},
	}
	return snap
}

func TestGetGatewaySnapshot_FromTheTelemetryStore(t *testing.T) {
	store := &memorySnapshotStore{}
	require.NoError(t, store.Put(reportedSnapshot("node-01-gateway")))
	svc := NewGatewayService(WithGatewaySnapshotStore(store))

	resp, err := svc.GetGatewaySnapshot(context.Background(), &platformv1.GetGatewaySnapshotRequest{GatewayId: "node-01-gateway"})
	require.NoError(t, err)
	snap := resp.GetSnapshot()
	require.NotNil(t, snap)

	assert.Equal(t, "node-01-gateway", snap.GetGatewayId())
	assert.Equal(t, "healthy", snap.GetHealth().GetStatus())
	require.Len(t, snap.GetBgp().GetPeers(), 1)
	peer := snap.GetBgp().GetPeers()[0]
	assert.Equal(t, int64(118), peer.GetPrefixesAccepted())
	require.NotNil(t, peer.GetBfd())
	assert.Equal(t, "up", peer.GetBfd().GetState())
	assert.Equal(t, int64(300), peer.GetBfd().GetTxIntervalMs())
	require.Len(t, snap.GetTunnels(), 1)
	assert.Equal(t, "ipsec", snap.GetTunnels()[0].GetTransport())
	assert.True(t, snap.GetTunnels()[0].GetBound())
	require.Len(t, snap.GetUplinks(), 1)
	assert.Equal(t, int32(101), snap.GetUplinks()[0].GetTable())
	assert.Equal(t, "no allocator", snap.GetServices()[0].GetRefusedReason())
	assert.Equal(t, uint32(26567), snap.GetFirewall().GetCtZones()["control-plane"])
	assert.True(t, snap.GetNat().GetUplinks()[0].GetIsDefault())
	assert.Equal(t, "secure", snap.GetPipeline().GetFailMode())
}

func TestGetGatewaySnapshot_UnknownAndUnconfigured(t *testing.T) {
	t.Run("a gateway that never reported is not found", func(t *testing.T) {
		svc := NewGatewayService(WithGatewaySnapshotStore(&memorySnapshotStore{}))
		_, err := svc.GetGatewaySnapshot(context.Background(), &platformv1.GetGatewaySnapshotRequest{GatewayId: "ghost"})
		assert.Equal(t, codes.NotFound, status.Code(err), "an absent report is NotFound, never an empty snapshot")
	})

	t.Run("no store and no local gateway", func(t *testing.T) {
		svc := NewGatewayService()
		_, err := svc.GetGatewaySnapshot(context.Background(), &platformv1.GetGatewaySnapshotRequest{})
		require.Error(t, err)
		_, err = svc.GetGatewaySnapshot(context.Background(), &platformv1.GetGatewaySnapshotRequest{GatewayId: "node-01-gateway"})
		require.Error(t, err)
		_, err = svc.ListGatewaySnapshots(context.Background(), &platformv1.ListGatewaySnapshotsRequest{})
		require.Error(t, err)
	})

	t.Run("a local gateway answers a read that names none", func(t *testing.T) {
		svc := NewGatewayService(WithGatewaySnapshotSource(localSnapshotSource{snap: reportedSnapshot("local-gw")}))
		resp, err := svc.GetGatewaySnapshot(context.Background(), &platformv1.GetGatewaySnapshotRequest{})
		require.NoError(t, err)
		assert.Equal(t, "local-gw", resp.GetSnapshot().GetGatewayId())
	})

	t.Run("a local gateway that collects nothing is an internal error", func(t *testing.T) {
		svc := NewGatewayService(WithGatewaySnapshotSource(localSnapshotSource{}))
		_, err := svc.GetGatewaySnapshot(context.Background(), &platformv1.GetGatewaySnapshotRequest{})
		assert.Equal(t, codes.Internal, status.Code(err))
	})
}

func TestListGatewaySnapshots(t *testing.T) {
	store := &memorySnapshotStore{}
	require.NoError(t, store.Put(reportedSnapshot("node-01-gateway")))
	require.NoError(t, store.Put(reportedSnapshot("node-02-gateway")))
	svc := NewGatewayService()
	svc.SetGatewaySnapshotStore(store)

	resp, err := svc.ListGatewaySnapshots(context.Background(), &platformv1.ListGatewaySnapshotsRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.GetSnapshots(), 2)

	t.Run("a store that cannot be read is an error, not an empty fleet", func(t *testing.T) {
		store.listErr = errors.New("disk gone")
		_, err := svc.ListGatewaySnapshots(context.Background(), &platformv1.ListGatewaySnapshotsRequest{})
		assert.Equal(t, codes.Internal, status.Code(err))
	})
}

func TestGatewayAdmittedVTEPs_FromSnapshotOverlay(t *testing.T) {
	store := &memorySnapshotStore{}
	require.NoError(t, store.Put(reportedOverlaySnapshot("node-01-gateway")))
	svc := NewGatewayService(WithGatewaySnapshotStore(store))

	list, err := svc.ListGatewayAdmittedVTEPs(context.Background(), &platformv1.ListGatewayAdmittedVTEPsRequest{GatewayId: "node-01-gateway"})
	require.NoError(t, err)
	require.Len(t, list.GetVteps(), 1)
	assert.Equal(t, "198.51.100.10", list.GetVteps()[0].GetVtep())
	assert.Equal(t, uint64(42), list.GetVteps()[0].GetDeviceId())

	get, err := svc.GetGatewayAdmittedVTEP(context.Background(), &platformv1.GetGatewayAdmittedVTEPRequest{GatewayId: "node-01-gateway", Vtep: "198.51.100.10"})
	require.NoError(t, err)
	assert.Equal(t, "alloc-42", get.GetVtep().GetAllocationId())

	_, err = svc.GetGatewayAdmittedVTEP(context.Background(), &platformv1.GetGatewayAdmittedVTEPRequest{GatewayId: "node-01-gateway", Vtep: "198.51.100.11"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestGatewayAdmittedVTEPs_RESTMapsDisabledOverlayTo503(t *testing.T) {
	store := &memorySnapshotStore{}
	require.NoError(t, store.Put(reportedSnapshot("no-overlay")))
	require.NoError(t, store.Put(reportedOverlaySnapshot("node-01-gateway")))
	svc := newGatewayRESTService(nil, discardLogger().Slog())
	svc.reader = NewGatewayService(WithGatewaySnapshotStore(store))

	_, err := svc.ListAdmittedVTEPs(context.Background(), "no-overlay")
	var disabled rest.ErrGatewayFeatureNotConfigured
	require.ErrorAs(t, err, &disabled, "a gateway with no overlay is a disabled capability, answered 503")
	_, err = svc.GetAdmittedVTEP(context.Background(), "no-overlay", "198.51.100.10")
	require.ErrorAs(t, err, &disabled)

	_, err = svc.GetAdmittedVTEP(context.Background(), "node-01-gateway", "198.51.100.11")
	var missing rest.ErrGatewayAdmittedVTEPNotFound
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, "198.51.100.11", missing.VTEP)

	internal := status.Error(codes.Internal, "disk gone")
	assert.Equal(t, internal, gatewayAdmissionErrToREST("", internal), "a server fault is never relabelled a disabled capability")
}

func TestGatewaySnapshotToProto_OverlayStatus(t *testing.T) {
	proto := gatewaySnapshotToProto(reportedOverlaySnapshot("node-01-gateway"))
	overlay := proto.GetOverlay()
	require.NotNil(t, overlay)
	assert.True(t, overlay.GetRunning())
	assert.Equal(t, "192.0.2.10", overlay.GetLocalVtep())
	assert.Equal(t, uint64(11), overlay.GetNdCounters().GetPunted())
	require.Len(t, overlay.GetAdmittedVteps(), 1)
	assert.Equal(t, "198.51.100.10", overlay.GetAdmittedVteps()[0].GetVtep())
}

func TestGatewaySnapshotToProto_AbsentSectionsStayNil(t *testing.T) {
	assert.Nil(t, gatewaySnapshotToProto(nil))

	snap := gatewaySnapshotToProto(&gwstate.Snapshot{GatewayID: "bare"})
	require.NotNil(t, snap)
	assert.Nil(t, snap.GetHostFirewall(), "a service that is not running carries no section")
	assert.Nil(t, snap.GetFirewall())
	assert.Nil(t, snap.GetNat())
	assert.Nil(t, snap.GetPipeline())
	assert.Empty(t, snap.GetTunnels())
	assert.Nil(t, snap.GetReportedAt(), "a snapshot with no report time carries no timestamp")
}

func TestGatewaySnapshotQUICAdapter(t *testing.T) {
	store := &memorySnapshotStore{}
	require.NoError(t, store.Put(reportedSnapshot("node-01-gateway")))
	adapter := gatewaySnapshotQUICAdapter{reader: NewGatewayService(WithGatewaySnapshotStore(store))}

	info, err := adapter.Snapshot(context.Background(), "node-01-gateway")
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "node-01-gateway", info.GatewayID)
	require.NotNil(t, info.BGP)
	require.Len(t, info.BGP.Peers, 1)
	assert.Equal(t, int64(118), info.BGP.Peers[0].PrefixesAccepted)
	require.NotNil(t, info.BGP.Peers[0].BFD)
	assert.Equal(t, uint8(3), info.BGP.Peers[0].BFD.DetectionMultiplier)
	require.Len(t, info.Tunnels, 1)
	assert.Equal(t, time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC).Unix(), info.Tunnels[0].LastRekey)
	require.NotNil(t, info.NAT)
	assert.Equal(t, uint16(23974), info.NAT.CTZone)

	list, err := adapter.ListSnapshots(context.Background())
	require.NoError(t, err)
	assert.Len(t, list, 1)

	t.Run("no reader configured", func(t *testing.T) {
		empty := gatewaySnapshotQUICAdapter{}
		_, err := empty.Snapshot(context.Background(), "")
		assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
		_, err = empty.ListSnapshots(context.Background())
		assert.ErrorIs(t, err, errGatewayFeatureNotConfigured)
	})

	t.Run("a tunnel never re-keyed carries no timestamp", func(t *testing.T) {
		plain := reportedSnapshot("plain")
		plain.Tunnels[0].LastRekey = time.Time{}
		require.NoError(t, store.Put(plain))
		info, err := adapter.Snapshot(context.Background(), "plain")
		require.NoError(t, err)
		assert.Zero(t, info.Tunnels[0].LastRekey, "an absent timestamp is zero, not the epoch")
	})
}

func TestGatewaySnapshotTools_MCP(t *testing.T) {
	store := &memorySnapshotStore{}
	require.NoError(t, store.Put(reportedSnapshot("node-01-gateway")))
	tools := gatewaySnapshotTools{reader: NewGatewayService(WithGatewaySnapshotStore(store))}

	snap, err := tools.GatewaySnapshot(context.Background(), "node-01-gateway")
	require.NoError(t, err)
	require.NotNil(t, snap)

	list, err := tools.GatewaySnapshots(context.Background())
	require.NoError(t, err)
	assert.Len(t, list, 1)

	t.Run("no snapshot surface configured", func(t *testing.T) {
		var empty gatewaySnapshotTools
		_, err := empty.GatewaySnapshot(context.Background(), "")
		var notImplemented ErrGatewayOperationNotImplemented
		require.True(t, errors.As(err, &notImplemented), "got %v", err)
		_, err = empty.GatewaySnapshots(context.Background())
		require.True(t, errors.As(err, &notImplemented), "got %v", err)
	})
}
