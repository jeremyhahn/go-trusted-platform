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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// GatewaySnapshotSource is the live gateway a node runs itself. A control
// plane has none and answers from the telemetry store instead.
type GatewaySnapshotSource interface {
	Snapshot() *gwstate.Snapshot
}

// WithGatewaySnapshotStore sets the telemetry store the control plane
// answers snapshot reads from — the same store POST /gateway/telemetry
// writes into.
func WithGatewaySnapshotStore(store gwstate.Store) GatewayServiceOption {
	return func(s *GatewayService) { s.snapshots = store }
}

// WithGatewaySnapshotSource sets the local gateway whose live state answers
// a snapshot read that names no gateway.
func WithGatewaySnapshotSource(source GatewaySnapshotSource) GatewayServiceOption {
	return func(s *GatewayService) { s.localSnapshot = source }
}

// SetGatewaySnapshotStore wires the telemetry store after construction,
// which is the order platformd builds these in: the store exists before the
// daemon does.
func (s *GatewayService) SetGatewaySnapshotStore(store gwstate.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots = store
}

// SetGatewaySnapshotSource wires the local gateway after construction.
func (s *GatewayService) SetGatewaySnapshotSource(source GatewaySnapshotSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localSnapshot = source
}

// GetGatewaySnapshot returns one gateway's telemetry snapshot: the live
// state when the request names no gateway and this node runs one, the
// stored report otherwise. A gateway that has never reported is NotFound —
// never an empty snapshot, which would read as a gateway running nothing.
func (s *GatewayService) GetGatewaySnapshot(ctx context.Context, req *platformv1.GetGatewaySnapshotRequest) (*platformv1.GetGatewaySnapshotResponse, error) {
	s.mu.RLock()
	store, local := s.snapshots, s.localSnapshot
	s.mu.RUnlock()

	id := req.GetGatewayId()
	if id == "" {
		if local == nil {
			return nil, serviceNotConfigured("gateway", "no gateway runs on this node; name a gateway_id to read a reported snapshot")
		}
		snap := local.Snapshot()
		if snap == nil {
			return nil, status.Error(codes.Internal, "failed to collect the gateway snapshot")
		}
		return &platformv1.GetGatewaySnapshotResponse{Snapshot: gatewaySnapshotToProto(snap)}, nil
	}

	if store == nil {
		return nil, serviceNotConfigured("gateway", "no gateway telemetry store is configured on this node")
	}
	snap, err := store.Get(id)
	if err != nil {
		var notFound gwstate.ErrSnapshotNotFound
		if errors.As(err, &notFound) {
			return nil, status.Errorf(codes.NotFound, "no gateway named %s has reported", id)
		}
		return nil, status.Errorf(codes.Internal, "failed to read the gateway snapshot: %v", err)
	}
	return &platformv1.GetGatewaySnapshotResponse{Snapshot: gatewaySnapshotToProto(snap)}, nil
}

// ListGatewaySnapshots returns every reported gateway's snapshot, newest
// report first.
func (s *GatewayService) ListGatewaySnapshots(ctx context.Context, req *platformv1.ListGatewaySnapshotsRequest) (*platformv1.ListGatewaySnapshotsResponse, error) {
	s.mu.RLock()
	store := s.snapshots
	s.mu.RUnlock()

	if store == nil {
		return nil, serviceNotConfigured("gateway", "no gateway telemetry store is configured on this node")
	}
	snaps, err := store.List()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list gateway snapshots: %v", err)
	}
	out := make([]*platformv1.GatewaySnapshot, 0, len(snaps))
	for _, snap := range snaps {
		out = append(out, gatewaySnapshotToProto(snap))
	}
	return &platformv1.ListGatewaySnapshotsResponse{Snapshots: out}, nil
}

// gatewaySnapshotToProto maps the telemetry snapshot onto the wire type. A
// section the snapshot does not carry stays nil on the wire, so a consumer
// can tell "not running" from "running and empty".
func gatewaySnapshotToProto(snap *gwstate.Snapshot) *platformv1.GatewaySnapshot {
	if snap == nil {
		return nil
	}
	out := &platformv1.GatewaySnapshot{
		GatewayId:   snap.GatewayID,
		Hostname:    snap.Hostname,
		Mode:        snap.Mode,
		Health:      snapshotHealthToProto(snap.Health),
		Bgp:         snapshotBGPToProto(snap.BGP),
		Annotations: snap.Annotations,
	}
	if !snap.ReportedAt.IsZero() {
		out.ReportedAt = timestamppb.New(snap.ReportedAt)
	}
	if !snap.ReceivedAt.IsZero() {
		out.ReceivedAt = timestamppb.New(snap.ReceivedAt)
	}
	for _, svc := range snap.Services {
		out.Services = append(out.Services, &platformv1.SnapshotService{
			Name:          svc.Name,
			Active:        svc.Active,
			Healthy:       svc.Healthy,
			RefusedReason: svc.RefusedReason,
		})
	}
	for _, tun := range snap.Tunnels {
		entry := &platformv1.SnapshotTunnel{
			Name:         tun.Name,
			Transport:    tun.Transport,
			Type:         tun.Type,
			State:        tun.State,
			Uplink:       tun.Uplink,
			Bound:        tun.Bound,
			LocalIp:      tun.LocalIP,
			RemoteIp:     tun.RemoteIP,
			TunnelIp:     tun.TunnelIP,
			RxBytes:      tun.RxBytes,
			TxBytes:      tun.TxBytes,
			RxPackets:    tun.RxPackets,
			TxPackets:    tun.TxPackets,
			RekeySeconds: tun.RekeySeconds,
		}
		if !tun.LastRekey.IsZero() {
			entry.LastRekey = timestamppb.New(tun.LastRekey)
		}
		out.Tunnels = append(out.Tunnels, entry)
	}
	for _, up := range snap.Uplinks {
		out.Uplinks = append(out.Uplinks, &platformv1.SnapshotUplink{
			Name:      up.Name,
			Interface: up.Interface,
			Table:     int32(up.Table),
			GatewayV4: up.GatewayV4,
			GatewayV6: up.GatewayV6,
			Addresses: up.Addresses,
			Priority:  int32(up.Priority),
			RuleCount: int32(up.RuleCount),
			Tunnels:   up.Tunnels,
		})
	}
	if hf := snap.HostFirewall; hf != nil {
		entry := &platformv1.SnapshotHostFirewall{
			Active:      hf.Active,
			Installed:   hf.Installed,
			Fingerprint: hf.Fingerprint,
			RuleCount:   int32(hf.RuleCount),
			LastError:   hf.LastError,
		}
		if !hf.LastReconcile.IsZero() {
			entry.LastReconcile = timestamppb.New(hf.LastReconcile)
		}
		out.HostFirewall = entry
	}
	if fw := snap.Firewall; fw != nil {
		entry := &platformv1.SnapshotFirewall{
			Active:    fw.Active,
			FlowCount: int32(fw.FlowCount),
		}
		if len(fw.CTZones) > 0 {
			entry.CtZones = make(map[string]uint32, len(fw.CTZones))
			for name, id := range fw.CTZones {
				entry.CtZones[name] = uint32(id)
			}
		}
		if !fw.LastReconcile.IsZero() {
			entry.LastReconcile = timestamppb.New(fw.LastReconcile)
		}
		out.Firewall = entry
	}
	if nat := snap.NAT; nat != nil {
		entry := &platformv1.SnapshotNAT{
			Active:      nat.Active,
			SnatEnabled: nat.SNATEnabled,
			DnatRules:   int32(nat.DNATRules),
			CtZone:      uint32(nat.CTZone),
		}
		for _, up := range nat.Uplinks {
			entry.Uplinks = append(entry.Uplinks, &platformv1.SnapshotNATUplink{
				Name:               up.Name,
				IsDefault:          up.Default,
				PoolAddresses:      int32(up.PoolAddresses),
				Ports:              int32(up.Ports),
				StaticTranslations: int32(up.Static),
			})
		}
		out.Nat = entry
	}
	if pipeline := snap.Pipeline; pipeline != nil {
		out.Pipeline = &platformv1.SnapshotPipeline{
			Installed: pipeline.Installed,
			Bridge:    pipeline.Bridge,
			Owner:     pipeline.Owner,
			Terminal:  pipeline.Terminal,
			FailMode:  pipeline.FailMode,
		}
	}
	return out
}

// snapshotHealthToProto maps the health summary.
func snapshotHealthToProto(health gwstate.HealthState) *platformv1.SnapshotHealth {
	return &platformv1.SnapshotHealth{
		Status:     health.Status,
		Components: health.Components,
		Message:    health.Message,
	}
}

// snapshotBGPToProto maps the BGP section, sessions included.
func snapshotBGPToProto(bgpState gwstate.BGPState) *platformv1.SnapshotBGP {
	out := &platformv1.SnapshotBGP{
		LocalAsn:          bgpState.LocalASN,
		RouterId:          bgpState.RouterID,
		PeerCount:         uint32(bgpState.PeerCount),
		EstablishedPeers:  uint32(bgpState.EstablishedPeers),
		AnnouncedPrefixes: bgpState.AnnouncedPrefixes,
		ReceivedPrefixes:  uint32(bgpState.ReceivedPrefixes),
	}
	for _, peer := range bgpState.Peers {
		entry := &platformv1.SnapshotBGPPeer{
			Address:          peer.Address,
			Asn:              peer.ASN,
			Description:      peer.Description,
			State:            peer.State,
			UptimeSeconds:    uint64(peer.UptimeSeconds),
			AdminDown:        peer.AdminDown,
			PrefixesReceived: peer.PrefixesReceived,
			PrefixesAccepted: peer.PrefixesAccepted,
			PrefixesSent:     peer.PrefixesSent,
			MessagesReceived: peer.MessagesReceived,
			MessagesSent:     peer.MessagesSent,
			LocalAddress:     peer.LocalAddress,
			RemoteRouterId:   peer.RemoteRouterID,
			HoldTimeSeconds:  uint32(peer.HoldTimeSeconds),
			Families:         peer.Families,
			LastError:        peer.LastError,
		}
		if peer.BFD != nil {
			bfd := &platformv1.SnapshotBFD{
				State:               peer.BFD.State,
				RemoteState:         peer.BFD.RemoteState,
				FailureTransitions:  peer.BFD.FailureTransitions,
				Diagnostic:          peer.BFD.Diagnostic,
				RemoteDiagnostic:    peer.BFD.RemoteDiagnostic,
				TxIntervalMs:        peer.BFD.TxIntervalMS,
				RxIntervalMs:        peer.BFD.RxIntervalMS,
				DetectionMultiplier: uint32(peer.BFD.DetectionMultiplier),
			}
			if !peer.BFD.LastFailure.IsZero() {
				bfd.LastFailure = timestamppb.New(peer.BFD.LastFailure)
			}
			entry.Bfd = bfd
		}
		out.Peers = append(out.Peers, entry)
	}
	return out
}
