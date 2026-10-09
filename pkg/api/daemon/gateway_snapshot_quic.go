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
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// GatewaySnapshotReader is the snapshot half of the gateway gRPC service.
// The QUIC and MCP surfaces read through it so every transport answers from
// the one implementation (#594).
type GatewaySnapshotReader interface {
	GetGatewaySnapshot(ctx context.Context, req *platformv1.GetGatewaySnapshotRequest) (*platformv1.GetGatewaySnapshotResponse, error)
	ListGatewaySnapshots(ctx context.Context, req *platformv1.ListGatewaySnapshotsRequest) (*platformv1.ListGatewaySnapshotsResponse, error)
	GetGatewayAdmittedVTEP(ctx context.Context, req *platformv1.GetGatewayAdmittedVTEPRequest) (*platformv1.GetGatewayAdmittedVTEPResponse, error)
	ListGatewayAdmittedVTEPs(ctx context.Context, req *platformv1.ListGatewayAdmittedVTEPsRequest) (*platformv1.ListGatewayAdmittedVTEPsResponse, error)
}

// Compile-time check: the gateway gRPC service is a snapshot reader.
var _ GatewaySnapshotReader = (*GatewayService)(nil)

// gatewaySnapshotQUICAdapter serves the QUIC snapshot sub-opcodes from the
// gateway gRPC service. It is embedded by the QUIC gateway adapters so the
// snapshot is reachable over QUIC on any node whose gateway service has a
// telemetry store or a local gateway.
type gatewaySnapshotQUICAdapter struct {
	reader GatewaySnapshotReader
}

// Snapshot returns one gateway's telemetry snapshot.
func (a gatewaySnapshotQUICAdapter) Snapshot(ctx context.Context, gatewayID string) (*quic.GatewaySnapshotInfo, error) {
	if a.reader == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	resp, err := a.reader.GetGatewaySnapshot(ctx, &platformv1.GetGatewaySnapshotRequest{GatewayId: gatewayID})
	if err != nil {
		return nil, err
	}
	return protoSnapshotToQUIC(resp.GetSnapshot()), nil
}

// ListSnapshots returns every reported gateway's telemetry snapshot.
func (a gatewaySnapshotQUICAdapter) ListSnapshots(ctx context.Context) ([]*quic.GatewaySnapshotInfo, error) {
	if a.reader == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	resp, err := a.reader.ListGatewaySnapshots(ctx, &platformv1.ListGatewaySnapshotsRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]*quic.GatewaySnapshotInfo, 0, len(resp.GetSnapshots()))
	for _, snap := range resp.GetSnapshots() {
		out = append(out, protoSnapshotToQUIC(snap))
	}
	return out, nil
}

func (a gatewaySnapshotQUICAdapter) GetAdmittedVTEP(ctx context.Context, gatewayID, vtep string) (*quic.GatewayAdmittedVTEPInfo, error) {
	if a.reader == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	resp, err := a.reader.GetGatewayAdmittedVTEP(ctx, &platformv1.GetGatewayAdmittedVTEPRequest{GatewayId: gatewayID, Vtep: vtep})
	if err != nil {
		return nil, err
	}
	entry := protoAdmittedVTEPToQUIC(resp.GetVtep())
	return &entry, nil
}

func (a gatewaySnapshotQUICAdapter) ListAdmittedVTEPs(ctx context.Context, gatewayID string) ([]*quic.GatewayAdmittedVTEPInfo, error) {
	if a.reader == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	resp, err := a.reader.ListGatewayAdmittedVTEPs(ctx, &platformv1.ListGatewayAdmittedVTEPsRequest{GatewayId: gatewayID})
	if err != nil {
		return nil, err
	}
	out := make([]*quic.GatewayAdmittedVTEPInfo, 0, len(resp.GetVteps()))
	for _, vtep := range resp.GetVteps() {
		entry := protoAdmittedVTEPToQUIC(vtep)
		out = append(out, &entry)
	}
	return out, nil
}

// protoSnapshotToQUIC maps the wire snapshot onto the QUIC codec types. A
// section the snapshot does not carry stays nil, so a QUIC client reads the
// same "not running" as every other transport.
func protoSnapshotToQUIC(snap *platformv1.GatewaySnapshot) *quic.GatewaySnapshotInfo {
	if snap == nil {
		return nil
	}
	out := &quic.GatewaySnapshotInfo{
		GatewayID:   snap.GetGatewayId(),
		Hostname:    snap.GetHostname(),
		Mode:        snap.GetMode(),
		ReportedAt:  protoUnix(snap.GetReportedAt()),
		ReceivedAt:  protoUnix(snap.GetReceivedAt()),
		Annotations: snap.GetAnnotations(),
	}
	if health := snap.GetHealth(); health != nil {
		out.HealthStatus = health.GetStatus()
		out.Components = health.GetComponents()
	}
	if bgpState := snap.GetBgp(); bgpState != nil {
		section := &quic.SnapshotBGPInfo{
			LocalAS:          bgpState.GetLocalAsn(),
			RouterID:         bgpState.GetRouterId(),
			PeerCount:        int(bgpState.GetPeerCount()),
			EstablishedPeers: int(bgpState.GetEstablishedPeers()),
			ReceivedPrefixes: int(bgpState.GetReceivedPrefixes()),
		}
		for _, peer := range bgpState.GetPeers() {
			entry := quic.SnapshotBGPPeerInfo{
				Address:          peer.GetAddress(),
				ASN:              peer.GetAsn(),
				Description:      peer.GetDescription(),
				State:            peer.GetState(),
				UptimeSeconds:    int64(peer.GetUptimeSeconds()),
				AdminDown:        peer.GetAdminDown(),
				PrefixesReceived: peer.GetPrefixesReceived(),
				PrefixesAccepted: peer.GetPrefixesAccepted(),
				PrefixesSent:     peer.GetPrefixesSent(),
				LocalAddress:     peer.GetLocalAddress(),
				RemoteRouterID:   peer.GetRemoteRouterId(),
				HoldTimeSeconds:  int(peer.GetHoldTimeSeconds()),
				Families:         peer.GetFamilies(),
				LastError:        peer.GetLastError(),
			}
			if bfd := peer.GetBfd(); bfd != nil {
				entry.BFD = &quic.SnapshotBFDInfo{
					State:               bfd.GetState(),
					RemoteState:         bfd.GetRemoteState(),
					FailureTransitions:  bfd.GetFailureTransitions(),
					LastFailure:         protoUnix(bfd.GetLastFailure()),
					Diagnostic:          bfd.GetDiagnostic(),
					RemoteDiagnostic:    bfd.GetRemoteDiagnostic(),
					TxIntervalMS:        bfd.GetTxIntervalMs(),
					RxIntervalMS:        bfd.GetRxIntervalMs(),
					DetectionMultiplier: uint8(min(bfd.GetDetectionMultiplier(), 255)),
				}
			}
			section.Peers = append(section.Peers, entry)
		}
		out.BGP = section
	}
	for _, svc := range snap.GetServices() {
		out.Services = append(out.Services, quic.SnapshotServiceInfo{
			Name:          svc.GetName(),
			Active:        svc.GetActive(),
			Healthy:       svc.GetHealthy(),
			RefusedReason: svc.GetRefusedReason(),
		})
	}
	for _, tun := range snap.GetTunnels() {
		out.Tunnels = append(out.Tunnels, quic.SnapshotTunnelInfo{
			Name:         tun.GetName(),
			Transport:    tun.GetTransport(),
			Type:         tun.GetType(),
			State:        tun.GetState(),
			Uplink:       tun.GetUplink(),
			Bound:        tun.GetBound(),
			LocalIP:      tun.GetLocalIp(),
			RemoteIP:     tun.GetRemoteIp(),
			TunnelIP:     tun.GetTunnelIp(),
			RxBytes:      tun.GetRxBytes(),
			TxBytes:      tun.GetTxBytes(),
			RxPackets:    tun.GetRxPackets(),
			TxPackets:    tun.GetTxPackets(),
			RekeySeconds: tun.GetRekeySeconds(),
			LastRekey:    protoUnix(tun.GetLastRekey()),
		})
	}
	for _, up := range snap.GetUplinks() {
		out.Uplinks = append(out.Uplinks, quic.SnapshotUplinkInfo{
			Name:      up.GetName(),
			Interface: up.GetInterface(),
			Table:     int(up.GetTable()),
			GatewayV4: up.GetGatewayV4(),
			GatewayV6: up.GetGatewayV6(),
			Addresses: up.GetAddresses(),
			Priority:  int(up.GetPriority()),
			RuleCount: int(up.GetRuleCount()),
			Tunnels:   up.GetTunnels(),
		})
	}
	if hf := snap.GetHostFirewall(); hf != nil {
		out.HostFirewall = &quic.SnapshotHostFirewallInfo{
			Active:        hf.GetActive(),
			Installed:     hf.GetInstalled(),
			Fingerprint:   hf.GetFingerprint(),
			RuleCount:     int(hf.GetRuleCount()),
			LastReconcile: protoUnix(hf.GetLastReconcile()),
			LastError:     hf.GetLastError(),
		}
	}
	if fw := snap.GetFirewall(); fw != nil {
		section := &quic.SnapshotFirewallInfo{
			Active:        fw.GetActive(),
			FlowCount:     int(fw.GetFlowCount()),
			LastReconcile: protoUnix(fw.GetLastReconcile()),
		}
		if zones := fw.GetCtZones(); len(zones) > 0 {
			section.CTZones = make(map[string]uint16, len(zones))
			for name, id := range zones {
				section.CTZones[name] = uint16(min(id, 65535))
			}
		}
		out.Firewall = section
	}
	if nat := snap.GetNat(); nat != nil {
		section := &quic.SnapshotNATInfo{
			Active:      nat.GetActive(),
			SNATEnabled: nat.GetSnatEnabled(),
			DNATRules:   int(nat.GetDnatRules()),
			CTZone:      uint16(min(nat.GetCtZone(), 65535)),
		}
		for _, up := range nat.GetUplinks() {
			section.Uplinks = append(section.Uplinks, quic.SnapshotNATUplinkInfo{
				Name:          up.GetName(),
				Default:       up.GetIsDefault(),
				PoolAddresses: int(up.GetPoolAddresses()),
				Ports:         int(up.GetPorts()),
				Static:        int(up.GetStaticTranslations()),
			})
		}
		out.NAT = section
	}
	if pipeline := snap.GetPipeline(); pipeline != nil {
		out.Pipeline = &quic.SnapshotPipelineInfo{
			Installed: pipeline.GetInstalled(),
			Bridge:    pipeline.GetBridge(),
			Owner:     pipeline.GetOwner(),
			Terminal:  pipeline.GetTerminal(),
			FailMode:  pipeline.GetFailMode(),
		}
	}
	if overlay := snap.GetOverlay(); overlay != nil {
		section := &quic.SnapshotOverlayInfo{
			Running:                  overlay.GetRunning(),
			LocalVTEP:                overlay.GetLocalVtep(),
			VNICount:                 overlay.GetVniCount(),
			RemoteVTEPCount:          overlay.GetRemoteVtepCount(),
			LocalMACCount:            overlay.GetLocalMacCount(),
			RemoteMACCount:           overlay.GetRemoteMacCount(),
			PrefixCount:              overlay.GetPrefixCount(),
			RefusedBindings:          overlay.GetRefusedBindings(),
			L3VNI:                    overlay.GetL3Vni(),
			ARPSuppressionEnabled:    overlay.GetArpSuppressionEnabled(),
			AnycastGatewayConfigured: overlay.GetAnycastGatewayConfigured(),
			StartedAt:                protoUnix(overlay.GetStartedAt()),
			UptimeSeconds:            overlay.GetUptimeSeconds(),
		}
		if counters := overlay.GetNdCounters(); counters != nil {
			section.NDCounters = quic.SnapshotOverlayNDCounterInfo{
				Punted:       counters.GetPunted(),
				Answered:     counters.GetAnswered(),
				MeterDropped: counters.GetMeterDropped(),
				QueueDropped: counters.GetQueueDropped(),
				FellThrough:  counters.GetFellThrough(),
			}
		}
		for _, admitted := range overlay.GetAdmittedVteps() {
			section.AdmittedVTEPs = append(section.AdmittedVTEPs, protoAdmittedVTEPToQUIC(admitted))
		}
		out.Overlay = section
	}
	return out
}

func protoAdmittedVTEPToQUIC(vtep *platformv1.GatewayAdmittedVTEP) quic.GatewayAdmittedVTEPInfo {
	return quic.GatewayAdmittedVTEPInfo{
		VTEP:           vtep.GetVtep(),
		DeviceID:       vtep.GetDeviceId(),
		HostID:         vtep.GetHostId(),
		Serial:         vtep.GetSerial(),
		Hostname:       vtep.GetHostname(),
		AllocationID:   vtep.GetAllocationId(),
		BaselineSource: vtep.GetBaselineSource(),
		ProfileID:      vtep.GetProfileId(),
		VerdictAt:      protoUnix(vtep.GetVerdictAt()),
	}
}

// protoUnix renders a wire timestamp as Unix seconds, or zero when the
// message carried none — an absent timestamp must not read as the epoch.
func protoUnix(ts *timestamppb.Timestamp) int64 {
	if ts == nil {
		return 0
	}
	t := ts.AsTime()
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
