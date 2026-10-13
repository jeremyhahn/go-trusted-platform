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

package gateway

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// snapshotTimeout bounds the live reads a snapshot makes (the BGP session
// table, the tunnel links). A reporter tick must not block on a wedged
// speaker or netlink socket.
const snapshotTimeout = 5 * time.Second

// Component health values reported in Snapshot.Health.Components.
const (
	componentHealthy   = "healthy"
	componentUnhealthy = "unhealthy"
)

// Overall health status values reported in Snapshot.Health.Status.
const (
	healthStatusHealthy   = "healthy"
	healthStatusDegraded  = "degraded"
	healthStatusUnhealthy = "unhealthy"
)

// Snapshot assembles the control-plane telemetry snapshot from the
// gateway's live service state. It reports only what the node actually
// runs: per-service health from the registered handlers, BGP identity
// from the configured speaker section, and PXE/DHCP liveness from their
// handlers. Fields whose subsystems are not enabled on this node are
// left at their zero values rather than fabricated.
func (g *Gateway) Snapshot() *gwstate.Snapshot {
	snap := &gwstate.Snapshot{
		GatewayID: g.config.ID,
	}
	if hostname, err := os.Hostname(); err == nil {
		snap.Hostname = hostname
	}

	services := g.ActiveServices()
	sort.Strings(services)
	snap.Mode = strings.Join(services, ",")

	ctx, cancel := context.WithTimeout(context.Background(), snapshotTimeout)
	defer cancel()

	snap.Health = g.collectHealth()
	snap.Services = g.collectServices()
	snap.BGP = g.collectBGP(ctx)
	snap.Tunnels, snap.Uplinks = g.collectTunnels(ctx)
	snap.HostFirewall = g.collectHostFirewall()
	snap.Firewall = g.collectFirewall()
	snap.NAT = g.collectNAT()
	snap.Pipeline = g.collectPipeline()
	snap.Overlay = g.collectOverlay(ctx)
	snap.PXE.Status = serviceStatus(g.hasActiveService(ServicePXE))
	snap.DHCP.Status = serviceStatus(g.hasActiveService(ServiceDHCP))
	snap.DesiredConfig = g.DesiredConfigState()
	snap.Interfaces = collectInterfaces()
	snap.Annotations = map[string]string{
		"state":  g.GetState().String(),
		"uptime": g.Uptime().String(),
	}
	return snap
}

// collectHealth walks the registered service handlers and summarizes
// per-component and overall health.
func (g *Gateway) collectHealth() gwstate.HealthState {
	reports := g.ServiceReports()
	health := gwstate.HealthState{
		Components: make(map[string]string, len(reports)),
	}
	unhealthy := 0
	for _, r := range reports {
		if r.Health != nil {
			health.Components[r.Name] = componentUnhealthy
			unhealthy++
			continue
		}
		health.Components[r.Name] = componentHealthy
	}

	switch {
	case !g.IsOperational():
		health.Status = healthStatusUnhealthy
	case unhealthy > 0:
		health.Status = healthStatusDegraded
	default:
		health.Status = healthStatusHealthy
	}
	return health
}

// collectServices reports one entry per registered service: whether the
// service is running, its own health verdict, and — for a section the
// gateway has no builder for — the blocker that stands in the way (#568).
func (g *Gateway) collectServices() []gwstate.ServiceState {
	g.mu.RLock()
	handlers := make(map[string]ServiceHandler, len(g.serviceHandlers))
	for name, h := range g.serviceHandlers {
		handlers[name] = h
	}
	g.mu.RUnlock()

	out := make([]gwstate.ServiceState, 0, len(handlers))
	for name, h := range handlers {
		entry := gwstate.ServiceState{
			Name:    name,
			Active:  h.IsActive(),
			Healthy: h.Health() == nil,
		}
		if refused, ok := h.(*refusedServiceHandler); ok {
			entry.RefusedReason = refused.reason
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// collectBGP reports the BGP speaker's identity and, when the transit
// service is running, every session the speaker holds: FSM state, prefix
// counters and the neighbour's BFD session. Peer counters come from the
// speaker, never from the configured neighbour list — a configured peer
// that never came up must not read as a session.
func (g *Gateway) collectBGP(ctx context.Context) gwstate.BGPState {
	var bgpState gwstate.BGPState
	if g.config.BGP != nil {
		bgpState.LocalASN = g.config.BGP.ASN
		if g.config.BGP.RouterID.IsValid() {
			bgpState.RouterID = g.config.BGP.RouterID.String()
		}
	}

	if g.supervisedHandler(ServiceTransit) {
		return g.collectSupervisedBGP(ctx, bgpState)
	}
	speaker := g.transitSpeaker()
	if speaker == nil {
		return bgpState
	}
	peers, err := speaker.ListPeers(ctx)
	if err != nil {
		g.logSnapshot("bgp peers unavailable for the snapshot", err)
		return bgpState
	}
	bgpState.Peers = make([]gwstate.BGPPeerState, 0, len(peers))
	for _, peer := range peers {
		if peer == nil {
			continue
		}
		bgpState.Peers = append(bgpState.Peers, peerState(peer))
	}
	sort.Slice(bgpState.Peers, func(i, j int) bool {
		return bgpState.Peers[i].Address < bgpState.Peers[j].Address
	})
	bgpState.PeerCount = len(bgpState.Peers)
	for i := range bgpState.Peers {
		if bgpState.Peers[i].State == bgp.PeerStateEstablished.String() {
			bgpState.EstablishedPeers++
		}
		bgpState.ReceivedPrefixes += int(bgpState.Peers[i].PrefixesAccepted)
	}
	return bgpState
}

// collectSupervisedBGP reads the BGP section from the child hosting the
// speaker. A child that cannot be read leaves the locally configured fields
// and the reason in the section's error, so the missing peer detail is
// reported rather than looking like a speaker with no peers.
func (g *Gateway) collectSupervisedBGP(ctx context.Context, local gwstate.BGPState) gwstate.BGPState {
	child, err := g.config.Supervisor.ServiceSnapshot(ctx, ServiceTransit)
	if err != nil {
		failure := &ErrSupervisedSnapshot{Service: ServiceTransit, Cause: err}
		g.logSnapshot("bgp peers unavailable for the snapshot", failure)
		local.Error = failure.Error()
		return local
	}
	return child.BGP
}

// supervisedHandler reports whether the service is registered as a relay
// to a supervised child rather than hosted in this process.
func (g *Gateway) supervisedHandler(name string) bool {
	g.mu.RLock()
	handler := g.serviceHandlers[name]
	g.mu.RUnlock()
	_, supervised := handler.(*supervisedServiceHandler)
	return supervised
}

// peerState maps one speaker peer onto its snapshot entry.
func peerState(peer *bgp.PeerInfo) gwstate.BGPPeerState {
	entry := gwstate.BGPPeerState{
		ASN:              peer.ASN,
		Description:      peer.Description,
		State:            peer.State.String(),
		UptimeSeconds:    int64(peer.Uptime / time.Second),
		AdminDown:        peer.AdminDown,
		PrefixesReceived: peer.PrefixesReceived,
		PrefixesAccepted: peer.PrefixesAccepted,
		PrefixesSent:     peer.PrefixesSent,
		MessagesReceived: peer.MessagesReceived,
		MessagesSent:     peer.MessagesSent,
		HoldTimeSeconds:  int(peer.NegotiatedHoldTime),
		LastError:        peer.LastError,
	}
	if peer.Address.IsValid() {
		entry.Address = peer.Address.String()
	}
	if peer.LocalAddress.IsValid() {
		entry.LocalAddress = peer.LocalAddress.String()
	}
	if peer.RemoteRouterID.IsValid() {
		entry.RemoteRouterID = peer.RemoteRouterID.String()
	}
	for _, family := range peer.EnabledFamilies {
		entry.Families = append(entry.Families, family.String())
	}
	if peer.BFD != nil {
		entry.BFD = &gwstate.BFDState{
			State:               string(peer.BFD.LocalState),
			RemoteState:         string(peer.BFD.RemoteState),
			FailureTransitions:  peer.BFD.FailureTransitions,
			LastFailure:         peer.BFD.LastFailure,
			Diagnostic:          peer.BFD.LocalDiagnostic,
			RemoteDiagnostic:    peer.BFD.RemoteDiagnostic,
			TxIntervalMS:        int64(peer.BFD.DesiredMinTxInterval / time.Millisecond),
			RxIntervalMS:        int64(peer.BFD.RequiredMinRxInterval / time.Millisecond),
			DetectionMultiplier: peer.BFD.DetectionMultiplier,
		}
	}
	return entry
}

// transitSpeaker returns the running BGP speaker, or nil when the transit
// service is not running.
func (g *Gateway) transitSpeaker() *bgp.Speaker {
	svc, ok := g.backend(ServiceTransit)
	if !ok {
		return nil
	}
	transit, ok := svc.(*transitBackend)
	if !ok {
		return nil
	}
	return transit.Speaker()
}

// collectTunnels reports every managed tunnel and the policy-routing state
// of the uplinks they are pinned to (#582). Both come from the tunnel
// manager the tunnels service drives; a gateway not running the service
// reports neither.
func (g *Gateway) collectTunnels(ctx context.Context) ([]gwstate.TunnelState, []gwstate.UplinkState) {
	svc, ok := g.backend(ServiceTunnels)
	if !ok {
		return nil, nil
	}
	tunnels, ok := svc.(*tunnelsBackend)
	if !ok {
		return nil, nil
	}

	var out []gwstate.TunnelState
	statuses, err := tunnels.Tunnels(ctx)
	if err != nil {
		g.logSnapshot("tunnel status unavailable for the snapshot", err)
	} else {
		out = make([]gwstate.TunnelState, 0, len(statuses))
		for _, st := range statuses {
			if st == nil {
				continue
			}
			out = append(out, gwstate.TunnelState{
				Name:         st.Name,
				Transport:    st.Transport,
				State:        string(st.State),
				Uplink:       st.Uplink,
				Bound:        st.Bound,
				LocalIP:      st.LocalIP,
				RemoteIP:     st.RemoteIP,
				TunnelIP:     st.TunnelIP,
				RxBytes:      st.RxBytes,
				TxBytes:      st.TxBytes,
				RxPackets:    st.RxPackets,
				TxPackets:    st.TxPackets,
				RekeySeconds: int64(st.RekeyInterval / time.Second),
				LastRekey:    st.LastRekey,
			})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		byName := make(map[string]string, len(g.config.Tunnels))
		for i := range g.config.Tunnels {
			byName[g.config.Tunnels[i].Name] = g.config.Tunnels[i].Type
		}
		for i := range out {
			out[i].Type = byName[out[i].Name]
		}
	}

	uplinks := tunnels.Uplinks()
	if len(uplinks) == 0 {
		return out, nil
	}
	routes := make([]gwstate.UplinkState, 0, len(uplinks))
	for _, up := range uplinks {
		routes = append(routes, gwstate.UplinkState{
			Name:      up.Name,
			Interface: up.Interface,
			Table:     up.Table,
			GatewayV4: up.GatewayV4,
			GatewayV6: up.GatewayV6,
			Addresses: up.Addresses,
			Priority:  up.Priority,
			RuleCount: up.RuleCount,
			Tunnels:   up.Tunnels,
		})
	}
	return out, routes
}

// collectHostFirewall reports the nftables host filter's fingerprint and
// last reconcile (#569); nil when the service is not running.
func (g *Gateway) collectHostFirewall() *gwstate.HostFirewallState {
	svc, ok := g.backend(ServiceHostFW)
	if !ok {
		return nil
	}
	backend, ok := svc.(hostFWBackend)
	if !ok {
		return nil
	}
	health := backend.Health()
	state := &gwstate.HostFirewallState{
		Active:        health.Active,
		Installed:     health.Installed,
		Fingerprint:   health.Fingerprint,
		RuleCount:     health.RuleCount,
		LastReconcile: health.LastReconcile,
	}
	if health.LastError != nil {
		state.LastError = health.LastError.Error()
	}
	return state
}

// collectFirewall reports the OVS conntrack firewall's installed flows and
// conntrack zones; nil when the service is not running.
func (g *Gateway) collectFirewall() *gwstate.FirewallState {
	svc, ok := g.backend(ServiceFirewall)
	if !ok {
		return nil
	}
	backend, ok := svc.(firewallBackend)
	if !ok {
		return nil
	}
	health := backend.Health()
	return &gwstate.FirewallState{
		Active:        health.Active,
		FlowCount:     health.FlowCount,
		LastReconcile: health.LastReconcile,
		CTZones:       health.CTZones,
	}
}

// collectNAT reports the NAT service's translations, including the
// per-uplink SNAT pools of a dual-uplink deployment (#586); nil when the
// service is not running.
func (g *Gateway) collectNAT() *gwstate.NATState {
	svc, ok := g.backend(ServiceNAT)
	if !ok {
		return nil
	}
	backend, ok := svc.(natBackend)
	if !ok {
		return nil
	}
	health := backend.Health()
	state := &gwstate.NATState{
		Active:      health.Active,
		SNATEnabled: health.SNATEnabled,
		DNATRules:   health.DNATRules,
		CTZone:      health.CTZone,
	}
	for _, up := range health.Uplinks {
		state.Uplinks = append(state.Uplinks, gwstate.NATUplinkState{
			Name:          up.Name,
			Default:       up.Default,
			PoolAddresses: up.PoolAddresses,
			Ports:         up.Ports,
			Static:        up.Static,
		})
	}
	return state
}

// collectPipeline reports the base OVS pipeline this gateway holds (#567);
// nil when the runtime holds none.
func (g *Gateway) collectPipeline() *gwstate.PipelineState {
	if g.config.Runtime == nil {
		return nil
	}
	status := g.config.Runtime.PipelineStatus()
	if !status.Installed {
		return nil
	}
	return &gwstate.PipelineState{
		Installed: true,
		Bridge:    status.Bridge,
		Owner:     status.Owner,
		Terminal:  string(status.Terminal),
		FailMode:  status.FailMode,
	}
}

type overlaySnapshotService interface {
	Status() *modes.OverlayModeStatus
	ListAdmittedVTEPs(ctx context.Context) ([]AdmittedVTEP, error)
}

func (g *Gateway) collectOverlay(ctx context.Context) *gwstate.OverlayState {
	g.mu.RLock()
	handler := g.serviceHandlers[ServiceOverlay]
	g.mu.RUnlock()

	backed, ok := handler.(*backedServiceHandler)
	if !ok {
		return nil
	}
	svc, ok := backed.service().(overlaySnapshotService)
	if !ok || svc == nil {
		return nil
	}
	status := svc.Status()
	if status == nil {
		return nil
	}

	out := &gwstate.OverlayState{
		Running:                  status.Running,
		LocalVTEP:                status.LocalVTEP.String(),
		VNICount:                 status.VNICount,
		RemoteVTEPCount:          status.RemoteVTEPCount,
		LocalMACCount:            status.LocalMACCount,
		RemoteMACCount:           status.RemoteMACCount,
		PrefixCount:              status.PrefixCount,
		RefusedBindings:          status.RefusedBindings,
		L3VNI:                    status.L3VNI,
		ARPSuppressionEnabled:    status.ARPSuppressionEnabled,
		AnycastGatewayConfigured: status.AnycastGatewayConfigured,
		StartedAt:                status.StartedAt,
		Uptime:                   status.Uptime,
		NDCounters: gwstate.OverlayNDCounterState{
			Punted:       status.NDCounters.Punted,
			Answered:     status.NDCounters.Answered,
			MeterDropped: status.NDCounters.MeterDropped,
			QueueDropped: status.NDCounters.QueueDropped,
			FellThrough:  status.NDCounters.FellThrough,
		},
	}
	vteps, err := svc.ListAdmittedVTEPs(ctx)
	if err != nil {
		g.logSnapshot("overlay admitted VTEPs unavailable for the snapshot", err)
		return out
	}
	for _, vtep := range vteps {
		out.AdmittedVTEPs = append(out.AdmittedVTEPs, admittedVTEPState(vtep))
	}
	sort.Slice(out.AdmittedVTEPs, func(i, j int) bool {
		return out.AdmittedVTEPs[i].VTEP < out.AdmittedVTEPs[j].VTEP
	})
	return out
}

func admittedVTEPState(vtep AdmittedVTEP) gwstate.AdmittedVTEPState {
	return gwstate.AdmittedVTEPState{
		VTEP:           vtep.VTEP.String(),
		DeviceID:       vtep.DeviceID,
		HostID:         vtep.HostID,
		Serial:         vtep.Serial,
		Hostname:       vtep.Hostname,
		AllocationID:   vtep.AllocationID,
		BaselineSource: vtep.BaselineSource,
		ProfileID:      vtep.ProfileID,
		VerdictAt:      vtep.VerdictAt,
	}
}

// logSnapshot records a section the snapshot could not read. A telemetry
// report is best-effort: a section that cannot be read is left out, and the
// reason is logged rather than reported as an empty section.
func (g *Gateway) logSnapshot(msg string, err error) {
	logger := g.config.hostRuntime().Logger
	if logger == nil {
		return
	}
	logger.Warn(msg, slog.Any("error", err))
}

// hasActiveService reports whether the named service is registered and
// currently active.
func (g *Gateway) hasActiveService(name string) bool {
	g.mu.RLock()
	h, ok := g.serviceHandlers[name]
	g.mu.RUnlock()
	return ok && h.IsActive()
}

// serviceStatus maps handler liveness onto the snapshot status vocabulary.
func serviceStatus(active bool) string {
	if active {
		return "running"
	}
	return "stopped"
}

// collectInterfaces reads the node's network interfaces for the
// control plane's NIC table. Failures yield an empty list rather than
// failing the snapshot.
func collectInterfaces() []gwstate.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]gwstate.Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		entry := gwstate.Interface{
			Name:   iface.Name,
			Status: interfaceStatus(iface.Flags),
			MAC:    iface.HardwareAddr.String(),
		}
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
					entry.Addresses = append(entry.Addresses, prefix)
				}
			}
		}
		out = append(out, entry)
	}
	return out
}

// interfaceStatus maps interface flags onto the snapshot status vocabulary.
func interfaceStatus(flags net.Flags) string {
	if flags&net.FlagUp != 0 {
		return "up"
	}
	return "down"
}
