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

// Package modes provides SDN gateway mode handlers for different networking scenarios.
package modes

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// OpenFlow table IDs for overlay mode pipeline.
//
// Tables 20, 21, and 25 are populated only when the gateway firewall or NAT
// services are enabled (pkg/sdn/gateway/services/firewall); tables 26, 28
// and 29 only when the load balancer is
// (pkg/sdn/gateway/services/loadbalancer). Table 27 is reserved for the
// NAT64 translator hand-off (#601). Overlay traffic — access ingress and
// authorised decap alike — enters table 20 from table 10; with no service
// enabled the table-20 miss continues to table 30.
const (
	TableIngress       uint8 = 0  // Ingress classification
	TableVXLANDecap    uint8 = 10 // Access ingress and VXLAN decap authorisation (tun_id, tun_src)
	TableCTGate        uint8 = 20 // Conntrack gate (firewall service)
	TableCTVerdict     uint8 = 21 // Conntrack verdict (firewall service)
	TableNAT           uint8 = 25 // NAT commit (NAT service)
	TableLoadBalancer  uint8 = 26 // Load balancer VIP dispatch (load-balancer service)
	TableNAT64         uint8 = 27 // NAT64 translator hand-off (nat64 service)
	TableLBHairpin     uint8 = 28 // Load balancer hairpin SNAT (load-balancer service)
	TableLBReply       uint8 = 29 // Load balancer reply reverse NAT (load-balancer service)
	TableMACLearning   uint8 = 30 // L2 forwarding by (VNI, MAC)
	TableARP           uint8 = 40 // ARP and ND suppression
	TableL3Routing     uint8 = 50 // Symmetric IRB routing (anycast gateway)
	TableEgress        uint8 = 60 // BUM ingress replication
	TableLocalDelivery uint8 = 70 // Out the access port
)

// overlayStaleFlowHold is how long a relaunched overlay keeps the flows its
// predecessor installed and it has not re-added: the BGP graceful-restart
// time, within which EVPN peers re-advertise the remote hosts whose flows
// those are. Like a peer's stale routes, they are then swept.
const overlayStaleFlowHold = time.Duration(bgp.DefaultGracefulRestartTime) * time.Second

// MACEntrySource indicates where a MAC entry was learned from.
type MACEntrySource uint8

const (
	// MACSourceLocal indicates a MAC on this VTEP's access port.
	MACSourceLocal MACEntrySource = iota
	// MACSourceRemote indicates a MAC behind another VTEP, learned via EVPN.
	MACSourceRemote
)

// String returns the source name.
func (s MACEntrySource) String() string {
	if s == MACSourceLocal {
		return "local"
	}
	return "remote"
}

// MACEntry is one MAC the overlay forwards to.
type MACEntry struct {
	// MAC is the host's hardware address.
	MAC net.HardwareAddr

	// IPs are the host's IP bindings, sorted.
	IPs []netip.Addr

	// VNI is the L2VNI the host is on.
	VNI uint32

	// VTEPIP is the VTEP the host sits behind; invalid for a local host.
	VTEPIP netip.Addr

	// Source is where the MAC was learned.
	Source MACEntrySource

	// UpdatedAt is when the entry last changed.
	UpdatedAt time.Time
}

// OverlayModeStatus represents the current status of the overlay mode.
type OverlayModeStatus struct {
	// Running indicates whether the overlay mode is running.
	Running bool

	// LocalVTEP is the local VTEP IP address.
	LocalVTEP netip.Addr

	// VNICount is the number of configured VNIs.
	VNICount int

	// RemoteVTEPCount is the number of distinct VTEPs on the VNIs'
	// ingress-replication lists.
	RemoteVTEPCount int

	// LocalMACCount is the number of local MACs.
	LocalMACCount int

	// RemoteMACCount is the number of remote MACs.
	RemoteMACCount int

	// PrefixCount is the number of Type-5 prefixes routed.
	PrefixCount int

	// RefusedBindings is how many remote MAC/IP bindings were refused for
	// claiming the anycast gateway's address, or held back for claiming a
	// local host's IP.
	RefusedBindings uint64

	// L3VNI is the IP-VRF of symmetric IRB; zero when off.
	L3VNI uint32

	// ARPSuppressionEnabled indicates whether ARP suppression is active.
	ARPSuppressionEnabled bool

	// NDSuppression contains Neighbor Discovery suppression counters.
	NDSuppression NDSuppressionStatus

	// AnycastGatewayConfigured indicates whether anycast gateway is configured.
	AnycastGatewayConfigured bool

	// StartedAt is when the overlay mode was started.
	StartedAt time.Time

	// Uptime is the duration the overlay mode has been running.
	Uptime time.Duration

	// NDCounters reports overlay neighbour-discovery handler counters.
	NDCounters OverlayNDCounters
}

// OverlayNDCounters reports overlay neighbour-discovery datapath counters.
type OverlayNDCounters struct {
	Punted       uint64
	Answered     uint64
	MeterDropped uint64
	QueueDropped uint64
	FellThrough  uint64
}

// NDSuppressionStatus reports ND suppression and counts the neighbor
// solicitations punted to the controller and what became of them. A
// punted solicitation is answered instead of flooded, or flooded by the
// controller; any drop makes the controller fall back to the flood.
type NDSuppressionStatus struct {
	// Suppressing is whether solicitations for known targets are punted
	// now; it is false while stopped and while fallen back to the flood.
	Suppressing bool
	// Received is the solicitations the controller took off its queue.
	Received uint64
	// Answered is those answered with a proxy advertisement.
	Answered uint64
	// Flooded is those the controller sent on to the segment's flood: a
	// DAD probe, one from the binding's own MAC, or one for an address
	// the overlay no longer knows or that more than one host now claims.
	Flooded uint64
	// Discarded is those neither answered nor flooded: invalid under
	// RFC 4861, or on a VNI with no segment here.
	Discarded uint64
	// SendFailed is the answers and floods the switch refused.
	SendFailed uint64
	// QueueDropped is the punts dropped because the controller's queue
	// was full.
	QueueDropped uint64
	// MeterDropped is the punts the switch's meter dropped over its rate,
	// read from the meter's statistics.
	MeterDropped uint64
	// Fallbacks is how many times a drop removed the punts so that every
	// solicitation floods.
	Fallbacks uint64
}

// OverlayOVSClient is the OVSDB client the overlay needs: the flow-based
// VXLAN port, and the OpenFlow number of the access port.
type OverlayOVSClient interface {
	vxlan.OVSClient
}

// OverlayOpenFlowClient is the OpenFlow client the overlay programs.
type OverlayOpenFlowClient interface {
	// IsConnected reports whether the management socket is up. It goes down
	// when the switch closes the socket, for example when OVS restarts.
	IsConnected() bool
	// Connect redials the management socket, which resubscribed packet-in
	// subscribers survive.
	Connect(ctx context.Context) error
	// SendFlowMods sends flow mods as one batch, followed by one barrier.
	SendFlowMods(ctx context.Context, flows []*openflow.FlowMod) error
	// QueryFlowStats reads the flows the filter selects, which the
	// generation sweep reads the cookies of.
	QueryFlowStats(ctx context.Context, filter openflow.FlowStatsFilter) ([]openflow.FlowStats, error)
	SendPacketOut(ctx context.Context, packet *openflow.PacketOut) error
	// SetMeter installs a drop meter, or updates the rate of an existing one.
	SetMeter(ctx context.Context, meterID uint32, rateKbps uint32, burstKbps uint32) error
	DeleteMeter(ctx context.Context, meterID uint32) error
	GetMeterStats(ctx context.Context, meterID uint32) (openflow.MeterStats, error)
	SubscribePacketIn(queueSize int) (*openflow.PacketInSubscription, error)
}

// VTEPAdmitter decides whether a remote VTEP may carry a VNI. The overlay
// asks before it forwards to a VTEP or authorises its decap, once for
// every (VNI, VTEP) pair a route names; a refusal leaves the route
// uninstalled.
type VTEPAdmitter interface {
	AdmitVTEP(ctx context.Context, vni uint32, vtep netip.Addr) error
}

// OverlayModeConfig holds configuration for the overlay mode handler.
type OverlayModeConfig struct {
	// VTEPConfig is the VTEP configuration; its local address must be
	// IPv4, the only tunnel family the flows set and match.
	VTEPConfig *vxlan.VTEPConfig

	// EVPNConfig is the EVPN manager configuration; nil runs the overlay
	// without a control plane, bridging local hosts only.
	EVPNConfig *bgp.EVPNManagerConfig

	// ARPSuppression answers ARP for every known IPv4 binding in the
	// switch, not only for the anycast gateway.
	ARPSuppression bool

	// AnycastGateways maps an L2VNI to the IPv4 address of its distributed
	// anycast gateway, answered for on that VNI's segment; with
	// AnycastGatewayMAC it turns on routing. A VNI without an entry is
	// bridged and routed only by hosts that know another gateway.
	AnycastGateways map[uint32]netip.Addr

	// Subnets maps a routed L2VNI to its IPv4 subnet, which holds the
	// VNI's anycast gateway. With L3VNI, each is originated as a Type-5
	// route in the IP-VRF while its VNI is joined.
	Subnets map[uint32]netip.Prefix

	// AnycastGatewayMAC is the distributed anycast gateway MAC, shared by
	// every VNI's gateway and by every VTEP.
	AnycastGatewayMAC net.HardwareAddr

	// L3VNI is the IP-VRF of symmetric IRB; zero routes between local
	// segments only. It needs the anycast gateway and the EVPN router MAC.
	L3VNI uint32

	// BridgeName is the OVS bridge name.
	BridgeName string

	// AccessPort is the bridge port that carries every local VNI as a
	// VLAN.
	AccessPort string

	// Admitter vets the remote VTEPs routes name; EVPN requires it.
	Admitter VTEPAdmitter

	// FloodPeers, when set, is told each change to a VNI's flood list as
	// the Type-3 route that made it, once the flows hold it; leaving a VNI
	// withdraws each VTEP that was on it. gatewayd's overlay IPsec follows
	// it, so an SA runs to exactly the VTEPs this node exchanges frames with.
	FloodPeers bgp.EVPNRouteHandler

	// Logger for logging operations.
	Logger *slog.Logger
}

// Validate validates the overlay mode configuration.
func (c *OverlayModeConfig) Validate() error {
	if c.VTEPConfig == nil {
		return ErrVTEPConfigNil
	}
	if err := c.VTEPConfig.Validate(); err != nil {
		return err
	}
	if !c.VTEPConfig.LocalIP.Is4() {
		return ErrInvalidVTEPIP
	}
	if c.BridgeName == "" {
		return ErrBridgeNameEmpty
	}
	if c.AccessPort == "" {
		return ErrAccessPortEmpty
	}
	if c.Logger == nil {
		return ErrLoggerNil
	}
	if c.EVPNConfig != nil && c.Admitter == nil {
		return ErrAdmitterNil
	}
	anycast := len(c.AnycastGateways) > 0 || c.AnycastGatewayMAC != nil
	if anycast && (len(c.AnycastGateways) == 0 || len(c.AnycastGatewayMAC) != 6) {
		return ErrAnycastGatewayIncomplete
	}
	for vni, ip := range c.AnycastGateways {
		if err := validateOverlayVNI(vni); err != nil {
			return err
		}
		if !ip.Is4() {
			return ErrAnycastGatewayIncomplete
		}
	}
	seen := make(map[netip.Prefix]struct{}, len(c.Subnets))
	for vni, subnet := range c.Subnets {
		gateway, ok := c.AnycastGateways[vni]
		if !ok || !subnet.Addr().Is4() || subnet != subnet.Masked() || !subnet.Contains(gateway) {
			return ErrRoutedSubnetInvalid
		}
		if _, repeated := seen[subnet]; repeated {
			return ErrRoutedSubnetInvalid
		}
		seen[subnet] = struct{}{}
	}
	if c.L3VNI == 0 {
		return nil
	}
	if err := validateOverlayVNI(c.L3VNI); err != nil {
		return err
	}
	if c.EVPNConfig == nil || len(c.EVPNConfig.RouterMAC) != 6 {
		return ErrRouterMACRequired
	}
	if !anycast {
		return ErrAnycastGatewayRequired
	}
	return nil
}

// hostKey names one MAC on one VNI.
type hostKey struct {
	vni uint32
	mac string
}

// overlaySegment is one L2VNI: its access VLAN, the remote VTEPs placed on
// it (its ingress-replication list, sorted) and the flows that carry it.
type overlaySegment struct {
	vlan  uint16
	flood []netip.Addr
	flows []*openflow.FlowMod
}

// irbBinding is what a remote IP binding needs to be routed to: the IP-VRF
// it was advertised in and the remote VTEP's router MAC.
type irbBinding struct {
	l3vni     uint32
	routerMAC net.HardwareAddr
}

// overlayHost is one MAC on one VNI. A local host has no VTEP. Its IP
// bindings key on the address; the invalid address is the MAC-only route.
type overlayHost struct {
	mac  net.HardwareAddr
	vtep netip.Addr
	ips  map[netip.Addr]irbBinding
	// held is a remote host's bindings to IPs a local host answers for:
	// the MAC is bridged, but their ARP replies and host routes wait for
	// the local host to go.
	held      map[netip.Addr]irbBinding
	updatedAt time.Time
	flows     []*openflow.FlowMod
}

func (h *overlayHost) local() bool {
	return !h.vtep.IsValid()
}

// sortedIPs returns the host's IP bindings, without the MAC-only route.
func (h *overlayHost) sortedIPs() []netip.Addr {
	ips := make([]netip.Addr, 0, len(h.ips))
	for ip := range h.ips {
		if ip.IsValid() {
			ips = append(ips, ip)
		}
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	return ips
}

// overlayPrefixRoute is one VTEP's Type-5 route to a prefix.
type overlayPrefixRoute struct {
	vtep      netip.Addr
	routerMAC net.HardwareAddr
}

// overlayPrefix is a Type-5 prefix and every VTEP advertising it. The
// lowest VTEP address carries the traffic, so every VTEP picks the same
// one and a withdrawal falls back to the next.
type overlayPrefix struct {
	routes map[netip.Addr]*overlayPrefixRoute
	flows  []*openflow.FlowMod
}

// best returns the route that carries the prefix, or nil when none is left.
func (p *overlayPrefix) best() *overlayPrefixRoute {
	var best *overlayPrefixRoute
	for vtep, route := range p.routes {
		if best == nil || vtep.Less(best.vtep) {
			best = route
		}
	}
	return best
}

// OverlayModeHandler forwards a VXLAN overlay between the local access
// port and remote VTEPs, programmed from EVPN routes: Type-2 routes become
// MAC forwarding, ARP replies and IRB host routes, Type-3 routes ingress
// replication and decap authorisation, Type-5 routes prefix routes.
type OverlayModeHandler struct {
	config      *OverlayModeConfig
	vtepManager *vxlan.VTEPManager
	evpnManager *bgp.EVPNManager
	ovsClient   OverlayOVSClient
	ofClient    OverlayOpenFlowClient
	logger      *slog.Logger

	// opMu serialises lifecycle, VNI and MAC operations. EVPN route
	// events take only mu: the EVPN manager runs them synchronously from
	// JoinVNI and WithdrawMACIP, so those calls are made without mu.
	opMu sync.Mutex
	// unwithdrawn is the IPs of forgotten local hosts whose Type-2
	// withdrawal BGP refused; ForgetMAC for the MAC tries them again.
	// opMu guards it.
	unwithdrawn map[hostKey]map[netip.Addr]struct{}

	// mu guards the state and the flows below.
	mu        sync.Mutex
	running   bool
	startedAt time.Time
	builder   *flowBuilder
	flows     *flowTable
	// cookie is OverlayCookie with the generation Start drew; every flow
	// this run installs carries it.
	cookie uint64
	// staleSweepAt is when the flows of an older generation, which a
	// killed predecessor left on the switch, are swept; zero once they are
	// and while stopped.
	staleSweepAt time.Time
	// drifted is set when the switch refused a put-back and may hold
	// flows the table does not; the next change rebuilds the switch, and so
	// does the ND watch, which retries a refused rebuild with a backoff:
	// rebuildBackoff is the last wait and rebuildRetryAt when it ends.
	drifted        bool
	rebuildBackoff time.Duration
	rebuildRetryAt time.Time
	// remap is set when the switch reconnects: a restarted ovs-vswitchd can
	// renumber the ports, so the rebuild first reads their numbers again and
	// regenerates the flows on them, and no change goes on until it has.
	remap    bool
	segments map[uint32]*overlaySegment
	vlans    map[uint16]uint32
	hosts    map[hostKey]*overlayHost
	prefixes map[netip.Prefix]*overlayPrefix
	// revocations counts each remote VTEP's revocations. A route handler
	// reads the count before it asks the admitter and installs only while
	// it is unchanged, so a revocation landing inside an admission is never
	// undone by the route that admission let through.
	revocations map[netip.Addr]uint64
	// refused holds each remote VTEP a route was refused or revoked from,
	// with the refusal count when it was last marked. BGP does not send an
	// unchanged route again, so ReplayVTEP hands the EVPN manager's routes
	// back through the handlers once the VTEP may be admitted.
	refused  map[netip.Addr]uint64
	refusals uint64

	// refusedBindings counts the remote bindings refused or held back for
	// a conflict.
	refusedBindings uint64

	// ndOwners indexes the hosts by their IPv6 bindings, for answering
	// punted solicitations; mu guards it.
	ndOwners map[ndKey][]hostKey
	// ndController answers punted solicitations and ndStopPoll ends the
	// ND watch, which closes ndPollDone; nil while stopped. mu guards
	// them.
	ndController *openflow.PacketInController
	ndStopPoll   context.CancelFunc
	ndPollDone   chan struct{}
	// ndSuppressing is set while the punt flows are on the switch; the
	// watch clears it to fall back to the flood and sets it again at
	// ndResumeAt. ndRefreshAt is when the punts are next re-added, before
	// their hard timeout. ndDropsSeen is the lost punts the watch last
	// saw. ndHoldDown is the last fallback's hold-down, zero before the
	// first, and ndResumedAt is when suppression last started. mu guards
	// them.
	ndSuppressing bool
	// ndMeterReady is set while meter 709 is known to be on the switch. A
	// punt through a missing meter reaches no controller, so suppression
	// resumes only once the meter is back; the poll retries a meter the
	// reconnected switch refused. mu guards it.
	ndMeterReady bool
	ndResumeAt   time.Time
	ndRefreshAt  time.Time
	ndDropsSeen  uint64
	ndHoldDown   time.Duration
	ndResumedAt  time.Time
	nd           ndCounters
}

// NewOverlayModeHandler creates a new overlay mode handler.
func NewOverlayModeHandler(
	config *OverlayModeConfig,
	ovsClient OverlayOVSClient,
	ofClient OverlayOpenFlowClient,
) (*OverlayModeHandler, error) {
	if config == nil {
		return nil, ErrConfigNil
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if ovsClient == nil {
		return nil, ErrOVSClientNil
	}
	if ofClient == nil {
		return nil, ErrOpenFlowClientNil
	}

	h := &OverlayModeHandler{
		config:      config,
		ovsClient:   ovsClient,
		ofClient:    ofClient,
		logger:      config.Logger,
		unwithdrawn: make(map[hostKey]map[netip.Addr]struct{}),
		flows:       newFlowTable(),
		segments:    make(map[uint32]*overlaySegment),
		vlans:       make(map[uint16]uint32),
		hosts:       make(map[hostKey]*overlayHost),
		prefixes:    make(map[netip.Prefix]*overlayPrefix),
		revocations: make(map[netip.Addr]uint64),
		refused:     make(map[netip.Addr]uint64),
		ndOwners:    make(map[ndKey][]hostKey),
	}

	vtepManager, err := vxlan.NewVTEPManager(*config.VTEPConfig, ovsClient, config.BridgeName, config.Logger)
	if err != nil {
		return nil, &ErrOverlayInitFailed{Component: "VTEPManager", Cause: err}
	}
	h.vtepManager = vtepManager

	if config.EVPNConfig != nil {
		evpnManager, err := bgp.NewEVPNManager(config.EVPNConfig)
		if err != nil {
			return nil, &ErrOverlayInitFailed{Component: "EVPNManager", Cause: err}
		}
		evpnManager.RegisterHandler(h.handleEVPNRoute)
		h.evpnManager = evpnManager
	}
	return h, nil
}

// Start creates the VXLAN port, starts the EVPN control plane and installs
// the base pipeline, replacing any overlay flows a previous run left.
func (h *OverlayModeHandler) Start(ctx context.Context) error {
	h.opMu.Lock()
	defer h.opMu.Unlock()

	h.mu.Lock()
	running := h.running
	h.mu.Unlock()
	if running {
		return ErrAlreadyRunning
	}

	cookie, err := ovs.NewGenerationCookie(OverlayCookie)
	if err != nil {
		return &ErrOverlayStartFailed{Component: "OpenFlow", Cause: err}
	}
	h.mu.Lock()
	h.cookie = cookie
	h.mu.Unlock()

	if err := h.vtepManager.Start(ctx); err != nil {
		return &ErrOverlayStartFailed{Component: "VTEPManager", Cause: err}
	}
	builder, err := h.newBuilder(ctx, cookie)
	if err != nil {
		h.abortStart(ctx, false)
		component := "OpenFlow"
		var unresolved *ErrOverlayPortUnresolved
		if errors.As(err, &unresolved) {
			component = unresolved.Port
		}
		return &ErrOverlayStartFailed{Component: component, Cause: err}
	}
	if h.evpnManager != nil {
		if err := h.evpnManager.Start(ctx); err != nil {
			h.abortStart(ctx, false)
			return &ErrOverlayStartFailed{Component: "EVPNManager", Cause: err}
		}
	}

	// The ND meter goes on before the flows that punt through it, so a
	// datapath without meters fails here with no flow installed.
	if err := h.startNDController(ctx); err != nil {
		h.abortStart(ctx, h.evpnManager != nil)
		return &ErrOverlayStartFailed{Component: "OpenFlow ND", Cause: err}
	}
	h.mu.Lock()
	err = h.installBase(ctx, builder)
	h.mu.Unlock()
	if err != nil {
		h.abortStart(ctx, h.evpnManager != nil)
		return &ErrOverlayStartFailed{Component: "OpenFlow", Cause: err}
	}

	h.logger.Info("overlay mode started",
		slog.String("local_vtep", h.config.VTEPConfig.LocalIP.String()),
		slog.String("vxlan_port", h.vtepManager.PortName()),
		slog.Uint64("l3vni", uint64(h.config.L3VNI)))
	return nil
}

// installBase installs the base pipeline under this run's generation, in
// fail-closed order, and marks the handler running. It flushes nothing: an
// ADD of the same table, priority and match replaces a predecessor's flow in
// place, so forwarding the relaunch still wants never gaps, and whatever the
// predecessor installed that this run does not is swept by generation once
// overlayStaleFlowHold has passed (sweepPredecessor). Caller holds mu.
func (h *OverlayModeHandler) installBase(ctx context.Context, builder *flowBuilder) error {
	h.flows.reset()
	h.drifted, h.remap = false, false
	plan, err := h.flows.plan(nil, builder.base())
	if err != nil {
		return err
	}
	if err := h.ofClient.SendFlowMods(ctx, failClosed(plan.mods)); err != nil {
		return h.resync(ctx, err, overlayFlush())
	}
	plan.commit()
	h.builder = builder
	h.running = true
	h.startedAt = time.Now()
	h.staleSweepAt = h.startedAt.Add(overlayStaleFlowHold)
	return nil
}

// sweepPredecessor deletes the flows of older overlay generations once the
// hold Start set has passed. A failure is logged and retried on the next
// tick. Called from the ND poll loop.
func (h *OverlayModeHandler) sweepPredecessor(ctx context.Context, now time.Time) {
	h.mu.Lock()
	due := h.running && !h.staleSweepAt.IsZero() && !now.Before(h.staleSweepAt)
	h.mu.Unlock()
	if !due {
		return
	}
	if err := h.sweepStaleGenerations(ctx); err != nil {
		h.logger.Warn("overlay stale generation sweep failed; retrying", "error", err)
	}
}

// sweepStaleGenerations deletes every flow under the overlay's owner cookie
// whose generation is not this run's, leaving this run's flows and every
// other owner's untouched. Each stale generation is deleted by its exact
// cookie, so a flow this run re-added in place, which now carries this run's
// cookie, survives. The flows an older release left under the exact
// legacyOverlayCookie are swept the same way.
func (h *OverlayModeHandler) sweepStaleGenerations(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running {
		return nil
	}
	stats, err := h.ofClient.QueryFlowStats(ctx, openflow.FlowStatsFilter{
		TableID:    openflow.OFPTTAll,
		Cookie:     OverlayCookie,
		CookieMask: ovs.OwnerCookieMask,
	})
	if err != nil {
		return &ErrFlowOperationFailed{Table: openflow.OFPTTAll, Operation: "read stale generations", Cause: err}
	}
	legacy, err := h.ofClient.QueryFlowStats(ctx, openflow.FlowStatsFilter{
		TableID:    openflow.OFPTTAll,
		Cookie:     legacyOverlayCookie,
		CookieMask: ^uint64(0),
	})
	if err != nil {
		return &ErrFlowOperationFailed{Table: openflow.OFPTTAll, Operation: "read stale generations", Cause: err}
	}
	stale := make(map[uint64]struct{})
	for _, s := range stats {
		if s.Cookie&ovs.OwnerCookieMask == OverlayCookie && s.Cookie != h.cookie {
			stale[s.Cookie] = struct{}{}
		}
	}
	if len(legacy) > 0 {
		stale[legacyOverlayCookie] = struct{}{}
	}
	if len(stale) > 0 {
		mods := make([]*openflow.FlowMod, 0, len(stale))
		for _, cookie := range slices.Sorted(maps.Keys(stale)) {
			mods = append(mods, generationDelete(cookie))
		}
		if err := h.ofClient.SendFlowMods(ctx, mods); err != nil {
			return &ErrFlowOperationFailed{Table: openflow.OFPTTAll, Operation: "sweep stale generations", Cause: err}
		}
		h.logger.Info("overlay flows of older generations swept", "generations", len(stale))
	}
	h.staleSweepAt = time.Time{}
	return nil
}

// newBuilder builds the overlay's flows on the current OpenFlow numbers of
// the VXLAN and access ports, read from OVS.
func (h *OverlayModeHandler) newBuilder(ctx context.Context, cookie uint64) (*flowBuilder, error) {
	vxlanPort, err := h.vtepManager.ResolveOFPort(ctx)
	if err != nil {
		return nil, &ErrOverlayPortUnresolved{Port: "VXLANPort", Cause: err}
	}
	accessPort, err := h.ovsClient.GetOFPort(ctx, h.config.AccessPort)
	if err == nil && accessPort <= 0 {
		err = ErrAccessPortUnresolved
	}
	if err != nil {
		return nil, &ErrOverlayPortUnresolved{Port: "AccessPort", Cause: err}
	}
	return newFlowBuilder(h.config, overlayPorts{vxlan: vxlanPort, access: uint32(accessPort)}, cookie)
}

// remapPorts reads the ports' OpenFlow numbers again, which a restarted
// ovs-vswitchd can change, and regenerates every committed flow on them in
// a new table, so the rebuild after it carries the switch's numbers rather
// than those the flows were built with. Hosts go in the order they were
// last updated, so where two hold one flow differently the later still
// wins. The switch is not touched. Caller holds mu.
func (h *OverlayModeHandler) remapPorts(ctx context.Context) error {
	builder, err := h.newBuilder(ctx, h.cookie)
	if err != nil {
		return err
	}
	segmentFlows := make(map[uint32][]*openflow.FlowMod, len(h.segments))
	prefixFlows := make(map[netip.Prefix][]*openflow.FlowMod, len(h.prefixes))
	hostFlows := make(map[hostKey][]*openflow.FlowMod, len(h.hosts))
	acquire := builder.base()
	for _, vni := range slices.Sorted(maps.Keys(h.segments)) {
		segmentFlows[vni] = builder.segment(vni, h.segments[vni])
		acquire = append(acquire, segmentFlows[vni]...)
	}
	for _, prefix := range slices.SortedFunc(maps.Keys(h.prefixes), netip.Prefix.Compare) {
		if best := h.prefixes[prefix].best(); best != nil {
			prefixFlows[prefix] = builder.prefix(prefix, best)
			acquire = append(acquire, prefixFlows[prefix]...)
		}
	}
	hosts := slices.SortedFunc(maps.Keys(h.hosts), func(a, b hostKey) int {
		return cmp.Or(h.hosts[a].updatedAt.Compare(h.hosts[b].updatedAt),
			cmp.Compare(a.vni, b.vni), cmp.Compare(a.mac, b.mac))
	})
	for _, key := range hosts {
		hostFlows[key] = builder.host(key.vni, h.segments[key.vni].vlan, h.hosts[key])
		acquire = append(acquire, hostFlows[key]...)
	}

	flows := newFlowTable()
	plan, err := flows.plan(nil, acquire)
	if err != nil {
		return err
	}
	plan.commit()
	for vni, segment := range h.segments {
		segment.flows = segmentFlows[vni]
	}
	for prefix, routes := range h.prefixes {
		routes.flows = prefixFlows[prefix]
	}
	for key, host := range h.hosts {
		host.flows = hostFlows[key]
	}
	h.builder, h.flows, h.remap = builder, flows, false
	h.logger.Info("overlay flows regenerated on the switch's port numbers",
		slog.Uint64("vxlan_ofport", uint64(builder.ports.vxlan)),
		slog.Uint64("access_ofport", uint64(builder.ports.access)))
	return nil
}

// abortStart undoes a partial Start. Its own failures are logged: the
// start error is the one the caller reports.
func (h *OverlayModeHandler) abortStart(ctx context.Context, evpnStarted bool) {
	if err := h.stopNDController(ctx); err != nil {
		h.logger.Error("removing the ND punts after a failed start", slog.Any("error", err))
	}
	if evpnStarted {
		if err := h.evpnManager.Stop(ctx); err != nil {
			h.logger.Error("stopping EVPN after a failed start", slog.Any("error", err))
		}
	}
	if err := h.vtepManager.Stop(ctx); err != nil {
		h.logger.Error("removing the VXLAN port after a failed start", slog.Any("error", err))
	}
}

// Stop withdraws this VTEP from every VNI, stops the control plane,
// removes every overlay flow and the VXLAN port. It carries on past a
// failure and reports them all.
func (h *OverlayModeHandler) Stop(ctx context.Context) error {
	h.opMu.Lock()
	defer h.opMu.Unlock()

	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return ErrNotRunning
	}
	h.running = false
	vnis := slices.Sorted(maps.Keys(h.segments))
	h.mu.Unlock()

	var errs []error
	if h.evpnManager != nil {
		for _, vni := range vnis {
			if err := h.leaveVNI(ctx, vni); err != nil {
				errs = append(errs, err)
			}
		}
		if err := h.evpnManager.Stop(ctx); err != nil {
			errs = append(errs, &ErrStopFailed{Component: "EVPNManager", Cause: err})
		}
	}
	clear(h.unwithdrawn)
	if err := h.stopNDController(ctx); err != nil {
		errs = append(errs, err)
	}

	h.mu.Lock()
	if err := h.ofClient.SendFlowMods(ctx, overlayFlush()); err != nil {
		errs = append(errs, &ErrFlowOperationFailed{Table: openflow.OFPTTAll, Operation: "delete", Cause: err})
	}
	h.flows.reset()
	h.staleSweepAt = time.Time{}
	clear(h.segments)
	clear(h.vlans)
	clear(h.hosts)
	clear(h.ndOwners)
	clear(h.prefixes)
	h.mu.Unlock()

	if err := h.vtepManager.Stop(ctx); err != nil {
		errs = append(errs, &ErrStopFailed{Component: "VTEPManager", Cause: err})
	}
	h.logger.Info("overlay mode stopped")
	return errors.Join(errs...)
}

// AddVNI carries an L2VNI on an access VLAN and places this VTEP on it in
// EVPN, which brings in the remote VTEPs and hosts already advertised.
func (h *OverlayModeHandler) AddVNI(ctx context.Context, vni uint32, vlan uint16) error {
	if err := validateOverlayVNI(vni); err != nil {
		return err
	}
	if vlan == 0 || vlan > 4094 {
		return ErrVLANOutOfRange
	}
	if vni == h.config.L3VNI {
		return &ErrVNIOperationFailed{VNI: vni, Operation: "add", Cause: ErrVNIAlreadyExists}
	}

	h.opMu.Lock()
	defer h.opMu.Unlock()

	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return ErrNotRunning
	}
	if _, ok := h.segments[vni]; ok {
		h.mu.Unlock()
		return ErrVNIAlreadyExists
	}
	if _, ok := h.vlans[vlan]; ok {
		h.mu.Unlock()
		return ErrVLANInUse
	}
	segment := &overlaySegment{vlan: vlan}
	segment.flows = h.builder.segment(vni, segment)
	if err := h.apply(ctx, nil, segment.flows); err != nil {
		h.mu.Unlock()
		return &ErrVNIOperationFailed{VNI: vni, Operation: "install", Cause: err}
	}
	h.segments[vni] = segment
	h.vlans[vlan] = vni
	h.mu.Unlock()

	if h.evpnManager == nil {
		return nil
	}
	if err := h.evpnManager.JoinVNI(ctx, vni, h.config.L3VNI); err != nil {
		h.mu.Lock()
		if removeErr := h.removeSegmentAndPeers(ctx, vni); removeErr != nil {
			h.logger.Error("removing a VNI EVPN refused", slog.Uint64("vni", uint64(vni)), slog.Any("error", removeErr))
		}
		h.mu.Unlock()
		return &ErrVNIOperationFailed{VNI: vni, Operation: "join", Cause: err}
	}
	if err := h.originateSubnet(ctx, vni); err != nil {
		if leaveErr := h.leaveVNI(ctx, vni); leaveErr != nil {
			h.logger.Error("leaving a VNI whose subnet EVPN refused", slog.Uint64("vni", uint64(vni)), slog.Any("error", leaveErr))
		}
		h.mu.Lock()
		if removeErr := h.removeSegmentAndPeers(ctx, vni); removeErr != nil {
			h.logger.Error("removing a VNI whose subnet EVPN refused", slog.Uint64("vni", uint64(vni)), slog.Any("error", removeErr))
		}
		h.mu.Unlock()
		return &ErrVNIOperationFailed{VNI: vni, Operation: "originate", Cause: err}
	}
	return nil
}

// originatedSubnet is the subnet vni originates as a Type-5 route: only a
// routed VNI does, and only with an L3VNI.
func (h *OverlayModeHandler) originatedSubnet(vni uint32) (netip.Prefix, bool) {
	if h.config.L3VNI == 0 {
		return netip.Prefix{}, false
	}
	subnet, ok := h.config.Subnets[vni]
	return subnet, ok
}

// originateSubnet advertises vni's subnet in the IP-VRF of the L3VNI.
func (h *OverlayModeHandler) originateSubnet(ctx context.Context, vni uint32) error {
	subnet, ok := h.originatedSubnet(vni)
	if !ok {
		return nil
	}
	return h.evpnManager.AdvertisePrefix(ctx, h.config.L3VNI, subnet)
}

// withdrawSubnet withdraws the Type-5 route originateSubnet advertised for
// vni; a subnet that is not advertised is no error.
func (h *OverlayModeHandler) withdrawSubnet(ctx context.Context, vni uint32) error {
	subnet, ok := h.originatedSubnet(vni)
	if !ok {
		return nil
	}
	err := h.evpnManager.WithdrawPrefix(ctx, h.config.L3VNI, subnet)
	var notJoined bgp.ErrVNINotJoined
	var notFound bgp.ErrPrefixNotFound
	if err == nil || errors.As(err, &notJoined) || errors.As(err, &notFound) {
		return nil
	}
	return &ErrVNIOperationFailed{VNI: vni, Operation: "withdraw", Cause: err}
}

// RemoveVNI takes this VTEP off an L2VNI and removes everything forwarded
// on it. The last VNI takes the Type-5 prefixes with it: EVPN drops the
// IP-VRF with its last member.
func (h *OverlayModeHandler) RemoveVNI(ctx context.Context, vni uint32) error {
	h.opMu.Lock()
	defer h.opMu.Unlock()

	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return ErrNotRunning
	}
	if _, ok := h.segments[vni]; !ok {
		h.mu.Unlock()
		return ErrVNINotFound
	}
	h.mu.Unlock()

	var errs []error
	if h.evpnManager != nil {
		if err := h.leaveVNI(ctx, vni); err != nil {
			errs = append(errs, err)
		}
	}

	h.mu.Lock()
	flood := h.segments[vni].flood
	if err := h.removeSegment(ctx, vni); err != nil {
		errs = append(errs, &ErrVNIOperationFailed{VNI: vni, Operation: "remove", Cause: err})
	} else {
		errs = append(errs, h.releaseHeld(ctx), h.withdrawFloodPeers(ctx, vni, flood))
	}
	h.mu.Unlock()
	return errors.Join(errs...)
}

// leaveVNI takes this VTEP off a VNI in EVPN, which withdraws the VNI's
// routes, those whose withdrawal BGP refused before included, and first
// the Type-5 route of its subnet. A VNI
// already left — by a removal whose flows the switch then refused — is not
// an error, so the removal can be retried and Stop still completes.
// Caller holds opMu.
func (h *OverlayModeHandler) leaveVNI(ctx context.Context, vni uint32) error {
	withdrawErr := h.withdrawSubnet(ctx, vni)
	err := h.evpnManager.LeaveVNI(ctx, vni)
	var notJoined bgp.ErrVNINotJoined
	if err == nil || errors.As(err, &notJoined) {
		maps.DeleteFunc(h.unwithdrawn, func(key hostKey, _ map[netip.Addr]struct{}) bool { return key.vni == vni })
		return withdrawErr
	}
	return errors.Join(withdrawErr, &ErrVNIOperationFailed{VNI: vni, Operation: "leave", Cause: err})
}

// removeSegment removes a VNI's flows and hosts, and the prefixes with
// the last VNI. Caller holds mu.
func (h *OverlayModeHandler) removeSegment(ctx context.Context, vni uint32) error {
	segment := h.segments[vni]
	release := slices.Clone(segment.flows)
	var hosts []hostKey
	for key, host := range h.hosts {
		if key.vni == vni {
			release = append(release, host.flows...)
			hosts = append(hosts, key)
		}
	}
	last := len(h.segments) == 1
	if last {
		for _, prefix := range h.prefixes {
			release = append(release, prefix.flows...)
		}
	}
	if err := h.apply(ctx, release, nil); err != nil {
		return err
	}
	var targets []ndKey
	for _, key := range hosts {
		targets = append(targets, h.indexND(key, h.hosts[key], nil)...)
		delete(h.hosts, key)
	}
	h.syncNDPunts(ctx, targets)
	if last {
		clear(h.prefixes)
	}
	delete(h.vlans, segment.vlan)
	delete(h.segments, vni)
	return nil
}

// removeSegmentAndPeers removes a VNI's segment, then withdraws each VTEP
// on its flood list from FloodPeers. Caller holds mu.
func (h *OverlayModeHandler) removeSegmentAndPeers(ctx context.Context, vni uint32) error {
	flood := h.segments[vni].flood
	if err := h.removeSegment(ctx, vni); err != nil {
		return err
	}
	return h.withdrawFloodPeers(ctx, vni, flood)
}

// withdrawFloodPeers tells FloodPeers that each VTEP of flood left vni, as
// the Type-3 withdrawal BGP would have sent. Every VTEP is tried and the
// failures are joined. Caller holds mu.
func (h *OverlayModeHandler) withdrawFloodPeers(ctx context.Context, vni uint32, flood []netip.Addr) error {
	var errs []error
	for _, vtep := range flood {
		errs = append(errs, h.tellFloodPeers(ctx, &bgp.EVPNRouteData{
			Type:       bgp.EVPNTypeInclusiveMulticast,
			IMET:       &bgp.IMETEntry{VNI: vni, VTEPIP: vtep},
			NextHop:    vtep,
			IsWithdraw: true,
		}))
	}
	return errors.Join(errs...)
}

// LearnMAC records a host on the access port — its MAC alone, or a MAC/IP
// binding when ip is valid — and advertises it in EVPN. The host is
// forwarded to locally even when advertising fails; learning it again
// retries the advertisement.
func (h *OverlayModeHandler) LearnMAC(ctx context.Context, vni uint32, mac net.HardwareAddr, ip netip.Addr) error {
	if err := validateOverlayMAC(mac); err != nil {
		return err
	}

	h.opMu.Lock()
	defer h.opMu.Unlock()

	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return ErrNotRunning
	}
	segment, ok := h.segments[vni]
	if !ok {
		h.mu.Unlock()
		return ErrVNINotFound
	}
	key := hostKey{vni: vni, mac: mac.String()}
	old := h.hosts[key]
	next := &overlayHost{mac: slices.Clone(mac), ips: make(map[netip.Addr]irbBinding), updatedAt: time.Now()}
	if old != nil && old.local() {
		maps.Copy(next.ips, old.ips)
	}
	next.ips[ip] = irbBinding{}
	if err := h.replaceHost(ctx, key, segment, old, next); err != nil {
		h.mu.Unlock()
		return &ErrMACOperationFailed{MAC: mac, Operation: "learn", Cause: err}
	}
	h.mu.Unlock()

	if h.evpnManager == nil {
		return nil
	}
	if err := h.evpnManager.AdvertiseMACIP(ctx, &bgp.MACIPEntry{MAC: mac, IP: ip, VNI: vni}); err != nil {
		return &ErrMACOperationFailed{MAC: mac, Operation: "advertise", Cause: err}
	}
	h.settleWithdrawal(key, ip)
	return nil
}

// ForgetMAC removes a host from the access port and withdraws its routes.
// A remote VTEP still advertising the MAC takes it over. A withdrawal BGP
// refuses is remembered: forgetting the MAC again, once the host is gone,
// tries it again, and RemoveVNI or Stop withdraws it with the VNI.
func (h *OverlayModeHandler) ForgetMAC(ctx context.Context, vni uint32, mac net.HardwareAddr) error {
	if err := validateOverlayMAC(mac); err != nil {
		return err
	}

	h.opMu.Lock()
	defer h.opMu.Unlock()

	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return ErrNotRunning
	}
	key := hostKey{vni: vni, mac: mac.String()}
	withdraw := maps.Clone(h.unwithdrawn[key])
	host, ok := h.hosts[key]
	local := ok && host.local()
	if !local && len(withdraw) == 0 {
		h.mu.Unlock()
		return ErrMACNotFound
	}
	var errs []error
	if local {
		if err := h.replaceHost(ctx, key, nil, host, nil); err != nil {
			h.mu.Unlock()
			return &ErrMACOperationFailed{MAC: mac, Operation: "forget", Cause: err}
		}
		errs = append(errs, h.releaseHeld(ctx))
		if withdraw == nil {
			withdraw = make(map[netip.Addr]struct{}, len(host.ips))
		}
		for ip := range host.ips {
			withdraw[ip] = struct{}{}
		}
	}
	h.mu.Unlock()

	if h.evpnManager == nil {
		return errors.Join(errs...)
	}
	for ip := range withdraw {
		if err := h.withdrawLocal(ctx, key, mac, ip); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// withdrawLocal withdraws the Type-2 route of a forgotten local binding.
// A withdrawal BGP refuses is kept in unwithdrawn for the next ForgetMAC
// of the MAC; one EVPN no longer holds is done. Caller holds opMu.
func (h *OverlayModeHandler) withdrawLocal(ctx context.Context, key hostKey, mac net.HardwareAddr, ip netip.Addr) error {
	err := h.evpnManager.WithdrawMACIP(ctx, key.vni, mac, ip)
	var notAdvertised bgp.ErrMACIPNotFound
	if err == nil || errors.As(err, &notAdvertised) {
		h.settleWithdrawal(key, ip)
		return nil
	}
	if h.unwithdrawn[key] == nil {
		h.unwithdrawn[key] = make(map[netip.Addr]struct{})
	}
	h.unwithdrawn[key][ip] = struct{}{}
	return &ErrMACOperationFailed{MAC: mac, Operation: "withdraw", Cause: err}
}

// settleWithdrawal forgets a pending withdrawal, once BGP took it or the
// binding was advertised again. Caller holds opMu.
func (h *OverlayModeHandler) settleWithdrawal(key hostKey, ip netip.Addr) {
	delete(h.unwithdrawn[key], ip)
	if len(h.unwithdrawn[key]) == 0 {
		delete(h.unwithdrawn, key)
	}
}

// replaceHost swaps a host's flows for its next state; a nil next removes
// it. Caller holds mu.
func (h *OverlayModeHandler) replaceHost(ctx context.Context, key hostKey, segment *overlaySegment, old, next *overlayHost) error {
	var release, acquire []*openflow.FlowMod
	if old != nil {
		release = old.flows
	}
	if next != nil {
		next.flows = h.builder.host(key.vni, segment.vlan, next)
		acquire = next.flows
	}
	if err := h.apply(ctx, release, acquire); err != nil {
		return err
	}
	targets := h.indexND(key, old, next)
	if next == nil {
		delete(h.hosts, key)
	} else {
		h.hosts[key] = next
	}
	h.syncNDPunts(ctx, targets)
	return nil
}

// LookupMAC returns the entry of a MAC on a VNI.
func (h *OverlayModeHandler) LookupMAC(vni uint32, mac net.HardwareAddr) (*MACEntry, error) {
	if err := validateOverlayMAC(mac); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	host, ok := h.hosts[hostKey{vni: vni, mac: mac.String()}]
	if !ok {
		return nil, ErrMACNotFound
	}
	entry := &MACEntry{
		MAC:       slices.Clone(host.mac),
		IPs:       host.sortedIPs(),
		VNI:       vni,
		VTEPIP:    host.vtep,
		Source:    MACSourceRemote,
		UpdatedAt: host.updatedAt,
	}
	if host.local() {
		entry.Source = MACSourceLocal
	}
	return entry, nil
}

// GetStatus returns the overlay's current status.
func (h *OverlayModeHandler) GetStatus() *OverlayModeStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	status := &OverlayModeStatus{
		Running:                  h.running,
		LocalVTEP:                h.config.VTEPConfig.LocalIP,
		VNICount:                 len(h.segments),
		PrefixCount:              len(h.prefixes),
		RefusedBindings:          h.refusedBindings,
		L3VNI:                    h.config.L3VNI,
		ARPSuppressionEnabled:    h.config.ARPSuppression,
		NDSuppression:            h.ndStatus(),
		AnycastGatewayConfigured: len(h.config.AnycastGateways) > 0,
	}
	vteps := make(map[netip.Addr]struct{})
	for _, segment := range h.segments {
		for _, vtep := range segment.flood {
			vteps[vtep] = struct{}{}
		}
	}
	status.RemoteVTEPCount = len(vteps)
	for _, host := range h.hosts {
		if host.local() {
			status.LocalMACCount++
		} else {
			status.RemoteMACCount++
		}
	}
	if h.running {
		status.StartedAt = h.startedAt
		status.Uptime = time.Since(h.startedAt)
	}
	return status
}

// apply moves the switch and the flow table from one set of an object's
// flows to the next. A switch can apply part of a batch and refuse the
// rest, so when it refuses anything apply puts back every flow the batch
// touched and leaves the table as it was. Caller holds mu.
func (h *OverlayModeHandler) apply(ctx context.Context, release, acquire []*openflow.FlowMod) error {
	// The caller built its flows on the port numbers from before the
	// reconnect; they go on once the ND watch has regenerated the table.
	if h.remap {
		return ErrSwitchNotRestored
	}
	if h.drifted {
		if err := h.rebuild(ctx); err != nil {
			return err
		}
	}
	plan, err := h.flows.plan(release, acquire)
	if err != nil {
		return err
	}
	if err := h.ofClient.SendFlowMods(ctx, plan.mods); err != nil {
		return h.resync(ctx, err, plan.restore)
	}
	plan.commit()
	return nil
}

// resync sends the mods that undo a refused batch and returns the batch's
// error, joined with an ErrFlowResyncFailed when the switch refuses those
// too and may now hold flows the table does not; the next change then
// rebuilds the switch first. Caller holds mu.
func (h *OverlayModeHandler) resync(ctx context.Context, cause error, restore []*openflow.FlowMod) error {
	err := h.ofClient.SendFlowMods(ctx, restore)
	if err == nil {
		return cause
	}
	h.drifted = true
	h.logger.Error("overlay flows could not be restored after a refused change; the next change rebuilds them",
		slog.Any("cause", cause), slog.Any("error", err))
	return errors.Join(cause, &ErrFlowResyncFailed{Cause: err})
}

// rebuild flushes the overlay's flows from the switch and installs every
// flow the table holds, in fail-closed order, for a switch that may hold
// flows the table does not. It stays due until the switch takes it. Due a
// remap, it regenerates the table first; while the ports do not resolve,
// it only flushes, since a flow on a stale port number can deliver to the
// wrong port. Caller holds mu.
func (h *OverlayModeHandler) rebuild(ctx context.Context) error {
	if h.remap {
		if err := h.remapPorts(ctx); err != nil {
			if flushErr := h.ofClient.SendFlowMods(ctx, overlayFlush()); flushErr != nil {
				return errors.Join(err, &ErrFlowResyncFailed{Cause: flushErr})
			}
			return err
		}
	}
	mods := append(overlayFlush(), h.flows.installed()...)
	if err := h.ofClient.SendFlowMods(ctx, mods); err != nil {
		return &ErrFlowResyncFailed{Cause: err}
	}
	h.drifted = false
	h.staleSweepAt = time.Time{}
	h.logger.Info("overlay flows rebuilt from the committed state")
	return nil
}

// overlayFlush deletes every overlay flow in every table, of every
// generation, and those an older release left under legacyOverlayCookie.
func overlayFlush() []*openflow.FlowMod {
	f := openflow.NewFlowMod(0)
	f.Command = openflow.OFPFCDelete
	f.TableID = openflow.OFPTTAll
	f.Cookie = OverlayCookie
	f.CookieMask = ovs.OwnerCookieMask
	return []*openflow.FlowMod{f, generationDelete(legacyOverlayCookie)}
}

// generationDelete deletes, from every table, the flows of one overlay
// generation.
func generationDelete(cookie uint64) *openflow.FlowMod {
	f := openflow.NewFlowMod(0)
	f.Command = openflow.OFPFCDelete
	f.TableID = openflow.OFPTTAll
	f.Cookie = cookie
	f.CookieMask = ^uint64(0)
	return f
}

// validateOverlayVNI checks a VNI is a non-zero 24-bit value.
func validateOverlayVNI(vni uint32) error {
	if vni == 0 || vni > 0xFFFFFF {
		return ErrVNIOutOfRange
	}
	return nil
}

// validateOverlayMAC checks a MAC is a 6-byte address.
func validateOverlayMAC(mac net.HardwareAddr) error {
	if mac == nil {
		return ErrMACNil
	}
	if len(mac) != 6 {
		return ErrMACInvalid
	}
	return nil
}
