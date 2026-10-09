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
	TableARP           uint8 = 40 // ARP suppression
	TableL3Routing     uint8 = 50 // Symmetric IRB routing (anycast gateway)
	TableEgress        uint8 = 60 // BUM ingress replication
	TableLocalDelivery uint8 = 70 // Out the access port
)

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

// OverlayOVSClient is the OVSDB client the overlay needs: the flow-based
// VXLAN port, and the OpenFlow number of the access port.
type OverlayOVSClient interface {
	vxlan.OVSClient
}

// OverlayOpenFlowClient is the OpenFlow client the overlay programs.
type OverlayOpenFlowClient interface {
	// SendFlowMods sends flow mods as one batch, followed by one barrier.
	SendFlowMods(ctx context.Context, flows []*openflow.FlowMod) error
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

	// AnycastGatewayIP is the distributed anycast gateway's IPv4 address;
	// with AnycastGatewayMAC it turns on routing.
	AnycastGatewayIP netip.Addr

	// AnycastGatewayMAC is the distributed anycast gateway MAC.
	// This MAC is shared across all nodes for seamless L3 routing.
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
	anycast := c.AnycastGatewayIP.IsValid() || c.AnycastGatewayMAC != nil
	if anycast && (!c.AnycastGatewayIP.Is4() || len(c.AnycastGatewayMAC) != 6) {
		return ErrAnycastGatewayIncomplete
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
	// drifted is set when the switch refused a put-back and may hold
	// flows the table does not; the next change rebuilds the switch.
	drifted  bool
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

	if err := h.vtepManager.Start(ctx); err != nil {
		return &ErrOverlayStartFailed{Component: "VTEPManager", Cause: err}
	}
	builder, err := h.newBuilder(ctx)
	if err != nil {
		h.abortStart(ctx, false)
		return err
	}
	if h.evpnManager != nil {
		if err := h.evpnManager.Start(ctx); err != nil {
			h.abortStart(ctx, false)
			return &ErrOverlayStartFailed{Component: "EVPNManager", Cause: err}
		}
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

// installBase replaces whatever overlay flows the bridge holds with the
// base pipeline, in fail-closed order, and marks the handler running.
// Caller holds mu.
func (h *OverlayModeHandler) installBase(ctx context.Context, builder *flowBuilder) error {
	h.flows.reset()
	h.drifted = false
	plan, err := h.flows.plan(nil, builder.base())
	if err != nil {
		return err
	}
	if err := h.ofClient.SendFlowMods(ctx, append([]*openflow.FlowMod{overlayFlush()}, failClosed(plan.mods)...)); err != nil {
		return h.resync(ctx, err, []*openflow.FlowMod{overlayFlush()})
	}
	plan.commit()
	h.builder = builder
	h.running = true
	h.startedAt = time.Now()
	return nil
}

// newBuilder resolves the OpenFlow numbers of the VXLAN and access ports.
func (h *OverlayModeHandler) newBuilder(ctx context.Context) (*flowBuilder, error) {
	vxlanPort, err := h.vtepManager.OFPort()
	if err != nil {
		return nil, &ErrOverlayStartFailed{Component: "VXLANPort", Cause: err}
	}
	accessPort, err := h.ovsClient.GetOFPort(ctx, h.config.AccessPort)
	if err != nil {
		return nil, &ErrOverlayStartFailed{Component: "AccessPort", Cause: err}
	}
	if accessPort <= 0 {
		return nil, &ErrOverlayStartFailed{Component: "AccessPort", Cause: ErrAccessPortUnresolved}
	}
	builder, err := newFlowBuilder(h.config, overlayPorts{vxlan: vxlanPort, access: uint32(accessPort)})
	if err != nil {
		return nil, &ErrOverlayStartFailed{Component: "OpenFlow", Cause: err}
	}
	return builder, nil
}

// abortStart undoes a partial Start. Its own failures are logged: the
// start error is the one the caller reports.
func (h *OverlayModeHandler) abortStart(ctx context.Context, evpnStarted bool) {
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

	h.mu.Lock()
	if err := h.ofClient.SendFlowMods(ctx, []*openflow.FlowMod{overlayFlush()}); err != nil {
		errs = append(errs, &ErrFlowOperationFailed{Table: openflow.OFPTTAll, Operation: "delete", Cause: err})
	}
	h.flows.reset()
	clear(h.segments)
	clear(h.vlans)
	clear(h.hosts)
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
		if removeErr := h.removeSegment(ctx, vni); removeErr != nil {
			h.logger.Error("removing a VNI EVPN refused", slog.Uint64("vni", uint64(vni)), slog.Any("error", removeErr))
		}
		h.mu.Unlock()
		return &ErrVNIOperationFailed{VNI: vni, Operation: "join", Cause: err}
	}
	return nil
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
	if err := h.removeSegment(ctx, vni); err != nil {
		errs = append(errs, &ErrVNIOperationFailed{VNI: vni, Operation: "remove", Cause: err})
	} else if err := h.releaseHeld(ctx); err != nil {
		errs = append(errs, err)
	}
	h.mu.Unlock()
	return errors.Join(errs...)
}

// leaveVNI takes this VTEP off a VNI in EVPN, which withdraws the VNI's
// routes, those whose withdrawal BGP refused before included. A VNI
// already left — by a removal whose flows the switch then refused — is not
// an error, so the removal can be retried and Stop still completes.
// Caller holds opMu.
func (h *OverlayModeHandler) leaveVNI(ctx context.Context, vni uint32) error {
	err := h.evpnManager.LeaveVNI(ctx, vni)
	var notJoined bgp.ErrVNINotJoined
	if err == nil || errors.As(err, &notJoined) {
		maps.DeleteFunc(h.unwithdrawn, func(key hostKey, _ map[netip.Addr]struct{}) bool { return key.vni == vni })
		return nil
	}
	return &ErrVNIOperationFailed{VNI: vni, Operation: "leave", Cause: err}
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
	for _, key := range hosts {
		delete(h.hosts, key)
	}
	if last {
		clear(h.prefixes)
	}
	delete(h.vlans, segment.vlan)
	delete(h.segments, vni)
	return nil
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
	if next == nil {
		delete(h.hosts, key)
		return nil
	}
	h.hosts[key] = next
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
		AnycastGatewayConfigured: h.config.AnycastGatewayIP.IsValid(),
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
// flows the table does not. It stays due until the switch takes it.
// Caller holds mu.
func (h *OverlayModeHandler) rebuild(ctx context.Context) error {
	mods := append([]*openflow.FlowMod{overlayFlush()}, h.flows.installed()...)
	if err := h.ofClient.SendFlowMods(ctx, mods); err != nil {
		return &ErrFlowResyncFailed{Cause: err}
	}
	h.drifted = false
	h.logger.Info("overlay flows rebuilt from the committed state")
	return nil
}

// overlayFlush deletes every overlay flow in every table.
func overlayFlush() *openflow.FlowMod {
	f := openflow.NewFlowMod(0)
	f.Command = openflow.OFPFCDelete
	f.TableID = openflow.OFPTTAll
	f.Cookie = OverlayCookie
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
