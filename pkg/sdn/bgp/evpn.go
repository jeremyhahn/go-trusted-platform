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

package bgp

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// EVPNSpeaker is the BGP speaker the EVPN manager originates into and
// learns from. *Speaker implements it: routes go into the global RIB with
// explicit RDs and RTs, never into a GoBGP VRF.
type EVPNSpeaker interface {
	// AddPath originates a path into the global RIB.
	AddPath(ctx context.Context, path *Path) error

	// DeletePath withdraws a path from the global RIB.
	DeletePath(ctx context.Context, path *Path) error

	// WatchEvent streams best-path changes.
	WatchEvent(ctx context.Context, opts ...WatchOption) (<-chan *Event, error)
}

// EVPNRouteHandler is told of every change to an imported remote route.
// Type-2 notifications follow MAC Mobility: an add names where the MAC now
// is, a withdrawal a binding gone from there — the last one, the MAC.
// Type-3 notifications are a VTEP joining or leaving a VNI.
//
// Handlers are called one notification at a time, in the order the changes
// were made: on the manager's event goroutine for received routes, and
// synchronously from JoinVNI and WithdrawMACIP for the routes those calls
// import or hand over. No lock the manager's lookups need is held, but a
// handler must not call JoinVNI, LeaveVNI or WithdrawMACIP. The route is
// the handler's own copy.
type EVPNRouteHandler func(ctx context.Context, route *EVPNRouteData) error

// EVPNManagerConfig configures an EVPN manager.
type EVPNManagerConfig struct {
	// Speaker is the BGP speaker; required.
	Speaker EVPNSpeaker

	// Logger is required.
	Logger *slog.Logger

	// LocalVTEP is this VTEP's IPv4 tunnel address: the next hop of every
	// route and the administrator of every RD it originates.
	LocalVTEP netip.Addr

	// OverlayASN is the private 2-octet ASN route targets are derived from.
	OverlayASN uint16

	// DomainID is the 4-bit site field of the derived route targets.
	DomainID uint8

	// RouterMAC is the VTEP's router MAC for symmetric IRB; required to
	// join a VNI with an L3VNI.
	RouterMAC net.HardwareAddr

	// Mobility tunes duplicate-MAC detection.
	Mobility MobilityConfig

	// Clock returns the current time; nil is time.Now.
	Clock func() time.Time
}

// Validate checks the configuration.
func (c *EVPNManagerConfig) Validate() error {
	if c.Speaker == nil {
		return ErrSpeakerNil
	}
	if c.Logger == nil {
		return ErrLoggerNil
	}
	if !c.LocalVTEP.Is4() || c.LocalVTEP.IsUnspecified() {
		return ErrInvalidIP{IP: c.LocalVTEP, Reason: "the local VTEP must be an IPv4 address: it administers Type-1 RDs"}
	}
	if _, err := AutoRouteTarget(c.OverlayASN, c.DomainID, MinVNI); err != nil {
		return err
	}
	if c.RouterMAC != nil {
		if err := validateUnicastMAC(c.RouterMAC); err != nil {
			return err
		}
	}
	return nil
}

// macKey names one MAC in one VNI.
type macKey struct {
	vni uint32
	mac string
}

// ipKey names one IP in one VNI.
type ipKey struct {
	vni uint32
	ip  netip.Addr
}

// bindingKey names one local MAC/IP binding.
type bindingKey struct {
	vni uint32
	mac string
	ip  netip.Addr
}

// evi is a joined L2VNI: its MAC-VRF's RD and RT, and its IP-VRF. An EVI
// is joined once its Type-3 route is advertised; until then it imports
// nothing and is not joined to callers.
type evi struct {
	l3vni  uint32
	rd     RouteDistinguisher
	rt     RouteTarget
	joined bool
	// ready is closed once the join that created the EVI has its outcome:
	// joined, or rolled back.
	ready chan struct{}
}

// ipVRF is the IP-VRF of an L3VNI, shared by every EVI that names it. It
// imports Type-5 routes while at least one of its EVIs is joined.
type ipVRF struct {
	rd       RouteDistinguisher
	rt       RouteTarget
	members  int
	joined   int
	prefixes map[netip.Prefix]struct{}
}

// evpnChanges is what processing one received route produced, acted on
// once the lock is released.
type evpnChanges struct {
	notify   []*EVPNRouteData
	withdraw []*EVPNRouteData
}

// EVPNManager runs the EVPN control plane of one VTEP: it originates the
// VTEP's Type-2, Type-3 and Type-5 routes and imports the remote ones whose
// route targets it derives, resolving MAC Mobility as they arrive.
type EVPNManager struct {
	config  EVPNManagerConfig
	speaker EVPNSpeaker
	logger  *slog.Logger
	clock   func() time.Time

	// notifyMu orders handler notifications: whatever changes imported
	// state holds it from the change until the handlers have been told,
	// so they are told every change in the order it was made. It is taken
	// before mu and never held across a call to the speaker that waits on
	// the event loop.
	notifyMu sync.Mutex

	mu       sync.Mutex
	rds      *rdAllocator
	evis     map[uint32]*evi
	ipVRFs   map[uint32]*ipVRF
	received map[string]*EVPNRouteData
	macs     map[macKey]*macState
	ipToMAC  map[ipKey]net.HardwareAddr
	vteps    map[uint32]map[netip.Addr]int
	handlers []EVPNRouteHandler
	// unwithdrawn is the local Type-2 routes released whose withdrawal
	// BGP refused; WithdrawMACIP again or LeaveVNI withdraws them.
	unwithdrawn map[bindingKey]*EVPNRouteData

	started atomic.Bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewEVPNManager creates an EVPN manager.
func NewEVPNManager(config *EVPNManagerConfig) (*EVPNManager, error) {
	if config == nil {
		return nil, ErrEntryNil{EntryType: "EVPNManagerConfig"}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	cfg := *config
	cfg.Mobility = cfg.Mobility.withDefaults()
	cfg.RouterMAC = cloneMAC(cfg.RouterMAC)
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &EVPNManager{
		config:   cfg,
		speaker:  cfg.Speaker,
		logger:   cfg.Logger,
		clock:    clock,
		rds:      newRDAllocator(cfg.LocalVTEP),
		evis:     make(map[uint32]*evi),
		ipVRFs:   make(map[uint32]*ipVRF),
		received: make(map[string]*EVPNRouteData),
		macs:     make(map[macKey]*macState),
		ipToMAC:  make(map[ipKey]net.HardwareAddr),
		vteps:    make(map[uint32]map[netip.Addr]int),

		unwithdrawn: make(map[bindingKey]*EVPNRouteData),
	}, nil
}

// Start subscribes to the speaker's EVPN best paths and processes them
// until Stop.
func (m *EVPNManager) Start(ctx context.Context) error {
	if !m.started.CompareAndSwap(false, true) {
		return ErrManagerAlreadyStarted
	}
	watchCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	events, err := m.speaker.WatchEvent(watchCtx, WithPathChanges(), WithFamilies(AFamilyEVPN))
	if err != nil {
		cancel()
		m.started.Store(false)
		return err
	}
	m.cancel = cancel
	m.done = make(chan struct{})
	go m.run(watchCtx, events)
	return nil
}

// Stop ends the subscription and waits for the event goroutine, or for ctx.
func (m *EVPNManager) Stop(ctx context.Context) error {
	if !m.started.CompareAndSwap(true, false) {
		return ErrManagerNotStarted
	}
	m.cancel()
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RegisterHandler adds a handler for imported route changes.
func (m *EVPNManager) RegisterHandler(handler EVPNRouteHandler) {
	if handler == nil {
		return
	}
	m.mu.Lock()
	m.handlers = append(m.handlers, handler)
	m.mu.Unlock()
}

// run processes events until the watch ends.
func (m *EVPNManager) run(ctx context.Context, events <-chan *Event) {
	defer close(m.done)
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			if event == nil || event.Path == nil || event.Path.EVPN == nil {
				continue
			}
			m.process(ctx, event.Path.EVPN)
		}
	}
}

// process applies one received route.
func (m *EVPNManager) process(ctx context.Context, route *EVPNRouteData) {
	if route.RD.Admin == m.config.LocalVTEP || (!route.IsWithdraw && route.NextHop == m.config.LocalVTEP) {
		return
	}
	route = route.Clone()
	route.ReceivedAt = m.clock()

	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	m.mu.Lock()
	changes := &evpnChanges{}
	old, had := m.received[route.Key()]
	// A refresh is a route sent again about the same thing and imported
	// alike: it updates the tables in place rather than leaving them.
	refresh := had && !route.IsWithdraw && indexKey(old) == indexKey(route) && m.imported(old) == m.imported(route)
	if had && !refresh {
		delete(m.received, old.Key())
		m.unindex(old, changes)
	}
	if !route.IsWithdraw {
		m.received[route.Key()] = route
		// A refreshed Type-3 route changes no VNI's membership.
		if !refresh || route.Type != EVPNTypeInclusiveMulticast {
			m.index(route, changes)
		}
	}
	handlers := slices.Clone(m.handlers)
	m.mu.Unlock()

	m.apply(ctx, changes, handlers)
}

// apply withdraws the local routes that lost a MAC and runs the handlers.
func (m *EVPNManager) apply(ctx context.Context, changes *evpnChanges, handlers []EVPNRouteHandler) {
	for _, route := range changes.withdraw {
		if err := m.speaker.DeletePath(ctx, evpnPath(route)); err != nil {
			m.logger.Error("withdrawing a displaced local route failed", "route", route.Key(), "error", err)
		}
	}
	for _, route := range changes.notify {
		for _, handler := range handlers {
			if err := handler(ctx, route.Clone()); err != nil {
				m.logger.Error("EVPN route handler failed", "route", route.Key(), "withdraw", route.IsWithdraw, "error", err)
			}
		}
	}
}

// indexKey is what a route says, apart from who sent it: what it is about
// and the VTEP it names. A replacement with another index key, a new next
// hop included, is a withdrawal of the old route and a new route.
func indexKey(route *EVPNRouteData) string {
	switch {
	case route.MACIP != nil:
		return "2|" + strconv.FormatUint(uint64(route.MACIP.VNI), 10) + "|" + route.MACIP.MAC.String() + "|" + route.MACIP.VTEPIP.String()
	case route.IMET != nil:
		return "3|" + strconv.FormatUint(uint64(route.IMET.VNI), 10) + "|" + route.IMET.VTEPIP.String()
	case route.PrefixData != nil:
		return "5|" + strconv.FormatUint(uint64(route.PrefixData.VNI), 10) + "|" + route.PrefixData.Prefix.String() + "|" + route.PrefixData.VTEPIP.String()
	}
	return ""
}

// imported reports whether a received route belongs to a joined VNI and
// carries that VNI's route target. Caller holds mu.
func (m *EVPNManager) imported(route *EVPNRouteData) bool {
	switch {
	case route.MACIP != nil:
		e, ok := m.joinedEVI(route.MACIP.VNI)
		return ok && route.hasRouteTarget(e.rt)
	case route.IMET != nil:
		e, ok := m.joinedEVI(route.IMET.VNI)
		return ok && route.hasRouteTarget(e.rt)
	case route.PrefixData != nil:
		v, ok := m.joinedVRF(route.PrefixData.VNI)
		return ok && route.hasRouteTarget(v.rt)
	}
	return false
}

// joinedEVI returns the EVI of a joined L2VNI. Caller holds mu.
func (m *EVPNManager) joinedEVI(l2vni uint32) (*evi, bool) {
	e, ok := m.evis[l2vni]
	if !ok || !e.joined {
		return nil, false
	}
	return e, true
}

// joinedVRF returns the IP-VRF of an L3VNI one of whose EVIs is joined.
// Caller holds mu.
func (m *EVPNManager) joinedVRF(l3vni uint32) (*ipVRF, bool) {
	vrf, ok := m.ipVRFs[l3vni]
	if !ok || vrf.joined == 0 {
		return nil, false
	}
	return vrf, true
}

// index takes an imported route into the tables. Caller holds mu.
func (m *EVPNManager) index(route *EVPNRouteData, changes *evpnChanges) {
	if !m.imported(route) {
		return
	}
	switch route.Type {
	case EVPNTypeMACIPAdvertisement:
		m.indexMACIP(m.irbScoped(route), changes)
	case EVPNTypeInclusiveMulticast:
		vteps := m.vteps[route.IMET.VNI]
		if vteps == nil {
			vteps = make(map[netip.Addr]int)
			m.vteps[route.IMET.VNI] = vteps
		}
		vteps[route.IMET.VTEPIP]++
		if vteps[route.IMET.VTEPIP] == 1 {
			changes.notify = append(changes.notify, route)
		}
	case EVPNTypeIPPrefix:
		changes.notify = append(changes.notify, route)
	}
}

// unindex removes a route from the tables. Caller holds mu.
func (m *EVPNManager) unindex(route *EVPNRouteData, changes *evpnChanges) {
	if !m.imported(route) {
		return
	}
	if route.Type == EVPNTypeMACIPAdvertisement {
		route = m.irbScoped(route)
	}
	withdrawn := route.Clone()
	withdrawn.IsWithdraw = true
	switch route.Type {
	case EVPNTypeMACIPAdvertisement:
		m.unindexMACIP(route, withdrawn, changes)
	case EVPNTypeInclusiveMulticast:
		vteps := m.vteps[route.IMET.VNI]
		if vteps[route.IMET.VTEPIP] == 0 {
			return
		}
		vteps[route.IMET.VTEPIP]--
		if vteps[route.IMET.VTEPIP] == 0 {
			delete(vteps, route.IMET.VTEPIP)
			changes.notify = append(changes.notify, withdrawn)
		}
	case EVPNTypeIPPrefix:
		changes.notify = append(changes.notify, withdrawn)
	}
}

// irbScoped returns an imported Type-2 route as the data plane takes it:
// its L3VNI label and router MAC name the EVI's IP-VRF only when the route
// also carries that IP-VRF's route target (RFC 9135 §5.1). Without it the
// MAC is bridged, not routed. Caller holds mu.
func (m *EVPNManager) irbScoped(route *EVPNRouteData) *EVPNRouteData {
	if route.MACIP.L3VNI == 0 && route.RouterMAC == nil {
		return route
	}
	if vrf, ok := m.ipVRFs[m.evis[route.MACIP.VNI].l3vni]; ok && route.hasRouteTarget(vrf.rt) {
		return route
	}
	bridged := route.Clone()
	bridged.MACIP.L3VNI = 0
	bridged.RouterMAC = nil
	return bridged
}

// indexMACIP applies MAC Mobility to an imported Type-2 route. Caller
// holds mu.
func (m *EVPNManager) indexMACIP(route *EVPNRouteData, changes *evpnChanges) {
	now := m.clock()
	key := macKey{vni: route.MACIP.VNI, mac: route.MACIP.MAC.String()}
	state := m.macs[key]
	if state == nil {
		state = newMACState()
		m.macs[key] = state
	}
	if state.frozen(now) {
		m.logger.Warn("ignoring a route for a duplicate MAC", "vni", key.vni, "mac", key.mac, "vtep", route.MACIP.VTEPIP)
		return
	}
	state.remotes[route.Key()] = route

	if state.local != nil {
		if !remoteBeatsLocal(route.MACIP.Sequence, route.MACIP.VTEPIP, state.local.seq, m.config.LocalVTEP) {
			// The other VTEP lost and withdraws its route (§15.1).
			return
		}
		changes.withdraw = append(changes.withdraw, m.localRoutes(key, state)...)
		m.dropLocalBindings(key, state)
		state.local = nil
	}

	best, _ := state.bestRemote()
	switch {
	case best != state.activeVTEP:
		m.promoteRemote(key, state, changes)
	case route.MACIP.VTEPIP == best:
		m.bindIP(key, route)
		changes.notify = append(changes.notify, route)
	}
}

// unindexMACIP removes a withdrawn Type-2 route and moves the MAC to the
// next best VTEP, or reports it gone. Caller holds mu.
func (m *EVPNManager) unindexMACIP(route, withdrawn *EVPNRouteData, changes *evpnChanges) {
	key := macKey{vni: route.MACIP.VNI, mac: route.MACIP.MAC.String()}
	state := m.macs[key]
	if state == nil {
		return
	}
	if _, ok := state.remotes[route.Key()]; !ok {
		return
	}
	delete(state.remotes, route.Key())
	if route.MACIP.IP.IsValid() && route.MACIP.VTEPIP == state.activeVTEP {
		delete(m.ipToMAC, ipKey{vni: key.vni, ip: route.MACIP.IP})
	}
	if route.MACIP.VTEPIP == state.activeVTEP {
		best, _ := state.bestRemote()
		switch {
		case !best.IsValid():
			state.activeVTEP = netip.Addr{}
			changes.notify = append(changes.notify, withdrawn)
		case best != state.activeVTEP:
			state.activeVTEP = best
			state.location = best
			for _, active := range state.routesAt(best) {
				m.bindIP(key, active)
				changes.notify = append(changes.notify, active)
			}
		default:
			// The MAC stays at the VTEP, without this route's binding.
			changes.notify = append(changes.notify, withdrawn)
		}
	}
	if state.idle(m.clock()) {
		delete(m.macs, key)
	}
}

// bindIP records the IP of a Type-2 route for ARP suppression. Caller
// holds mu.
func (m *EVPNManager) bindIP(key macKey, route *EVPNRouteData) {
	if route.MACIP.IP.IsValid() {
		m.ipToMAC[ipKey{vni: key.vni, ip: route.MACIP.IP}] = route.MACIP.MAC
	}
}

// dropLocalBindings forgets the IPs of a local MAC. Caller holds mu.
func (m *EVPNManager) dropLocalBindings(key macKey, state *macState) {
	for ip := range state.local.ips {
		if ip.IsValid() {
			delete(m.ipToMAC, ipKey{vni: key.vni, ip: ip})
		}
	}
}

// JoinVNI places this VTEP on an L2VNI: it assigns the EVI its RD, imports
// its route target, advertises its Type-3 route and takes in the routes
// already received for it. A non-zero l3vni attaches the EVI to that
// IP-VRF for symmetric IRB. Joining again with the same L3VNI is a no-op.
// The VNI is joined, and imports routes, once its Type-3 route is
// advertised. A join made while another waits on BGP waits for its
// outcome (or ctx): it returns nil once the VNI is joined, and tries
// itself when the other join was rolled back.
func (m *EVPNManager) JoinVNI(ctx context.Context, l2vni, l3vni uint32) error {
	if err := validateVNI(l2vni); err != nil {
		return err
	}
	if l3vni != 0 {
		if err := validateVNI(l3vni); err != nil {
			return err
		}
		if l3vni == l2vni {
			return ErrInvalidVNI{VNI: l3vni, Reason: "the L3VNI must differ from the L2VNI"}
		}
		if err := validateUnicastMAC(m.config.RouterMAC); err != nil {
			return err
		}
	}

	m.mu.Lock()
	for {
		existing, ok := m.evis[l2vni]
		if !ok {
			break
		}
		if existing.l3vni != l3vni {
			m.mu.Unlock()
			return ErrInvalidVNI{VNI: l2vni, Reason: "already joined with another L3VNI"}
		}
		if existing.joined {
			m.mu.Unlock()
			return nil
		}
		// Another join waits on BGP: its outcome is this one's, and a
		// rolled-back join leaves the VNI for this one to try.
		m.mu.Unlock()
		select {
		case <-existing.ready:
		case <-ctx.Done():
			return ctx.Err()
		}
		m.mu.Lock()
	}
	e, err := m.addEVI(l2vni, l3vni)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	imet := &EVPNRouteData{
		Type:         EVPNTypeInclusiveMulticast,
		RD:           e.rd,
		RouteTargets: []RouteTarget{e.rt},
		IMET:         &IMETEntry{VNI: l2vni, VTEPIP: m.config.LocalVTEP},
		NextHop:      m.config.LocalVTEP,
	}
	m.mu.Unlock()

	if err := m.speaker.AddPath(ctx, evpnPath(imet)); err != nil {
		m.mu.Lock()
		m.removeEVI(l2vni)
		close(e.ready)
		m.mu.Unlock()
		return ErrRouteAdvertisementFailed{RouteType: EVPNTypeInclusiveMulticast, Cause: err}
	}
	m.importEVI(ctx, l2vni, e)
	return nil
}

// importEVI marks an EVI joined and takes in the routes received for it,
// telling the handlers in order with every other change.
func (m *EVPNManager) importEVI(ctx context.Context, l2vni uint32, e *evi) {
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	m.mu.Lock()
	e.joined = true
	close(e.ready)
	if vrf, ok := m.ipVRFs[e.l3vni]; ok {
		vrf.joined++
	}
	changes := &evpnChanges{}
	for _, route := range m.receivedFor(l2vni, e.l3vni) {
		m.index(route, changes)
	}
	handlers := slices.Clone(m.handlers)
	m.mu.Unlock()

	m.apply(ctx, changes, handlers)
}

// addEVI records a joined EVI and its IP-VRF. Caller holds mu.
func (m *EVPNManager) addEVI(l2vni, l3vni uint32) (*evi, error) {
	rt, err := AutoRouteTarget(m.config.OverlayASN, m.config.DomainID, l2vni)
	if err != nil {
		return nil, err
	}
	rd, err := m.rds.allocate(rdInstance{vni: l2vni})
	if err != nil {
		return nil, err
	}
	if l3vni != 0 {
		vrf, ok := m.ipVRFs[l3vni]
		if !ok {
			vrfRT, err := AutoRouteTarget(m.config.OverlayASN, m.config.DomainID, l3vni)
			if err != nil {
				m.rds.release(rdInstance{vni: l2vni})
				return nil, err
			}
			vrfRD, err := m.rds.allocate(rdInstance{ipVRF: true, vni: l3vni})
			if err != nil {
				m.rds.release(rdInstance{vni: l2vni})
				return nil, err
			}
			vrf = &ipVRF{rd: vrfRD, rt: vrfRT, prefixes: make(map[netip.Prefix]struct{})}
			m.ipVRFs[l3vni] = vrf
		}
		vrf.members++
	}
	e := &evi{l3vni: l3vni, rd: rd, rt: rt, ready: make(chan struct{})}
	m.evis[l2vni] = e
	return e, nil
}

// receivedFor returns the received routes a new join imports. Caller holds
// mu.
func (m *EVPNManager) receivedFor(l2vni, l3vni uint32) []*EVPNRouteData {
	// The IP-VRF's Type-5 routes are already imported unless this is the
	// first of its EVIs to join.
	vrf, ok := m.ipVRFs[l3vni]
	firstOfVRF := ok && vrf.joined == 1
	var routes []*EVPNRouteData
	for _, route := range m.received {
		switch {
		case route.MACIP != nil && route.MACIP.VNI == l2vni,
			route.IMET != nil && route.IMET.VNI == l2vni,
			route.PrefixData != nil && firstOfVRF && route.PrefixData.VNI == l3vni:
			routes = append(routes, route)
		}
	}
	return routes
}

// LeaveVNI takes this VTEP off an L2VNI: it withdraws the EVI's Type-3 and
// local Type-2 routes, and the IP-VRF's Type-5 routes when no other EVI
// uses it, and forgets the remote routes it imported. The routes stay
// received, so a later join takes them in again.
func (m *EVPNManager) LeaveVNI(ctx context.Context, l2vni uint32) error {
	m.notifyMu.Lock()
	m.mu.Lock()
	var withdraw []*EVPNRouteData
	_, ok := m.joinedEVI(l2vni)
	if ok {
		withdraw, ok = m.removeEVI(l2vni)
	}
	m.mu.Unlock()
	m.notifyMu.Unlock()
	if !ok {
		return ErrVNINotJoined{VNI: l2vni}
	}
	var firstErr error
	for _, route := range withdraw {
		if err := m.speaker.DeletePath(ctx, evpnPath(route)); err != nil && firstErr == nil {
			firstErr = ErrRouteWithdrawalFailed{RouteType: route.Type, Cause: err}
		}
	}
	return firstErr
}

// removeEVI drops an EVI and everything imported into it, returning the
// local routes to withdraw. Caller holds mu.
func (m *EVPNManager) removeEVI(l2vni uint32) ([]*EVPNRouteData, bool) {
	e, ok := m.evis[l2vni]
	if !ok {
		return nil, false
	}
	withdraw := []*EVPNRouteData{{
		Type:         EVPNTypeInclusiveMulticast,
		RD:           e.rd,
		RouteTargets: []RouteTarget{e.rt},
		IMET:         &IMETEntry{VNI: l2vni, VTEPIP: m.config.LocalVTEP},
		NextHop:      m.config.LocalVTEP,
	}}
	for key, state := range m.macs {
		if key.vni != l2vni {
			continue
		}
		if state.local != nil {
			withdraw = append(withdraw, m.localRoutes(key, state)...)
		}
		delete(m.macs, key)
	}
	for key := range m.ipToMAC {
		if key.vni == l2vni {
			delete(m.ipToMAC, key)
		}
	}
	for key, route := range m.unwithdrawn {
		if key.vni == l2vni {
			withdraw = append(withdraw, route)
			delete(m.unwithdrawn, key)
		}
	}
	delete(m.vteps, l2vni)

	if vrf, ok := m.ipVRFs[e.l3vni]; ok {
		vrf.members--
		if e.joined {
			vrf.joined--
		}
		if vrf.members == 0 {
			for prefix := range vrf.prefixes {
				withdraw = append(withdraw, m.prefixRoute(e.l3vni, vrf, prefix))
			}
			m.rds.release(rdInstance{ipVRF: true, vni: e.l3vni})
			delete(m.ipVRFs, e.l3vni)
		}
	}
	m.rds.release(rdInstance{vni: l2vni})
	delete(m.evis, l2vni)
	return withdraw, true
}

// AdvertiseMACIP advertises a MAC, or a MAC/IP binding, learned on this
// VTEP. A MAC another VTEP advertises takes that VTEP's sequence number
// plus one (RFC 7432 §15.1); a duplicate MAC is refused while it is frozen.
// The entry's VTEP, L3VNI and sequence number are the manager's to set.
func (m *EVPNManager) AdvertiseMACIP(ctx context.Context, entry *MACIPEntry) error {
	if entry == nil {
		return ErrEntryNil{EntryType: "MACIPEntry"}
	}
	if err := validateUnicastMAC(entry.MAC); err != nil {
		return err
	}
	now := m.clock()
	key := macKey{vni: entry.VNI, mac: entry.MAC.String()}

	m.mu.Lock()
	e, ok := m.joinedEVI(entry.VNI)
	if !ok {
		m.mu.Unlock()
		return ErrVNINotJoined{VNI: entry.VNI}
	}
	state := m.macs[key]
	if state == nil {
		state = newMACState()
		m.macs[key] = state
	}
	if state.frozen(now) {
		m.mu.Unlock()
		return ErrDampeningActive
	}
	resequenced := false
	if state.local == nil {
		var seq uint32
		if best, bestSeq := state.bestRemote(); best.IsValid() {
			seq = bestSeq + 1
		}
		state.activeVTEP = netip.Addr{}
		if state.recordLocation(m.config.LocalVTEP, now, m.config.Mobility) {
			m.logger.Warn("duplicate MAC detected; frozen", "vni", key.vni, "mac", key.mac, "hold", m.config.Mobility.Hold)
			m.mu.Unlock()
			return ErrDampeningActive
		}
		state.local = &localMAC{mac: cloneMAC(entry.MAC), ips: make(map[netip.Addr]struct{}), seq: seq}
		resequenced = true
	}
	_, known := state.local.ips[entry.IP]
	state.local.ips[entry.IP] = struct{}{}
	if entry.IP.IsValid() {
		m.ipToMAC[ipKey{vni: entry.VNI, ip: entry.IP}] = cloneMAC(entry.MAC)
	}
	route := m.localRoute(entry.VNI, e, state.local, entry.IP)
	m.mu.Unlock()

	if err := m.speaker.AddPath(ctx, evpnPath(route)); err != nil {
		m.mu.Lock()
		if state.local != nil && !known {
			delete(state.local.ips, entry.IP)
			delete(m.ipToMAC, ipKey{vni: entry.VNI, ip: entry.IP})
			if resequenced && len(state.local.ips) == 0 {
				state.local = nil
			}
		}
		m.mu.Unlock()
		return ErrRouteAdvertisementFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: err}
	}
	m.mu.Lock()
	delete(m.unwithdrawn, bindingKey{vni: entry.VNI, mac: key.mac, ip: entry.IP})
	m.mu.Unlock()
	return nil
}

// WithdrawMACIP withdraws a local MAC, or MAC/IP binding; an invalid ip is
// the MAC-only route. A route BGP refused to withdraw is kept: calling
// WithdrawMACIP again, or LeaveVNI, withdraws it.
func (m *EVPNManager) WithdrawMACIP(ctx context.Context, vni uint32, mac net.HardwareAddr, ip netip.Addr) error {
	route, err := m.releaseMACIP(ctx, vni, mac, ip)
	if err != nil {
		return err
	}
	binding := bindingKey{vni: vni, mac: mac.String(), ip: ip}
	err = m.speaker.DeletePath(ctx, evpnPath(route))
	m.mu.Lock()
	if err != nil && !m.boundLocally(binding) {
		m.unwithdrawn[binding] = route
	} else {
		delete(m.unwithdrawn, binding)
	}
	m.mu.Unlock()
	if err != nil {
		return ErrRouteWithdrawalFailed{RouteType: EVPNTypeMACIPAdvertisement, Cause: err}
	}
	return nil
}

// releaseMACIP forgets a local binding and returns its route to withdraw.
// A MAC with no local binding left goes to the best remote VTEP still
// advertising it, and the handlers are told before the route is withdrawn,
// in order with every other change.
func (m *EVPNManager) releaseMACIP(ctx context.Context, vni uint32, mac net.HardwareAddr, ip netip.Addr) (*EVPNRouteData, error) {
	key := macKey{vni: vni, mac: mac.String()}

	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	m.mu.Lock()
	e, ok := m.joinedEVI(vni)
	state := m.macs[key]
	bound := ok && state != nil && state.local != nil
	if bound {
		_, bound = state.local.ips[ip]
	}
	if !bound {
		route, retry := m.unwithdrawn[bindingKey{vni: vni, mac: key.mac, ip: ip}]
		m.mu.Unlock()
		if retry {
			return route, nil
		}
		return nil, ErrMACIPNotFound{VNI: vni, MAC: mac, IP: ip}
	}
	route := m.localRoute(vni, e, state.local, ip)
	delete(state.local.ips, ip)
	if ip.IsValid() {
		delete(m.ipToMAC, ipKey{vni: vni, ip: ip})
	}
	changes := &evpnChanges{}
	if len(state.local.ips) == 0 {
		state.local = nil
		m.promoteRemote(key, state, changes)
	}
	if state.idle(m.clock()) {
		delete(m.macs, key)
	}
	handlers := slices.Clone(m.handlers)
	m.mu.Unlock()

	m.apply(ctx, changes, handlers)
	return route, nil
}

// boundLocally reports whether the binding is advertised from this VTEP,
// as it is again once AdvertiseMACIP runs alongside a withdrawal. The
// caller holds mu.
func (m *EVPNManager) boundLocally(binding bindingKey) bool {
	state := m.macs[macKey{vni: binding.vni, mac: binding.mac}]
	if state == nil || state.local == nil {
		return false
	}
	_, ok := state.local.ips[binding.ip]
	return ok
}

// promoteRemote hands a MAC this VTEP no longer has to the best remote VTEP
// still advertising it. Caller holds mu.
func (m *EVPNManager) promoteRemote(key macKey, state *macState, changes *evpnChanges) {
	best, _ := state.bestRemote()
	if !best.IsValid() {
		return
	}
	state.activeVTEP = best
	if state.recordLocation(best, m.clock(), m.config.Mobility) {
		m.logger.Warn("duplicate MAC detected; frozen", "vni", key.vni, "mac", key.mac, "hold", m.config.Mobility.Hold)
	}
	for _, active := range state.routesAt(best) {
		m.bindIP(key, active)
		changes.notify = append(changes.notify, active)
	}
}

// localRoute builds one of this VTEP's Type-2 routes. Symmetric IRB adds
// the IP-VRF's L3VNI, its route target and the router MAC. Caller holds mu.
func (m *EVPNManager) localRoute(vni uint32, e *evi, local *localMAC, ip netip.Addr) *EVPNRouteData {
	route := &EVPNRouteData{
		Type:         EVPNTypeMACIPAdvertisement,
		RD:           e.rd,
		RouteTargets: []RouteTarget{e.rt},
		MACIP: &MACIPEntry{
			MAC:      cloneMAC(local.mac),
			IP:       ip,
			VNI:      vni,
			VTEPIP:   m.config.LocalVTEP,
			Sequence: local.seq,
		},
		NextHop: m.config.LocalVTEP,
	}
	if vrf, ok := m.ipVRFs[e.l3vni]; ok {
		route.MACIP.L3VNI = e.l3vni
		route.RouteTargets = append(route.RouteTargets, vrf.rt)
		route.RouterMAC = cloneMAC(m.config.RouterMAC)
	}
	return route
}

// localRoutes builds every Type-2 route this VTEP advertises for a MAC.
// Caller holds mu.
func (m *EVPNManager) localRoutes(key macKey, state *macState) []*EVPNRouteData {
	e, ok := m.evis[key.vni]
	if !ok {
		return nil
	}
	routes := make([]*EVPNRouteData, 0, len(state.local.ips))
	for ip := range state.local.ips {
		routes = append(routes, m.localRoute(key.vni, e, state.local, ip))
	}
	return routes
}

// AdvertisePrefix advertises a prefix in the IP-VRF of an L3VNI as an
// interface-less Type-5 route.
func (m *EVPNManager) AdvertisePrefix(ctx context.Context, l3vni uint32, prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return ErrPrefixInvalid{Prefix: prefix, Reason: "the Type-5 prefix is invalid"}
	}
	prefix = prefix.Masked()
	m.mu.Lock()
	vrf, ok := m.joinedVRF(l3vni)
	if !ok {
		m.mu.Unlock()
		return ErrVNINotJoined{VNI: l3vni}
	}
	_, known := vrf.prefixes[prefix]
	vrf.prefixes[prefix] = struct{}{}
	route := m.prefixRoute(l3vni, vrf, prefix)
	m.mu.Unlock()

	if err := m.speaker.AddPath(ctx, evpnPath(route)); err != nil {
		if !known {
			m.mu.Lock()
			delete(vrf.prefixes, prefix)
			m.mu.Unlock()
		}
		return ErrRouteAdvertisementFailed{RouteType: EVPNTypeIPPrefix, Cause: err}
	}
	return nil
}

// WithdrawPrefix withdraws a Type-5 route.
func (m *EVPNManager) WithdrawPrefix(ctx context.Context, l3vni uint32, prefix netip.Prefix) error {
	prefix = prefix.Masked()
	m.mu.Lock()
	vrf, ok := m.joinedVRF(l3vni)
	if !ok {
		m.mu.Unlock()
		return ErrVNINotJoined{VNI: l3vni}
	}
	if _, ok := vrf.prefixes[prefix]; !ok {
		m.mu.Unlock()
		return ErrPrefixNotFound{VNI: l3vni, Prefix: prefix}
	}
	delete(vrf.prefixes, prefix)
	route := m.prefixRoute(l3vni, vrf, prefix)
	m.mu.Unlock()

	if err := m.speaker.DeletePath(ctx, evpnPath(route)); err != nil {
		return ErrRouteWithdrawalFailed{RouteType: EVPNTypeIPPrefix, Cause: err}
	}
	return nil
}

// prefixRoute builds one of this VTEP's Type-5 routes. Caller holds mu.
func (m *EVPNManager) prefixRoute(l3vni uint32, vrf *ipVRF, prefix netip.Prefix) *EVPNRouteData {
	return &EVPNRouteData{
		Type:         EVPNTypeIPPrefix,
		RD:           vrf.rd,
		RouteTargets: []RouteTarget{vrf.rt},
		PrefixData:   &PrefixRoute{Prefix: prefix, VNI: l3vni, VTEPIP: m.config.LocalVTEP},
		NextHop:      m.config.LocalVTEP,
		RouterMAC:    cloneMAC(m.config.RouterMAC),
	}
}

// LookupMACForIP returns the MAC bound to ip in vni, for ARP suppression.
func (m *EVPNManager) LookupMACForIP(vni uint32, ip netip.Addr) (net.HardwareAddr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mac, ok := m.ipToMAC[ipKey{vni: vni, ip: ip}]
	return cloneMAC(mac), ok
}

// RemoteMAC returns the remote VTEP a MAC is reached at.
func (m *EVPNManager) RemoteMAC(vni uint32, mac net.HardwareAddr) (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.macs[macKey{vni: vni, mac: mac.String()}]
	if state == nil || !state.activeVTEP.IsValid() {
		return netip.Addr{}, false
	}
	return state.activeVTEP, true
}

// RemoteVTEPs returns the remote VTEPs on a VNI, from their Type-3 routes:
// the VNI's ingress-replication list.
func (m *EVPNManager) RemoteVTEPs(vni uint32) []netip.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	vteps := make([]netip.Addr, 0, len(m.vteps[vni]))
	for vtep := range m.vteps[vni] {
		vteps = append(vteps, vtep)
	}
	slices.SortFunc(vteps, netip.Addr.Compare)
	return vteps
}

// RouteDistinguisher returns the RD of a joined L2VNI's EVI.
func (m *EVPNManager) RouteDistinguisher(l2vni uint32) (RouteDistinguisher, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rds.lookup(rdInstance{vni: l2vni})
}

// evpnPath wraps a route as a speaker path.
func evpnPath(route *EVPNRouteData) *Path {
	return &Path{Family: AFamilyEVPN, NextHop: route.NextHop, Origin: OriginIGP, EVPN: route}
}
