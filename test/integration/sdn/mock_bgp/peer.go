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

//go:build integration

package mock_bgp

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

// MockBGPPeer represents a mock BGP peer for integration testing.
// It uses GoBGP to implement a real BGP speaker that can establish sessions,
// receive and send routes, and simulate various peer behaviors.
type MockBGPPeer struct {
	config  *MockBGPPeerConfig
	server  *server.BgpServer
	logger  *slog.Logger
	started atomic.Bool

	// Route storage
	receivedRoutes *RouteStore
	injectedRoutes *RouteStore

	// State tracking
	neighborStates   map[string]*NeighborState
	neighborStatesMu sync.RWMutex

	// Event channels
	stateChanges     []StateChangeEvent
	stateChangesMu   sync.RWMutex
	stateChangeCh    chan StateChangeEvent
	routeReceivedCh  chan *ReceivedRoute
	routeWithdrawnCh chan *ReceivedRoute

	// Shutdown coordination
	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

// NewMockBGPPeer creates a new mock BGP peer with the given configuration.
func NewMockBGPPeer(config *MockBGPPeerConfig, logger *slog.Logger) (*MockBGPPeer, error) {
	if config == nil {
		return nil, ErrNilConfig
	}
	if logger == nil {
		return nil, ErrNilLogger
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	peer := &MockBGPPeer{
		config:           config,
		logger:           logger,
		receivedRoutes:   NewRouteStore(),
		injectedRoutes:   NewRouteStore(),
		neighborStates:   make(map[string]*NeighborState),
		stateChanges:     make([]StateChangeEvent, 0),
		stateChangeCh:    make(chan StateChangeEvent, 100),
		routeReceivedCh:  make(chan *ReceivedRoute, 1000),
		routeWithdrawnCh: make(chan *ReceivedRoute, 1000),
		shutdownCh:       make(chan struct{}),
	}

	return peer, nil
}

// Start initializes and starts the mock BGP peer.
func (p *MockBGPPeer) Start(ctx context.Context) error {
	if p.started.Load() {
		return ErrPeerAlreadyStarted
	}

	p.logger.Info("starting mock BGP peer",
		slog.String("router_id", p.config.RouterID),
		slog.Uint64("asn", uint64(p.config.ASN)),
		slog.String("listen_addr", p.config.ListenAddr))

	// Create GoBGP server
	p.server = server.NewBgpServer()

	// Start server goroutine
	go p.server.Serve()

	// Parse listen address to get port
	listenPort := int32(179)
	if p.config.ListenAddr != "" {
		_, portStr, err := splitHostPort(p.config.ListenAddr)
		if err == nil && portStr != "" {
			port := parsePort(portStr)
			if port > 0 {
				listenPort = int32(port)
			}
		}
	}

	// Configure BGP global settings
	global := &api.Global{
		Asn:        p.config.ASN,
		RouterId:   p.config.RouterID,
		ListenPort: listenPort,
	}

	// Set listen addresses
	if p.config.ListenAddr != "" {
		host, _, _ := splitHostPort(p.config.ListenAddr)
		if host != "" {
			global.ListenAddresses = []string{host}
		}
	}

	// Configure graceful restart
	if p.config.GracefulRestartEnabled {
		global.GracefulRestart = &api.GracefulRestart{
			Enabled:     true,
			RestartTime: uint32(p.config.GracefulRestartTime),
		}
	}

	// Start BGP
	if err := p.server.StartBgp(ctx, &api.StartBgpRequest{Global: global}); err != nil {
		p.server.Stop()
		return &ErrServerOperationFailed{Operation: "start_bgp", Cause: err}
	}

	// Add configured neighbors
	for _, neighbor := range p.config.Neighbors {
		if err := p.addNeighbor(ctx, &neighbor); err != nil {
			p.logger.Warn("failed to add neighbor",
				slog.String("address", neighbor.Address),
				slog.Any("error", err))
		}
	}

	p.started.Store(true)

	// Start event watcher
	p.wg.Add(1)
	go p.watchEvents(ctx)

	p.logger.Info("mock BGP peer started successfully",
		slog.String("router_id", p.config.RouterID),
		slog.Uint64("asn", uint64(p.config.ASN)))

	return nil
}

// Stop gracefully shuts down the mock BGP peer.
func (p *MockBGPPeer) Stop(ctx context.Context) error {
	if !p.started.Load() {
		return ErrPeerNotStarted
	}

	p.logger.Info("stopping mock BGP peer")

	// Signal shutdown
	close(p.shutdownCh)

	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		p.logger.Warn("context canceled while waiting for goroutines")
	}

	// Stop BGP
	if err := p.server.StopBgp(ctx, &api.StopBgpRequest{}); err != nil {
		p.logger.Warn("error stopping BGP", slog.Any("error", err))
	}

	// Stop server
	p.server.Stop()
	p.started.Store(false)

	// Close channels
	close(p.stateChangeCh)
	close(p.routeReceivedCh)
	close(p.routeWithdrawnCh)

	p.logger.Info("mock BGP peer stopped")

	return nil
}

// IsStarted returns true if the peer is running.
func (p *MockBGPPeer) IsStarted() bool {
	return p.started.Load()
}

// Config returns the peer configuration.
func (p *MockBGPPeer) Config() *MockBGPPeerConfig {
	return p.config
}

// addNeighbor adds a BGP neighbor to the peer.
func (p *MockBGPPeer) addNeighbor(ctx context.Context, cfg *MockNeighborConfig) error {
	holdTime := uint64(90)
	if cfg.HoldTime > 0 {
		holdTime = uint64(cfg.HoldTime)
	}

	keepalive := uint64(30)
	if cfg.KeepaliveInterval > 0 {
		keepalive = uint64(cfg.KeepaliveInterval)
	}

	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: cfg.Address,
			PeerAsn:         cfg.ASN,
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				HoldTime:          holdTime,
				KeepaliveInterval: keepalive,
			},
		},
		Transport: &api.Transport{
			PassiveMode: cfg.PassiveMode,
		},
		AfiSafis: make([]*api.AfiSafi, 0),
	}

	// Configure address families
	families := cfg.EnabledFamilies
	if len(families) == 0 {
		families = p.config.EnabledFamilies
	}
	if len(families) == 0 {
		families = []AddressFamily{AFamilyIPv4Unicast}
	}

	for _, af := range families {
		afiSafi := &api.AfiSafi{
			Config: &api.AfiSafiConfig{
				Enabled: true,
			},
		}

		switch af {
		case AFamilyIPv4Unicast:
			afiSafi.Config.Family = &api.Family{
				Afi:  api.Family_AFI_IP,
				Safi: api.Family_SAFI_UNICAST,
			}
		case AFamilyIPv6Unicast:
			afiSafi.Config.Family = &api.Family{
				Afi:  api.Family_AFI_IP6,
				Safi: api.Family_SAFI_UNICAST,
			}
		case AFamilyEVPN:
			afiSafi.Config.Family = &api.Family{
				Afi:  api.Family_AFI_L2VPN,
				Safi: api.Family_SAFI_EVPN,
			}
		}

		peer.AfiSafis = append(peer.AfiSafis, afiSafi)
	}

	if err := p.server.AddPeer(ctx, &api.AddPeerRequest{Peer: peer}); err != nil {
		return &ErrPeerOperationFailed{
			Operation:   "add_neighbor",
			PeerAddress: netip.MustParseAddr(cfg.Address),
			Cause:       err,
		}
	}

	// Initialize neighbor state
	addr := netip.MustParseAddr(cfg.Address)
	p.neighborStatesMu.Lock()
	p.neighborStates[cfg.Address] = &NeighborState{
		Address:         addr,
		ASN:             cfg.ASN,
		State:           PeerStateIdle,
		LastStateChange: time.Now(),
	}
	p.neighborStatesMu.Unlock()

	p.logger.Info("neighbor added",
		slog.String("address", cfg.Address),
		slog.Uint64("asn", uint64(cfg.ASN)))

	return nil
}

// AddNeighbor dynamically adds a new BGP neighbor.
func (p *MockBGPPeer) AddNeighbor(ctx context.Context, cfg *MockNeighborConfig) error {
	if !p.started.Load() {
		return ErrPeerNotStarted
	}
	if cfg == nil {
		return ErrNilConfig
	}

	return p.addNeighbor(ctx, cfg)
}

// RemoveNeighbor removes a BGP neighbor.
func (p *MockBGPPeer) RemoveNeighbor(ctx context.Context, address string) error {
	if !p.started.Load() {
		return ErrPeerNotStarted
	}

	addr, err := netip.ParseAddr(address)
	if err != nil {
		return &ErrConfigValidation{
			Field:  "address",
			Value:  address,
			Reason: "invalid IP address",
		}
	}

	if err := p.server.DeletePeer(ctx, &api.DeletePeerRequest{Address: address}); err != nil {
		return &ErrPeerOperationFailed{
			Operation:   "remove_neighbor",
			PeerAddress: addr,
			Cause:       err,
		}
	}

	p.neighborStatesMu.Lock()
	delete(p.neighborStates, address)
	p.neighborStatesMu.Unlock()

	p.logger.Info("neighbor removed", slog.String("address", address))

	return nil
}

// GetNeighborState returns the current state of a neighbor.
func (p *MockBGPPeer) GetNeighborState(address string) (*NeighborState, error) {
	p.neighborStatesMu.RLock()
	defer p.neighborStatesMu.RUnlock()

	state, ok := p.neighborStates[address]
	if !ok {
		return nil, ErrNeighborNotFound
	}

	// Return a copy
	stateCopy := *state
	return &stateCopy, nil
}

// GetAllNeighborStates returns the state of all neighbors.
func (p *MockBGPPeer) GetAllNeighborStates() []*NeighborState {
	p.neighborStatesMu.RLock()
	defer p.neighborStatesMu.RUnlock()

	states := make([]*NeighborState, 0, len(p.neighborStates))
	for _, state := range p.neighborStates {
		stateCopy := *state
		states = append(states, &stateCopy)
	}

	return states
}

// GetReceivedRoutes returns all routes received from peers.
func (p *MockBGPPeer) GetReceivedRoutes() []*ReceivedRoute {
	return p.receivedRoutes.GetAll()
}

// GetReceivedRoutesByFamily returns routes of a specific address family.
func (p *MockBGPPeer) GetReceivedRoutesByFamily(family AddressFamily) []*ReceivedRoute {
	return p.receivedRoutes.GetByFamily(family)
}

// GetReceivedRouteCount returns the number of received routes.
func (p *MockBGPPeer) GetReceivedRouteCount() int {
	return p.receivedRoutes.Count()
}

// GetRouteHistory returns the history of route events.
func (p *MockBGPPeer) GetRouteHistory() []RouteEvent {
	return p.receivedRoutes.GetHistory()
}

// ClearReceivedRoutes clears all received routes and history.
func (p *MockBGPPeer) ClearReceivedRoutes() {
	p.receivedRoutes.Clear()
}

// GetStateChanges returns all recorded state change events.
func (p *MockBGPPeer) GetStateChanges() []StateChangeEvent {
	p.stateChangesMu.RLock()
	defer p.stateChangesMu.RUnlock()

	changes := make([]StateChangeEvent, len(p.stateChanges))
	copy(changes, p.stateChanges)
	return changes
}

// ClearStateChanges clears recorded state change events.
func (p *MockBGPPeer) ClearStateChanges() {
	p.stateChangesMu.Lock()
	defer p.stateChangesMu.Unlock()

	p.stateChanges = make([]StateChangeEvent, 0)
}

// StateChangeChan returns a channel for state change notifications.
func (p *MockBGPPeer) StateChangeChan() <-chan StateChangeEvent {
	return p.stateChangeCh
}

// RouteReceivedChan returns a channel for route received notifications.
func (p *MockBGPPeer) RouteReceivedChan() <-chan *ReceivedRoute {
	return p.routeReceivedCh
}

// RouteWithdrawnChan returns a channel for route withdrawn notifications.
func (p *MockBGPPeer) RouteWithdrawnChan() <-chan *ReceivedRoute {
	return p.routeWithdrawnCh
}

// watchEvents watches for BGP events and processes them.
func (p *MockBGPPeer) watchEvents(ctx context.Context) {
	defer p.wg.Done()

	// Build watch request for all events
	watchReq := &api.WatchEventRequest{
		Peer: &api.WatchEventRequest_Peer{},
		Table: &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{
				{
					Type: api.WatchEventRequest_Table_Filter_BEST,
					Init: true,
				},
			},
		},
	}

	// Create a context that can be canceled
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Cancel watch when shutdown is signaled
	go func() {
		select {
		case <-p.shutdownCh:
			cancel()
		case <-watchCtx.Done():
		}
	}()

	err := p.server.WatchEvent(watchCtx, watchReq, func(resp *api.WatchEventResponse) {
		p.handleWatchEvent(resp)
	})

	if err != nil && watchCtx.Err() == nil {
		p.logger.Error("watch event error", slog.Any("error", err))
	}
}

// handleWatchEvent processes a single watch event response.
func (p *MockBGPPeer) handleWatchEvent(resp *api.WatchEventResponse) {
	// Handle peer state changes
	if peerEvent := resp.GetPeer(); peerEvent != nil {
		p.handlePeerEvent(peerEvent)
	}

	// Handle path changes
	if tableEvent := resp.GetTable(); tableEvent != nil {
		p.handleTableEvent(tableEvent)
	}
}

// handlePeerEvent processes peer state change events.
func (p *MockBGPPeer) handlePeerEvent(event *api.WatchEventResponse_PeerEvent) {
	if event.Peer == nil || event.Peer.Conf == nil {
		return
	}

	address := event.Peer.Conf.NeighborAddress
	var newState PeerState

	if event.Peer.State != nil {
		newState = apiStateToPeerState(event.Peer.State.SessionState)
	}

	p.neighborStatesMu.Lock()
	state, ok := p.neighborStates[address]
	if !ok {
		addr, _ := netip.ParseAddr(address)
		state = &NeighborState{
			Address:         addr,
			ASN:             event.Peer.Conf.PeerAsn,
			LastStateChange: time.Now(),
		}
		p.neighborStates[address] = state
	}

	oldState := state.State
	state.State = newState
	state.LastStateChange = time.Now()

	if newState == PeerStateEstablished {
		state.Uptime = 0 // Will be calculated on query
	}
	p.neighborStatesMu.Unlock()

	// Record state change
	if oldState != newState {
		addr, _ := netip.ParseAddr(address)
		change := StateChangeEvent{
			PeerAddress: addr,
			OldState:    oldState,
			NewState:    newState,
			Timestamp:   time.Now(),
		}

		p.stateChangesMu.Lock()
		p.stateChanges = append(p.stateChanges, change)
		p.stateChangesMu.Unlock()

		// Non-blocking send to channel
		select {
		case p.stateChangeCh <- change:
		default:
		}

		p.logger.Info("peer state changed",
			slog.String("address", address),
			slog.String("old_state", oldState.String()),
			slog.String("new_state", newState.String()))
	}
}

// handleTableEvent processes route advertisement/withdrawal events.
func (p *MockBGPPeer) handleTableEvent(event *api.WatchEventResponse_TableEvent) {
	for _, path := range event.Paths {
		route := p.apiPathToReceivedRoute(path)
		if route == nil {
			continue
		}

		if path.IsWithdraw {
			route.IsWithdraw = true
			p.receivedRoutes.Remove(route)

			// Non-blocking send
			select {
			case p.routeWithdrawnCh <- route:
			default:
			}

			p.logger.Debug("route withdrawn",
				slog.String("prefix", route.Prefix.String()),
				slog.String("peer", route.PeerAddress.String()))
		} else {
			p.receivedRoutes.Add(route)

			// Non-blocking send
			select {
			case p.routeReceivedCh <- route:
			default:
			}

			p.logger.Debug("route received",
				slog.String("prefix", route.Prefix.String()),
				slog.String("peer", route.PeerAddress.String()),
				slog.String("next_hop", route.NextHop.String()))
		}
	}
}

// apiPathToReceivedRoute converts a GoBGP path to our ReceivedRoute type.
func (p *MockBGPPeer) apiPathToReceivedRoute(path *api.Path) *ReceivedRoute {
	if path == nil {
		return nil
	}

	route := &ReceivedRoute{
		ReceivedAt: time.Now(),
		IsWithdraw: path.IsWithdraw,
	}

	// Determine family from path
	if path.Family != nil {
		switch {
		case path.Family.Afi == api.Family_AFI_IP && path.Family.Safi == api.Family_SAFI_UNICAST:
			route.Family = AFamilyIPv4Unicast
		case path.Family.Afi == api.Family_AFI_IP6 && path.Family.Safi == api.Family_SAFI_UNICAST:
			route.Family = AFamilyIPv6Unicast
		case path.Family.Afi == api.Family_AFI_L2VPN && path.Family.Safi == api.Family_SAFI_EVPN:
			route.Family = AFamilyEVPN
		}
	}

	// Parse NLRI
	if path.Nlri != nil {
		p.parseNLRI(path.Nlri, route)
	}

	// Parse path attributes
	for _, attr := range path.Pattrs {
		p.parsePathAttribute(attr, route)
	}

	// Parse source peer
	if path.SourceAsn > 0 {
		// Try to find peer by ASN
		p.neighborStatesMu.RLock()
		for _, state := range p.neighborStates {
			if state.ASN == path.SourceAsn {
				route.PeerAddress = state.Address
				break
			}
		}
		p.neighborStatesMu.RUnlock()
	}

	return route
}

// parseNLRI parses NLRI from protobuf Any.
func (p *MockBGPPeer) parseNLRI(nlri *anypb.Any, route *ReceivedRoute) {
	var ipPrefix api.IPAddressPrefix
	if err := nlri.UnmarshalTo(&ipPrefix); err == nil {
		prefix, err := netip.ParsePrefix(ipPrefix.Prefix + "/" + intToStr(int(ipPrefix.PrefixLen)))
		if err == nil {
			route.Prefix = prefix
		}
		return
	}

	// Try EVPN NLRI types
	var evpnMacIP api.EVPNMACIPAdvertisementRoute
	if err := nlri.UnmarshalTo(&evpnMacIP); err == nil {
		route.EVPNRoute = &EVPNRouteData{
			Type:               EVPNTypeMACIP,
			RouteDistinguisher: evpnMacIP.Rd.String(),
			EthernetTag:        evpnMacIP.EthernetTag,
		}
		if evpnMacIP.MacAddress != "" {
			mac, _ := parseMAC(evpnMacIP.MacAddress)
			route.EVPNRoute.MAC = mac
		}
		if evpnMacIP.IpAddress != "" {
			ip, _ := netip.ParseAddr(evpnMacIP.IpAddress)
			route.EVPNRoute.IP = ip
		}
		if len(evpnMacIP.Labels) > 0 {
			route.EVPNRoute.VNI = evpnMacIP.Labels[0]
			route.EVPNRoute.Labels = evpnMacIP.Labels
		}
		return
	}

	var evpnMulticast api.EVPNInclusiveMulticastEthernetTagRoute
	if err := nlri.UnmarshalTo(&evpnMulticast); err == nil {
		route.EVPNRoute = &EVPNRouteData{
			Type:               EVPNTypeMulticast,
			RouteDistinguisher: evpnMulticast.Rd.String(),
			EthernetTag:        evpnMulticast.EthernetTag,
		}
		if evpnMulticast.IpAddress != "" {
			ip, _ := netip.ParseAddr(evpnMulticast.IpAddress)
			route.EVPNRoute.OriginatingIP = ip
		}
		return
	}

	var evpnPrefix api.EVPNIPPrefixRoute
	if err := nlri.UnmarshalTo(&evpnPrefix); err == nil {
		route.EVPNRoute = &EVPNRouteData{
			Type:               EVPNTypeIPPrefix,
			RouteDistinguisher: evpnPrefix.Rd.String(),
			EthernetTag:        evpnPrefix.EthernetTag,
		}
		if evpnPrefix.IpPrefix != "" {
			prefix, _ := netip.ParsePrefix(evpnPrefix.IpPrefix + "/" + intToStr(int(evpnPrefix.IpPrefixLen)))
			route.EVPNRoute.IPPrefix = prefix
		}
		if evpnPrefix.GwAddress != "" {
			gw, _ := netip.ParseAddr(evpnPrefix.GwAddress)
			route.EVPNRoute.GatewayIP = gw
		}
		if evpnPrefix.Label > 0 {
			route.EVPNRoute.VNI = evpnPrefix.Label
		}
		return
	}
}

// parsePathAttribute parses a single path attribute.
func (p *MockBGPPeer) parsePathAttribute(attr *anypb.Any, route *ReceivedRoute) {
	if attr == nil {
		return
	}

	var origin api.OriginAttribute
	if err := attr.UnmarshalTo(&origin); err == nil {
		route.Origin = uint8(origin.Origin)
		return
	}

	var nextHop api.NextHopAttribute
	if err := attr.UnmarshalTo(&nextHop); err == nil {
		nh, _ := netip.ParseAddr(nextHop.NextHop)
		route.NextHop = nh
		return
	}

	var mpReach api.MpReachNLRIAttribute
	if err := attr.UnmarshalTo(&mpReach); err == nil {
		if len(mpReach.NextHops) > 0 {
			nh, _ := netip.ParseAddr(mpReach.NextHops[0])
			route.NextHop = nh
		}
		return
	}

	var asPath api.AsPathAttribute
	if err := attr.UnmarshalTo(&asPath); err == nil {
		for _, seg := range asPath.Segments {
			route.ASPath = append(route.ASPath, seg.Numbers...)
		}
		return
	}

	var localPref api.LocalPrefAttribute
	if err := attr.UnmarshalTo(&localPref); err == nil {
		route.LocalPref = localPref.LocalPref
		return
	}

	var med api.MultiExitDiscAttribute
	if err := attr.UnmarshalTo(&med); err == nil {
		route.MED = med.Med
		return
	}

	var communities api.CommunitiesAttribute
	if err := attr.UnmarshalTo(&communities); err == nil {
		route.Communities = communities.Communities
		return
	}

	var extCommunities api.ExtendedCommunitiesAttribute
	if err := attr.UnmarshalTo(&extCommunities); err == nil {
		for _, ec := range extCommunities.Communities {
			route.ExtendedCommunities = append(route.ExtendedCommunities, ec.String())
		}
		return
	}

	var largeCommunities api.LargeCommunitiesAttribute
	if err := attr.UnmarshalTo(&largeCommunities); err == nil {
		for _, lc := range largeCommunities.Communities {
			route.LargeCommunities = append(route.LargeCommunities,
				intToStr(int(lc.GlobalAdmin))+":"+intToStr(int(lc.LocalData1))+":"+intToStr(int(lc.LocalData2)))
		}
		return
	}
}

// apiStateToPeerState converts GoBGP session state to our PeerState.
func apiStateToPeerState(state api.PeerState_SessionState) PeerState {
	switch state {
	case api.PeerState_IDLE:
		return PeerStateIdle
	case api.PeerState_CONNECT:
		return PeerStateConnect
	case api.PeerState_ACTIVE:
		return PeerStateActive
	case api.PeerState_OPENSENT:
		return PeerStateOpenSent
	case api.PeerState_OPENCONFIRM:
		return PeerStateOpenConfirm
	case api.PeerState_ESTABLISHED:
		return PeerStateEstablished
	default:
		return PeerStateIdle
	}
}

// validateConfig validates the mock BGP peer configuration.
func validateConfig(config *MockBGPPeerConfig) error {
	if config.ASN == 0 {
		return ErrInvalidASN
	}

	if config.RouterID == "" {
		return ErrInvalidRouterID
	}

	// Validate router ID is a valid IPv4 address
	if _, err := netip.ParseAddr(config.RouterID); err != nil {
		return &ErrConfigValidation{
			Field:  "RouterID",
			Value:  config.RouterID,
			Reason: "must be a valid IPv4 address",
		}
	}

	return nil
}

// Helper functions

func splitHostPort(addr string) (host, port string, err error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "", nil
}

func parsePort(s string) int {
	port := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		port = port*10 + int(c-'0')
	}
	return port
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + intToStr(-n)
	}
	buf := make([]byte, 20)
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n%10) + '0'
		n /= 10
	}
	return string(buf[i:])
}

func parseMAC(s string) ([]byte, error) {
	mac := make([]byte, 6)
	idx := 0
	val := byte(0)
	nibble := 0

	for _, c := range s {
		if c == ':' || c == '-' {
			if nibble > 0 {
				mac[idx] = val
				idx++
				val = 0
				nibble = 0
			}
			continue
		}

		var n byte
		switch {
		case c >= '0' && c <= '9':
			n = byte(c - '0')
		case c >= 'a' && c <= 'f':
			n = byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n = byte(c - 'A' + 10)
		default:
			return nil, ErrInvalidConfig
		}

		val = val<<4 | n
		nibble++

		if nibble == 2 {
			mac[idx] = val
			idx++
			val = 0
			nibble = 0
		}
	}

	if nibble > 0 && idx < 6 {
		mac[idx] = val
	}

	return mac, nil
}
