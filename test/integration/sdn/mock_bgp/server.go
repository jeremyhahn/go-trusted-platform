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
	"time"

	api "github.com/osrg/gobgp/v4/api"
)

// MockBGPServer provides higher-level control over mock BGP peers for testing.
// It wraps MockBGPPeer with additional testing utilities.
type MockBGPServer struct {
	peer   *MockBGPPeer
	logger *slog.Logger

	// Simulation state
	simulatedDown bool
	flapInterval  time.Duration
	flapCancel    context.CancelFunc
	flapWg        sync.WaitGroup

	mu sync.RWMutex
}

// NewMockBGPServer creates a new mock BGP server.
func NewMockBGPServer(config *MockBGPPeerConfig, logger *slog.Logger) (*MockBGPServer, error) {
	peer, err := NewMockBGPPeer(config, logger)
	if err != nil {
		return nil, err
	}

	return &MockBGPServer{
		peer:   peer,
		logger: logger,
	}, nil
}

// Start starts the mock BGP server.
func (s *MockBGPServer) Start(ctx context.Context) error {
	return s.peer.Start(ctx)
}

// Stop stops the mock BGP server.
func (s *MockBGPServer) Stop(ctx context.Context) error {
	// Stop any flapping simulation
	s.StopFlapping()

	return s.peer.Stop(ctx)
}

// IsStarted returns true if the server is running.
func (s *MockBGPServer) IsStarted() bool {
	return s.peer.IsStarted()
}

// Peer returns the underlying MockBGPPeer.
func (s *MockBGPServer) Peer() *MockBGPPeer {
	return s.peer
}

// InjectRoute injects a route to be announced to peers.
func (s *MockBGPServer) InjectRoute(ctx context.Context, route *RouteInjection) error {
	if !s.peer.IsStarted() {
		return ErrPeerNotStarted
	}

	if route == nil {
		return ErrNilConfig
	}

	// Validate route
	if err := validateRouteInjection(route); err != nil {
		return err
	}

	s.logger.Info("injecting route",
		slog.String("prefix", route.Prefix.String()),
		slog.String("next_hop", route.NextHop.String()),
		slog.String("family", route.Family.String()))

	// Build API path
	apiPath, err := s.buildAPIPath(route)
	if err != nil {
		return &ErrRouteOperationFailed{
			Operation: "inject",
			Prefix:    route.Prefix,
			Cause:     err,
		}
	}

	// Add path to BGP
	_, err = s.peer.server.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      apiPath,
	})
	if err != nil {
		return &ErrRouteOperationFailed{
			Operation: "inject",
			Prefix:    route.Prefix,
			Cause:     err,
		}
	}

	// Track injected route
	received := &ReceivedRoute{
		Family:      route.Family,
		Prefix:      route.Prefix,
		NextHop:     route.NextHop,
		ASPath:      route.ASPath,
		LocalPref:   route.LocalPref,
		MED:         route.MED,
		Communities: route.Communities,
		Origin:      route.Origin,
		ReceivedAt:  time.Now(),
	}
	s.peer.injectedRoutes.Add(received)

	s.logger.Info("route injected successfully",
		slog.String("prefix", route.Prefix.String()))

	return nil
}

// WithdrawRoute withdraws a previously injected route.
func (s *MockBGPServer) WithdrawRoute(ctx context.Context, family AddressFamily, prefix netip.Prefix) error {
	if !s.peer.IsStarted() {
		return ErrPeerNotStarted
	}

	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	s.logger.Info("withdrawing route",
		slog.String("prefix", prefix.String()),
		slog.String("family", family.String()))

	// Build path for withdrawal
	apiPath := &api.Path{
		Family:     familyToAPIFamily(family),
		IsWithdraw: true,
	}

	// Set NLRI
	apiPath.Nlri = &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		PrefixLen: uint32(prefix.Bits()),
		Prefix:    prefix.Addr().String(),
	}}}

	// Delete path from BGP
	err := s.peer.server.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      apiPath,
	})
	if err != nil {
		return &ErrRouteOperationFailed{
			Operation: "withdraw",
			Prefix:    prefix,
			Cause:     err,
		}
	}

	// Remove from injected routes
	route, ok := s.peer.injectedRoutes.Get(prefix)
	if ok {
		s.peer.injectedRoutes.Remove(route)
	}

	s.logger.Info("route withdrawn successfully",
		slog.String("prefix", prefix.String()))

	return nil
}

// InjectEVPNRoute injects an EVPN route.
func (s *MockBGPServer) InjectEVPNRoute(ctx context.Context, route *RouteInjection) error {
	if !s.peer.IsStarted() {
		return ErrPeerNotStarted
	}

	if route == nil || route.EVPNRoute == nil {
		return ErrNilConfig
	}

	route.Family = AFamilyEVPN

	s.logger.Info("injecting EVPN route",
		slog.String("type", route.EVPNRoute.Type.String()),
		slog.String("next_hop", route.NextHop.String()))

	// Build API path for EVPN
	apiPath, err := s.buildEVPNAPIPath(route)
	if err != nil {
		return &ErrRouteOperationFailed{
			Operation: "inject_evpn",
			Cause:     err,
		}
	}

	// Add path to BGP
	_, err = s.peer.server.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Path:      apiPath,
	})
	if err != nil {
		return &ErrRouteOperationFailed{
			Operation: "inject_evpn",
			Cause:     err,
		}
	}

	s.logger.Info("EVPN route injected successfully",
		slog.String("type", route.EVPNRoute.Type.String()))

	return nil
}

// SimulateDown simulates the peer going down (disables all neighbors).
func (s *MockBGPServer) SimulateDown(ctx context.Context) error {
	if !s.peer.IsStarted() {
		return ErrPeerNotStarted
	}

	s.mu.Lock()
	s.simulatedDown = true
	s.mu.Unlock()

	s.logger.Info("simulating peer down")

	// Disable all neighbors
	for address := range s.peer.neighborStates {
		if err := s.disableNeighbor(ctx, address); err != nil {
			s.logger.Warn("failed to disable neighbor",
				slog.String("address", address),
				slog.Any("error", err))
		}
	}

	return nil
}

// SimulateUp simulates the peer coming back up (enables all neighbors).
func (s *MockBGPServer) SimulateUp(ctx context.Context) error {
	if !s.peer.IsStarted() {
		return ErrPeerNotStarted
	}

	s.mu.Lock()
	s.simulatedDown = false
	s.mu.Unlock()

	s.logger.Info("simulating peer up")

	// Enable all neighbors
	for address := range s.peer.neighborStates {
		if err := s.enableNeighbor(ctx, address); err != nil {
			s.logger.Warn("failed to enable neighbor",
				slog.String("address", address),
				slog.Any("error", err))
		}
	}

	return nil
}

// SimulateFlapping starts simulating peer flapping (up/down cycles).
func (s *MockBGPServer) SimulateFlapping(ctx context.Context, interval time.Duration) error {
	if !s.peer.IsStarted() {
		return ErrPeerNotStarted
	}

	if interval <= 0 {
		interval = 10 * time.Second
	}

	s.mu.Lock()
	if s.flapCancel != nil {
		s.mu.Unlock()
		return nil // Already flapping
	}

	flapCtx, cancel := context.WithCancel(ctx)
	s.flapCancel = cancel
	s.flapInterval = interval
	s.mu.Unlock()

	s.logger.Info("starting flapping simulation",
		slog.Duration("interval", interval))

	s.flapWg.Add(1)
	go s.flapLoop(flapCtx)

	return nil
}

// StopFlapping stops flapping simulation.
func (s *MockBGPServer) StopFlapping() {
	s.mu.Lock()
	if s.flapCancel != nil {
		s.flapCancel()
		s.flapCancel = nil
	}
	s.mu.Unlock()

	s.flapWg.Wait()
	s.logger.Info("stopped flapping simulation")
}

// flapLoop runs the flapping simulation.
func (s *MockBGPServer) flapLoop(ctx context.Context) {
	defer s.flapWg.Done()

	ticker := time.NewTicker(s.flapInterval)
	defer ticker.Stop()

	isDown := false

	for {
		select {
		case <-ctx.Done():
			// Ensure we come back up before stopping
			if isDown {
				if err := s.SimulateUp(context.Background()); err != nil {
					s.logger.Warn("failed to restore peer during flap stop",
						slog.Any("error", err))
				}
			}
			return
		case <-ticker.C:
			if isDown {
				if err := s.SimulateUp(ctx); err != nil {
					s.logger.Warn("flap up failed", slog.Any("error", err))
				}
			} else {
				if err := s.SimulateDown(ctx); err != nil {
					s.logger.Warn("flap down failed", slog.Any("error", err))
				}
			}
			isDown = !isDown
		}
	}
}

// disableNeighbor disables a specific neighbor.
func (s *MockBGPServer) disableNeighbor(ctx context.Context, address string) error {
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: address,
		},
		State: &api.PeerState{
			AdminState: api.PeerState_ADMIN_STATE_DOWN,
		},
	}

	_, err := s.peer.server.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: peer})
	return err
}

// enableNeighbor enables a specific neighbor.
func (s *MockBGPServer) enableNeighbor(ctx context.Context, address string) error {
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: address,
		},
		State: &api.PeerState{
			AdminState: api.PeerState_ADMIN_STATE_UP,
		},
	}

	_, err := s.peer.server.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: peer})
	return err
}

// ResetNeighbor resets a BGP session with a neighbor.
func (s *MockBGPServer) ResetNeighbor(ctx context.Context, address string) error {
	if !s.peer.IsStarted() {
		return ErrPeerNotStarted
	}

	s.logger.Info("resetting neighbor", slog.String("address", address))

	return s.peer.server.ResetPeer(ctx, &api.ResetPeerRequest{
		Address: address,
		Soft:    false,
	})
}

// SoftResetNeighbor performs a soft reset of a BGP session.
func (s *MockBGPServer) SoftResetNeighbor(ctx context.Context, address string) error {
	if !s.peer.IsStarted() {
		return ErrPeerNotStarted
	}

	s.logger.Info("soft resetting neighbor", slog.String("address", address))

	return s.peer.server.ResetPeer(ctx, &api.ResetPeerRequest{
		Address: address,
		Soft:    true,
	})
}

// GetRIB returns routes from the routing information base.
func (s *MockBGPServer) GetRIB(ctx context.Context, family AddressFamily) ([]*ReceivedRoute, error) {
	if !s.peer.IsStarted() {
		return nil, ErrPeerNotStarted
	}

	var routes []*ReceivedRoute

	err := s.peer.server.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    familyToAPIFamily(family),
	}, func(dest *api.Destination) {
		for _, path := range dest.Paths {
			route := s.peer.apiPathToReceivedRoute(path)
			if route != nil {
				routes = append(routes, route)
			}
		}
	})

	if err != nil {
		return nil, &ErrServerOperationFailed{
			Operation: "list_rib",
			Cause:     err,
		}
	}

	return routes, nil
}

// WaitForSession waits for a session to reach a specific state.
func (s *MockBGPServer) WaitForSession(ctx context.Context, address string, state PeerState) error {
	// Check immediately
	current, err := s.peer.GetNeighborState(address)
	if err == nil && current.State == state {
		return nil
	}

	// Wait for state change
	for {
		select {
		case <-ctx.Done():
			return &ErrWaitTimeout{
				Condition: "session state " + state.String(),
				Duration:  "context canceled",
			}
		case change := <-s.peer.StateChangeChan():
			if change.PeerAddress.String() == address && change.NewState == state {
				return nil
			}
		}
	}
}

// WaitForEstablished waits for a session to become established.
func (s *MockBGPServer) WaitForEstablished(ctx context.Context, address string) error {
	return s.WaitForSession(ctx, address, PeerStateEstablished)
}

// WaitForRouteCount waits until the received route count reaches the expected value.
func (s *MockBGPServer) WaitForRouteCount(ctx context.Context, count int) error {
	for {
		if s.peer.GetReceivedRouteCount() >= count {
			return nil
		}

		select {
		case <-ctx.Done():
			return &ErrWaitTimeout{
				Condition: "route count >= " + intToStr(count),
				Duration:  "context canceled",
			}
		case <-s.peer.RouteReceivedChan():
			// Check again after receiving a route
		}
	}
}

// buildAPIPath builds a GoBGP API path from a route injection.
func (s *MockBGPServer) buildAPIPath(route *RouteInjection) (*api.Path, error) {
	apiPath := &api.Path{
		Family: familyToAPIFamily(route.Family),
		Pattrs: make([]*api.Attribute, 0, 6),
	}

	// Set NLRI
	apiPath.Nlri = &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
		PrefixLen: uint32(route.Prefix.Bits()),
		Prefix:    route.Prefix.Addr().String(),
	}}}

	// Add origin attribute
	apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{
		Origin: uint32(route.Origin),
	}}})

	// Add next hop
	if route.NextHop.IsValid() {
		if route.NextHop.Is4() {
			apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{
				NextHop: route.NextHop.String(),
			}}})
		} else {
			apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: &api.MpReachNLRIAttribute{
				Family:   familyToAPIFamily(route.Family),
				NextHops: []string{route.NextHop.String()},
				Nlris:    []*api.NLRI{apiPath.Nlri},
			}}})
		}
	}

	// Add AS path
	if len(route.ASPath) > 0 {
		apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_AsPath{AsPath: &api.AsPathAttribute{
			Segments: []*api.AsSegment{{
				Type:    api.AsSegment_TYPE_AS_SEQUENCE,
				Numbers: route.ASPath,
			}},
		}}})
	}

	// Add local preference
	if route.LocalPref > 0 {
		apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_LocalPref{LocalPref: &api.LocalPrefAttribute{
			LocalPref: route.LocalPref,
		}}})
	}

	// Add MED
	if route.MED > 0 {
		apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_MultiExitDisc{MultiExitDisc: &api.MultiExitDiscAttribute{
			Med: route.MED,
		}}})
	}

	// Add communities
	if len(route.Communities) > 0 {
		apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_Communities{Communities: &api.CommunitiesAttribute{
			Communities: route.Communities,
		}}})
	}

	return apiPath, nil
}

// buildEVPNAPIPath builds a GoBGP API path for EVPN routes.
func (s *MockBGPServer) buildEVPNAPIPath(route *RouteInjection) (*api.Path, error) {
	family := &api.Family{
		Afi:  api.Family_AFI_L2VPN,
		Safi: api.Family_SAFI_EVPN,
	}
	apiPath := &api.Path{
		Family: family,
		Pattrs: make([]*api.Attribute, 0, 3),
	}

	rd := &api.RouteDistinguisher{Rd: &api.RouteDistinguisher_TwoOctetAsn{TwoOctetAsn: &api.RouteDistinguisherTwoOctetASN{
		Admin:    s.peer.config.ASN,
		Assigned: route.EVPNRoute.VNI,
	}}}

	// Build NLRI based on EVPN route type
	switch route.EVPNRoute.Type {
	case EVPNTypeMACIP:
		apiPath.Nlri = &api.NLRI{Nlri: &api.NLRI_EvpnMacadv{EvpnMacadv: &api.EVPNMACIPAdvertisementRoute{
			Rd:          rd,
			Esi:         &api.EthernetSegmentIdentifier{},
			EthernetTag: route.EVPNRoute.EthernetTag,
			MacAddress:  route.EVPNRoute.MAC.String(),
			IpAddress:   route.EVPNRoute.IP.String(),
			Labels:      []uint32{route.EVPNRoute.VNI},
		}}}
	case EVPNTypeMulticast:
		apiPath.Nlri = &api.NLRI{Nlri: &api.NLRI_EvpnMulticast{EvpnMulticast: &api.EVPNInclusiveMulticastEthernetTagRoute{
			Rd:          rd,
			EthernetTag: route.EVPNRoute.EthernetTag,
			IpAddress:   route.EVPNRoute.OriginatingIP.String(),
		}}}
	case EVPNTypeIPPrefix:
		apiPath.Nlri = &api.NLRI{Nlri: &api.NLRI_EvpnIpPrefix{EvpnIpPrefix: &api.EVPNIPPrefixRoute{
			Rd:          rd,
			Esi:         &api.EthernetSegmentIdentifier{},
			EthernetTag: route.EVPNRoute.EthernetTag,
			IpPrefixLen: uint32(route.EVPNRoute.IPPrefix.Bits()),
			IpPrefix:    route.EVPNRoute.IPPrefix.Addr().String(),
			GwAddress:   route.EVPNRoute.GatewayIP.String(),
			Label:       route.EVPNRoute.VNI,
		}}}
	default:
		return nil, ErrInvalidConfig
	}

	// Add origin attribute
	apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{
		Origin: uint32(route.Origin),
	}}})

	// Add MP_REACH_NLRI with next hop
	if route.NextHop.IsValid() {
		apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: &api.MpReachNLRIAttribute{
			Family:   family,
			NextHops: []string{route.NextHop.String()},
			Nlris:    []*api.NLRI{apiPath.Nlri},
		}}})
	}

	// Add AS path
	if len(route.ASPath) > 0 {
		apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_AsPath{AsPath: &api.AsPathAttribute{
			Segments: []*api.AsSegment{{
				Type:    api.AsSegment_TYPE_AS_SEQUENCE,
				Numbers: route.ASPath,
			}},
		}}})
	}

	return apiPath, nil
}

// familyToAPIFamily converts our AddressFamily to GoBGP API family.
func familyToAPIFamily(af AddressFamily) *api.Family {
	switch af {
	case AFamilyIPv4Unicast:
		return &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		}
	case AFamilyIPv6Unicast:
		return &api.Family{
			Afi:  api.Family_AFI_IP6,
			Safi: api.Family_SAFI_UNICAST,
		}
	case AFamilyEVPN:
		return &api.Family{
			Afi:  api.Family_AFI_L2VPN,
			Safi: api.Family_SAFI_EVPN,
		}
	default:
		return &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		}
	}
}

// validateRouteInjection validates a route injection request.
func validateRouteInjection(route *RouteInjection) error {
	if route.Family == AFamilyEVPN {
		// EVPN routes validated separately
		return nil
	}

	if !route.Prefix.IsValid() {
		return ErrInvalidPrefix
	}

	if !route.NextHop.IsValid() {
		return ErrInvalidNextHop
	}

	return nil
}
