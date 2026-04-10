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
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

// BGPServerInterface abstracts GoBGP server operations for testing.
type BGPServerInterface interface {
	Start() error
	Stop()
	StartBgp(ctx context.Context, req *api.StartBgpRequest) error
	StopBgp(ctx context.Context, req *api.StopBgpRequest) error
	AddPeer(ctx context.Context, req *api.AddPeerRequest) error
	DeletePeer(ctx context.Context, req *api.DeletePeerRequest) error
	UpdatePeer(ctx context.Context, req *api.UpdatePeerRequest, doSoftResetIn bool) (*api.UpdatePeerResponse, error)
	GetBgp(ctx context.Context, req *api.GetBgpRequest) (*api.GetBgpResponse, error)
	ListPeer(ctx context.Context, req *api.ListPeerRequest, fn func(*api.Peer)) error
	ResetPeer(ctx context.Context, req *api.ResetPeerRequest) error
	EnableMrt(ctx context.Context, req *api.EnableMrtRequest) error
	DisableMrt(ctx context.Context, req *api.DisableMrtRequest) error
	AddPath(ctx context.Context, req *api.AddPathRequest) (*api.AddPathResponse, error)
	DeletePath(ctx context.Context, req *api.DeletePathRequest) error
	ListPath(ctx context.Context, req *api.ListPathRequest, fn func(*api.Destination)) error
	WatchEvent(ctx context.Context, req *api.WatchEventRequest, fn func(*api.WatchEventResponse)) error
}

// gobgpServerWrapper wraps a real GoBGP server to implement BGPServerInterface.
type gobgpServerWrapper struct {
	server *server.BgpServer
}

func (w *gobgpServerWrapper) Start() error {
	w.server.Serve()
	return nil
}

func (w *gobgpServerWrapper) Stop() {
	w.server.Stop()
}

func (w *gobgpServerWrapper) StartBgp(ctx context.Context, req *api.StartBgpRequest) error {
	return w.server.StartBgp(ctx, req)
}

func (w *gobgpServerWrapper) StopBgp(ctx context.Context, req *api.StopBgpRequest) error {
	return w.server.StopBgp(ctx, req)
}

func (w *gobgpServerWrapper) AddPeer(ctx context.Context, req *api.AddPeerRequest) error {
	return w.server.AddPeer(ctx, req)
}

func (w *gobgpServerWrapper) DeletePeer(ctx context.Context, req *api.DeletePeerRequest) error {
	return w.server.DeletePeer(ctx, req)
}

func (w *gobgpServerWrapper) UpdatePeer(ctx context.Context, req *api.UpdatePeerRequest, doSoftResetIn bool) (*api.UpdatePeerResponse, error) {
	return w.server.UpdatePeer(ctx, req)
}

func (w *gobgpServerWrapper) GetBgp(ctx context.Context, req *api.GetBgpRequest) (*api.GetBgpResponse, error) {
	return w.server.GetBgp(ctx, req)
}

func (w *gobgpServerWrapper) ListPeer(ctx context.Context, req *api.ListPeerRequest, fn func(*api.Peer)) error {
	return w.server.ListPeer(ctx, req, fn)
}

func (w *gobgpServerWrapper) ResetPeer(ctx context.Context, req *api.ResetPeerRequest) error {
	return w.server.ResetPeer(ctx, req)
}

func (w *gobgpServerWrapper) EnableMrt(ctx context.Context, req *api.EnableMrtRequest) error {
	return w.server.EnableMrt(ctx, req)
}

func (w *gobgpServerWrapper) DisableMrt(ctx context.Context, req *api.DisableMrtRequest) error {
	return w.server.DisableMrt(ctx, req)
}

func (w *gobgpServerWrapper) AddPath(ctx context.Context, req *api.AddPathRequest) (*api.AddPathResponse, error) {
	return w.server.AddPath(ctx, req)
}

func (w *gobgpServerWrapper) DeletePath(ctx context.Context, req *api.DeletePathRequest) error {
	return w.server.DeletePath(ctx, req)
}

func (w *gobgpServerWrapper) ListPath(ctx context.Context, req *api.ListPathRequest, fn func(*api.Destination)) error {
	return w.server.ListPath(ctx, req, fn)
}

func (w *gobgpServerWrapper) WatchEvent(ctx context.Context, req *api.WatchEventRequest, fn func(*api.WatchEventResponse)) error {
	return w.server.WatchEvent(ctx, req, fn)
}

// Speaker wraps a GoBGP server instance to provide BGP speaker functionality.
type Speaker struct {
	config    *BGPConfig
	server    BGPServerInterface
	logger    *slog.Logger
	startTime time.Time

	started atomic.Bool
	mu      sync.RWMutex

	// Callbacks for event notification
	onPeerStateChange func(addr netip.Addr, state PeerState)
	onRouteReceived   func(route interface{})
}

// SpeakerOption configures the speaker.
type SpeakerOption func(*Speaker)

// WithPeerStateCallback sets the callback for peer state changes.
func WithPeerStateCallback(fn func(addr netip.Addr, state PeerState)) SpeakerOption {
	return func(s *Speaker) {
		s.onPeerStateChange = fn
	}
}

// WithRouteReceivedCallback sets the callback for received routes.
func WithRouteReceivedCallback(fn func(route interface{})) SpeakerOption {
	return func(s *Speaker) {
		s.onRouteReceived = fn
	}
}

// WithBGPServer sets a custom BGP server implementation (for testing).
func WithBGPServer(srv BGPServerInterface) SpeakerOption {
	return func(s *Speaker) {
		s.server = srv
	}
}

// NewSpeaker creates a new BGP speaker with the provided configuration.
func NewSpeaker(config *BGPConfig, logger *slog.Logger, opts ...SpeakerOption) (*Speaker, error) {
	if config == nil {
		return nil, ErrConfigNil
	}
	if logger == nil {
		return nil, ErrLoggerNil
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	s := &Speaker{
		config: config,
		logger: logger,
	}

	// Apply options
	for _, opt := range opts {
		opt(s)
	}

	// Create real GoBGP server if not injected
	if s.server == nil {
		bgpServer := server.NewBgpServer()
		s.server = &gobgpServerWrapper{server: bgpServer}
	}

	return s, nil
}

// Start initializes and starts the BGP server.
func (s *Speaker) Start(ctx context.Context) error {
	if s.started.Load() {
		return ErrSpeakerAlreadyRunning
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("starting BGP speaker",
		"router_id", s.config.RouterID,
		"asn", s.config.ASN,
		"port", s.config.ListenPort)

	// Start the server goroutine
	if err := s.server.Start(); err != nil {
		return &ErrServerOperationFailed{Operation: "start", Cause: err}
	}

	// Configure BGP global settings
	global := &api.Global{
		Asn:        s.config.ASN,
		RouterId:   s.config.RouterID.String(),
		ListenPort: int32(s.config.ListenPort),
	}

	// Add listen addresses if specified
	if len(s.config.ListenAddresses) > 0 {
		addrs := make([]string, len(s.config.ListenAddresses))
		for i, addr := range s.config.ListenAddresses {
			addrs[i] = addr.String()
		}
		global.ListenAddresses = addrs
	}

	// Configure graceful restart if enabled
	if s.config.GracefulRestartEnabled {
		global.GracefulRestart = &api.GracefulRestart{
			Enabled:     true,
			RestartTime: uint32(s.config.GracefulRestartTime),
		}
	}

	req := &api.StartBgpRequest{Global: global}
	if err := s.server.StartBgp(ctx, req); err != nil {
		s.server.Stop()
		return &ErrServerOperationFailed{Operation: "start_bgp", Cause: err}
	}

	s.startTime = time.Now()
	s.started.Store(true)

	s.logger.Info("BGP speaker started successfully",
		"router_id", s.config.RouterID,
		"asn", s.config.ASN)

	return nil
}

// Stop gracefully shuts down the BGP server.
func (s *Speaker) Stop(ctx context.Context) error {
	if !s.started.Load() {
		return ErrSpeakerNotStarted
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("stopping BGP speaker")

	// Stop BGP protocol
	if err := s.server.StopBgp(ctx, &api.StopBgpRequest{}); err != nil {
		s.logger.Warn("error stopping BGP protocol", "error", err)
	}

	// Stop the server
	s.server.Stop()
	s.started.Store(false)

	s.logger.Info("BGP speaker stopped")

	return nil
}

// AddPeer adds a BGP neighbor.
func (s *Speaker) AddPeer(ctx context.Context, cfg *NeighborConfig) error {
	if !s.started.Load() {
		return ErrSpeakerNotStarted
	}
	if cfg == nil {
		return ErrConfigNil
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	peer := s.neighborConfigToPeer(cfg)

	s.logger.Info("adding BGP peer",
		"address", cfg.Address,
		"asn", cfg.ASN,
		"description", cfg.Description)

	if err := s.server.AddPeer(ctx, &api.AddPeerRequest{Peer: peer}); err != nil {
		return &ErrPeerOperationFailed{
			Operation:   "add",
			PeerAddress: cfg.Address,
			Cause:       err,
		}
	}

	return nil
}

// DeletePeer removes a BGP neighbor.
func (s *Speaker) DeletePeer(ctx context.Context, addr netip.Addr) error {
	if !s.started.Load() {
		return ErrSpeakerNotStarted
	}
	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("deleting BGP peer", "address", addr)

	if err := s.server.DeletePeer(ctx, &api.DeletePeerRequest{Address: addr.String()}); err != nil {
		return &ErrPeerOperationFailed{
			Operation:   "delete",
			PeerAddress: addr,
			Cause:       err,
		}
	}

	return nil
}

// GetPeer returns peer information for the specified address.
func (s *Speaker) GetPeer(ctx context.Context, addr netip.Addr) (*PeerInfo, error) {
	if !s.started.Load() {
		return nil, ErrSpeakerNotStarted
	}
	if !addr.IsValid() {
		return nil, ErrInvalidPeerAddress
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var result *PeerInfo
	err := s.server.ListPeer(ctx, &api.ListPeerRequest{
		Address: addr.String(),
	}, func(p *api.Peer) {
		result = s.peerToPeerInfo(p)
	})

	if err != nil {
		return nil, &ErrPeerOperationFailed{
			Operation:   "get",
			PeerAddress: addr,
			Cause:       err,
		}
	}

	if result == nil {
		return nil, ErrPeerNotFound
	}

	return result, nil
}

// ListPeers returns all configured peers.
func (s *Speaker) ListPeers(ctx context.Context) ([]*PeerInfo, error) {
	if !s.started.Load() {
		return nil, ErrSpeakerNotStarted
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var peers []*PeerInfo
	err := s.server.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		peers = append(peers, s.peerToPeerInfo(p))
	})

	if err != nil {
		return nil, &ErrServerOperationFailed{Operation: "list_peers", Cause: err}
	}

	return peers, nil
}

// GetPeerState returns the session state for a peer.
func (s *Speaker) GetPeerState(ctx context.Context, addr netip.Addr) (PeerState, error) {
	peer, err := s.GetPeer(ctx, addr)
	if err != nil {
		return PeerStateIdle, err
	}
	return peer.State, nil
}

// ResetPeer resets a BGP session.
func (s *Speaker) ResetPeer(ctx context.Context, addr netip.Addr, soft bool) error {
	if !s.started.Load() {
		return ErrSpeakerNotStarted
	}
	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("resetting BGP peer", "address", addr, "soft", soft)

	req := &api.ResetPeerRequest{
		Address: addr.String(),
		Soft:    soft,
	}

	if err := s.server.ResetPeer(ctx, req); err != nil {
		return &ErrPeerOperationFailed{
			Operation:   "reset",
			PeerAddress: addr,
			Cause:       err,
		}
	}

	return nil
}

// EnablePeer enables a disabled peer.
func (s *Speaker) EnablePeer(ctx context.Context, addr netip.Addr) error {
	if !s.started.Load() {
		return ErrSpeakerNotStarted
	}
	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("enabling BGP peer", "address", addr)

	// Update peer with AdminDown = false
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: addr.String(),
		},
		State: &api.PeerState{
			AdminState: api.PeerState_UP,
		},
	}

	_, err := s.server.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: peer}, false)
	if err != nil {
		return &ErrPeerOperationFailed{
			Operation:   "enable",
			PeerAddress: addr,
			Cause:       err,
		}
	}

	return nil
}

// DisablePeer disables a peer without removing config.
func (s *Speaker) DisablePeer(ctx context.Context, addr netip.Addr) error {
	if !s.started.Load() {
		return ErrSpeakerNotStarted
	}
	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("disabling BGP peer", "address", addr)

	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: addr.String(),
		},
		State: &api.PeerState{
			AdminState: api.PeerState_DOWN,
		},
	}

	_, err := s.server.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: peer}, false)
	if err != nil {
		return &ErrPeerOperationFailed{
			Operation:   "disable",
			PeerAddress: addr,
			Cause:       err,
		}
	}

	return nil
}

// AddPath adds a route to the RIB.
func (s *Speaker) AddPath(ctx context.Context, path *Path) error {
	if !s.started.Load() {
		return ErrSpeakerNotStarted
	}
	if path == nil {
		return ErrPrefixInvalid{Reason: "path is nil"}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	apiPath, err := s.pathToAPIPath(path)
	if err != nil {
		return err
	}

	s.logger.Debug("adding BGP path",
		"family", path.Family,
		"prefix", path.Prefix,
		"next_hop", path.NextHop)

	_, err = s.server.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      apiPath,
	})
	if err != nil {
		return &ErrPathOperationFailed{
			Operation: "add",
			Prefix:    path.Prefix,
			Cause:     err,
		}
	}

	return nil
}

// DeletePath removes a route from the RIB.
func (s *Speaker) DeletePath(ctx context.Context, path *Path) error {
	if !s.started.Load() {
		return ErrSpeakerNotStarted
	}
	if path == nil {
		return ErrPrefixInvalid{Reason: "path is nil"}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	apiPath, err := s.pathToAPIPath(path)
	if err != nil {
		return err
	}

	s.logger.Debug("deleting BGP path",
		"family", path.Family,
		"prefix", path.Prefix)

	err = s.server.DeletePath(ctx, &api.DeletePathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      apiPath,
	})
	if err != nil {
		return &ErrPathOperationFailed{
			Operation: "delete",
			Prefix:    path.Prefix,
			Cause:     err,
		}
	}

	return nil
}

// GetRIB returns routes from the specified RIB.
func (s *Speaker) GetRIB(ctx context.Context, family AddressFamily, ribType RIBType) ([]*Path, error) {
	if !s.started.Load() {
		return nil, ErrSpeakerNotStarted
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	apiFamily := s.addressFamilyToAPI(family)
	tableType := s.ribTypeToTableType(ribType)

	var paths []*Path
	err := s.server.ListPath(ctx, &api.ListPathRequest{
		TableType: tableType,
		Family:    apiFamily,
	}, func(dest *api.Destination) {
		for _, p := range dest.Paths {
			if converted := s.apiPathToPath(p, family); converted != nil {
				paths = append(paths, converted)
			}
		}
	})

	if err != nil {
		return nil, &ErrRIBQueryFailed{
			Family:  family,
			RIBType: ribType,
			Cause:   err,
		}
	}

	return paths, nil
}

// WatchEvent subscribes to BGP events.
func (s *Speaker) WatchEvent(ctx context.Context, opts ...WatchOption) (<-chan *Event, error) {
	if !s.started.Load() {
		return nil, ErrSpeakerNotStarted
	}

	// Parse options
	wopts := &watchOptions{}
	for _, opt := range opts {
		opt(wopts)
	}

	eventCh := make(chan *Event, 100)

	// Build watch request
	req := &api.WatchEventRequest{}

	if wopts.peerStateChanges {
		req.Peer = &api.WatchEventRequest_Peer{}
	}

	if wopts.pathChanges {
		tableReq := &api.WatchEventRequest_Table{
			Filters: []*api.WatchEventRequest_Table_Filter{},
		}

		// Add family filters
		for _, fam := range wopts.families {
			filter := &api.WatchEventRequest_Table_Filter{
				Type: api.WatchEventRequest_Table_Filter_BEST,
			}
			if wopts.bestPathOnly {
				filter.Type = api.WatchEventRequest_Table_Filter_BEST
			}
			filter.Init = true

			// Set address family
			switch fam {
			case AFamilyIPv4Unicast:
				tableReq.Filters = append(tableReq.Filters, &api.WatchEventRequest_Table_Filter{
					Type: filter.Type,
					Init: filter.Init,
				})
			case AFamilyIPv6Unicast:
				tableReq.Filters = append(tableReq.Filters, &api.WatchEventRequest_Table_Filter{
					Type: filter.Type,
					Init: filter.Init,
				})
			case AFamilyEVPN:
				tableReq.Filters = append(tableReq.Filters, &api.WatchEventRequest_Table_Filter{
					Type: filter.Type,
					Init: filter.Init,
				})
			}
		}

		req.Table = tableReq
	}

	// Start watching in goroutine
	go func() {
		defer close(eventCh)

		watchErr := s.server.WatchEvent(ctx, req, func(resp *api.WatchEventResponse) {
			event := s.watchResponseToEvent(resp, wopts)
			if event != nil {
				select {
				case eventCh <- event:
				case <-ctx.Done():
					return
				}
			}
		})

		if watchErr != nil {
			s.logger.Error("watch event error", "error", watchErr)
		}
	}()

	return eventCh, nil
}

// GetServerInfo returns BGP server information.
func (s *Speaker) GetServerInfo(ctx context.Context) (*ServerInfo, error) {
	if !s.started.Load() {
		return nil, ErrSpeakerNotStarted
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	resp, err := s.server.GetBgp(ctx, &api.GetBgpRequest{})
	if err != nil {
		return nil, &ErrServerOperationFailed{Operation: "get_info", Cause: err}
	}

	// Count peers
	peerCount := 0
	establishedCount := 0
	err = s.server.ListPeer(ctx, &api.ListPeerRequest{}, func(p *api.Peer) {
		peerCount++
		if p.State != nil && p.State.SessionState == api.PeerState_ESTABLISHED {
			establishedCount++
		}
	})
	if err != nil {
		s.logger.Warn("error counting peers", "error", err)
	}

	// Count paths
	var pathCount int64
	err = s.server.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family: &api.Family{
			Afi:  api.Family_AFI_IP,
			Safi: api.Family_SAFI_UNICAST,
		},
	}, func(dest *api.Destination) {
		pathCount += int64(len(dest.Paths))
	})
	if err != nil {
		s.logger.Warn("error counting paths", "error", err)
	}

	routerID, _ := netip.ParseAddr(resp.Global.RouterId)

	return &ServerInfo{
		RouterID:               routerID,
		ASN:                    resp.Global.Asn,
		ListenPort:             uint16(resp.Global.ListenPort),
		PeerCount:              peerCount,
		EstablishedCount:       establishedCount,
		Uptime:                 time.Since(s.startTime),
		PathCount:              pathCount,
		GracefulRestartEnabled: resp.Global.GracefulRestart != nil && resp.Global.GracefulRestart.Enabled,
	}, nil
}

// IsStarted returns true if the speaker is started.
func (s *Speaker) IsStarted() bool {
	return s.started.Load()
}

// Config returns the speaker configuration.
func (s *Speaker) Config() *BGPConfig {
	return s.config
}

// neighborConfigToPeer converts our NeighborConfig to GoBGP's api.Peer.
func (s *Speaker) neighborConfigToPeer(cfg *NeighborConfig) *api.Peer {
	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: cfg.Address.String(),
			PeerAsn:         cfg.ASN,
			Description:     cfg.Description,
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				HoldTime:          uint64(cfg.HoldTime),
				KeepaliveInterval: uint64(cfg.KeepaliveInterval),
				ConnectRetry:      uint64(cfg.ConnectRetry),
			},
		},
		Transport: &api.Transport{
			PassiveMode: cfg.PassiveMode,
		},
		AfiSafis: make([]*api.AfiSafi, 0),
	}

	// Set MD5 password if provided
	if cfg.Password != "" {
		peer.Conf.AuthPassword = cfg.Password
	}

	// Set EBGP multihop
	if cfg.EBGPMultihop > 0 {
		peer.EbgpMultihop = &api.EbgpMultihop{
			Enabled:     true,
			MultihopTtl: uint32(cfg.EBGPMultihop),
		}
	}

	// Set route reflector client
	if cfg.RouteReflectorClient {
		peer.RouteReflector = &api.RouteReflector{
			RouteReflectorClient: true,
		}
	}

	// Configure address families
	for _, af := range cfg.EnabledFamilies {
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

	// Set admin state
	if cfg.AdminDown {
		peer.State = &api.PeerState{
			AdminState: api.PeerState_DOWN,
		}
	}

	return peer
}

// peerToPeerInfo converts GoBGP's api.Peer to our PeerInfo.
func (s *Speaker) peerToPeerInfo(p *api.Peer) *PeerInfo {
	if p == nil || p.Conf == nil {
		return nil
	}

	addr, _ := netip.ParseAddr(p.Conf.NeighborAddress)

	info := &PeerInfo{
		Address:     addr,
		ASN:         p.Conf.PeerAsn,
		Description: p.Conf.Description,
	}

	if p.State != nil {
		info.State = s.sessionStateToState(p.State.SessionState)
		info.AdminDown = p.State.AdminState == api.PeerState_DOWN

		if p.State.RouterId != "" {
			info.RemoteRouterID, _ = netip.ParseAddr(p.State.RouterId)
		}

		if p.State.Messages != nil {
			if p.State.Messages.Received != nil {
				info.MessagesReceived = int64(p.State.Messages.Received.Total)
			}
			if p.State.Messages.Sent != nil {
				info.MessagesSent = int64(p.State.Messages.Sent.Total)
			}
		}
	}

	if p.Timers != nil && p.Timers.State != nil {
		info.NegotiatedHoldTime = uint16(p.Timers.State.NegotiatedHoldTime)
		if p.Timers.State.Uptime != nil {
			info.Uptime = time.Duration(p.Timers.State.Uptime.Seconds) * time.Second
		}
	}

	// Get local address from transport
	if p.Transport != nil && p.Transport.LocalAddress != "" {
		info.LocalAddress, _ = netip.ParseAddr(p.Transport.LocalAddress)
	}

	// Parse enabled families
	for _, afiSafi := range p.AfiSafis {
		if afiSafi.Config != nil && afiSafi.Config.Family != nil {
			family := s.apiFamilyToAddressFamily(afiSafi.Config.Family)
			info.EnabledFamilies = append(info.EnabledFamilies, family)
		}
	}

	return info
}

// sessionStateToState converts GoBGP's session state to our PeerState.
func (s *Speaker) sessionStateToState(state api.PeerState_SessionState) PeerState {
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

// addressFamilyToAPI converts our AddressFamily to GoBGP's api.Family.
func (s *Speaker) addressFamilyToAPI(af AddressFamily) *api.Family {
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

// apiFamilyToAddressFamily converts GoBGP's api.Family to our AddressFamily.
func (s *Speaker) apiFamilyToAddressFamily(f *api.Family) AddressFamily {
	if f == nil {
		return AFamilyIPv4Unicast
	}

	switch {
	case f.Afi == api.Family_AFI_IP && f.Safi == api.Family_SAFI_UNICAST:
		return AFamilyIPv4Unicast
	case f.Afi == api.Family_AFI_IP6 && f.Safi == api.Family_SAFI_UNICAST:
		return AFamilyIPv6Unicast
	case f.Afi == api.Family_AFI_L2VPN && f.Safi == api.Family_SAFI_EVPN:
		return AFamilyEVPN
	default:
		return AFamilyIPv4Unicast
	}
}

// ribTypeToTableType converts our RIBType to GoBGP's api.TableType.
func (s *Speaker) ribTypeToTableType(rt RIBType) api.TableType {
	switch rt {
	case RIBLocal:
		return api.TableType_LOCAL
	case RIBAdjIn:
		return api.TableType_ADJ_IN
	case RIBAdjOut:
		return api.TableType_ADJ_OUT
	default:
		return api.TableType_GLOBAL
	}
}

// pathToAPIPath converts our Path to GoBGP's api.Path.
func (s *Speaker) pathToAPIPath(path *Path) (*api.Path, error) {
	apiPath := &api.Path{
		Family: s.addressFamilyToAPI(path.Family),
		Pattrs: make([]*anypb.Any, 0),
	}

	// Set NLRI based on family
	switch path.Family {
	case AFamilyIPv4Unicast, AFamilyIPv6Unicast:
		if !path.Prefix.IsValid() {
			return nil, ErrPrefixInvalid{Reason: "prefix is invalid"}
		}

		nlri, err := anypb.New(&api.IPAddressPrefix{
			PrefixLen: uint32(path.Prefix.Bits()),
			Prefix:    path.Prefix.Addr().String(),
		})
		if err != nil {
			return nil, ErrRouteEncodingFailed{Cause: err}
		}
		apiPath.Nlri = nlri

	case AFamilyEVPN:
		if path.EVPNRoute == nil {
			return nil, ErrInvalidEVPNRoute{RouteType: 0, Reason: "EVPN route data is nil"}
		}
		// EVPN NLRI encoding would go here
		// This is complex and depends on the route type
	}

	// Add origin attribute
	origin, err := anypb.New(&api.OriginAttribute{
		Origin: uint32(path.Origin),
	})
	if err != nil {
		return nil, ErrRouteEncodingFailed{Cause: err}
	}
	apiPath.Pattrs = append(apiPath.Pattrs, origin)

	// Add next hop
	if path.NextHop.IsValid() {
		var nhAttr *anypb.Any
		if path.NextHop.Is4() {
			nhAttr, err = anypb.New(&api.NextHopAttribute{
				NextHop: path.NextHop.String(),
			})
		} else {
			nhAttr, err = anypb.New(&api.MpReachNLRIAttribute{
				Family:   s.addressFamilyToAPI(path.Family),
				NextHops: []string{path.NextHop.String()},
			})
		}
		if err != nil {
			return nil, ErrRouteEncodingFailed{Cause: err}
		}
		apiPath.Pattrs = append(apiPath.Pattrs, nhAttr)
	}

	// Add AS path
	if len(path.ASPath) > 0 {
		segments := []*api.AsSegment{
			{
				Type:    api.AsSegment_AS_SEQUENCE,
				Numbers: path.ASPath,
			},
		}
		asPathAttr, err := anypb.New(&api.AsPathAttribute{
			Segments: segments,
		})
		if err != nil {
			return nil, ErrRouteEncodingFailed{Cause: err}
		}
		apiPath.Pattrs = append(apiPath.Pattrs, asPathAttr)
	}

	// Add local preference
	if path.LocalPref > 0 {
		lpAttr, err := anypb.New(&api.LocalPrefAttribute{
			LocalPref: path.LocalPref,
		})
		if err != nil {
			return nil, ErrRouteEncodingFailed{Cause: err}
		}
		apiPath.Pattrs = append(apiPath.Pattrs, lpAttr)
	}

	// Add MED
	if path.MED > 0 {
		medAttr, err := anypb.New(&api.MultiExitDiscAttribute{
			Med: path.MED,
		})
		if err != nil {
			return nil, ErrRouteEncodingFailed{Cause: err}
		}
		apiPath.Pattrs = append(apiPath.Pattrs, medAttr)
	}

	// Add communities
	if len(path.Communities) > 0 {
		commAttr, err := anypb.New(&api.CommunitiesAttribute{
			Communities: path.Communities,
		})
		if err != nil {
			return nil, ErrRouteEncodingFailed{Cause: err}
		}
		apiPath.Pattrs = append(apiPath.Pattrs, commAttr)
	}

	return apiPath, nil
}

// apiPathToPath converts GoBGP's api.Path to our Path.
func (s *Speaker) apiPathToPath(p *api.Path, family AddressFamily) *Path {
	if p == nil {
		return nil
	}

	path := &Path{
		Family: family,
		Best:   p.Best,
		Stale:  p.Stale,
	}

	// Parse NLRI
	if p.Nlri != nil {
		var ipPrefix api.IPAddressPrefix
		if err := p.Nlri.UnmarshalTo(&ipPrefix); err == nil {
			prefix, err := netip.ParsePrefix(ipPrefix.Prefix + "/" + string(rune(ipPrefix.PrefixLen)))
			if err == nil {
				path.Prefix = prefix
			}
		}
	}

	// Parse path attributes
	for _, attr := range p.Pattrs {
		s.parsePathAttribute(attr, path)
	}

	// Set age
	if p.Age != nil {
		path.Age = p.Age.AsTime()
	}

	return path
}

// parsePathAttribute parses a single path attribute.
func (s *Speaker) parsePathAttribute(attr *anypb.Any, path *Path) {
	if attr == nil {
		return
	}

	// Try each attribute type
	var origin api.OriginAttribute
	if err := attr.UnmarshalTo(&origin); err == nil {
		path.Origin = OriginType(origin.Origin)
		return
	}

	var nextHop api.NextHopAttribute
	if err := attr.UnmarshalTo(&nextHop); err == nil {
		path.NextHop, _ = netip.ParseAddr(nextHop.NextHop)
		return
	}

	var mpReach api.MpReachNLRIAttribute
	if err := attr.UnmarshalTo(&mpReach); err == nil {
		if len(mpReach.NextHops) > 0 {
			path.NextHop, _ = netip.ParseAddr(mpReach.NextHops[0])
		}
		return
	}

	var asPath api.AsPathAttribute
	if err := attr.UnmarshalTo(&asPath); err == nil {
		for _, seg := range asPath.Segments {
			path.ASPath = append(path.ASPath, seg.Numbers...)
		}
		return
	}

	var localPref api.LocalPrefAttribute
	if err := attr.UnmarshalTo(&localPref); err == nil {
		path.LocalPref = localPref.LocalPref
		return
	}

	var med api.MultiExitDiscAttribute
	if err := attr.UnmarshalTo(&med); err == nil {
		path.MED = med.Med
		return
	}

	var communities api.CommunitiesAttribute
	if err := attr.UnmarshalTo(&communities); err == nil {
		path.Communities = communities.Communities
		return
	}
}

// watchResponseToEvent converts GoBGP's watch response to our Event.
func (s *Speaker) watchResponseToEvent(resp *api.WatchEventResponse, wopts *watchOptions) *Event {
	if resp == nil {
		return nil
	}

	event := &Event{
		Timestamp: time.Now(),
	}

	// Handle peer events
	if resp.GetPeer() != nil {
		event.Type = EventPeerStateChange

		if resp.GetPeer().Peer != nil && resp.GetPeer().Peer.Conf != nil {
			event.PeerAddress, _ = netip.ParseAddr(resp.GetPeer().Peer.Conf.NeighborAddress)
		}

		if resp.GetPeer().Peer != nil && resp.GetPeer().Peer.State != nil {
			event.PeerState = s.sessionStateToState(resp.GetPeer().Peer.State.SessionState)
		}

		// Filter by peer address if specified
		if wopts.peerAddress.IsValid() && event.PeerAddress != wopts.peerAddress {
			return nil
		}

		// Invoke callback
		if s.onPeerStateChange != nil {
			s.onPeerStateChange(event.PeerAddress, event.PeerState)
		}

		return event
	}

	// Handle table events (path changes)
	if resp.GetTable() != nil {
		for _, dest := range resp.GetTable().Paths {
			if dest.IsWithdraw {
				event.Type = EventPathWithdrawn
			} else {
				event.Type = EventPathReceived
			}

			// Convert path
			family := AFamilyIPv4Unicast
			if dest.Family != nil {
				family = s.apiFamilyToAddressFamily(dest.Family)
			}

			// Filter by family if specified
			if len(wopts.families) > 0 {
				found := false
				for _, f := range wopts.families {
					if f == family {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			event.Path = s.apiPathToPath(dest, family)

			// Invoke callback
			if s.onRouteReceived != nil {
				s.onRouteReceived(event.Path)
			}

			return event
		}
	}

	return nil
}
