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
	"math"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// BGPServerInterface abstracts GoBGP server operations for testing.
type BGPServerInterface interface {
	Start() error
	Stop()
	StartBgp(ctx context.Context, req *api.StartBgpRequest) error
	StopBgp(ctx context.Context, req *api.StopBgpRequest) error
	AddPeer(ctx context.Context, req *api.AddPeerRequest) error
	DeletePeer(ctx context.Context, req *api.DeletePeerRequest) error
	UpdatePeer(ctx context.Context, req *api.UpdatePeerRequest) (*api.UpdatePeerResponse, error)
	GetBgp(ctx context.Context, req *api.GetBgpRequest) (*api.GetBgpResponse, error)
	ListPeer(ctx context.Context, req *api.ListPeerRequest, fn func(*api.Peer)) error
	ResetPeer(ctx context.Context, req *api.ResetPeerRequest) error
	EnableMrt(ctx context.Context, req *api.EnableMrtRequest) error
	DisableMrt(ctx context.Context, req *api.DisableMrtRequest) error
	AddPath(ctx context.Context, req *api.AddPathRequest) (*api.AddPathResponse, error)
	DeletePath(ctx context.Context, req *api.DeletePathRequest) error
	ListPath(ctx context.Context, req *api.ListPathRequest, fn func(*api.Destination)) error
	WatchEvent(ctx context.Context, req *api.WatchEventRequest, fn func(*api.WatchEventResponse)) error
	AddTcpAoKeychain(ctx context.Context, req *api.AddTcpAoKeychainRequest) error
	SetPolicies(ctx context.Context, req *api.SetPoliciesRequest) error
	SetPolicyAssignment(ctx context.Context, req *api.SetPolicyAssignmentRequest) error
}

// gobgpServerWrapper wraps a real GoBGP server to implement BGPServerInterface.
type gobgpServerWrapper struct {
	server *server.BgpServer
}

// NewGoBGPServerAdapter adapts a GoBGP v4 server to BGPServerInterface: the
// wire-shaped api.* vocabulary in, GoBGP's native in-process API underneath.
// It is the one place the platform converts between the two, shared by the
// speaker and by the integration mock peer.
func NewGoBGPServerAdapter(srv *server.BgpServer) BGPServerInterface {
	return &gobgpServerWrapper{server: srv}
}

// Start runs the server's event loop. GoBGP v4's Serve blocks until Stop,
// so it runs on its own goroutine; every later call reaches it through the
// server's management channel, which Serve drains.
func (w *gobgpServerWrapper) Start() error {
	go w.server.Serve()
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

func (w *gobgpServerWrapper) UpdatePeer(ctx context.Context, req *api.UpdatePeerRequest) (*api.UpdatePeerResponse, error) {
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

// AddPath installs a locally originated path. GoBGP v4 takes native
// apiutil paths on its in-process API; the wire-shaped api.Path the
// speaker builds is converted here so the seam stays the gRPC vocabulary
// every mock already speaks.
func (w *gobgpServerWrapper) AddPath(ctx context.Context, req *api.AddPathRequest) (*api.AddPathResponse, error) {
	if req == nil || req.Path == nil {
		return nil, ErrPrefixInvalid{Reason: "path is nil"}
	}
	path, err := apiPathToNative(req.Path)
	if err != nil {
		return nil, err
	}
	resp, err := w.server.AddPath(apiutil.AddPathRequest{VRFID: req.VrfId, Paths: []*apiutil.Path{path}})
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return &api.AddPathResponse{}, nil
	}
	if resp[0].Error != nil {
		return nil, resp[0].Error
	}
	id, err := resp[0].UUID.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &api.AddPathResponse{Uuid: id}, nil
}

// DeletePath withdraws a locally originated path.
func (w *gobgpServerWrapper) DeletePath(ctx context.Context, req *api.DeletePathRequest) error {
	if req == nil || req.Path == nil {
		return ErrPrefixInvalid{Reason: "path is nil"}
	}
	path, err := apiPathToNative(req.Path)
	if err != nil {
		return err
	}
	return w.server.DeletePath(apiutil.DeletePathRequest{VRFID: req.VrfId, Paths: []*apiutil.Path{path}})
}

// ListPath walks a RIB, handing each destination back in wire shape.
func (w *gobgpServerWrapper) ListPath(ctx context.Context, req *api.ListPathRequest, fn func(*api.Destination)) error {
	if req == nil {
		return ErrPrefixInvalid{Reason: "request is nil"}
	}
	family := gobgp.Family(0)
	if req.Family != nil {
		family = apiutil.ToFamily(req.Family)
	}
	nreq := apiutil.ListPathRequest{
		TableType:      req.TableType,
		Name:           req.Name,
		Family:         family,
		SortType:       req.SortType,
		EnableFiltered: req.EnableFiltered,
	}
	return w.server.ListPath(nreq, func(prefix gobgp.NLRI, paths []*apiutil.Path) {
		if ctx.Err() != nil {
			return
		}
		dest := &api.Destination{Prefix: prefix.String(), Paths: make([]*api.Path, 0, len(paths))}
		for _, np := range paths {
			if p := nativePathToAPI(np); p != nil {
				dest.Paths = append(dest.Paths, p)
			}
		}
		fn(dest)
	})
}

// fsmStateToAPI converts GoBGP's internal 0-based FSM state (BGP_FSM_IDLE=0 …
// BGP_FSM_ESTABLISHED=5, pkg/packet/bgp/constant.go) to the gRPC enum, whose
// value 0 is SESSION_STATE_UNSPECIFIED and whose IDLE is 1 (api/gobgp.pb.go).
// The +1 is the same conversion GoBGP's own grpc_server.go applies; it is not
// an off-by-one.
func fsmStateToAPI(state gobgp.FSMState) api.PeerState_SessionState {
	return api.PeerState_SessionState(int(state) + 1)
}

// WatchEvent subscribes to peer and table events. GoBGP v4 replaced the
// request/response stream with callbacks and options; both are mapped
// back to the wire shape so the speaker's event loop is unchanged.
func (w *gobgpServerWrapper) WatchEvent(ctx context.Context, req *api.WatchEventRequest, fn func(*api.WatchEventResponse)) error {
	if req == nil {
		return ErrPrefixInvalid{Reason: "request is nil"}
	}
	opts := make([]server.WatchOption, 0)
	if req.GetPeer() != nil {
		opts = append(opts, server.WatchPeer())
	}
	if t := req.GetTable(); t != nil {
		for _, filter := range t.Filters {
			switch filter.Type {
			case api.WatchEventRequest_Table_Filter_TYPE_BEST:
				opts = append(opts, server.WatchBestPath(filter.Init))
			case api.WatchEventRequest_Table_Filter_TYPE_ADJIN:
				opts = append(opts, server.WatchUpdate(filter.Init, filter.PeerAddress, filter.PeerGroup))
			case api.WatchEventRequest_Table_Filter_TYPE_POST_POLICY:
				opts = append(opts, server.WatchPostUpdate(filter.Init, filter.PeerAddress, filter.PeerGroup))
			case api.WatchEventRequest_Table_Filter_TYPE_EOR:
				opts = append(opts, server.WatchEor(filter.Init))
			default:
				return &ErrServerOperationFailed{Operation: "watch", Cause: ErrWatchFilterUnknown{Type: filter.Type.String()}}
			}
		}
	}
	if len(opts) == 0 {
		return &ErrServerOperationFailed{Operation: "watch", Cause: ErrWatchFilterUnknown{Type: "none"}}
	}
	sendPaths := func(paths []*apiutil.Path) {
		out := make([]*api.Path, 0, len(paths))
		for _, np := range paths {
			if p := nativePathToAPI(np); p != nil {
				out = append(out, p)
			}
		}
		fn(&api.WatchEventResponse{Event: &api.WatchEventResponse_Table{Table: &api.WatchEventResponse_TableEvent{Paths: out}}})
	}
	callbacks := server.WatchEventMessageCallbacks{
		OnPathUpdate: func(paths []*apiutil.Path, _ time.Time) { sendPaths(paths) },
		OnBestPath:   func(paths []*apiutil.Path, _ time.Time) { sendPaths(paths) },
		OnPathEor:    func(path *apiutil.Path, _ time.Time) { sendPaths([]*apiutil.Path{path}) },
		OnPeerUpdate: func(peer *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
			if peer == nil {
				return
			}
			p := peer.Peer
			fn(&api.WatchEventResponse{Event: &api.WatchEventResponse_Peer{Peer: &api.WatchEventResponse_PeerEvent{
				Type: api.WatchEventResponse_PeerEvent_Type(peer.Type),
				Peer: &api.Peer{
					Conf: &api.PeerConf{
						PeerAsn:         p.Conf.PeerASN,
						LocalAsn:        p.Conf.LocalASN,
						NeighborAddress: p.Conf.NeighborAddress.String(),
						PeerGroup:       p.Conf.PeerGroup,
					},
					State: &api.PeerState{
						PeerAsn:         p.State.PeerASN,
						LocalAsn:        p.State.LocalASN,
						NeighborAddress: p.State.NeighborAddress.String(),
						SessionState:    fsmStateToAPI(p.State.SessionState),
						AdminState:      p.State.AdminState,
						RouterId:        p.State.RouterID.String(),
						PeerGroup:       p.State.PeerGroup,
					},
					Transport: &api.Transport{
						LocalAddress: p.Transport.LocalAddress.String(),
						LocalPort:    p.Transport.LocalPort,
						RemotePort:   p.Transport.RemotePort,
					},
				},
			}}})
		},
	}
	if err := w.server.WatchEvent(ctx, callbacks, opts...); err != nil {
		return &ErrServerOperationFailed{Operation: "watch", Cause: err}
	}
	<-ctx.Done()
	return nil
}

// AddTcpAoKeychain registers a TCP-AO keychain with the server.
func (w *gobgpServerWrapper) AddTcpAoKeychain(ctx context.Context, req *api.AddTcpAoKeychainRequest) error {
	return w.server.AddTcpAoKeychain(ctx, req)
}

// SetPolicies replaces the server's routing policy set atomically.
func (w *gobgpServerWrapper) SetPolicies(ctx context.Context, req *api.SetPoliciesRequest) error {
	return w.server.SetPolicies(ctx, req)
}

// SetPolicyAssignment replaces one direction's policy assignment.
func (w *gobgpServerWrapper) SetPolicyAssignment(ctx context.Context, req *api.SetPolicyAssignmentRequest) error {
	return w.server.SetPolicyAssignment(ctx, req)
}

// apiPathToNative turns a wire-shaped path into the native path GoBGP v4's
// in-process API consumes.
func apiPathToNative(p *api.Path) (*apiutil.Path, error) {
	nlri, err := apiutil.GetNativeNlri(p)
	if err != nil {
		return nil, ErrRouteEncodingFailed{Cause: err}
	}
	attrs, err := apiutil.GetNativePathAttributes(p)
	if err != nil {
		return nil, ErrRouteEncodingFailed{Cause: err}
	}
	family := gobgp.Family(0)
	if p.Family != nil {
		family = apiutil.ToFamily(p.Family)
	}
	src, _ := netip.ParseAddr(p.SourceId)
	neighbor, _ := netip.ParseAddr(p.NeighborIp)
	return &apiutil.Path{
		Family:             family,
		Nlri:               nlri,
		Attrs:              attrs,
		Age:                p.GetAge().GetSeconds(),
		Best:               p.Best,
		Stale:              p.Stale,
		Withdrawal:         p.IsWithdraw,
		PeerASN:            p.SourceAsn,
		PeerID:             src,
		PeerAddress:        neighbor,
		IsFromExternal:     p.IsFromExternal,
		NoImplicitWithdraw: p.NoImplicitWithdraw,
		LocalID:            p.LocalIdentifier,
		RemoteID:           p.Identifier,
	}, nil
}

// nativePathToAPI turns a native path back into wire shape. A path whose
// NLRI or attributes cannot be marshalled is dropped rather than returned
// half-converted.
func nativePathToAPI(np *apiutil.Path) *api.Path {
	if np == nil || np.Nlri == nil {
		return nil
	}
	p, err := apiutil.NewPath(np.Family, np.Nlri, np.Withdrawal, np.Attrs, time.Unix(np.Age, 0))
	if err != nil {
		return nil
	}
	p.Best = np.Best
	p.Stale = np.Stale
	p.Filtered = np.Filtered
	p.SourceAsn = np.PeerASN
	if np.PeerID.IsValid() {
		p.SourceId = np.PeerID.String()
	}
	if np.PeerAddress.IsValid() {
		p.NeighborIp = np.PeerAddress.String()
	}
	p.IsFromExternal = np.IsFromExternal
	p.NoImplicitWithdraw = np.NoImplicitWithdraw
	p.IsNexthopInvalid = np.IsNexthopInvalid
	p.Identifier = np.RemoteID
	p.LocalIdentifier = np.LocalID
	return p
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

	// Graceful restart (RFC 4724) is on unless the configuration turns it
	// off: a speaker restart must not withdraw the site's prefixes.
	if s.config.GracefulRestartEnabled() {
		restartTime := s.config.GracefulRestartTime
		if restartTime == 0 {
			restartTime = DefaultGracefulRestartTime
		}
		global.GracefulRestart = &api.GracefulRestart{
			Enabled:             true,
			RestartTime:         uint32(restartTime),
			NotificationEnabled: true,
		}
	}

	req := &api.StartBgpRequest{Global: global}
	if err := s.server.StartBgp(ctx, req); err != nil {
		s.server.Stop()
		return &ErrServerOperationFailed{Operation: "start_bgp", Cause: err}
	}

	// TCP-AO keychains must exist before a peer references them.
	for i := range s.config.Keychains {
		chain := &s.config.Keychains[i]
		if err := s.server.AddTcpAoKeychain(ctx, &api.AddTcpAoKeychainRequest{Keychain: keychainToAPI(chain)}); err != nil {
			s.server.Stop()
			return &ErrServerOperationFailed{Operation: "add_keychain", Cause: err}
		}
	}

	// RFC 8212: every peer's import and export default to reject. The two
	// global policies are installed, then assigned to the global RIB once;
	// later SetPolicies calls keep the assignment (policy.go).
	if err := s.installPolicies(ctx); err != nil {
		s.server.Stop()
		return err
	}
	for _, assignment := range globalAssignments() {
		if err := s.server.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{Assignment: assignment}); err != nil {
			s.server.Stop()
			return &ErrServerOperationFailed{Operation: "set_policy_assignment", Cause: err}
		}
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

	// The direction rules need the speaker's own ASN, which Validate does
	// not have. A peer added at runtime gets the same check the configured
	// ones get in BGPConfig.Validate.
	if s.config != nil {
		if err := cfg.validateAttributeDirections(s.config.ASN); err != nil {
			return err
		}
	}

	if cfg.AuthType == AuthTypeTCPAO {
		// GoBGP v4.9.0 stores keychains but has no field binding one to a
		// neighbor session; running the session anyway would be an
		// unauthenticated session the configuration calls tcp-ao.
		return ErrTCPAOSessionBindingUnsupported{Peer: cfg.Address.String(), GoBGP: goBGPVersion}
	}

	peer := s.neighborConfigToPeer(cfg)

	// The peer's import/export policy must exist before the session does:
	// a runtime-added neighbor that is not in the initial config would
	// otherwise reference a policy name nothing installed and run without
	// its prefix filtering. Register it, re-install the set, then add the
	// session; a failed add takes the registration back out.
	registered := s.registerNeighbor(cfg)
	if registered {
		if err := s.installPolicies(ctx); err != nil {
			s.unregisterNeighbor(cfg.Address)
			return err
		}
	}

	s.logger.Info("adding BGP peer",
		"address", cfg.Address,
		"asn", cfg.ASN,
		"description", cfg.Description,
		"import_attributes", cfg.Policy.Import.describe(),
		"export_attributes", cfg.Policy.Export.describe())

	if err := s.server.AddPeer(ctx, &api.AddPeerRequest{Peer: peer}); err != nil {
		if registered {
			s.unregisterNeighbor(cfg.Address)
		}
		return &ErrPeerOperationFailed{
			Operation:   "add",
			PeerAddress: cfg.Address,
			Cause:       err,
		}
	}

	return nil
}

// installPolicies builds the policy set for the configured neighbors and
// installs it. Callers hold s.mu.
func (s *Speaker) installPolicies(ctx context.Context) error {
	set, err := s.policySet()
	if err != nil {
		return err
	}
	if err := s.server.SetPolicies(ctx, set); err != nil {
		return &ErrServerOperationFailed{Operation: "set_policies", Cause: err}
	}
	return nil
}

// registerNeighbor adds cfg to the speaker's neighbor list when no neighbor
// with that address is configured, so policySet covers it. It reports
// whether it added anything. Callers hold s.mu.
func (s *Speaker) registerNeighbor(cfg *NeighborConfig) bool {
	if s.config == nil {
		return false
	}
	for i := range s.config.Neighbors {
		if s.config.Neighbors[i].Address == cfg.Address {
			return false
		}
	}
	s.config.Neighbors = append(s.config.Neighbors, *cfg)
	return true
}

// unregisterNeighbor removes the neighbor with addr from the speaker's
// neighbor list. Callers hold s.mu.
func (s *Speaker) unregisterNeighbor(addr netip.Addr) {
	if s.config == nil {
		return
	}
	for i := range s.config.Neighbors {
		if s.config.Neighbors[i].Address == addr {
			s.config.Neighbors = append(s.config.Neighbors[:i], s.config.Neighbors[i+1:]...)
			return
		}
	}
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
	// The neighbor leaves the configured set with its session, so the
	// policy set re-installed by a later AddPeer no longer carries it.
	s.unregisterNeighbor(addr)

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
			AdminState: api.PeerState_ADMIN_STATE_UP,
		},
	}

	_, err := s.server.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: peer})
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
			AdminState: api.PeerState_ADMIN_STATE_DOWN,
		},
	}

	_, err := s.server.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: peer})
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
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
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
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
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
				Type: api.WatchEventRequest_Table_Filter_TYPE_BEST,
			}
			if wopts.bestPathOnly {
				filter.Type = api.WatchEventRequest_Table_Filter_TYPE_BEST
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
		if p.State != nil && p.State.SessionState == api.PeerState_SESSION_STATE_ESTABLISHED {
			establishedCount++
		}
	})
	if err != nil {
		s.logger.Warn("error counting peers", "error", err)
	}

	// Count paths
	var pathCount int64
	err = s.server.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
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

// goBGPVersion is the GoBGP release the speaker is built against; it is
// named in the refusal for capabilities that release does not carry.
const goBGPVersion = "v4.9.0"

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
		// No ApplyPolicy: GoBGP ignores a per-peer assignment on any peer
		// that is not a route-server client. The peer's RFC 8212 policy is
		// its statements in the global policies (policy.go).
		AfiSafis: make([]*api.AfiSafi, 0),
	}

	// MD5 session authentication (non-FIPS compatibility path). The secret
	// was resolved from its reference; a reference is never used directly.
	if cfg.AuthType == AuthTypeMD5 && cfg.AuthKey != "" {
		peer.Conf.AuthPassword = cfg.AuthKey
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

	if cfg.RemovePrivateAS {
		peer.Conf.RemovePrivate = api.RemovePrivate_REMOVE_PRIVATE_ALL
	}

	// Single-hop BFD (RFC 5881) for fast failure detection.
	if cfg.BFD != nil && cfg.BFD.Enabled {
		peer.Bfd = &api.BfdPeerConfig{
			Enabled:                  true,
			Port:                     uint32(cfg.BFD.Port),
			DesiredMinimumTxInterval: uint32(cfg.BFD.DesiredMinTxInterval / time.Microsecond),
			RequiredMinimumReceive:   uint32(cfg.BFD.RequiredMinRxInterval / time.Microsecond),
			DetectionMultiplier:      uint32(cfg.BFD.DetectionMultiplier),
		}
	}

	// Graceful restart per peer follows the global setting.
	if s.config != nil && s.config.GracefulRestartEnabled() {
		peer.GracefulRestart = &api.GracefulRestart{
			Enabled:             true,
			RestartTime:         uint32(s.config.GracefulRestartTime),
			NotificationEnabled: true,
		}
	}

	// Configure address families, each with its own prefix limit.
	for _, af := range cfg.Families() {
		family := s.addressFamilyToAPI(af)
		if family == nil {
			continue
		}
		peer.AfiSafis = append(peer.AfiSafis, &api.AfiSafi{
			Config: &api.AfiSafiConfig{
				Enabled: true,
				Family:  family,
			},
			PrefixLimits: &api.PrefixLimit{
				Family:               family,
				MaxPrefixes:          cfg.PrefixLimit(af),
				ShutdownThresholdPct: prefixLimitWarnPct,
			},
		})
	}

	// Set admin state
	if cfg.AdminDown {
		peer.State = &api.PeerState{
			AdminState: api.PeerState_ADMIN_STATE_DOWN,
		}
	}

	return peer
}

// prefixLimitWarnPct is the percentage of the prefix limit at which GoBGP
// logs a warning before the session is torn down at the limit itself.
const prefixLimitWarnPct = 80

// keychainToAPI converts a resolved keychain to GoBGP's shape. The master
// key travels here and nowhere else.
func keychainToAPI(c *TCPAOKeychainConfig) *api.TcpAoKeychain {
	out := &api.TcpAoKeychain{Name: c.Name, Keys: make([]*api.TcpAoKey, 0, len(c.Keys))}
	for i := range c.Keys {
		k := &c.Keys[i]
		out.Keys = append(out.Keys, &api.TcpAoKey{
			SendId:            uint32(k.SendID),
			ReceiveId:         uint32(k.ReceiveID),
			Algorithm:         tcpAOAlgorithmToAPI(k.Algorithm),
			MasterKey:         k.MasterKey,
			ExcludeTcpOptions: k.ExcludeTCPOptions,
		})
	}
	return out
}

// tcpAOAlgorithmToAPI maps the configured algorithm to GoBGP's enum.
func tcpAOAlgorithmToAPI(a TCPAOAlgorithm) api.TcpAoAlgorithm {
	switch a {
	case TCPAOAlgorithmHMACSHA256_96:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_96
	case TCPAOAlgorithmAES128CMAC96:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96
	case TCPAOAlgorithmHMACSHA1_96:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96
	default:
		return api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128
	}
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
		info.AdminDown = p.State.AdminState == api.PeerState_ADMIN_STATE_DOWN

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

	// Parse enabled families and sum their prefix counters.
	for _, afiSafi := range p.AfiSafis {
		if afiSafi.Config != nil && afiSafi.Config.Family != nil {
			family := s.apiFamilyToAddressFamily(afiSafi.Config.Family)
			info.EnabledFamilies = append(info.EnabledFamilies, family)
		}
		if afiSafi.State != nil {
			info.PrefixesReceived += int64(afiSafi.State.Received)
			info.PrefixesAccepted += int64(afiSafi.State.Accepted)
			info.PrefixesSent += int64(afiSafi.State.Advertised)
		}
	}

	info.BFD = bfdSessionInfo(p)

	return info
}

// bfdSessionStates maps GoBGP's BFD session states onto the speaker's
// vocabulary.
var bfdSessionStates = map[api.BfdSessionState]BFDSessionState{
	api.BfdSessionState_BFD_SESSION_STATE_UP:         BFDSessionUp,
	api.BfdSessionState_BFD_SESSION_STATE_DOWN:       BFDSessionDown,
	api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN: BFDSessionAdminDown,
	api.BfdSessionState_BFD_SESSION_STATE_INIT:       BFDSessionInit,
}

// bfdSessionStateToState converts a GoBGP BFD session state; an unknown or
// unspecified value is reported as such rather than guessed.
func bfdSessionStateToState(state api.BfdSessionState) BFDSessionState {
	if mapped, ok := bfdSessionStates[state]; ok {
		return mapped
	}
	return BFDSessionUnknown
}

// bfdDiagnosticNames spells the RFC 5880 §4.1 diagnostic codes.
var bfdDiagnosticNames = map[api.BfdDiagnosticCode]string{
	api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_NO_DIAGNOSTIC:                  "none",
	api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_DETECTION_TIMEOUT:              "detection-timeout",
	api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_ECHO_FAILED:                    "echo-failed",
	api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_NEIGHBOR_SIGNALED_SESSION_DOWN: "neighbor-signaled-down",
	api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_FORWARDING_PLANE_RESET:         "forwarding-plane-reset",
	api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_PATH_DOWN:                      "path-down",
	api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_CONCATENATED_PATH_DOWN:         "concatenated-path-down",
	api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_ADMINISTRATIVELY_DOWN:          "administratively-down",
	api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_REVERSE_CONCATENATED_PATH_DOWN: "reverse-concatenated-path-down",
}

// bfdDiagnosticName spells a diagnostic code; an unknown code is reported
// by number so nothing is hidden.
func bfdDiagnosticName(code api.BfdDiagnosticCode) string {
	if name, ok := bfdDiagnosticNames[code]; ok {
		return name
	}
	return "code-" + strconv.Itoa(int(code))
}

// bfdSessionInfo reads the peer's BFD configuration and session state. It
// returns nil when BFD is not enabled toward the peer, so a snapshot never
// shows a session that was never asked for.
func bfdSessionInfo(p *api.Peer) *BFDSessionInfo {
	if p.Bfd == nil || !p.Bfd.Enabled {
		return nil
	}
	info := &BFDSessionInfo{
		LocalState:            BFDSessionUnknown,
		RemoteState:           BFDSessionUnknown,
		DesiredMinTxInterval:  time.Duration(p.Bfd.DesiredMinimumTxInterval) * time.Microsecond,
		RequiredMinRxInterval: time.Duration(p.Bfd.RequiredMinimumReceive) * time.Microsecond,
		DetectionMultiplier:   uint8(min(p.Bfd.DetectionMultiplier, 255)),
	}
	if p.State == nil || p.State.BfdState == nil {
		return info
	}
	st := p.State.BfdState
	info.LocalState = bfdSessionStateToState(st.SessionState)
	info.RemoteState = bfdSessionStateToState(st.RemoteSessionState)
	info.LocalDiscriminator = st.LocalDiscriminator
	info.RemoteDiscriminator = st.RemoteDiscriminator
	info.FailureTransitions = st.FailureTransitions
	if st.LastFailureTime > 0 {
		info.LastFailure = time.Unix(int64(min(st.LastFailureTime, math.MaxInt64)), 0).UTC()
	}
	info.LocalDiagnostic = bfdDiagnosticName(st.LocalDiagnosticCode)
	info.RemoteDiagnostic = bfdDiagnosticName(st.RemoteDiagnosticCode)
	return info
}

// sessionStateToState converts GoBGP's session state to our PeerState.
func (s *Speaker) sessionStateToState(state api.PeerState_SessionState) PeerState {
	switch state {
	case api.PeerState_SESSION_STATE_IDLE:
		return PeerStateIdle
	case api.PeerState_SESSION_STATE_CONNECT:
		return PeerStateConnect
	case api.PeerState_SESSION_STATE_ACTIVE:
		return PeerStateActive
	case api.PeerState_SESSION_STATE_OPENSENT:
		return PeerStateOpenSent
	case api.PeerState_SESSION_STATE_OPENCONFIRM:
		return PeerStateOpenConfirm
	case api.PeerState_SESSION_STATE_ESTABLISHED:
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
		// An unknown family is never substituted with IPv4 unicast: the
		// enumerating caller skips a nil and a request caller fails loudly
		// in GoBGP rather than programming the wrong AFI.
		return nil
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
		return api.TableType_TABLE_TYPE_LOCAL
	case RIBAdjIn:
		return api.TableType_TABLE_TYPE_ADJ_IN
	case RIBAdjOut:
		return api.TableType_TABLE_TYPE_ADJ_OUT
	default:
		return api.TableType_TABLE_TYPE_GLOBAL
	}
}

// pathToAPIPath converts our Path to GoBGP's api.Path.
func (s *Speaker) pathToAPIPath(path *Path) (*api.Path, error) {
	apiPath := &api.Path{
		Family: s.addressFamilyToAPI(path.Family),
		Pattrs: make([]*api.Attribute, 0, 6),
	}

	// Set NLRI based on family
	switch path.Family {
	case AFamilyIPv4Unicast, AFamilyIPv6Unicast:
		if !path.Prefix.IsValid() {
			return nil, ErrPrefixInvalid{Reason: "prefix is invalid"}
		}
		apiPath.Nlri = &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{
			PrefixLen: uint32(path.Prefix.Bits()),
			Prefix:    path.Prefix.Addr().String(),
		}}}

	case AFamilyEVPN:
		if path.EVPNRoute == nil {
			return nil, ErrInvalidEVPNRoute{RouteType: 0, Reason: "EVPN route data is nil"}
		}
		// EVPN NLRI encoding would go here
		// This is complex and depends on the route type
	}

	// Add origin attribute
	apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{
		Origin: uint32(path.Origin),
	}}})

	// Add next hop. IPv4 unicast carries it in NEXT_HOP; everything else in
	// MP_REACH_NLRI, which for the MP families must also carry the NLRI.
	if path.NextHop.IsValid() {
		if path.NextHop.Is4() {
			apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{
				NextHop: path.NextHop.String(),
			}}})
		} else {
			mp := &api.MpReachNLRIAttribute{
				Family:   s.addressFamilyToAPI(path.Family),
				NextHops: []string{path.NextHop.String()},
			}
			if apiPath.Nlri != nil {
				mp.Nlris = []*api.NLRI{apiPath.Nlri}
			}
			apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: mp}})
		}
	}

	// Add AS path
	if len(path.ASPath) > 0 {
		apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_AsPath{AsPath: &api.AsPathAttribute{
			Segments: []*api.AsSegment{{
				Type:    api.AsSegment_TYPE_AS_SEQUENCE,
				Numbers: path.ASPath,
			}},
		}}})
	}

	// Add local preference
	if path.LocalPref > 0 {
		apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_LocalPref{LocalPref: &api.LocalPrefAttribute{
			LocalPref: path.LocalPref,
		}}})
	}

	// Add MED
	if path.MED > 0 {
		apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_MultiExitDisc{MultiExitDisc: &api.MultiExitDiscAttribute{
			Med: path.MED,
		}}})
	}

	// Add communities
	if len(path.Communities) > 0 {
		apiPath.Pattrs = append(apiPath.Pattrs, &api.Attribute{Attr: &api.Attribute_Communities{Communities: &api.CommunitiesAttribute{
			Communities: path.Communities,
		}}})
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
	if ipPrefix := p.GetNlri().GetPrefix(); ipPrefix != nil {
		prefix, err := netip.ParsePrefix(ipPrefix.Prefix + "/" + strconv.FormatUint(uint64(ipPrefix.PrefixLen), 10))
		if err == nil {
			path.Prefix = prefix
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
func (s *Speaker) parsePathAttribute(attr *api.Attribute, path *Path) {
	if attr == nil {
		return
	}
	switch a := attr.Attr.(type) {
	case *api.Attribute_Origin:
		path.Origin = OriginType(a.Origin.GetOrigin())
	case *api.Attribute_NextHop:
		path.NextHop, _ = netip.ParseAddr(a.NextHop.GetNextHop())
	case *api.Attribute_MpReach:
		if hops := a.MpReach.GetNextHops(); len(hops) > 0 {
			path.NextHop, _ = netip.ParseAddr(hops[0])
		}
	case *api.Attribute_AsPath:
		for _, seg := range a.AsPath.GetSegments() {
			path.ASPath = append(path.ASPath, seg.Numbers...)
		}
	case *api.Attribute_LocalPref:
		path.LocalPref = a.LocalPref.GetLocalPref()
	case *api.Attribute_MultiExitDisc:
		path.MED = a.MultiExitDisc.GetMed()
	case *api.Attribute_Communities:
		path.Communities = a.Communities.GetCommunities()
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
