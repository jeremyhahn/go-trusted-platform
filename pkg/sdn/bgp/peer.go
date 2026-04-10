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
)

// PeerType represents the type of BGP peering.
type PeerType uint8

const (
	// PeerTypeUnknown indicates an unknown peer type.
	PeerTypeUnknown PeerType = iota

	// PeerTypeIBGP indicates an internal BGP peer.
	PeerTypeIBGP

	// PeerTypeEBGP indicates an external BGP peer.
	PeerTypeEBGP
)

// String returns a human-readable representation of the peer type.
func (t PeerType) String() string {
	switch t {
	case PeerTypeIBGP:
		return "iBGP"
	case PeerTypeEBGP:
		return "eBGP"
	default:
		return "unknown"
	}
}

// PeerNeighborConfig holds configuration for a BGP neighbor in the peer manager.
// This is a specialized config for the peer manager that differs from the speaker-level NeighborConfig.
type PeerNeighborConfig struct {
	// Address is the IP address of the neighbor.
	Address netip.Addr

	// RemoteAS is the AS number of the neighbor.
	RemoteAS uint32

	// LocalAS is the local AS number (if different from global).
	LocalAS uint32

	// Type is the peering type (iBGP or eBGP).
	Type PeerType

	// Description is a human-readable description of the neighbor.
	Description string

	// MD5Secret is the MD5 authentication password.
	MD5Secret string

	// HoldTime is the hold timer in seconds.
	HoldTime uint16

	// KeepaliveInterval is the keepalive interval in seconds.
	KeepaliveInterval uint16

	// ConnectRetry is the connect retry interval in seconds.
	ConnectRetry uint16

	// Passive indicates whether the peer should be passive (not initiate connections).
	Passive bool

	// RouteReflectorClient indicates if this is a route reflector client.
	RouteReflectorClient bool

	// BFDEnabled indicates whether BFD is enabled for this peer.
	BFDEnabled bool

	// AdminDown indicates if the peer is administratively disabled.
	AdminDown bool
}

// Validate validates the neighbor configuration.
func (c *PeerNeighborConfig) Validate() error {
	if !c.Address.IsValid() {
		return ErrInvalidPeerAddress
	}
	if c.Address.IsUnspecified() {
		return ErrInvalidPeerAddress
	}
	if c.RemoteAS == 0 {
		return ErrInvalidRemoteAS
	}
	if c.Type == PeerTypeUnknown {
		return ErrInvalidPeerType
	}
	return nil
}

// ManagedPeer wraps a peer with management state.
type ManagedPeer struct {
	// Config is the peer configuration.
	Config *PeerNeighborConfig

	// State is the current peer state.
	State PeerState

	// LastStateChange is when the state last changed.
	LastStateChange time.Time

	// ConsecutiveFails is the number of consecutive connection failures.
	ConsecutiveFails int

	// Enabled indicates if the peer is enabled.
	Enabled bool

	// AdminDown indicates if the peer is administratively down.
	AdminDown bool

	// LastError contains the last error message.
	LastError string

	// EstablishedAt is when the peer was last established.
	EstablishedAt time.Time

	// RoutesReceived is the number of routes received from this peer.
	RoutesReceived int64

	// RoutesSent is the number of routes sent to this peer.
	RoutesSent int64
}

// Uptime returns the duration since the peer was established.
// Returns zero if not established.
func (p *ManagedPeer) Uptime() time.Duration {
	if p.State != PeerStateEstablished {
		return 0
	}
	return time.Since(p.EstablishedAt)
}

// PeerHealth contains peer health information.
type PeerHealth struct {
	// Address is the peer address.
	Address netip.Addr

	// Healthy indicates if the peer is healthy (Established).
	Healthy bool

	// State is the current peer state.
	State PeerState

	// Uptime is the duration since establishment.
	Uptime time.Duration

	// LastError is the last error message.
	LastError string

	// FailCount is the consecutive failure count.
	FailCount int

	// RoutesReceived is the number of routes received.
	RoutesReceived int64

	// RoutesSent is the number of routes sent.
	RoutesSent int64
}

// PeerSpeakerInterface defines the interface for peer operations on the speaker.
type PeerSpeakerInterface interface {
	// AddPeer adds a BGP peer.
	AddPeer(ctx context.Context, cfg *PeerNeighborConfig) error

	// RemovePeer removes a BGP peer.
	RemovePeer(ctx context.Context, addr netip.Addr) error

	// GetPeerState gets the state of a peer.
	GetPeerState(ctx context.Context, addr netip.Addr) (PeerState, error)

	// EnablePeer enables a peer.
	EnablePeer(ctx context.Context, addr netip.Addr) error

	// DisablePeer disables a peer.
	DisablePeer(ctx context.Context, addr netip.Addr) error

	// IsStarted returns true if the speaker is running.
	IsStarted() bool
}

// PeerManager handles BGP neighbor management and monitoring.
type PeerManager struct {
	speaker PeerSpeakerInterface
	logger  *slog.Logger

	// peers maps peer IP to managed peer state
	peers map[string]*ManagedPeer
	mu    sync.RWMutex

	// Health monitoring configuration
	healthCheckInterval time.Duration
	unhealthyThreshold  int

	// Started state
	started atomic.Bool

	// Health monitoring
	healthCancel context.CancelFunc
	healthDone   chan struct{}
}

// PeerManagerOption configures the PeerManager.
type PeerManagerOption func(*PeerManager)

// WithHealthCheckInterval sets the health check interval.
func WithHealthCheckInterval(interval time.Duration) PeerManagerOption {
	return func(m *PeerManager) {
		if interval > 0 {
			m.healthCheckInterval = interval
		}
	}
}

// WithUnhealthyThreshold sets the unhealthy threshold.
func WithUnhealthyThreshold(threshold int) PeerManagerOption {
	return func(m *PeerManager) {
		if threshold > 0 {
			m.unhealthyThreshold = threshold
		}
	}
}

// NewPeerManager creates a peer manager.
func NewPeerManager(
	speaker PeerSpeakerInterface,
	logger *slog.Logger,
	opts ...PeerManagerOption,
) (*PeerManager, error) {
	if speaker == nil {
		return nil, ErrSpeakerNil
	}
	if logger == nil {
		return nil, ErrLoggerNil
	}

	m := &PeerManager{
		speaker:             speaker,
		logger:              logger,
		peers:               make(map[string]*ManagedPeer),
		healthCheckInterval: 30 * time.Second,
		unhealthyThreshold:  3,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m, nil
}

// Start initializes the peer manager.
func (p *PeerManager) Start(ctx context.Context) error {
	if p.started.Load() {
		return ErrManagerAlreadyStarted
	}

	if !p.speaker.IsStarted() {
		return ErrSpeakerNotStarted
	}

	p.started.Store(true)

	p.logger.Info("peer manager started",
		slog.Duration("health_check_interval", p.healthCheckInterval),
		slog.Int("unhealthy_threshold", p.unhealthyThreshold),
	)

	return nil
}

// Stop shuts down the peer manager.
func (p *PeerManager) Stop() error {
	if !p.started.Load() {
		return nil
	}

	// Cancel health monitoring if running
	if p.healthCancel != nil {
		p.healthCancel()
		<-p.healthDone
	}

	p.started.Store(false)

	p.logger.Info("peer manager stopped")

	return nil
}

// IsStarted returns true if the peer manager is running.
func (p *PeerManager) IsStarted() bool {
	return p.started.Load()
}

// AddPeer adds and starts monitoring a peer.
func (p *PeerManager) AddPeer(ctx context.Context, cfg *PeerNeighborConfig) error {
	if !p.started.Load() {
		return ErrManagerNotStarted
	}

	if cfg == nil {
		return ErrInvalidPeerConfig
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	key := cfg.Address.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check for duplicate
	if _, exists := p.peers[key]; exists {
		return &ErrPeerExists{Address: cfg.Address}
	}

	// Add peer to speaker
	if err := p.speaker.AddPeer(ctx, cfg); err != nil {
		return &ErrPeerOperationFailed{
			PeerAddress: cfg.Address,
			Operation:   "add",
			Cause:       err,
		}
	}

	// Create managed peer
	now := time.Now()
	managed := &ManagedPeer{
		Config:          cfg,
		State:           PeerStateIdle,
		LastStateChange: now,
		Enabled:         !cfg.AdminDown,
		AdminDown:       cfg.AdminDown,
	}

	p.peers[key] = managed

	p.logger.Info("peer added",
		slog.String("address", cfg.Address.String()),
		slog.Uint64("remote_as", uint64(cfg.RemoteAS)),
		slog.String("type", cfg.Type.String()),
	)

	return nil
}

// RemovePeer removes a peer.
func (p *PeerManager) RemovePeer(ctx context.Context, addr netip.Addr) error {
	if !p.started.Load() {
		return ErrManagerNotStarted
	}

	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	key := addr.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.peers[key]; !exists {
		return ErrPeerNotFound
	}

	// Remove from speaker
	if err := p.speaker.RemovePeer(ctx, addr); err != nil {
		return &ErrPeerOperationFailed{
			PeerAddress: addr,
			Operation:   "remove",
			Cause:       err,
		}
	}

	delete(p.peers, key)

	p.logger.Info("peer removed",
		slog.String("address", addr.String()),
	)

	return nil
}

// GetPeer retrieves a peer by address.
func (p *PeerManager) GetPeer(addr netip.Addr) (*ManagedPeer, error) {
	if !addr.IsValid() {
		return nil, ErrInvalidPeerAddress
	}

	key := addr.String()

	p.mu.RLock()
	defer p.mu.RUnlock()

	peer, exists := p.peers[key]
	if !exists {
		return nil, ErrPeerNotFound
	}

	// Return a copy
	peerCopy := *peer
	configCopy := *peer.Config
	peerCopy.Config = &configCopy

	return &peerCopy, nil
}

// GetPeerHealth returns health status for a peer.
func (p *PeerManager) GetPeerHealth(addr netip.Addr) (*PeerHealth, error) {
	if !addr.IsValid() {
		return nil, ErrInvalidPeerAddress
	}

	key := addr.String()

	p.mu.RLock()
	defer p.mu.RUnlock()

	peer, exists := p.peers[key]
	if !exists {
		return nil, ErrPeerNotFound
	}

	return &PeerHealth{
		Address:        addr,
		Healthy:        peer.State == PeerStateEstablished,
		State:          peer.State,
		Uptime:         peer.Uptime(),
		LastError:      peer.LastError,
		FailCount:      peer.ConsecutiveFails,
		RoutesReceived: peer.RoutesReceived,
		RoutesSent:     peer.RoutesSent,
	}, nil
}

// ListPeers returns all managed peers.
func (p *PeerManager) ListPeers() []*ManagedPeer {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*ManagedPeer, 0, len(p.peers))
	for _, peer := range p.peers {
		peerCopy := *peer
		configCopy := *peer.Config
		peerCopy.Config = &configCopy
		result = append(result, &peerCopy)
	}

	return result
}

// ListUnhealthyPeers returns peers not in Established state.
func (p *PeerManager) ListUnhealthyPeers() []*ManagedPeer {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*ManagedPeer, 0)
	for _, peer := range p.peers {
		if peer.State != PeerStateEstablished && peer.Enabled && !peer.AdminDown {
			peerCopy := *peer
			configCopy := *peer.Config
			peerCopy.Config = &configCopy
			result = append(result, &peerCopy)
		}
	}

	return result
}

// ListEstablishedPeers returns all established peers.
func (p *PeerManager) ListEstablishedPeers() []*ManagedPeer {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*ManagedPeer, 0)
	for _, peer := range p.peers {
		if peer.State == PeerStateEstablished {
			peerCopy := *peer
			configCopy := *peer.Config
			peerCopy.Config = &configCopy
			result = append(result, &peerCopy)
		}
	}

	return result
}

// EnablePeer enables a peer.
func (p *PeerManager) EnablePeer(ctx context.Context, addr netip.Addr) error {
	if !p.started.Load() {
		return ErrManagerNotStarted
	}

	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	key := addr.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	peer, exists := p.peers[key]
	if !exists {
		return ErrPeerNotFound
	}

	if peer.Enabled && !peer.AdminDown {
		return nil
	}

	if err := p.speaker.EnablePeer(ctx, addr); err != nil {
		return &ErrPeerOperationFailed{
			PeerAddress: addr,
			Operation:   "enable",
			Cause:       err,
		}
	}

	peer.Enabled = true
	peer.AdminDown = false
	peer.LastStateChange = time.Now()

	p.logger.Info("peer enabled",
		slog.String("address", addr.String()),
	)

	return nil
}

// DisablePeer disables a peer.
func (p *PeerManager) DisablePeer(ctx context.Context, addr netip.Addr) error {
	if !p.started.Load() {
		return ErrManagerNotStarted
	}

	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	key := addr.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	peer, exists := p.peers[key]
	if !exists {
		return ErrPeerNotFound
	}

	if peer.AdminDown {
		return nil
	}

	if err := p.speaker.DisablePeer(ctx, addr); err != nil {
		return &ErrPeerOperationFailed{
			PeerAddress: addr,
			Operation:   "disable",
			Cause:       err,
		}
	}

	peer.AdminDown = true
	peer.Enabled = false
	peer.State = PeerStateIdle
	peer.LastStateChange = time.Now()

	p.logger.Info("peer disabled",
		slog.String("address", addr.String()),
	)

	return nil
}

// StartHealthMonitor starts background health monitoring.
func (p *PeerManager) StartHealthMonitor(ctx context.Context) error {
	if !p.started.Load() {
		return ErrManagerNotStarted
	}

	if p.healthCancel != nil {
		return ErrHealthMonitorAlreadyRunning
	}

	healthCtx, cancel := context.WithCancel(ctx)
	p.healthCancel = cancel
	p.healthDone = make(chan struct{})

	go p.runHealthMonitor(healthCtx)

	p.logger.Info("health monitor started",
		slog.Duration("interval", p.healthCheckInterval),
	)

	return nil
}

// StopHealthMonitor stops background health monitoring.
func (p *PeerManager) StopHealthMonitor() {
	if p.healthCancel != nil {
		p.healthCancel()
		<-p.healthDone
		p.healthCancel = nil
		p.healthDone = nil

		p.logger.Info("health monitor stopped")
	}
}

// runHealthMonitor runs the health monitoring loop.
func (p *PeerManager) runHealthMonitor(ctx context.Context) {
	defer close(p.healthDone)

	ticker := time.NewTicker(p.healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkPeerHealth(ctx)
		}
	}
}

// checkPeerHealth checks the health of all peers.
func (p *PeerManager) checkPeerHealth(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for key, peer := range p.peers {
		if peer.AdminDown {
			continue
		}

		// Get current state from speaker
		state, err := p.speaker.GetPeerState(ctx, peer.Config.Address)
		if err != nil {
			p.logger.Error("failed to get peer state",
				slog.String("address", key),
				slog.Any("error", err),
			)
			peer.ConsecutiveFails++
			peer.LastError = err.Error()
			continue
		}

		// Check for state change
		if state != peer.State {
			oldState := peer.State
			peer.State = state
			peer.LastStateChange = time.Now()

			if state == PeerStateEstablished {
				peer.EstablishedAt = time.Now()
				peer.ConsecutiveFails = 0
				peer.LastError = ""
			}

			p.logger.Info("peer state changed",
				slog.String("address", key),
				slog.String("old_state", oldState.String()),
				slog.String("new_state", state.String()),
			)
		}

		// Track failures for non-established peers
		if state != PeerStateEstablished && peer.Enabled {
			peer.ConsecutiveFails++
		}
	}
}

// UpdatePeerState updates the state of a peer.
// This is typically called when receiving state updates from the speaker.
func (p *PeerManager) UpdatePeerState(addr netip.Addr, state PeerState) error {
	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	key := addr.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	peer, exists := p.peers[key]
	if !exists {
		return ErrPeerNotFound
	}

	if peer.State == state {
		return nil
	}

	oldState := peer.State
	peer.State = state
	peer.LastStateChange = time.Now()

	if state == PeerStateEstablished {
		peer.EstablishedAt = time.Now()
		peer.ConsecutiveFails = 0
		peer.LastError = ""
	}

	p.logger.Debug("peer state updated",
		slog.String("address", key),
		slog.String("old_state", oldState.String()),
		slog.String("new_state", state.String()),
	)

	return nil
}

// UpdatePeerRouteCount updates the route counts for a peer.
func (p *PeerManager) UpdatePeerRouteCount(addr netip.Addr, received, sent int64) error {
	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	key := addr.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	peer, exists := p.peers[key]
	if !exists {
		return ErrPeerNotFound
	}

	peer.RoutesReceived = received
	peer.RoutesSent = sent

	return nil
}

// SetPeerError sets an error message for a peer.
func (p *PeerManager) SetPeerError(addr netip.Addr, errMsg string) error {
	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	key := addr.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	peer, exists := p.peers[key]
	if !exists {
		return ErrPeerNotFound
	}

	peer.LastError = errMsg

	return nil
}

// PeerCount returns the total number of managed peers.
func (p *PeerManager) PeerCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.peers)
}

// EstablishedCount returns the number of established peers.
func (p *PeerManager) EstablishedCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	count := 0
	for _, peer := range p.peers {
		if peer.State == PeerStateEstablished {
			count++
		}
	}

	return count
}

// GetPeersByType returns all peers of a specific type.
func (p *PeerManager) GetPeersByType(peerType PeerType) []*ManagedPeer {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*ManagedPeer, 0)
	for _, peer := range p.peers {
		if peer.Config.Type == peerType {
			peerCopy := *peer
			configCopy := *peer.Config
			peerCopy.Config = &configCopy
			result = append(result, &peerCopy)
		}
	}

	return result
}

// GetPeersByAS returns all peers with a specific AS number.
func (p *PeerManager) GetPeersByAS(asn uint32) []*ManagedPeer {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]*ManagedPeer, 0)
	for _, peer := range p.peers {
		if peer.Config.RemoteAS == asn {
			peerCopy := *peer
			configCopy := *peer.Config
			peerCopy.Config = &configCopy
			result = append(result, &peerCopy)
		}
	}

	return result
}

// ClearPeerFailures resets the failure count for a peer.
func (p *PeerManager) ClearPeerFailures(addr netip.Addr) error {
	if !addr.IsValid() {
		return ErrInvalidPeerAddress
	}

	key := addr.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	peer, exists := p.peers[key]
	if !exists {
		return ErrPeerNotFound
	}

	peer.ConsecutiveFails = 0
	peer.LastError = ""

	return nil
}
