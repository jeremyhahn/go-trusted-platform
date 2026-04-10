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

// Package modes provides gateway mode handlers for BGP transit operations.
package modes

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// RouteSigningKey holds cryptographic keys for route signing.
type RouteSigningKey struct {
	// KeyID is a unique identifier for this key.
	KeyID string

	// PublicKey is the Ed25519 public key for verification.
	PublicKey ed25519.PublicKey

	// PrivateKey is the Ed25519 private key for signing (only set on coordinator).
	PrivateKey ed25519.PrivateKey
}

// TransitModeConfig holds configuration for the transit mode handler.
type TransitModeConfig struct {
	// Tier determines announcement scope (backbone, datacenter, coordinator).
	Tier bgp.SpeakerTier

	// IPv6Prefixes are the IPv6 prefixes to announce (e.g., 2602:F5BB::/36 or /48).
	IPv6Prefixes []net.IPNet

	// IPv4Prefixes are the IPv4 prefixes to announce (e.g., 23.143.36.0/24).
	IPv4Prefixes []net.IPNet

	// ExternalPeers are the BGP neighbors (ISPs, fabric switches).
	ExternalPeers []bgp.NeighborConfig

	// RPKIEnabled enables RPKI validation for received routes.
	RPKIEnabled bool

	// RPKIValidators are the RPKI validator server addresses.
	RPKIValidators []string

	// DampeningConfig configures route flap dampening.
	DampeningConfig *bgp.DampeningConfig

	// RouteSigningKey for coordinator tier route signing.
	RouteSigningKey *RouteSigningKey

	// MinGatewaysForRoute is the minimum gateways that must verify a route before acceptance.
	MinGatewaysForRoute int

	// LocalASN is the local autonomous system number.
	LocalASN uint32

	// NextHop is the default next-hop address for announcements.
	NextHop netip.Addr

	// LocalPref is the default LOCAL_PREF value.
	LocalPref uint32

	// MED is the default Multi-Exit Discriminator.
	MED uint32
}

// Validate validates the transit mode configuration.
func (c *TransitModeConfig) Validate() error {
	if !c.Tier.Valid() {
		return ErrInvalidTier
	}

	if len(c.IPv6Prefixes) == 0 && len(c.IPv4Prefixes) == 0 {
		return ErrNoPrefixesConfigured
	}

	for _, prefix := range c.IPv6Prefixes {
		if prefix.IP == nil || prefix.Mask == nil {
			return ErrInvalidIPv6Prefix
		}
		if prefix.IP.To4() != nil {
			return ErrInvalidIPv6Prefix
		}
	}

	for _, prefix := range c.IPv4Prefixes {
		if prefix.IP == nil || prefix.Mask == nil {
			return ErrInvalidIPv4Prefix
		}
		if prefix.IP.To4() == nil {
			return ErrInvalidIPv4Prefix
		}
	}

	if c.LocalASN == 0 {
		return ErrInvalidASN
	}

	if c.RPKIEnabled && len(c.RPKIValidators) == 0 {
		return ErrNoRPKIValidators
	}

	if c.Tier == bgp.SpeakerTierCoordinator && c.RouteSigningKey == nil {
		return ErrSigningKeyRequired
	}

	if c.MinGatewaysForRoute < 0 {
		return ErrInvalidMinGateways
	}

	return nil
}

// TransitModeStatus contains the current status of the transit mode handler.
type TransitModeStatus struct {
	// Running indicates if the handler is currently running.
	Running bool

	// Tier is the speaker tier.
	Tier bgp.SpeakerTier

	// AnnouncedPrefixes is the count of announced prefixes.
	AnnouncedPrefixes int

	// ExternalPeers is the total number of external peers.
	ExternalPeers int

	// EstablishedPeers is the number of established peer sessions.
	EstablishedPeers int

	// RPKIEnabled indicates if RPKI validation is enabled.
	RPKIEnabled bool

	// RPKIValidatorStatus contains status for each RPKI validator.
	RPKIValidatorStatus []RPKIValidatorStatus

	// DampenedRoutes is the count of routes currently dampened.
	DampenedRoutes int

	// StartedAt is when the handler was started.
	StartedAt time.Time

	// LastError is the most recent error encountered.
	LastError string

	// LastErrorTime is when the last error occurred.
	LastErrorTime time.Time
}

// RPKIValidatorStatus contains status information for an RPKI validator.
type RPKIValidatorStatus struct {
	// Address is the validator address.
	Address string

	// Connected indicates if we are connected to the validator.
	Connected bool

	// ROACount is the number of ROAs received from this validator.
	ROACount int

	// LastUpdate is when we last received data from this validator.
	LastUpdate time.Time
}

// TransitModeHandler handles BGP transit mode operations for announcing
// platform IPv4/IPv6 blocks to ISPs and fabric switches.
type TransitModeHandler struct {
	config         *TransitModeConfig
	bgpSpeaker     *bgp.Speaker
	transitManager *bgp.TransitManager
	rpkiValidator  *bgp.RPKIValidator
	dampening      *bgp.DampeningManager
	logger         *slog.Logger

	// Announced prefixes tracking
	announcedPrefixes map[string]bool
	prefixMu          sync.RWMutex

	// Peer tracking
	peers   map[string]*peerState
	peersMu sync.RWMutex

	// Route signature cache
	signatures   map[string]*routeSignature
	signaturesMu sync.RWMutex

	// Multi-gateway verification tracking
	routeVerifications   map[string]*routeVerificationState
	routeVerificationsMu sync.RWMutex

	// Running state
	running   atomic.Bool
	startedAt time.Time

	// Error tracking
	lastError     string
	lastErrorTime time.Time
	errorMu       sync.RWMutex

	// Shutdown coordination
	stopCh   chan struct{}
	stopOnce sync.Once
}

// peerState tracks the state of a BGP peer.
type peerState struct {
	config      bgp.NeighborConfig
	state       bgp.PeerState
	established bool
	lastChange  time.Time
}

// routeSignature holds a route's cryptographic signature.
type routeSignature struct {
	prefix    netip.Prefix
	signature []byte
	signerID  string
	signedAt  time.Time
}

// routeVerificationState tracks multi-gateway route verification.
type routeVerificationState struct {
	prefix        netip.Prefix
	verifiers     map[string]time.Time
	verified      bool
	verifiedAt    time.Time
	firstVerified time.Time
}

// TransitModeOption configures the TransitModeHandler.
type TransitModeOption func(*TransitModeHandler)

// WithTransitLogger sets the logger for the handler.
func WithTransitLogger(logger *slog.Logger) TransitModeOption {
	return func(h *TransitModeHandler) {
		h.logger = logger
	}
}

// WithTransitManager sets a custom transit manager.
func WithTransitManager(tm *bgp.TransitManager) TransitModeOption {
	return func(h *TransitModeHandler) {
		h.transitManager = tm
	}
}

// WithRPKIValidator sets a custom RPKI validator.
func WithRPKIValidator(rv *bgp.RPKIValidator) TransitModeOption {
	return func(h *TransitModeHandler) {
		h.rpkiValidator = rv
	}
}

// WithDampeningManager sets a custom dampening manager.
func WithDampeningManager(dm *bgp.DampeningManager) TransitModeOption {
	return func(h *TransitModeHandler) {
		h.dampening = dm
	}
}

// NewTransitModeHandler creates a new transit mode handler.
func NewTransitModeHandler(
	config *TransitModeConfig,
	speaker *bgp.Speaker,
	opts ...TransitModeOption,
) (*TransitModeHandler, error) {
	if config == nil {
		return nil, ErrConfigNil
	}
	if speaker == nil {
		return nil, ErrSpeakerNil
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	h := &TransitModeHandler{
		config:             config,
		bgpSpeaker:         speaker,
		announcedPrefixes:  make(map[string]bool),
		peers:              make(map[string]*peerState),
		signatures:         make(map[string]*routeSignature),
		routeVerifications: make(map[string]*routeVerificationState),
		stopCh:             make(chan struct{}),
	}

	for _, opt := range opts {
		opt(h)
	}

	if h.logger == nil {
		h.logger = slog.Default()
	}

	return h, nil
}

// Start starts the transit mode handler.
func (h *TransitModeHandler) Start(ctx context.Context) error {
	if h.running.Load() {
		return ErrAlreadyRunning
	}

	h.logger.Info("starting transit mode handler",
		slog.String("tier", h.config.Tier.String()),
		slog.Int("ipv6_prefixes", len(h.config.IPv6Prefixes)),
		slog.Int("ipv4_prefixes", len(h.config.IPv4Prefixes)),
		slog.Int("external_peers", len(h.config.ExternalPeers)),
	)

	// Initialize RPKI validator if enabled
	if h.config.RPKIEnabled && h.rpkiValidator == nil {
		rv, err := h.initializeRPKIValidator(ctx)
		if err != nil {
			h.recordError("failed to initialize RPKI validator", err)
			return &ErrComponentInitFailed{Component: "rpki_validator", Cause: err}
		}
		h.rpkiValidator = rv
	}

	// Initialize dampening manager if configured
	if h.config.DampeningConfig != nil && h.dampening == nil {
		dm, err := h.initializeDampeningManager(ctx)
		if err != nil {
			h.recordError("failed to initialize dampening manager", err)
			return &ErrComponentInitFailed{Component: "dampening_manager", Cause: err}
		}
		h.dampening = dm
	}

	// Add external peers
	if err := h.addExternalPeers(ctx); err != nil {
		h.recordError("failed to add external peers", err)
		return &ErrComponentInitFailed{Component: "external_peers", Cause: err}
	}

	// Set running before announcing prefixes (AnnouncePrefix checks running state)
	h.startedAt = time.Now()
	h.running.Store(true)

	// Announce configured prefixes
	if err := h.announceConfiguredPrefixes(ctx); err != nil {
		h.running.Store(false) // Rollback on failure
		h.recordError("failed to announce prefixes", err)
		return &ErrComponentInitFailed{Component: "prefix_announcement", Cause: err}
	}

	h.logger.Info("transit mode handler started",
		slog.String("tier", h.config.Tier.String()),
	)

	return nil
}

// Stop stops the transit mode handler.
func (h *TransitModeHandler) Stop(ctx context.Context) error {
	if !h.running.Load() {
		return nil
	}

	h.logger.Info("stopping transit mode handler")

	h.stopOnce.Do(func() {
		close(h.stopCh)
	})

	// Withdraw all announced prefixes
	if err := h.withdrawAllPrefixes(ctx); err != nil {
		h.logger.Warn("error withdrawing prefixes during shutdown",
			slog.Any("error", err),
		)
	}

	// Stop RPKI validator
	if h.rpkiValidator != nil {
		if err := h.rpkiValidator.Stop(); err != nil {
			h.logger.Warn("error stopping RPKI validator",
				slog.Any("error", err),
			)
		}
	}

	// Stop dampening manager
	if h.dampening != nil {
		if err := h.dampening.Stop(); err != nil {
			h.logger.Warn("error stopping dampening manager",
				slog.Any("error", err),
			)
		}
	}

	h.running.Store(false)

	h.logger.Info("transit mode handler stopped")

	return nil
}

// AnnouncePrefix announces a prefix to external peers.
func (h *TransitModeHandler) AnnouncePrefix(ctx context.Context, prefix net.IPNet) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	netipPrefix, err := h.netIPNetToPrefix(prefix)
	if err != nil {
		return &ErrInvalidPrefixFormat{Prefix: prefix.String(), Cause: err}
	}

	// Check if already announced
	key := netipPrefix.String()
	h.prefixMu.Lock()
	if h.announcedPrefixes[key] {
		h.prefixMu.Unlock()
		return &ErrPrefixAlreadyAnnounced{Prefix: netipPrefix}
	}
	h.prefixMu.Unlock()

	// Verify announcement scope based on tier
	if err := h.verifyAnnouncementScope(netipPrefix); err != nil {
		return err
	}

	// For coordinator tier, sign the route
	if h.config.Tier == bgp.SpeakerTierCoordinator {
		if _, err := h.SignRoute(ctx, netipPrefix); err != nil {
			h.logger.Warn("failed to sign route",
				slog.String("prefix", netipPrefix.String()),
				slog.Any("error", err),
			)
		}
	}

	// Announce via transit manager if available
	if h.transitManager != nil {
		if netipPrefix.Addr().Is6() {
			if err := h.transitManager.AnnounceIPv6Prefix(ctx, netipPrefix); err != nil {
				return &ErrAnnounceFailed{Prefix: netipPrefix, Cause: err}
			}
		} else {
			if err := h.transitManager.AnnounceIPv4Prefix(ctx, netipPrefix); err != nil {
				return &ErrAnnounceFailed{Prefix: netipPrefix, Cause: err}
			}
		}
	}

	h.prefixMu.Lock()
	h.announcedPrefixes[key] = true
	h.prefixMu.Unlock()

	h.logger.Info("prefix announced",
		slog.String("prefix", netipPrefix.String()),
		slog.String("tier", h.config.Tier.String()),
	)

	return nil
}

// WithdrawPrefix withdraws a prefix from announcement.
func (h *TransitModeHandler) WithdrawPrefix(ctx context.Context, prefix net.IPNet) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	netipPrefix, err := h.netIPNetToPrefix(prefix)
	if err != nil {
		return &ErrInvalidPrefixFormat{Prefix: prefix.String(), Cause: err}
	}

	key := netipPrefix.String()

	h.prefixMu.Lock()
	if !h.announcedPrefixes[key] {
		h.prefixMu.Unlock()
		return &ErrPrefixNotAnnounced{Prefix: netipPrefix}
	}
	h.prefixMu.Unlock()

	// Withdraw via transit manager if available
	if h.transitManager != nil {
		if err := h.transitManager.WithdrawPrefix(ctx, netipPrefix); err != nil {
			return &ErrWithdrawFailed{Prefix: netipPrefix, Cause: err}
		}
	}

	h.prefixMu.Lock()
	delete(h.announcedPrefixes, key)
	h.prefixMu.Unlock()

	// Remove signature if exists
	h.signaturesMu.Lock()
	delete(h.signatures, key)
	h.signaturesMu.Unlock()

	h.logger.Info("prefix withdrawn",
		slog.String("prefix", netipPrefix.String()),
	)

	return nil
}

// ListAnnouncedPrefixes returns all currently announced prefixes.
func (h *TransitModeHandler) ListAnnouncedPrefixes() []net.IPNet {
	h.prefixMu.RLock()
	defer h.prefixMu.RUnlock()

	result := make([]net.IPNet, 0, len(h.announcedPrefixes))
	for key := range h.announcedPrefixes {
		prefix, err := netip.ParsePrefix(key)
		if err != nil {
			continue
		}
		result = append(result, h.prefixToNetIPNet(prefix))
	}

	return result
}

// ValidateRoute validates a route via RPKI.
func (h *TransitModeHandler) ValidateRoute(
	ctx context.Context,
	prefix net.IPNet,
	originAS uint32,
) (bgp.RPKIValidationState, error) {
	if !h.running.Load() {
		return bgp.RPKIStateUnknown, ErrNotRunning
	}

	if !h.config.RPKIEnabled {
		return bgp.RPKIStateNotFound, nil
	}

	if h.rpkiValidator == nil {
		return bgp.RPKIStateUnknown, ErrRPKINotInitialized
	}

	netipPrefix, err := h.netIPNetToPrefix(prefix)
	if err != nil {
		return bgp.RPKIStateUnknown, &ErrInvalidPrefixFormat{Prefix: prefix.String(), Cause: err}
	}

	state, err := h.rpkiValidator.ValidateRoute(netipPrefix, originAS)
	if err != nil {
		return bgp.RPKIStateUnknown, &ErrRPKIValidationFailed{Prefix: netipPrefix, Cause: err}
	}

	h.logger.Debug("route validated via RPKI",
		slog.String("prefix", netipPrefix.String()),
		slog.Uint64("origin_as", uint64(originAS)),
		slog.String("state", state.String()),
	)

	return state, nil
}

// SignRoute signs a route announcement (coordinator tier only).
func (h *TransitModeHandler) SignRoute(ctx context.Context, prefix netip.Prefix) ([]byte, error) {
	if !h.running.Load() {
		return nil, ErrNotRunning
	}

	if h.config.Tier != bgp.SpeakerTierCoordinator {
		return nil, ErrNotCoordinatorTier
	}

	if h.config.RouteSigningKey == nil || h.config.RouteSigningKey.PrivateKey == nil {
		return nil, ErrSigningKeyNotConfigured
	}

	// Create message to sign: prefix + timestamp
	message := h.createSigningMessage(prefix)

	// Sign using Ed25519
	signature := ed25519.Sign(h.config.RouteSigningKey.PrivateKey, message)

	// Cache the signature
	key := prefix.String()
	h.signaturesMu.Lock()
	h.signatures[key] = &routeSignature{
		prefix:    prefix,
		signature: signature,
		signerID:  h.config.RouteSigningKey.KeyID,
		signedAt:  time.Now(),
	}
	h.signaturesMu.Unlock()

	h.logger.Debug("route signed",
		slog.String("prefix", prefix.String()),
		slog.String("key_id", h.config.RouteSigningKey.KeyID),
	)

	return signature, nil
}

// VerifyRouteSignature verifies a route signature.
func (h *TransitModeHandler) VerifyRouteSignature(
	ctx context.Context,
	prefix netip.Prefix,
	signature []byte,
	signerID string,
) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	if len(signature) == 0 {
		return ErrEmptySignature
	}

	if signerID == "" {
		return ErrEmptySignerID
	}

	// For self-verification, use our own public key
	var publicKey ed25519.PublicKey
	if h.config.RouteSigningKey != nil && h.config.RouteSigningKey.KeyID == signerID {
		publicKey = h.config.RouteSigningKey.PublicKey
	} else {
		// In production, this would look up the public key from a trusted key store
		return ErrSignerNotFound{SignerID: signerID}
	}

	// Verify signature
	message := h.createSigningMessage(prefix)
	if !ed25519.Verify(publicKey, message, signature) {
		return &ErrSignatureInvalid{Prefix: prefix, SignerID: signerID}
	}

	// Record verification for multi-gateway tracking
	h.recordRouteVerification(prefix, signerID)

	h.logger.Debug("route signature verified",
		slog.String("prefix", prefix.String()),
		slog.String("signer_id", signerID),
	)

	return nil
}

// GetStatus returns the current transit mode status.
func (h *TransitModeHandler) GetStatus() *TransitModeStatus {
	status := &TransitModeStatus{
		Running:     h.running.Load(),
		Tier:        h.config.Tier,
		RPKIEnabled: h.config.RPKIEnabled,
		StartedAt:   h.startedAt,
	}

	// Count announced prefixes
	h.prefixMu.RLock()
	status.AnnouncedPrefixes = len(h.announcedPrefixes)
	h.prefixMu.RUnlock()

	// Count peers
	h.peersMu.RLock()
	status.ExternalPeers = len(h.peers)
	for _, peer := range h.peers {
		if peer.established {
			status.EstablishedPeers++
		}
	}
	h.peersMu.RUnlock()

	// Get RPKI validator status
	if h.rpkiValidator != nil {
		for _, addr := range h.rpkiValidator.ListValidators() {
			status.RPKIValidatorStatus = append(status.RPKIValidatorStatus, RPKIValidatorStatus{
				Address:    addr,
				Connected:  h.rpkiValidator.IsStarted(),
				ROACount:   h.rpkiValidator.ROACount(),
				LastUpdate: h.rpkiValidator.LastUpdateTime(),
			})
		}
	}

	// Get dampened route count
	if h.dampening != nil {
		status.DampenedRoutes = h.dampening.SuppressedCount()
	}

	// Get last error
	h.errorMu.RLock()
	status.LastError = h.lastError
	status.LastErrorTime = h.lastErrorTime
	h.errorMu.RUnlock()

	return status
}

// IsRouteVerified checks if a route has been verified by the minimum number of gateways.
func (h *TransitModeHandler) IsRouteVerified(prefix netip.Prefix) bool {
	if h.config.MinGatewaysForRoute <= 0 {
		return true
	}

	key := prefix.String()

	h.routeVerificationsMu.RLock()
	defer h.routeVerificationsMu.RUnlock()

	state, exists := h.routeVerifications[key]
	if !exists {
		return false
	}

	return state.verified
}

// GetRouteVerificationCount returns the number of gateways that have verified a route.
func (h *TransitModeHandler) GetRouteVerificationCount(prefix netip.Prefix) int {
	key := prefix.String()

	h.routeVerificationsMu.RLock()
	defer h.routeVerificationsMu.RUnlock()

	state, exists := h.routeVerifications[key]
	if !exists {
		return 0
	}

	return len(state.verifiers)
}

// Internal helper methods

// initializeRPKIValidator creates and starts the RPKI validator.
func (h *TransitModeHandler) initializeRPKIValidator(ctx context.Context) (*bgp.RPKIValidator, error) {
	// Create a speaker interface adapter
	speakerAdapter := &rpkiSpeakerAdapter{speaker: h.bgpSpeaker}

	validator, err := bgp.NewRPKIValidator(
		speakerAdapter,
		h.config.RPKIValidators,
		h.logger,
		bgp.WithFailOpen(true), // Graceful degradation
	)
	if err != nil {
		return nil, err
	}

	if err := validator.Start(ctx); err != nil {
		return nil, err
	}

	return validator, nil
}

// initializeDampeningManager creates and starts the dampening manager.
func (h *TransitModeHandler) initializeDampeningManager(ctx context.Context) (*bgp.DampeningManager, error) {
	// Create a speaker interface adapter
	speakerAdapter := &dampeningSpeakerAdapter{speaker: h.bgpSpeaker}

	manager, err := bgp.NewDampeningManager(
		speakerAdapter,
		h.config.DampeningConfig,
		h.logger,
	)
	if err != nil {
		return nil, err
	}

	if err := manager.Start(ctx); err != nil {
		return nil, err
	}

	return manager, nil
}

// addExternalPeers adds all configured external peers.
func (h *TransitModeHandler) addExternalPeers(ctx context.Context) error {
	for _, peerConfig := range h.config.ExternalPeers {
		if err := h.bgpSpeaker.AddPeer(ctx, &peerConfig); err != nil {
			h.logger.Warn("failed to add peer",
				slog.String("address", peerConfig.Address.String()),
				slog.Any("error", err),
			)
			continue
		}

		h.peersMu.Lock()
		h.peers[peerConfig.Address.String()] = &peerState{
			config:     peerConfig,
			state:      bgp.PeerStateIdle,
			lastChange: time.Now(),
		}
		h.peersMu.Unlock()
	}

	return nil
}

// announceConfiguredPrefixes announces all configured prefixes.
func (h *TransitModeHandler) announceConfiguredPrefixes(ctx context.Context) error {
	// Announce IPv6 prefixes
	for _, prefix := range h.config.IPv6Prefixes {
		if err := h.AnnouncePrefix(ctx, prefix); err != nil {
			h.logger.Warn("failed to announce IPv6 prefix",
				slog.String("prefix", prefix.String()),
				slog.Any("error", err),
			)
		}
	}

	// Announce IPv4 prefixes
	for _, prefix := range h.config.IPv4Prefixes {
		if err := h.AnnouncePrefix(ctx, prefix); err != nil {
			h.logger.Warn("failed to announce IPv4 prefix",
				slog.String("prefix", prefix.String()),
				slog.Any("error", err),
			)
		}
	}

	return nil
}

// withdrawAllPrefixes withdraws all announced prefixes.
func (h *TransitModeHandler) withdrawAllPrefixes(ctx context.Context) error {
	h.prefixMu.Lock()
	prefixes := make([]string, 0, len(h.announcedPrefixes))
	for key := range h.announcedPrefixes {
		prefixes = append(prefixes, key)
	}
	h.prefixMu.Unlock()

	var lastErr error
	for _, key := range prefixes {
		prefix, err := netip.ParsePrefix(key)
		if err != nil {
			continue
		}

		netIPNet := h.prefixToNetIPNet(prefix)
		if err := h.WithdrawPrefix(ctx, netIPNet); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// verifyAnnouncementScope verifies that the prefix announcement is allowed for this tier.
func (h *TransitModeHandler) verifyAnnouncementScope(prefix netip.Prefix) error {
	bits := prefix.Bits()

	switch h.config.Tier {
	case bgp.SpeakerTierBackbone:
		// Backbone can announce any prefix size
		return nil

	case bgp.SpeakerTierDatacenter:
		// Datacenter speakers should announce regional prefixes (/48 for IPv6, /24 for IPv4)
		if prefix.Addr().Is6() && bits < 48 {
			return &ErrPrefixTooLarge{Prefix: prefix, MaxBits: 48, Tier: h.config.Tier}
		}
		if prefix.Addr().Is4() && bits < 24 {
			return &ErrPrefixTooLarge{Prefix: prefix, MaxBits: 24, Tier: h.config.Tier}
		}
		return nil

	case bgp.SpeakerTierCoordinator:
		// Coordinator tier doesn't announce directly to external peers
		return nil

	default:
		return ErrInvalidTier
	}
}

// netIPNetToPrefix converts net.IPNet to netip.Prefix.
func (h *TransitModeHandler) netIPNetToPrefix(ipnet net.IPNet) (netip.Prefix, error) {
	addr, ok := netip.AddrFromSlice(ipnet.IP)
	if !ok {
		return netip.Prefix{}, ErrInvalidIPAddress
	}

	ones, _ := ipnet.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones), nil
}

// prefixToNetIPNet converts netip.Prefix to net.IPNet.
func (h *TransitModeHandler) prefixToNetIPNet(prefix netip.Prefix) net.IPNet {
	return net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

// createSigningMessage creates the message to be signed for a route.
func (h *TransitModeHandler) createSigningMessage(prefix netip.Prefix) []byte {
	// Hash prefix + timestamp (rounded to hour for replay prevention)
	timestamp := time.Now().Truncate(time.Hour).Unix()
	data := append([]byte(prefix.String()), byte(timestamp>>24), byte(timestamp>>16), byte(timestamp>>8), byte(timestamp))
	hash := sha256.Sum256(data)
	return hash[:]
}

// recordRouteVerification records a route verification from a gateway.
func (h *TransitModeHandler) recordRouteVerification(prefix netip.Prefix, verifierID string) {
	key := prefix.String()

	h.routeVerificationsMu.Lock()
	defer h.routeVerificationsMu.Unlock()

	state, exists := h.routeVerifications[key]
	if !exists {
		state = &routeVerificationState{
			prefix:        prefix,
			verifiers:     make(map[string]time.Time),
			firstVerified: time.Now(),
		}
		h.routeVerifications[key] = state
	}

	state.verifiers[verifierID] = time.Now()

	// Check if minimum gateways threshold is met
	if len(state.verifiers) >= h.config.MinGatewaysForRoute && !state.verified {
		state.verified = true
		state.verifiedAt = time.Now()

		h.logger.Info("route verified by minimum gateways",
			slog.String("prefix", prefix.String()),
			slog.Int("verifiers", len(state.verifiers)),
			slog.Int("required", h.config.MinGatewaysForRoute),
		)
	}
}

// recordError records an error for status reporting.
func (h *TransitModeHandler) recordError(msg string, err error) {
	h.errorMu.Lock()
	defer h.errorMu.Unlock()

	if err != nil {
		h.lastError = msg + ": " + err.Error()
	} else {
		h.lastError = msg
	}
	h.lastErrorTime = time.Now()

	h.logger.Error(msg, slog.Any("error", err))
}

// rpkiSpeakerAdapter adapts the BGP speaker to the RPKI speaker interface.
type rpkiSpeakerAdapter struct {
	speaker *bgp.Speaker
}

func (a *rpkiSpeakerAdapter) IsStarted() bool {
	return a.speaker.IsStarted()
}

func (a *rpkiSpeakerAdapter) GetASN() uint32 {
	return a.speaker.Config().ASN
}

// dampeningSpeakerAdapter adapts the BGP speaker to the dampening speaker interface.
type dampeningSpeakerAdapter struct {
	speaker *bgp.Speaker
}

func (a *dampeningSpeakerAdapter) IsStarted() bool {
	return a.speaker.IsStarted()
}

func (a *dampeningSpeakerAdapter) SuppressRoute(ctx context.Context, prefix netip.Prefix) error {
	// Implementation would suppress the route
	return nil
}

func (a *dampeningSpeakerAdapter) UnsuppressRoute(ctx context.Context, prefix netip.Prefix) error {
	// Implementation would unsuppress the route
	return nil
}
