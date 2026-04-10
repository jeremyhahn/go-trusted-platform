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

// AnnouncedPrefix represents a prefix that is being announced via BGP.
type AnnouncedPrefix struct {
	// Prefix is the network prefix being announced.
	Prefix netip.Prefix

	// NextHop is the next-hop address for this prefix.
	NextHop netip.Addr

	// LocalPref is the LOCAL_PREF value for iBGP.
	LocalPref uint32

	// MED is the Multi-Exit Discriminator value.
	MED uint32

	// ASPathPrepend is the number of times to prepend our AS.
	ASPathPrepend int

	// Communities are the BGP communities attached to this prefix.
	Communities []string

	// Origin indicates how the route was originated.
	Origin RouteOrigin

	// AnnouncedAt is when this prefix was first announced.
	AnnouncedAt time.Time

	// UpdatedAt is when this prefix was last updated.
	UpdatedAt time.Time
}

// RouteOrigin indicates how a route was originated.
type RouteOrigin uint8

const (
	// RouteOriginIGP indicates the route was learned via IGP.
	RouteOriginIGP RouteOrigin = iota

	// RouteOriginEGP indicates the route was learned via EGP.
	RouteOriginEGP

	// RouteOriginIncomplete indicates the route origin is incomplete.
	RouteOriginIncomplete
)

// String returns a human-readable representation of the route origin.
func (o RouteOrigin) String() string {
	switch o {
	case RouteOriginIGP:
		return "igp"
	case RouteOriginEGP:
		return "egp"
	case RouteOriginIncomplete:
		return "incomplete"
	default:
		return "unknown"
	}
}

// announceConfig holds configuration for prefix announcement.
type announceConfig struct {
	nextHop       netip.Addr
	localPref     uint32
	med           uint32
	asPathPrepend int
	communities   []string
}

// AnnounceOption configures prefix announcement.
type AnnounceOption func(*announceConfig)

// WithNextHop sets the next-hop address for the announcement.
func WithNextHop(nh netip.Addr) AnnounceOption {
	return func(cfg *announceConfig) {
		cfg.nextHop = nh
	}
}

// WithLocalPref sets the LOCAL_PREF value for the announcement.
func WithLocalPref(lp uint32) AnnounceOption {
	return func(cfg *announceConfig) {
		cfg.localPref = lp
	}
}

// WithMED sets the Multi-Exit Discriminator for the announcement.
func WithMED(med uint32) AnnounceOption {
	return func(cfg *announceConfig) {
		cfg.med = med
	}
}

// WithASPathPrepend sets the AS path prepend count for the announcement.
func WithASPathPrepend(count int) AnnounceOption {
	return func(cfg *announceConfig) {
		if count >= 0 {
			cfg.asPathPrepend = count
		}
	}
}

// WithCommunities sets the BGP communities for the announcement.
func WithCommunities(communities ...string) AnnounceOption {
	return func(cfg *announceConfig) {
		cfg.communities = communities
	}
}

// TransitManager handles IP prefix announcements to external peers.
// It manages the announcement of platform-owned IP blocks to upstream ISPs.
type TransitManager struct {
	speaker SpeakerInterface
	tier    SpeakerTier
	logger  *slog.Logger

	// Announced prefixes
	ipv6Prefixes map[string]*AnnouncedPrefix
	ipv4Prefixes map[string]*AnnouncedPrefix
	mu           sync.RWMutex

	// Default configuration
	defaultLocalPref uint32
	defaultMED       uint32

	// Started state
	started atomic.Bool
}

// SpeakerInterface defines the interface for BGP speaker operations.
// This allows for mocking in tests.
type SpeakerInterface interface {
	// AnnouncePrefix announces a prefix to BGP peers.
	AnnouncePrefix(ctx context.Context, prefix netip.Prefix, nextHop netip.Addr, attrs *PathAttributes) error

	// WithdrawPrefix withdraws a previously announced prefix.
	WithdrawPrefix(ctx context.Context, prefix netip.Prefix) error

	// IsStarted returns true if the speaker is running.
	IsStarted() bool

	// GetRouterID returns the router ID.
	GetRouterID() string

	// GetASN returns the local AS number.
	GetASN() uint32
}

// PathAttributes holds BGP path attributes for announcements.
type PathAttributes struct {
	LocalPref     uint32
	MED           uint32
	ASPathPrepend int
	Communities   []string
	Origin        RouteOrigin
}

// TransitManagerOption configures the TransitManager.
type TransitManagerOption func(*TransitManager)

// WithDefaultLocalPref sets the default LOCAL_PREF for announcements.
func WithDefaultLocalPref(lp uint32) TransitManagerOption {
	return func(m *TransitManager) {
		m.defaultLocalPref = lp
	}
}

// WithDefaultMED sets the default MED for announcements.
func WithDefaultMED(med uint32) TransitManagerOption {
	return func(m *TransitManager) {
		m.defaultMED = med
	}
}

// NewTransitManager creates a transit manager for the given tier.
func NewTransitManager(
	speaker SpeakerInterface,
	tier SpeakerTier,
	logger *slog.Logger,
	opts ...TransitManagerOption,
) (*TransitManager, error) {
	if speaker == nil {
		return nil, ErrSpeakerNil
	}
	if logger == nil {
		return nil, ErrLoggerNil
	}
	if tier == SpeakerTierUnknown {
		return nil, ErrInvalidSpeakerTier
	}

	m := &TransitManager{
		speaker:          speaker,
		tier:             tier,
		logger:           logger,
		ipv6Prefixes:     make(map[string]*AnnouncedPrefix),
		ipv4Prefixes:     make(map[string]*AnnouncedPrefix),
		defaultLocalPref: 100,
		defaultMED:       0,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m, nil
}

// Start initializes the transit manager.
func (t *TransitManager) Start(ctx context.Context) error {
	if t.started.Load() {
		return ErrManagerAlreadyStarted
	}

	if !t.speaker.IsStarted() {
		return ErrSpeakerNotStarted
	}

	t.started.Store(true)

	t.logger.Info("transit manager started",
		slog.String("tier", t.tier.String()),
		slog.String("router_id", t.speaker.GetRouterID()),
		slog.Uint64("asn", uint64(t.speaker.GetASN())),
	)

	return nil
}

// Stop shuts down the transit manager and withdraws all prefixes.
func (t *TransitManager) Stop(ctx context.Context) error {
	if !t.started.Load() {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.started.Store(false)

	// Withdraw all announced prefixes
	var lastErr error
	for _, prefix := range t.ipv6Prefixes {
		if err := t.speaker.WithdrawPrefix(ctx, prefix.Prefix); err != nil {
			t.logger.Error("failed to withdraw IPv6 prefix during shutdown",
				slog.String("prefix", prefix.Prefix.String()),
				slog.Any("error", err),
			)
			lastErr = err
		}
	}

	for _, prefix := range t.ipv4Prefixes {
		if err := t.speaker.WithdrawPrefix(ctx, prefix.Prefix); err != nil {
			t.logger.Error("failed to withdraw IPv4 prefix during shutdown",
				slog.String("prefix", prefix.Prefix.String()),
				slog.Any("error", err),
			)
			lastErr = err
		}
	}

	// Clear prefix maps
	t.ipv6Prefixes = make(map[string]*AnnouncedPrefix)
	t.ipv4Prefixes = make(map[string]*AnnouncedPrefix)

	t.logger.Info("transit manager stopped")

	return lastErr
}

// IsStarted returns true if the transit manager is running.
func (t *TransitManager) IsStarted() bool {
	return t.started.Load()
}

// GetTier returns the speaker tier.
func (t *TransitManager) GetTier() SpeakerTier {
	return t.tier
}

// AnnounceIPv6Prefix announces an IPv6 prefix.
func (t *TransitManager) AnnounceIPv6Prefix(
	ctx context.Context,
	prefix netip.Prefix,
	opts ...AnnounceOption,
) error {
	if !t.started.Load() {
		return ErrManagerNotStarted
	}

	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	if !prefix.Addr().Is6() {
		return ErrIPv6Required
	}

	cfg := t.buildAnnounceConfig(opts)
	return t.announcePrefix(ctx, prefix, cfg, true)
}

// AnnounceIPv4Prefix announces an IPv4 prefix.
func (t *TransitManager) AnnounceIPv4Prefix(
	ctx context.Context,
	prefix netip.Prefix,
	opts ...AnnounceOption,
) error {
	if !t.started.Load() {
		return ErrManagerNotStarted
	}

	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	if !prefix.Addr().Is4() {
		return ErrIPv4Required
	}

	cfg := t.buildAnnounceConfig(opts)
	return t.announcePrefix(ctx, prefix, cfg, false)
}

// announcePrefix handles the common announcement logic.
func (t *TransitManager) announcePrefix(
	ctx context.Context,
	prefix netip.Prefix,
	cfg *announceConfig,
	isIPv6 bool,
) error {
	key := prefix.String()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check for duplicate
	var existing *AnnouncedPrefix
	if isIPv6 {
		existing = t.ipv6Prefixes[key]
	} else {
		existing = t.ipv4Prefixes[key]
	}

	if existing != nil {
		return &ErrPrefixAlreadyAnnounced{Prefix: prefix}
	}

	// Build path attributes
	attrs := &PathAttributes{
		LocalPref:     cfg.localPref,
		MED:           cfg.med,
		ASPathPrepend: cfg.asPathPrepend,
		Communities:   cfg.communities,
		Origin:        RouteOriginIGP,
	}

	// Announce via speaker
	if err := t.speaker.AnnouncePrefix(ctx, prefix, cfg.nextHop, attrs); err != nil {
		return &ErrAnnouncementFailed{Prefix: prefix, Cause: err}
	}

	// Store announcement
	now := time.Now()
	announced := &AnnouncedPrefix{
		Prefix:        prefix,
		NextHop:       cfg.nextHop,
		LocalPref:     cfg.localPref,
		MED:           cfg.med,
		ASPathPrepend: cfg.asPathPrepend,
		Communities:   cfg.communities,
		Origin:        RouteOriginIGP,
		AnnouncedAt:   now,
		UpdatedAt:     now,
	}

	if isIPv6 {
		t.ipv6Prefixes[key] = announced
	} else {
		t.ipv4Prefixes[key] = announced
	}

	t.logger.Info("prefix announced",
		slog.String("prefix", prefix.String()),
		slog.String("next_hop", cfg.nextHop.String()),
		slog.Uint64("local_pref", uint64(cfg.localPref)),
		slog.Uint64("med", uint64(cfg.med)),
		slog.Int("as_path_prepend", cfg.asPathPrepend),
	)

	return nil
}

// WithdrawPrefix withdraws a previously announced prefix.
func (t *TransitManager) WithdrawPrefix(ctx context.Context, prefix netip.Prefix) error {
	if !t.started.Load() {
		return ErrManagerNotStarted
	}

	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	key := prefix.String()
	isIPv6 := prefix.Addr().Is6()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if prefix exists
	var exists bool
	if isIPv6 {
		_, exists = t.ipv6Prefixes[key]
	} else {
		_, exists = t.ipv4Prefixes[key]
	}

	if !exists {
		return ErrPrefixNotAnnounced
	}

	// Withdraw via speaker
	if err := t.speaker.WithdrawPrefix(ctx, prefix); err != nil {
		return &ErrWithdrawalFailed{Prefix: prefix, Cause: err}
	}

	// Remove from local state
	if isIPv6 {
		delete(t.ipv6Prefixes, key)
	} else {
		delete(t.ipv4Prefixes, key)
	}

	t.logger.Info("prefix withdrawn",
		slog.String("prefix", prefix.String()),
	)

	return nil
}

// ListAnnouncedPrefixes returns all currently announced prefixes.
func (t *TransitManager) ListAnnouncedPrefixes() []netip.Prefix {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]netip.Prefix, 0, len(t.ipv6Prefixes)+len(t.ipv4Prefixes))

	for _, p := range t.ipv6Prefixes {
		result = append(result, p.Prefix)
	}

	for _, p := range t.ipv4Prefixes {
		result = append(result, p.Prefix)
	}

	return result
}

// ListAnnouncedIPv6Prefixes returns all announced IPv6 prefixes.
func (t *TransitManager) ListAnnouncedIPv6Prefixes() []*AnnouncedPrefix {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*AnnouncedPrefix, 0, len(t.ipv6Prefixes))
	for _, p := range t.ipv6Prefixes {
		prefixCopy := *p
		result = append(result, &prefixCopy)
	}

	return result
}

// ListAnnouncedIPv4Prefixes returns all announced IPv4 prefixes.
func (t *TransitManager) ListAnnouncedIPv4Prefixes() []*AnnouncedPrefix {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*AnnouncedPrefix, 0, len(t.ipv4Prefixes))
	for _, p := range t.ipv4Prefixes {
		prefixCopy := *p
		result = append(result, &prefixCopy)
	}

	return result
}

// GetAnnouncedPrefix retrieves an announced prefix by its network.
func (t *TransitManager) GetAnnouncedPrefix(prefix netip.Prefix) (*AnnouncedPrefix, error) {
	if !prefix.IsValid() {
		return nil, ErrInvalidPrefix
	}

	key := prefix.String()
	isIPv6 := prefix.Addr().Is6()

	t.mu.RLock()
	defer t.mu.RUnlock()

	var announced *AnnouncedPrefix
	if isIPv6 {
		announced = t.ipv6Prefixes[key]
	} else {
		announced = t.ipv4Prefixes[key]
	}

	if announced == nil {
		return nil, ErrPrefixNotAnnounced
	}

	// Return a copy
	prefixCopy := *announced
	return &prefixCopy, nil
}

// SetASPathPrepend sets AS path prepending for a prefix.
func (t *TransitManager) SetASPathPrepend(prefix netip.Prefix, count int) error {
	if !t.started.Load() {
		return ErrManagerNotStarted
	}

	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	if count < 0 {
		return ErrInvalidASPathPrepend
	}

	key := prefix.String()
	isIPv6 := prefix.Addr().Is6()

	t.mu.Lock()
	defer t.mu.Unlock()

	var announced *AnnouncedPrefix
	if isIPv6 {
		announced = t.ipv6Prefixes[key]
	} else {
		announced = t.ipv4Prefixes[key]
	}

	if announced == nil {
		return ErrPrefixNotAnnounced
	}

	announced.ASPathPrepend = count
	announced.UpdatedAt = time.Now()

	t.logger.Info("AS path prepend updated",
		slog.String("prefix", prefix.String()),
		slog.Int("prepend_count", count),
	)

	return nil
}

// SetCommunities sets BGP communities for a prefix.
func (t *TransitManager) SetCommunities(prefix netip.Prefix, communities []string) error {
	if !t.started.Load() {
		return ErrManagerNotStarted
	}

	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	key := prefix.String()
	isIPv6 := prefix.Addr().Is6()

	t.mu.Lock()
	defer t.mu.Unlock()

	var announced *AnnouncedPrefix
	if isIPv6 {
		announced = t.ipv6Prefixes[key]
	} else {
		announced = t.ipv4Prefixes[key]
	}

	if announced == nil {
		return ErrPrefixNotAnnounced
	}

	// Copy communities slice
	announced.Communities = make([]string, len(communities))
	copy(announced.Communities, communities)
	announced.UpdatedAt = time.Now()

	t.logger.Info("BGP communities updated",
		slog.String("prefix", prefix.String()),
		slog.Any("communities", communities),
	)

	return nil
}

// SetMED sets the MED for a prefix.
func (t *TransitManager) SetMED(prefix netip.Prefix, med uint32) error {
	if !t.started.Load() {
		return ErrManagerNotStarted
	}

	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	key := prefix.String()
	isIPv6 := prefix.Addr().Is6()

	t.mu.Lock()
	defer t.mu.Unlock()

	var announced *AnnouncedPrefix
	if isIPv6 {
		announced = t.ipv6Prefixes[key]
	} else {
		announced = t.ipv4Prefixes[key]
	}

	if announced == nil {
		return ErrPrefixNotAnnounced
	}

	announced.MED = med
	announced.UpdatedAt = time.Now()

	t.logger.Info("MED updated",
		slog.String("prefix", prefix.String()),
		slog.Uint64("med", uint64(med)),
	)

	return nil
}

// SetLocalPref sets the LOCAL_PREF for a prefix.
func (t *TransitManager) SetLocalPref(prefix netip.Prefix, localPref uint32) error {
	if !t.started.Load() {
		return ErrManagerNotStarted
	}

	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	key := prefix.String()
	isIPv6 := prefix.Addr().Is6()

	t.mu.Lock()
	defer t.mu.Unlock()

	var announced *AnnouncedPrefix
	if isIPv6 {
		announced = t.ipv6Prefixes[key]
	} else {
		announced = t.ipv4Prefixes[key]
	}

	if announced == nil {
		return ErrPrefixNotAnnounced
	}

	announced.LocalPref = localPref
	announced.UpdatedAt = time.Now()

	t.logger.Info("LOCAL_PREF updated",
		slog.String("prefix", prefix.String()),
		slog.Uint64("local_pref", uint64(localPref)),
	)

	return nil
}

// PrefixCount returns the total number of announced prefixes.
func (t *TransitManager) PrefixCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.ipv6Prefixes) + len(t.ipv4Prefixes)
}

// IPv6PrefixCount returns the number of announced IPv6 prefixes.
func (t *TransitManager) IPv6PrefixCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.ipv6Prefixes)
}

// IPv4PrefixCount returns the number of announced IPv4 prefixes.
func (t *TransitManager) IPv4PrefixCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.ipv4Prefixes)
}

// buildAnnounceConfig builds an announce configuration from options.
func (t *TransitManager) buildAnnounceConfig(opts []AnnounceOption) *announceConfig {
	cfg := &announceConfig{
		localPref:     t.defaultLocalPref,
		med:           t.defaultMED,
		asPathPrepend: 0,
		communities:   nil,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}
