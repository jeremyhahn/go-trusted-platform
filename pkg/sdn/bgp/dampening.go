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

// Package bgp provides BGP route flap dampening per RFC 2439.
package bgp

import (
	"context"
	"log/slog"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Default dampening parameters per RFC 2439 and platform requirements.
const (
	// DefaultHalfLife is the default penalty half-life (15 minutes).
	DefaultHalfLife = 15 * time.Minute

	// DefaultReuseThreshold is the penalty below which a route is reused.
	DefaultReuseThreshold = 750

	// DefaultSuppressThreshold is the penalty above which a route is suppressed.
	DefaultSuppressThreshold = 2000

	// DefaultMaxSuppressTime is the maximum time a route can be suppressed (60 minutes).
	DefaultMaxSuppressTime = 60 * time.Minute

	// DefaultFlapPenalty is the penalty added for each flap event.
	DefaultFlapPenalty = 1000

	// DefaultDecayInterval is the interval for penalty decay calculations.
	DefaultDecayInterval = 5 * time.Second
)

// DampeningState tracks the dampening state for a single route.
type DampeningState struct {
	// Prefix is the network prefix being tracked.
	Prefix netip.Prefix

	// Penalty is the current penalty value.
	Penalty int

	// Suppressed indicates if the route is currently suppressed.
	Suppressed bool

	// SuppressedAt is when the route was suppressed.
	SuppressedAt time.Time

	// ReuseAt is the estimated time when the route will be reused.
	ReuseAt time.Time

	// FlapCount is the total number of flaps recorded.
	FlapCount int

	// LastFlap is when the last flap occurred.
	LastFlap time.Time

	// FirstFlap is when the first flap was recorded.
	FirstFlap time.Time

	// LastDecay is when the penalty was last decayed.
	LastDecay time.Time
}

// IsActive returns true if dampening is currently active for this route.
func (d *DampeningState) IsActive() bool {
	return d.Suppressed && time.Now().Before(d.ReuseAt)
}

// SuppressedRoute contains information about a suppressed route.
type SuppressedRoute struct {
	// Prefix is the suppressed prefix.
	Prefix netip.Prefix

	// Penalty is the current penalty.
	Penalty int

	// SuppressedAt is when the route was suppressed.
	SuppressedAt time.Time

	// ReuseAt is the estimated reuse time.
	ReuseAt time.Time

	// FlapCount is the number of flaps.
	FlapCount int

	// Duration is how long the route has been suppressed.
	Duration time.Duration
}

// DampeningConfig configures dampening parameters.
type DampeningConfig struct {
	// HalfLife is the time for penalty to decay by half (default: 15 minutes).
	HalfLife time.Duration

	// ReuseThreshold is the penalty below which a route is reused (default: 750).
	ReuseThreshold int

	// SuppressThreshold is the penalty above which a route is suppressed (default: 2000).
	SuppressThreshold int

	// MaxSuppressTime is the maximum suppression duration (default: 60 minutes).
	MaxSuppressTime time.Duration

	// FlapPenalty is the penalty added for each flap (default: 1000).
	FlapPenalty int

	// DecayInterval is the interval for decay calculations (default: 5 seconds).
	DecayInterval time.Duration
}

// DefaultDampeningConfig returns the default dampening configuration.
func DefaultDampeningConfig() *DampeningConfig {
	return &DampeningConfig{
		HalfLife:          DefaultHalfLife,
		ReuseThreshold:    DefaultReuseThreshold,
		SuppressThreshold: DefaultSuppressThreshold,
		MaxSuppressTime:   DefaultMaxSuppressTime,
		FlapPenalty:       DefaultFlapPenalty,
		DecayInterval:     DefaultDecayInterval,
	}
}

// Validate validates the dampening configuration.
func (c *DampeningConfig) Validate() error {
	if c.HalfLife <= 0 {
		return ErrInvalidHalfLife
	}
	if c.ReuseThreshold <= 0 {
		return ErrInvalidReuseThreshold
	}
	if c.SuppressThreshold <= 0 {
		return ErrInvalidSuppressThreshold
	}
	if c.ReuseThreshold >= c.SuppressThreshold {
		return ErrReuseExceedsSuppressThreshold
	}
	if c.MaxSuppressTime <= 0 {
		return ErrInvalidMaxSuppressTime
	}
	if c.FlapPenalty <= 0 {
		return ErrInvalidFlapPenalty
	}
	return nil
}

// DampeningSpeakerInterface defines the interface for dampening operations on the speaker.
type DampeningSpeakerInterface interface {
	// IsStarted returns true if the speaker is running.
	IsStarted() bool

	// SuppressRoute suppresses a route.
	SuppressRoute(ctx context.Context, prefix netip.Prefix) error

	// UnsuppressRoute unsuppresses a route.
	UnsuppressRoute(ctx context.Context, prefix netip.Prefix) error
}

// DampeningManager implements BGP route flap dampening per RFC 2439.
type DampeningManager struct {
	speaker DampeningSpeakerInterface
	logger  *slog.Logger
	config  *DampeningConfig

	// Dampening state per route: key is prefix string
	routes map[string]*DampeningState
	mu     sync.RWMutex

	// Decay factor computed from half-life
	decayFactor float64

	// Maximum penalty computed from max suppress time
	maxPenalty int

	// Started state
	started atomic.Bool

	// Decay timer control
	decayCancel context.CancelFunc
	decayDone   chan struct{}
}

// DampeningManagerOption configures the DampeningManager.
type DampeningManagerOption func(*DampeningManager)

// NewDampeningManager creates a dampening manager.
func NewDampeningManager(
	speaker DampeningSpeakerInterface,
	cfg *DampeningConfig,
	logger *slog.Logger,
	opts ...DampeningManagerOption,
) (*DampeningManager, error) {
	if speaker == nil {
		return nil, ErrSpeakerNil
	}
	if logger == nil {
		return nil, ErrLoggerNil
	}

	if cfg == nil {
		cfg = DefaultDampeningConfig()
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	m := &DampeningManager{
		speaker: speaker,
		logger:  logger,
		config:  cfg,
		routes:  make(map[string]*DampeningState),
	}

	// Calculate decay factor: penalty * e^(-t/halflife) = penalty / 2
	// Therefore: decayFactor = e^(-decayInterval/halflife)
	decayIntervalSeconds := cfg.DecayInterval.Seconds()
	halfLifeSeconds := cfg.HalfLife.Seconds()
	m.decayFactor = math.Exp(-decayIntervalSeconds / halfLifeSeconds * math.Ln2)

	// Calculate maximum penalty based on max suppress time
	// penalty * decayFactor^n = reuseThreshold, where n = maxSuppressTime / decayInterval
	n := cfg.MaxSuppressTime.Seconds() / cfg.DecayInterval.Seconds()
	m.maxPenalty = int(float64(cfg.ReuseThreshold) / math.Pow(m.decayFactor, n))

	for _, opt := range opts {
		opt(m)
	}

	return m, nil
}

// Start initializes the dampening manager.
func (d *DampeningManager) Start(ctx context.Context) error {
	if d.started.Load() {
		return ErrManagerAlreadyStarted
	}

	if !d.speaker.IsStarted() {
		return ErrSpeakerNotStarted
	}

	d.started.Store(true)

	d.logger.Info("dampening manager started",
		slog.Duration("half_life", d.config.HalfLife),
		slog.Int("reuse_threshold", d.config.ReuseThreshold),
		slog.Int("suppress_threshold", d.config.SuppressThreshold),
		slog.Duration("max_suppress_time", d.config.MaxSuppressTime),
		slog.Float64("decay_factor", d.decayFactor),
		slog.Int("max_penalty", d.maxPenalty),
	)

	return nil
}

// Stop shuts down the dampening manager.
func (d *DampeningManager) Stop() error {
	if !d.started.Load() {
		return nil
	}

	// Stop decay timer if running
	if d.decayCancel != nil {
		d.decayCancel()
		<-d.decayDone
	}

	d.started.Store(false)

	d.logger.Info("dampening manager stopped")

	return nil
}

// IsStarted returns true if the dampening manager is running.
func (d *DampeningManager) IsStarted() bool {
	return d.started.Load()
}

// RecordFlap records a route flap event.
func (d *DampeningManager) RecordFlap(prefix netip.Prefix) error {
	if !d.started.Load() {
		return ErrManagerNotStarted
	}

	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	key := prefix.String()
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	state, exists := d.routes[key]
	if !exists {
		state = &DampeningState{
			Prefix:    prefix,
			FirstFlap: now,
			LastDecay: now,
		}
		d.routes[key] = state
	}

	// Apply any pending decay before adding new penalty
	d.decayPenalty(state, now)

	// Add flap penalty
	state.Penalty += d.config.FlapPenalty
	state.FlapCount++
	state.LastFlap = now

	// Cap at maximum penalty
	if state.Penalty > d.maxPenalty {
		state.Penalty = d.maxPenalty
	}

	// Check if route should be suppressed
	wasSuppressed := state.Suppressed
	if state.Penalty >= d.config.SuppressThreshold && !state.Suppressed {
		state.Suppressed = true
		state.SuppressedAt = now
		state.ReuseAt = d.calculateReuseTime(state.Penalty, now)

		d.logger.Info("route suppressed",
			slog.String("prefix", prefix.String()),
			slog.Int("penalty", state.Penalty),
			slog.Time("reuse_at", state.ReuseAt),
		)
	}

	// Log the flap
	d.logger.Debug("route flap recorded",
		slog.String("prefix", prefix.String()),
		slog.Int("penalty", state.Penalty),
		slog.Int("flap_count", state.FlapCount),
		slog.Bool("suppressed", state.Suppressed),
		slog.Bool("newly_suppressed", state.Suppressed && !wasSuppressed),
	)

	return nil
}

// IsSuppressed checks if a route is currently suppressed.
func (d *DampeningManager) IsSuppressed(prefix netip.Prefix) bool {
	if !prefix.IsValid() {
		return false
	}

	key := prefix.String()

	d.mu.RLock()
	defer d.mu.RUnlock()

	state, exists := d.routes[key]
	if !exists {
		return false
	}

	return state.Suppressed
}

// GetDampeningState returns dampening state for a prefix.
func (d *DampeningManager) GetDampeningState(prefix netip.Prefix) (*DampeningState, error) {
	if !prefix.IsValid() {
		return nil, ErrInvalidPrefix
	}

	key := prefix.String()

	d.mu.RLock()
	defer d.mu.RUnlock()

	state, exists := d.routes[key]
	if !exists {
		return nil, ErrDampeningStateNotFound
	}

	// Return a copy
	stateCopy := *state
	return &stateCopy, nil
}

// ListSuppressedRoutes returns all suppressed routes.
func (d *DampeningManager) ListSuppressedRoutes() []*SuppressedRoute {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now()
	result := make([]*SuppressedRoute, 0)

	for _, state := range d.routes {
		if state.Suppressed {
			result = append(result, &SuppressedRoute{
				Prefix:       state.Prefix,
				Penalty:      state.Penalty,
				SuppressedAt: state.SuppressedAt,
				ReuseAt:      state.ReuseAt,
				FlapCount:    state.FlapCount,
				Duration:     now.Sub(state.SuppressedAt),
			})
		}
	}

	return result
}

// ClearDampening clears dampening for a specific route.
func (d *DampeningManager) ClearDampening(prefix netip.Prefix) error {
	if !d.started.Load() {
		return ErrManagerNotStarted
	}

	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	key := prefix.String()

	d.mu.Lock()
	defer d.mu.Unlock()

	state, exists := d.routes[key]
	if !exists {
		return ErrDampeningStateNotFound
	}

	wasSuppressed := state.Suppressed

	delete(d.routes, key)

	d.logger.Info("dampening cleared",
		slog.String("prefix", prefix.String()),
		slog.Bool("was_suppressed", wasSuppressed),
	)

	return nil
}

// ClearAllDampening clears all dampening state.
func (d *DampeningManager) ClearAllDampening() error {
	if !d.started.Load() {
		return ErrManagerNotStarted
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	count := len(d.routes)
	d.routes = make(map[string]*DampeningState)

	d.logger.Info("all dampening cleared",
		slog.Int("routes_cleared", count),
	)

	return nil
}

// StartDecayTimer starts the penalty decay timer.
func (d *DampeningManager) StartDecayTimer(ctx context.Context) error {
	if !d.started.Load() {
		return ErrManagerNotStarted
	}

	if d.decayCancel != nil {
		return ErrDecayTimerAlreadyRunning
	}

	decayCtx, cancel := context.WithCancel(ctx)
	d.decayCancel = cancel
	d.decayDone = make(chan struct{})

	go d.runDecayTimer(decayCtx)

	d.logger.Info("decay timer started",
		slog.Duration("interval", d.config.DecayInterval),
	)

	return nil
}

// StopDecayTimer stops the penalty decay timer.
func (d *DampeningManager) StopDecayTimer() {
	if d.decayCancel != nil {
		d.decayCancel()
		<-d.decayDone
		d.decayCancel = nil
		d.decayDone = nil

		d.logger.Info("decay timer stopped")
	}
}

// runDecayTimer runs the decay timer loop.
func (d *DampeningManager) runDecayTimer(ctx context.Context) {
	defer close(d.decayDone)

	ticker := time.NewTicker(d.config.DecayInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.processDecay()
		}
	}
}

// processDecay processes penalty decay for all routes.
func (d *DampeningManager) processDecay() {
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	routesToDelete := make([]string, 0)

	for key, state := range d.routes {
		d.decayPenalty(state, now)

		// Check if route should be unsuppressed
		if state.Suppressed && state.Penalty <= d.config.ReuseThreshold {
			state.Suppressed = false

			d.logger.Info("route unsuppressed",
				slog.String("prefix", state.Prefix.String()),
				slog.Int("penalty", state.Penalty),
				slog.Duration("suppressed_duration", now.Sub(state.SuppressedAt)),
			)
		}

		// Remove routes with zero penalty that are not suppressed
		if state.Penalty <= 0 && !state.Suppressed {
			routesToDelete = append(routesToDelete, key)
		}
	}

	// Clean up fully decayed routes
	for _, key := range routesToDelete {
		delete(d.routes, key)
	}
}

// decayPenalty applies penalty decay based on elapsed time.
func (d *DampeningManager) decayPenalty(state *DampeningState, now time.Time) {
	if state.Penalty <= 0 {
		return
	}

	elapsed := now.Sub(state.LastDecay)
	if elapsed <= 0 {
		return
	}

	// Calculate number of decay intervals
	intervals := elapsed.Seconds() / d.config.DecayInterval.Seconds()

	// Apply exponential decay
	newPenalty := float64(state.Penalty) * math.Pow(d.decayFactor, intervals)
	state.Penalty = int(newPenalty)
	state.LastDecay = now

	// Update reuse time if still suppressed
	if state.Suppressed {
		state.ReuseAt = d.calculateReuseTime(state.Penalty, now)
	}
}

// calculateReuseTime estimates when a route will be reused.
func (d *DampeningManager) calculateReuseTime(penalty int, now time.Time) time.Time {
	if penalty <= d.config.ReuseThreshold {
		return now
	}

	// Calculate time to decay from current penalty to reuse threshold
	// penalty * decayFactor^n = reuseThreshold
	// n = log(reuseThreshold/penalty) / log(decayFactor)
	ratio := float64(d.config.ReuseThreshold) / float64(penalty)
	intervals := math.Log(ratio) / math.Log(d.decayFactor)

	decayTime := time.Duration(intervals * d.config.DecayInterval.Seconds() * float64(time.Second))

	// Cap at max suppress time
	if decayTime > d.config.MaxSuppressTime {
		decayTime = d.config.MaxSuppressTime
	}

	return now.Add(decayTime)
}

// GetConfig returns a copy of the dampening configuration.
func (d *DampeningManager) GetConfig() *DampeningConfig {
	return &DampeningConfig{
		HalfLife:          d.config.HalfLife,
		ReuseThreshold:    d.config.ReuseThreshold,
		SuppressThreshold: d.config.SuppressThreshold,
		MaxSuppressTime:   d.config.MaxSuppressTime,
		FlapPenalty:       d.config.FlapPenalty,
		DecayInterval:     d.config.DecayInterval,
	}
}

// RouteCount returns the number of routes being tracked.
func (d *DampeningManager) RouteCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return len(d.routes)
}

// SuppressedCount returns the number of suppressed routes.
func (d *DampeningManager) SuppressedCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	count := 0
	for _, state := range d.routes {
		if state.Suppressed {
			count++
		}
	}

	return count
}

// GetDampeningStats returns dampening statistics.
type DampeningStats struct {
	// TotalRoutes is the number of routes being tracked.
	TotalRoutes int

	// SuppressedRoutes is the number of suppressed routes.
	SuppressedRoutes int

	// TotalFlaps is the total number of flaps recorded.
	TotalFlaps int

	// AveragePenalty is the average penalty across all routes.
	AveragePenalty float64

	// MaxPenalty is the highest penalty value.
	MaxPenalty int

	// OldestFlap is the time of the oldest tracked flap.
	OldestFlap time.Time

	// NewestFlap is the time of the most recent flap.
	NewestFlap time.Time
}

// GetStats returns dampening statistics.
func (d *DampeningManager) GetStats() *DampeningStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := &DampeningStats{}

	if len(d.routes) == 0 {
		return stats
	}

	totalPenalty := 0
	var oldestFlap, newestFlap time.Time

	for _, state := range d.routes {
		stats.TotalRoutes++
		stats.TotalFlaps += state.FlapCount
		totalPenalty += state.Penalty

		if state.Suppressed {
			stats.SuppressedRoutes++
		}

		if state.Penalty > stats.MaxPenalty {
			stats.MaxPenalty = state.Penalty
		}

		if oldestFlap.IsZero() || state.FirstFlap.Before(oldestFlap) {
			oldestFlap = state.FirstFlap
		}

		if newestFlap.IsZero() || state.LastFlap.After(newestFlap) {
			newestFlap = state.LastFlap
		}
	}

	if stats.TotalRoutes > 0 {
		stats.AveragePenalty = float64(totalPenalty) / float64(stats.TotalRoutes)
	}

	stats.OldestFlap = oldestFlap
	stats.NewestFlap = newestFlap

	return stats
}

// ListAllRoutes returns all tracked routes.
func (d *DampeningManager) ListAllRoutes() []*DampeningState {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]*DampeningState, 0, len(d.routes))

	for _, state := range d.routes {
		stateCopy := *state
		result = append(result, &stateCopy)
	}

	return result
}

// GetMaxPenalty returns the calculated maximum penalty.
func (d *DampeningManager) GetMaxPenalty() int {
	return d.maxPenalty
}

// GetDecayFactor returns the calculated decay factor.
func (d *DampeningManager) GetDecayFactor() float64 {
	return d.decayFactor
}
