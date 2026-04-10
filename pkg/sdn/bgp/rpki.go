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

// RPKIValidationState represents the RPKI validation state of a route.
type RPKIValidationState uint8

const (
	// RPKIStateNotFound indicates no ROA was found for the prefix.
	RPKIStateNotFound RPKIValidationState = iota

	// RPKIStateValid indicates the route is valid according to RPKI.
	RPKIStateValid

	// RPKIStateInvalid indicates the route is invalid according to RPKI.
	RPKIStateInvalid

	// RPKIStateUnknown indicates the validation state could not be determined.
	RPKIStateUnknown
)

// String returns a human-readable representation of the RPKI validation state.
func (s RPKIValidationState) String() string {
	switch s {
	case RPKIStateNotFound:
		return "NotFound"
	case RPKIStateValid:
		return "Valid"
	case RPKIStateInvalid:
		return "Invalid"
	default:
		return "Unknown"
	}
}

// Valid returns true if the RPKI validation state is a valid value.
func (r RPKIValidationState) Valid() bool {
	return r <= RPKIStateUnknown
}

// IsAcceptable returns true if the route should be accepted based on RPKI state.
func (r RPKIValidationState) IsAcceptable() bool {
	return r == RPKIStateValid || r == RPKIStateNotFound || r == RPKIStateUnknown
}

// ROAEntry represents a Route Origin Authorization.
type ROAEntry struct {
	// Prefix is the IP prefix covered by this ROA.
	Prefix netip.Prefix

	// MaxLength is the maximum prefix length allowed.
	MaxLength int

	// ASN is the authorized origin AS number.
	ASN uint32

	// ExpiresAt is when this ROA expires.
	ExpiresAt time.Time

	// Source indicates where this ROA was obtained from.
	Source string

	// SerialNumber is the RPKI serial number.
	SerialNumber uint32
}

// IsExpired returns true if the ROA has expired.
func (r *ROAEntry) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// Covers returns true if this ROA covers the given prefix with the specified origin AS.
func (r *ROAEntry) Covers(prefix netip.Prefix, originASN uint32) bool {
	// Check if the prefix is covered
	if !r.Prefix.Contains(prefix.Addr()) {
		return false
	}

	// Check if the prefix length is within the allowed range
	if prefix.Bits() > r.MaxLength {
		return false
	}

	// Check if the AS matches
	return r.ASN == originASN
}

// RPKIStats contains RPKI validation statistics.
type RPKIStats struct {
	// ValidCount is the number of valid routes.
	ValidCount int64

	// InvalidCount is the number of invalid routes.
	InvalidCount int64

	// NotFoundCount is the number of routes with no ROA.
	NotFoundCount int64

	// ValidatorCount is the number of active validators.
	ValidatorCount int

	// ROACount is the total number of ROAs in the cache.
	ROACount int

	// LastUpdate is when the ROA cache was last updated.
	LastUpdate time.Time

	// LastSerial is the last RPKI serial number received.
	LastSerial uint32
}

// RPKISpeakerInterface defines the interface for RPKI operations on the speaker.
type RPKISpeakerInterface interface {
	// IsStarted returns true if the speaker is running.
	IsStarted() bool

	// GetASN returns the local AS number.
	GetASN() uint32
}

// RPKIValidatorConfig holds configuration for an RPKI validator.
type RPKIValidatorConfig struct {
	// Address is the validator address (host:port).
	Address string

	// Timeout is the connection timeout.
	Timeout time.Duration

	// RefreshInterval is how often to refresh the ROA cache.
	RefreshInterval time.Duration
}

// RPKIValidator handles RPKI-based route validation.
type RPKIValidator struct {
	speaker    RPKISpeakerInterface
	validators []string
	logger     *slog.Logger

	// ROA cache: key is prefix string
	roaCache map[string][]*ROAEntry
	mu       sync.RWMutex

	// Graceful degradation
	failOpen bool

	// Statistics
	validCount    atomic.Int64
	invalidCount  atomic.Int64
	notFoundCount atomic.Int64

	// Cache management
	lastUpdate   time.Time
	lastSerial   uint32
	cacheTimeout time.Duration

	// Started state
	started atomic.Bool

	// Refresh control
	refreshCancel context.CancelFunc
	refreshDone   chan struct{}
}

// RPKIValidatorOption configures the RPKIValidator.
type RPKIValidatorOption func(*RPKIValidator)

// WithFailOpen configures graceful degradation when validators are unavailable.
func WithFailOpen(failOpen bool) RPKIValidatorOption {
	return func(v *RPKIValidator) {
		v.failOpen = failOpen
	}
}

// WithCacheTimeout sets the ROA cache timeout.
func WithCacheTimeout(timeout time.Duration) RPKIValidatorOption {
	return func(v *RPKIValidator) {
		if timeout > 0 {
			v.cacheTimeout = timeout
		}
	}
}

// NewRPKIValidator creates an RPKI validator.
func NewRPKIValidator(
	speaker RPKISpeakerInterface,
	validators []string,
	logger *slog.Logger,
	opts ...RPKIValidatorOption,
) (*RPKIValidator, error) {
	if speaker == nil {
		return nil, ErrSpeakerNil
	}
	if logger == nil {
		return nil, ErrLoggerNil
	}

	v := &RPKIValidator{
		speaker:      speaker,
		validators:   make([]string, len(validators)),
		logger:       logger,
		roaCache:     make(map[string][]*ROAEntry),
		failOpen:     false,
		cacheTimeout: 1 * time.Hour,
	}

	copy(v.validators, validators)

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

// Start initializes the RPKI validator.
func (r *RPKIValidator) Start(ctx context.Context) error {
	if r.started.Load() {
		return ErrManagerAlreadyStarted
	}

	if !r.speaker.IsStarted() {
		return ErrSpeakerNotStarted
	}

	r.started.Store(true)

	r.logger.Info("RPKI validator started",
		slog.Int("validator_count", len(r.validators)),
		slog.Bool("fail_open", r.failOpen),
		slog.Duration("cache_timeout", r.cacheTimeout),
	)

	return nil
}

// Stop shuts down the RPKI validator.
func (r *RPKIValidator) Stop() error {
	if !r.started.Load() {
		return nil
	}

	// Cancel refresh if running
	if r.refreshCancel != nil {
		r.refreshCancel()
		<-r.refreshDone
	}

	r.started.Store(false)

	r.logger.Info("RPKI validator stopped")

	return nil
}

// IsStarted returns true if the RPKI validator is running.
func (r *RPKIValidator) IsStarted() bool {
	return r.started.Load()
}

// ValidateRoute checks route against RPKI ROAs.
func (r *RPKIValidator) ValidateRoute(prefix netip.Prefix, originASN uint32) (RPKIValidationState, error) {
	if !r.started.Load() {
		return RPKIStateUnknown, ErrManagerNotStarted
	}

	if !prefix.IsValid() {
		return RPKIStateUnknown, ErrInvalidPrefix
	}

	if originASN == 0 {
		return RPKIStateUnknown, ErrInvalidOriginAS
	}

	// Check if validators are available
	if len(r.validators) == 0 {
		if r.failOpen {
			r.notFoundCount.Add(1)
			return RPKIStateNotFound, nil
		}
		return RPKIStateUnknown, ErrNoValidatorsAvailable
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Look for matching ROAs
	roas := r.findCoveringROAs(prefix)

	if len(roas) == 0 {
		r.notFoundCount.Add(1)
		return RPKIStateNotFound, nil
	}

	// Check if any ROA validates the route
	for _, roa := range roas {
		if roa.IsExpired() {
			continue
		}

		if roa.Covers(prefix, originASN) {
			r.validCount.Add(1)
			return RPKIStateValid, nil
		}
	}

	// ROAs exist but none validate the route
	r.invalidCount.Add(1)
	return RPKIStateInvalid, nil
}

// findCoveringROAs finds all ROAs that could potentially cover the prefix.
func (r *RPKIValidator) findCoveringROAs(prefix netip.Prefix) []*ROAEntry {
	result := make([]*ROAEntry, 0)

	// Check all ROAs in the cache
	for _, roas := range r.roaCache {
		for _, roa := range roas {
			if roa.Prefix.Contains(prefix.Addr()) {
				result = append(result, roa)
			}
		}
	}

	return result
}

// AddValidator adds an RPKI validator server.
func (r *RPKIValidator) AddValidator(addr string) error {
	if !r.started.Load() {
		return ErrManagerNotStarted
	}

	if addr == "" {
		return ErrInvalidValidatorAddress
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate
	for _, existing := range r.validators {
		if existing == addr {
			return ErrValidatorExists
		}
	}

	r.validators = append(r.validators, addr)

	r.logger.Info("RPKI validator added",
		slog.String("address", addr),
		slog.Int("total_validators", len(r.validators)),
	)

	return nil
}

// RemoveValidator removes an RPKI validator.
func (r *RPKIValidator) RemoveValidator(addr string) error {
	if !r.started.Load() {
		return ErrManagerNotStarted
	}

	if addr == "" {
		return ErrInvalidValidatorAddress
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	found := false
	newValidators := make([]string, 0, len(r.validators))

	for _, existing := range r.validators {
		if existing == addr {
			found = true
			continue
		}
		newValidators = append(newValidators, existing)
	}

	if !found {
		return ErrValidatorNotFound
	}

	r.validators = newValidators

	r.logger.Info("RPKI validator removed",
		slog.String("address", addr),
		slog.Int("remaining_validators", len(r.validators)),
	)

	return nil
}

// ListValidators returns all configured validators.
func (r *RPKIValidator) ListValidators() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]string, len(r.validators))
	copy(result, r.validators)

	return result
}

// GetValidationStats returns RPKI validation statistics.
func (r *RPKIValidator) GetValidationStats() *RPKIStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	roaCount := 0
	for _, roas := range r.roaCache {
		roaCount += len(roas)
	}

	return &RPKIStats{
		ValidCount:     r.validCount.Load(),
		InvalidCount:   r.invalidCount.Load(),
		NotFoundCount:  r.notFoundCount.Load(),
		ValidatorCount: len(r.validators),
		ROACount:       roaCount,
		LastUpdate:     r.lastUpdate,
		LastSerial:     r.lastSerial,
	}
}

// SetFailOpen configures graceful degradation.
func (r *RPKIValidator) SetFailOpen(failOpen bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.failOpen = failOpen

	r.logger.Info("fail-open mode updated",
		slog.Bool("fail_open", failOpen),
	)
}

// IsFailOpen returns true if fail-open mode is enabled.
func (r *RPKIValidator) IsFailOpen() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.failOpen
}

// AddROA adds a ROA entry to the cache.
// This is typically called when receiving ROAs from a validator.
func (r *RPKIValidator) AddROA(roa *ROAEntry) error {
	if roa == nil {
		return ErrInvalidROA
	}

	if !roa.Prefix.IsValid() {
		return ErrInvalidPrefix
	}

	if roa.ASN == 0 {
		return ErrInvalidOriginAS
	}

	key := roa.Prefix.String()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate
	existing := r.roaCache[key]
	for _, e := range existing {
		if e.ASN == roa.ASN && e.MaxLength == roa.MaxLength {
			// Update existing entry
			e.ExpiresAt = roa.ExpiresAt
			e.Source = roa.Source
			e.SerialNumber = roa.SerialNumber
			return nil
		}
	}

	// Add new entry
	r.roaCache[key] = append(existing, roa)
	r.lastUpdate = time.Now()

	return nil
}

// RemoveROA removes a ROA entry from the cache.
func (r *RPKIValidator) RemoveROA(prefix netip.Prefix, asn uint32, maxLength int) error {
	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}

	key := prefix.String()

	r.mu.Lock()
	defer r.mu.Unlock()

	existing := r.roaCache[key]
	if len(existing) == 0 {
		return ErrROANotFound
	}

	newROAs := make([]*ROAEntry, 0, len(existing))
	found := false

	for _, roa := range existing {
		if roa.ASN == asn && roa.MaxLength == maxLength {
			found = true
			continue
		}
		newROAs = append(newROAs, roa)
	}

	if !found {
		return ErrROANotFound
	}

	if len(newROAs) == 0 {
		delete(r.roaCache, key)
	} else {
		r.roaCache[key] = newROAs
	}

	r.lastUpdate = time.Now()

	return nil
}

// ClearROACache clears the entire ROA cache.
func (r *RPKIValidator) ClearROACache() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.roaCache = make(map[string][]*ROAEntry)
	r.lastUpdate = time.Now()

	r.logger.Info("ROA cache cleared")
}

// GetROA retrieves ROAs for a specific prefix.
func (r *RPKIValidator) GetROA(prefix netip.Prefix) ([]*ROAEntry, error) {
	if !prefix.IsValid() {
		return nil, ErrInvalidPrefix
	}

	key := prefix.String()

	r.mu.RLock()
	defer r.mu.RUnlock()

	roas := r.roaCache[key]
	if len(roas) == 0 {
		return nil, ErrROANotFound
	}

	// Return copies
	result := make([]*ROAEntry, len(roas))
	for i, roa := range roas {
		roaCopy := *roa
		result[i] = &roaCopy
	}

	return result, nil
}

// ROACount returns the number of ROAs in the cache.
func (r *RPKIValidator) ROACount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0
	for _, roas := range r.roaCache {
		count += len(roas)
	}

	return count
}

// PruneExpiredROAs removes expired ROAs from the cache.
func (r *RPKIValidator) PruneExpiredROAs() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	pruned := 0

	for key, roas := range r.roaCache {
		activeROAs := make([]*ROAEntry, 0, len(roas))
		for _, roa := range roas {
			if !roa.IsExpired() {
				activeROAs = append(activeROAs, roa)
			} else {
				pruned++
			}
		}

		if len(activeROAs) == 0 {
			delete(r.roaCache, key)
		} else {
			r.roaCache[key] = activeROAs
		}
	}

	if pruned > 0 {
		r.logger.Info("expired ROAs pruned",
			slog.Int("pruned_count", pruned),
		)
	}

	return pruned
}

// UpdateSerial updates the last known serial number.
func (r *RPKIValidator) UpdateSerial(serial uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lastSerial = serial
	r.lastUpdate = time.Now()
}

// GetSerial returns the last known serial number.
func (r *RPKIValidator) GetSerial() uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.lastSerial
}

// LastUpdateTime returns the time of the last cache update.
func (r *RPKIValidator) LastUpdateTime() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.lastUpdate
}

// ResetStats resets validation statistics.
func (r *RPKIValidator) ResetStats() {
	r.validCount.Store(0)
	r.invalidCount.Store(0)
	r.notFoundCount.Store(0)

	r.logger.Info("RPKI validation stats reset")
}

// ValidatorCount returns the number of configured validators.
func (r *RPKIValidator) ValidatorCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.validators)
}

// HasValidators returns true if at least one validator is configured.
func (r *RPKIValidator) HasValidators() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.validators) > 0
}
