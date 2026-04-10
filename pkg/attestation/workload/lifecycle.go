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

package workload

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// LifecycleHook provides hooks for workload lifecycle events.
type LifecycleHook interface {
	// OnWorkloadStart is called when a workload starts.
	// This triggers PCR extension with the workload measurement.
	OnWorkloadStart(ctx context.Context, wt WorkloadType, id, imageDigest string) error

	// OnWorkloadStop is called when a workload stops.
	// This is for audit logging purposes only; PCR values cannot be decremented.
	OnWorkloadStop(ctx context.Context, wt WorkloadType, id string) error
}

// WorkloadEvent represents a workload lifecycle event.
type WorkloadEvent struct {
	// Type indicates if this is a start or stop event.
	Type WorkloadEventType

	// Timestamp is when the event occurred.
	Timestamp time.Time

	// WorkloadType is the type of workload.
	WorkloadType WorkloadType

	// WorkloadID is the unique identifier for the workload.
	WorkloadID string

	// ImageDigest is the digest of the workload image (only for start events).
	ImageDigest string

	// ChainEntry is the chain entry created for start events.
	ChainEntry *ChainEntry
}

// WorkloadEventType indicates the type of lifecycle event.
type WorkloadEventType string

const (
	// WorkloadEventStart indicates a workload start event.
	WorkloadEventStart WorkloadEventType = "start"

	// WorkloadEventStop indicates a workload stop event.
	WorkloadEventStop WorkloadEventType = "stop"
)

// LifecycleManager manages workload lifecycle events and PCR extensions.
type LifecycleManager struct {
	mu          sync.RWMutex
	chain       ChainManager
	config      *config.WorkloadConfig
	initialized atomic.Bool
	closed      atomic.Bool
	logger      *slog.Logger
	// Track active workloads for stop event validation
	activeWorkloads map[string]*WorkloadEvent
	// Event history for audit purposes
	events []*WorkloadEvent
}

// LifecycleManagerOption configures a lifecycle manager.
type LifecycleManagerOption func(*LifecycleManager)

// WithLifecycleLogger sets the logger for the lifecycle manager.
func WithLifecycleLogger(logger *slog.Logger) LifecycleManagerOption {
	return func(lm *LifecycleManager) {
		lm.logger = logger
	}
}

// NewLifecycleManager creates a new lifecycle manager.
func NewLifecycleManager(chain ChainManager, cfg *config.WorkloadConfig, opts ...LifecycleManagerOption) (*LifecycleManager, error) {
	if chain == nil {
		return nil, ErrInvalidConfig{Field: "chain", Reason: "chain manager cannot be nil"}
	}
	if cfg == nil {
		return nil, ErrInvalidConfig{Field: "config", Reason: "configuration cannot be nil"}
	}

	lm := &LifecycleManager{
		chain:           chain,
		config:          cfg,
		activeWorkloads: make(map[string]*WorkloadEvent),
		events:          make([]*WorkloadEvent, 0),
	}

	for _, opt := range opts {
		opt(lm)
	}

	if lm.logger == nil {
		lm.logger = slog.Default()
	}

	lm.initialized.Store(true)

	lm.logger.Info("lifecycle manager initialized",
		"enabled", cfg.Enabled,
		"pcr", cfg.PCR,
	)

	return lm, nil
}

// OnWorkloadStart handles a workload start event.
func (lm *LifecycleManager) OnWorkloadStart(ctx context.Context, wt WorkloadType, id, imageDigest string) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "OnWorkloadStart"}
	default:
	}

	if !lm.initialized.Load() {
		return ErrLifecycleNotInitialized{}
	}

	if lm.closed.Load() {
		return ErrLifecycleNotInitialized{}
	}

	// Create measurement
	measurement := &WorkloadMeasurement{
		WorkloadType: wt,
		WorkloadID:   id,
		ImageDigest:  imageDigest,
	}

	// Extend PCR only if enabled
	var chainEntry *ChainEntry
	var err error
	if lm.config.Enabled {
		chainEntry, err = lm.chain.ExtendPCR(ctx, measurement)
		if err != nil {
			return err
		}
	}

	// Record the event
	event := &WorkloadEvent{
		Type:         WorkloadEventStart,
		Timestamp:    time.Now().UTC(),
		WorkloadType: wt,
		WorkloadID:   id,
		ImageDigest:  imageDigest,
		ChainEntry:   chainEntry,
	}

	lm.mu.Lock()
	lm.activeWorkloads[id] = event
	lm.events = append(lm.events, event)
	lm.mu.Unlock()

	lm.logger.Info("workload started",
		"type", wt,
		"id", id,
		"image_digest", imageDigest,
		"pcr_extended", lm.config.Enabled,
	)

	return nil
}

// OnWorkloadStop handles a workload stop event.
func (lm *LifecycleManager) OnWorkloadStop(ctx context.Context, wt WorkloadType, id string) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "OnWorkloadStop"}
	default:
	}

	if !lm.initialized.Load() {
		return ErrLifecycleNotInitialized{}
	}

	if lm.closed.Load() {
		return ErrLifecycleNotInitialized{}
	}

	lm.mu.Lock()
	_, exists := lm.activeWorkloads[id]
	if exists {
		delete(lm.activeWorkloads, id)
	}

	// Record the event even if workload wasn't tracked
	event := &WorkloadEvent{
		Type:         WorkloadEventStop,
		Timestamp:    time.Now().UTC(),
		WorkloadType: wt,
		WorkloadID:   id,
	}
	lm.events = append(lm.events, event)
	lm.mu.Unlock()

	lm.logger.Info("workload stopped",
		"type", wt,
		"id", id,
		"was_tracked", exists,
	)

	return nil
}

// GetActiveWorkloads returns a list of currently active workloads.
func (lm *LifecycleManager) GetActiveWorkloads() []*WorkloadEvent {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	result := make([]*WorkloadEvent, 0, len(lm.activeWorkloads))
	for _, event := range lm.activeWorkloads {
		eventCopy := *event
		if event.ChainEntry != nil {
			entryCopy := *event.ChainEntry
			entryCopy.Digest = make([]byte, len(event.ChainEntry.Digest))
			copy(entryCopy.Digest, event.ChainEntry.Digest)
			entryCopy.PCRValue = make([]byte, len(event.ChainEntry.PCRValue))
			copy(entryCopy.PCRValue, event.ChainEntry.PCRValue)
			eventCopy.ChainEntry = &entryCopy
		}
		result = append(result, &eventCopy)
	}
	return result
}

// GetEventHistory returns all lifecycle events.
func (lm *LifecycleManager) GetEventHistory() []*WorkloadEvent {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	result := make([]*WorkloadEvent, len(lm.events))
	for i, event := range lm.events {
		eventCopy := *event
		if event.ChainEntry != nil {
			entryCopy := *event.ChainEntry
			entryCopy.Digest = make([]byte, len(event.ChainEntry.Digest))
			copy(entryCopy.Digest, event.ChainEntry.Digest)
			entryCopy.PCRValue = make([]byte, len(event.ChainEntry.PCRValue))
			copy(entryCopy.PCRValue, event.ChainEntry.PCRValue)
			eventCopy.ChainEntry = &entryCopy
		}
		result[i] = &eventCopy
	}
	return result
}

// IsWorkloadActive checks if a workload is currently active.
func (lm *LifecycleManager) IsWorkloadActive(id string) bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	_, exists := lm.activeWorkloads[id]
	return exists
}

// GetEventCount returns the total number of events recorded.
func (lm *LifecycleManager) GetEventCount() int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return len(lm.events)
}

// GetActiveWorkloadCount returns the number of active workloads.
func (lm *LifecycleManager) GetActiveWorkloadCount() int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return len(lm.activeWorkloads)
}

// Close releases resources held by the lifecycle manager.
func (lm *LifecycleManager) Close() error {
	if lm.closed.Swap(true) {
		return nil
	}

	lm.logger.Info("lifecycle manager closed",
		"total_events", len(lm.events),
		"active_workloads", len(lm.activeWorkloads),
	)

	return nil
}
