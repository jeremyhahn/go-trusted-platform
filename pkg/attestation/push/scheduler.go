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

package push

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// ManifestProvider is an interface for getting the current manifest data.
type ManifestProvider interface {
	// GetCurrentManifest returns the current manifest payload.
	GetCurrentManifest(ctx context.Context) (*PushRequest, error)

	// HasChanged returns true if the manifest has changed since last push.
	HasChanged() bool

	// MarkPushed marks the manifest as pushed.
	MarkPushed()
}

// PushHandler is called when a push operation completes.
type PushHandler func(result *PushBatchResult)

// Scheduler manages the scheduling and triggering of push operations.
type Scheduler struct {
	config           *SchedulerConfig
	client           *Client
	targets          []*PushTarget
	manifestProvider ManifestProvider

	running  atomic.Bool
	stopped  atomic.Bool
	ctx      context.Context
	cancelFn context.CancelFunc
	wg       sync.WaitGroup

	// Channels for control
	triggerCh chan TriggerType
	changeCh  chan struct{}
	resultCh  chan *PushBatchResult

	// Handler for push results
	handler atomic.Pointer[PushHandler]

	// Lock-free counters using atomics
	pushCount    atomic.Uint64
	successCount atomic.Uint64
	failureCount atomic.Uint64

	// Last push time
	lastPushTime atomic.Pointer[time.Time]

	// Debounce tracking for on-change
	lastChangeTime  atomic.Pointer[time.Time]
	pendingDebounce atomic.Bool
}

// SchedulerOption configures the scheduler.
type SchedulerOption func(*schedulerOptions)

type schedulerOptions struct {
	handler          PushHandler
	manifestProvider ManifestProvider
}

// WithHandler sets a callback handler for push results.
func WithHandler(h PushHandler) SchedulerOption {
	return func(o *schedulerOptions) {
		o.handler = h
	}
}

// WithManifestProvider sets the manifest provider.
func WithManifestProvider(p ManifestProvider) SchedulerOption {
	return func(o *schedulerOptions) {
		o.manifestProvider = p
	}
}

// NewScheduler creates a new push scheduler.
func NewScheduler(config *SchedulerConfig, client *Client, targets []*PushTarget, opts ...SchedulerOption) (*Scheduler, error) {
	if config == nil {
		return nil, ErrInvalidConfig{Field: "config", Reason: "cannot be nil"}
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	if client == nil {
		return nil, ErrClientNotInitialized{}
	}

	if len(targets) == 0 {
		return nil, ErrNoTargetsConfigured{}
	}

	options := &schedulerOptions{}
	for _, opt := range opts {
		opt(options)
	}

	s := &Scheduler{
		config:    config,
		client:    client,
		targets:   targets,
		triggerCh: make(chan TriggerType, 10),
		changeCh:  make(chan struct{}, 1),
		resultCh:  make(chan *PushBatchResult, 100),
	}

	if options.handler != nil {
		s.handler.Store(&options.handler)
	}

	s.manifestProvider = options.manifestProvider

	return s, nil
}

// Start starts the scheduler.
func (s *Scheduler) Start(ctx context.Context) error {
	if s.stopped.Load() {
		return ErrSchedulerStopped{}
	}

	if !s.running.CompareAndSwap(false, true) {
		return ErrSchedulerAlreadyRunning{}
	}

	s.ctx, s.cancelFn = context.WithCancel(ctx)

	s.wg.Add(1)
	go s.run()

	s.wg.Add(1)
	go s.processResults()

	return nil
}

// Stop stops the scheduler.
func (s *Scheduler) Stop() error {
	if !s.running.Load() {
		return nil
	}

	s.stopped.Store(true)
	s.running.Store(false)

	if s.cancelFn != nil {
		s.cancelFn()
	}

	// Wait for goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(10 * time.Second):
		return ErrContextCanceled{Operation: "scheduler stop"}
	}
}

// TriggerPush triggers an immediate push operation.
func (s *Scheduler) TriggerPush() error {
	if !s.running.Load() {
		return ErrSchedulerStopped{}
	}

	select {
	case s.triggerCh <- TriggerManual:
		return nil
	default:
		return ErrContextCanceled{Operation: "trigger push"}
	}
}

// NotifyChange notifies the scheduler that the manifest has changed.
func (s *Scheduler) NotifyChange() {
	if !s.running.Load() {
		return
	}

	now := time.Now()
	s.lastChangeTime.Store(&now)

	select {
	case s.changeCh <- struct{}{}:
	default:
		// Channel full, change already pending
	}
}

// IsRunning returns true if the scheduler is running.
func (s *Scheduler) IsRunning() bool {
	return s.running.Load()
}

// Stats returns scheduler statistics.
func (s *Scheduler) Stats() SchedulerStats {
	var lastPush time.Time
	if t := s.lastPushTime.Load(); t != nil {
		lastPush = *t
	}

	return SchedulerStats{
		PushCount:    s.pushCount.Load(),
		SuccessCount: s.successCount.Load(),
		FailureCount: s.failureCount.Load(),
		LastPushTime: lastPush,
		IsRunning:    s.running.Load(),
	}
}

// SetHandler sets the push result handler.
func (s *Scheduler) SetHandler(h PushHandler) {
	s.handler.Store(&h)
}

// SetTargets updates the targets.
func (s *Scheduler) SetTargets(targets []*PushTarget) {
	s.targets = targets
}

// run is the main scheduler loop.
func (s *Scheduler) run() {
	defer s.wg.Done()

	var ticker *time.Ticker
	var tickerCh <-chan time.Time

	if s.config.TriggerType == TriggerPeriodic {
		ticker = time.NewTicker(s.config.PushInterval)
		tickerCh = ticker.C
		defer ticker.Stop()
	}

	for {
		select {
		case <-s.ctx.Done():
			return

		case <-tickerCh:
			s.executePush(TriggerPeriodic)

		case trigger := <-s.triggerCh:
			s.executePush(trigger)

		case <-s.changeCh:
			if s.config.TriggerType == TriggerOnChange {
				s.handleChange()
			}
		}
	}
}

// handleChange handles on-change triggers with debouncing.
func (s *Scheduler) handleChange() {
	if s.pendingDebounce.Load() {
		return
	}

	if s.config.OnChangeDebounce > 0 {
		s.pendingDebounce.Store(true)
		go func() {
			select {
			case <-s.ctx.Done():
				s.pendingDebounce.Store(false)
				return
			case <-time.After(s.config.OnChangeDebounce):
				s.pendingDebounce.Store(false)
				s.executePush(TriggerOnChange)
			}
		}()
	} else {
		s.executePush(TriggerOnChange)
	}
}

// executePush executes a push operation.
func (s *Scheduler) executePush(trigger TriggerType) {
	if s.manifestProvider == nil {
		return
	}

	// For on-change, check if actually changed
	if trigger == TriggerOnChange && !s.manifestProvider.HasChanged() {
		return
	}

	request, err := s.manifestProvider.GetCurrentManifest(s.ctx)
	if err != nil {
		// Log error but don't stop scheduler
		return
	}

	if request == nil {
		return
	}

	request.Trigger = trigger

	s.pushCount.Add(1)
	now := time.Now()
	s.lastPushTime.Store(&now)

	// Get enabled targets
	enabledTargets := make([]*PushTarget, 0, len(s.targets))
	for _, t := range s.targets {
		if t.Enabled {
			enabledTargets = append(enabledTargets, t)
		}
	}

	if len(enabledTargets) == 0 {
		return
	}

	result, err := s.client.PushBatch(s.ctx, enabledTargets, request)
	if err != nil {
		s.failureCount.Add(1)
		return
	}

	// Update counters
	if result.AllSuccess() {
		s.successCount.Add(1)
		s.manifestProvider.MarkPushed()
	} else {
		s.failureCount.Add(1)
	}

	// Send result to channel
	select {
	case s.resultCh <- result:
	default:
		// Channel full, drop result
	}
}

// processResults processes push results and calls handlers.
func (s *Scheduler) processResults() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		case result := <-s.resultCh:
			if hp := s.handler.Load(); hp != nil {
				(*hp)(result)
			}
		}
	}
}

// SchedulerStats contains scheduler statistics.
type SchedulerStats struct {
	PushCount    uint64
	SuccessCount uint64
	FailureCount uint64
	LastPushTime time.Time
	IsRunning    bool
}

// SimpleManifestProvider is a basic implementation of ManifestProvider.
type SimpleManifestProvider struct {
	payload     atomic.Pointer[[]byte]
	manifestID  atomic.Pointer[string]
	contentType string
	changed     atomic.Bool
}

// NewSimpleManifestProvider creates a new SimpleManifestProvider.
func NewSimpleManifestProvider(contentType string) *SimpleManifestProvider {
	return &SimpleManifestProvider{
		contentType: contentType,
	}
}

// SetManifest sets the current manifest data.
func (p *SimpleManifestProvider) SetManifest(id string, payload []byte) {
	p.manifestID.Store(&id)
	p.payload.Store(&payload)
	p.changed.Store(true)
}

// GetCurrentManifest returns the current manifest payload.
func (p *SimpleManifestProvider) GetCurrentManifest(ctx context.Context) (*PushRequest, error) {
	payload := p.payload.Load()
	if payload == nil || len(*payload) == 0 {
		return nil, nil
	}

	id := ""
	if mid := p.manifestID.Load(); mid != nil {
		id = *mid
	}

	return &PushRequest{
		ManifestID:  id,
		Payload:     *payload,
		ContentType: p.contentType,
		Metadata:    make(map[string]string),
	}, nil
}

// HasChanged returns true if the manifest has changed since last push.
func (p *SimpleManifestProvider) HasChanged() bool {
	return p.changed.Load()
}

// MarkPushed marks the manifest as pushed.
func (p *SimpleManifestProvider) MarkPushed() {
	p.changed.Store(false)
}
