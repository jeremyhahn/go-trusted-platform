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

package reporting

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// QuoteSource obtains fresh attestation evidence from a device.
//
// This is the ONLY interface in the platform that reaches a device's TPM for
// attestation, and the collector is its only caller. Slice B of #226
// implements it — the reporting service dialling the node over mTLS. Keeping
// it an interface is what lets the collector, the cache and the invariant be
// built and tested before that exists.
type QuoteSource interface {
	// Collect asks a device for a quote over the supplied nonce and returns
	// the encoded evidence. The nonce is generated per collection by the
	// collector: a quote over a nonce the device chose proves nothing about
	// freshness.
	Collect(ctx context.Context, deviceID string, nonce []byte) ([]byte, error)
}

// Verifier verifies collected evidence.
//
// Declared here as the narrow thing the collector needs rather than imported
// from the transport package that implements it today, so a background
// collector does not depend on an API layer. The platform's existing device
// quote verifier satisfies it through a small adapter.
type Verifier interface {
	// VerifyDeviceQuote verifies evidence against the device's enrolled
	// attestation key and PCR policy. An error means the evidence could not
	// be EVALUATED; a negative verdict is a non-error Report with Verified
	// false.
	VerifyDeviceQuote(ctx context.Context, deviceID string, evidence []byte) (*Report, error)
}

// ClockSource reports a device's own clock trust state.
//
// It is separate from QuoteSource because it is optional and because it
// carries no evidence: a collector with no ClockSource produces reports
// whose TimeSynced is absent, which is the honest rendering of "nobody
// asked". Like QuoteSource it reaches a device, so the Collector is its
// only caller.
type ClockSource interface {
	// ClockSynced reports whether the device's time daemon currently
	// disciplines its clock. An error means the state could not be read,
	// which the collector records as unknown rather than as unsynced.
	ClockSynced(ctx context.Context, deviceID string) (bool, error)
}

// DeviceLister names the devices to collect from.
type DeviceLister interface {
	// AttestableDevices returns the device ids currently expected to attest.
	AttestableDevices(ctx context.Context) ([]string, error)
}

// NonceFunc generates a fresh anti-replay nonce per collection.
type NonceFunc func() ([]byte, error)

// Config configures a Collector.
type Config struct {
	// Source reaches devices. Required.
	Source QuoteSource
	// Verifier evaluates evidence. Required.
	Verifier Verifier
	// Clock reads devices' clock trust state. Optional: with none, every
	// report's TimeSynced is absent.
	Clock ClockSource
	// Devices names what to collect from. Optional: with none, the collector
	// serves only enqueued work.
	Devices DeviceLister
	// Cache receives verified reports. Optional; one is created if nil.
	Cache *Cache
	// Interval is the refresh cycle. Zero uses DefaultInterval.
	Interval time.Duration
	// Nonce generates per-collection nonces. Zero uses a crypto/rand source.
	Nonce NonceFunc
	// Logger is optional.
	Logger *slog.Logger
}

// Collector refreshes attestation reports on a schedule and serves them from
// a cache.
//
// It is the only component holding a QuoteSource. Request handlers are given
// the Cache (as a Reader) and therefore cannot reach a device — see the
// package comment.
type Collector struct {
	source   QuoteSource
	verifier Verifier
	clock    ClockSource
	devices  DeviceLister
	cache    *Cache
	interval time.Duration
	nonce    NonceFunc
	logger   *slog.Logger
	clk      clock

	// inflight serializes collection per device and coalesces concurrent
	// requests for the same one. Without it an operator clicking twice, or a
	// scheduled cycle overlapping an enqueued refresh, would put two quote
	// requests on one TPM — which is the exhaustion this design exists to
	// prevent, arriving by a different door than the one it guards.
	mu       sync.Mutex
	inflight map[string]chan struct{}

	enqueue chan string
	running bool

	// onCoalesce, when set, is called with the device id each time a
	// collection is suppressed because one is already in flight for that
	// device. It is a test observer, fixed at construction and nil in
	// production, following the onSweep seam in pkg/security/ratelimit.
	//
	// It exists because coalescing is otherwise unobservable from outside: a
	// caller that coalesced and a caller that has not yet reached the check
	// look identical, so a test could only distinguish them by waiting a
	// while and hoping. That is the timing guess this repo has banned.
	onCoalesce func(deviceID string)
}

// NewCollector creates a Collector. It fails closed on a missing source or
// verifier rather than returning one that silently collects or stores
// nothing.
func NewCollector(cfg Config) (*Collector, error) {
	return newCollectorWithClock(cfg, realClock{})
}

func newCollectorWithClock(cfg Config, clk clock) (*Collector, error) {
	if cfg.Source == nil {
		return nil, ErrNoQuoteSource{}
	}
	if cfg.Verifier == nil {
		return nil, ErrNoVerifier{}
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	cache := cfg.Cache
	if cache == nil {
		cache = newCacheWithClock(2*interval, clk)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	nonce := cfg.Nonce
	if nonce == nil {
		nonce = randomNonce
	}
	return &Collector{
		source:   cfg.Source,
		verifier: cfg.Verifier,
		clock:    cfg.Clock,
		devices:  cfg.Devices,
		cache:    cache,
		interval: interval,
		nonce:    nonce,
		logger:   logger,
		clk:      clk,
		inflight: make(map[string]chan struct{}),
		enqueue:  make(chan string, 64),
	}, nil
}

// Cache returns the report cache. Hand this to request handlers — as a
// Reader, so they get the read-only view.
func (c *Collector) Cache() *Cache { return c.cache }

// Run drives the collector until ctx is cancelled.
//
// It waits on the clock rather than sleeping, and selects on ctx.Done() in
// every wait, so cancellation is observed immediately rather than after the
// current interval.
func (c *Collector) Run(ctx context.Context) error {
	c.mu.Lock()
	c.running = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	// Collect once at start rather than waiting a full interval: a control
	// plane that has just come up with an empty cache would otherwise report
	// every device as never-collected for the first cycle.
	c.CollectAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case deviceID := <-c.enqueue:
			c.Collect(ctx, deviceID)
		case <-c.clk.After(c.interval):
			c.CollectAll(ctx)
		}
	}
}

// Enqueue asks for a device to be refreshed out of cycle.
//
// This is the operator action's path, and it is on the COLLECTOR, not on the
// Reader a handler holds. The request still goes through the collector's
// per-device serialization and coalescing, so an operator cannot produce more
// TPM load than the schedule would.
//
// It does not block: a full queue drops the request rather than stalling a
// request handler, because the scheduled cycle will collect the device anyway
// and a blocked handler is a worse outcome than a slightly later refresh.
func (c *Collector) Enqueue(deviceID string) error {
	c.mu.Lock()
	running := c.running
	c.mu.Unlock()
	if !running {
		return ErrCollectorStopped{}
	}
	select {
	case c.enqueue <- deviceID:
		return nil
	default:
		c.logger.Warn("attestation reporting: refresh queue full, relying on the scheduled cycle",
			"device_id", deviceID)
		return nil
	}
}

// CollectAll refreshes every attestable device once.
func (c *Collector) CollectAll(ctx context.Context) {
	if c.devices == nil {
		return
	}
	ids, err := c.devices.AttestableDevices(ctx)
	if err != nil {
		c.logger.Error("attestation reporting: could not list devices", "error", err)
		return
	}
	for _, id := range ids {
		select {
		case <-ctx.Done():
			return
		default:
		}
		c.Collect(ctx, id)
	}
}

// Collect refreshes one device, coalescing with any collection already in
// flight for it.
//
// A failure to collect or to verify leaves the PREVIOUS report in place and
// records nothing new. That is deliberate and it is the rule the design of
// record states for quarantine: absence of evidence is NOT failed
// attestation. Writing a failed report because a node was unreachable would
// convert a network problem into an attestation verdict, and #197 is this
// repo already shipping that conflation once.
func (c *Collector) Collect(ctx context.Context, deviceID string) {
	if deviceID == "" {
		return
	}

	c.mu.Lock()
	if wait, busy := c.inflight[deviceID]; busy {
		observer := c.onCoalesce
		c.mu.Unlock()
		if observer != nil {
			observer(deviceID)
		}
		// Coalesce: wait for the in-flight collection rather than starting a
		// second quote on the same TPM.
		select {
		case <-wait:
		case <-ctx.Done():
		}
		return
	}
	done := make(chan struct{})
	c.inflight[deviceID] = done
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.inflight, deviceID)
		c.mu.Unlock()
		close(done)
	}()

	report, err := c.collectOnce(ctx, deviceID)
	if err != nil {
		c.logger.Warn("attestation reporting: no new evidence for device",
			"device_id", deviceID, "error", err,
			"note", "previous report retained; this is not a failed attestation")
		return
	}
	c.cache.Store(report)
}

// collectOnce performs one collect-and-verify without touching the cache.
func (c *Collector) collectOnce(ctx context.Context, deviceID string) (*Report, error) {
	nonce, err := c.nonce()
	if err != nil {
		return nil, ErrCollectionFailed{DeviceID: deviceID, Cause: err}
	}

	evidence, err := c.source.Collect(ctx, deviceID, nonce)
	if err != nil {
		return nil, ErrCollectionFailed{DeviceID: deviceID, Cause: err}
	}

	report, err := c.verifier.VerifyDeviceQuote(ctx, deviceID, evidence)
	if err != nil {
		return nil, ErrVerificationUnavailable{DeviceID: deviceID, Cause: err}
	}
	if report == nil {
		return nil, ErrVerificationUnavailable{DeviceID: deviceID, Cause: ErrNoVerifier{}}
	}

	report.DeviceID = deviceID
	report.CollectedAt = c.clk.Now()
	report.TimeSynced = c.clockState(ctx, deviceID)
	return report, nil
}

// clockState reads the device's clock trust state for this collection.
//
// A failure is NOT a negative answer: it returns nil, the report renders
// time_synced as absent, and the verdict stands on its own. Recording false
// because the read failed would report a healthy node's clock as wrong on
// the strength of a network error.
func (c *Collector) clockState(ctx context.Context, deviceID string) *bool {
	if c.clock == nil {
		return nil
	}
	synced, err := c.clock.ClockSynced(ctx, deviceID)
	if err != nil {
		c.logger.Debug("attestation reporting: clock state unavailable for device",
			"device_id", deviceID, "error", err,
			"note", "the report records time_synced as unknown, not as unsynced")
		return nil
	}
	return &synced
}
