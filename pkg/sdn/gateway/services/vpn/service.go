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

package vpn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// nonceBytes is the length of an issued challenge.
const nonceBytes = 32

// expirySweep is how often the service sweeps for expired leases.
const expirySweep = 30 * time.Second

// Health is the service's status snapshot.
type Health struct {
	Active            bool
	ActiveLeases      int
	LeasesByDataPlane map[DataPlaneKind]int
	Admissions        uint64
	Refusals          uint64
	LastRefusal       string
}

// Service is the attested remote-access service. It has the same lifecycle
// shape as the other gateway services so the gateway's service handler can
// mount it: New, Start, Stop, Active, Health.
type Service struct {
	cfg    Config
	deps   Deps
	logger *slog.Logger

	mu     sync.Mutex
	active bool
	cancel context.CancelFunc
	done   chan struct{}

	// devices serialises lease operations per (tenant, device).
	devices *keyLock

	// nonces are the outstanding challenges, keyed by hex nonce, with the
	// instant they expire.
	nonces map[string]time.Time

	// enrolments is the control plane's peer set; nil until the first
	// delivery, which refuses every admission.
	enrolments atomic.Pointer[enrolmentSet]
	// enrolGate makes a lease commit atomic with an enrolment update.
	// SetEnrolments holds it exclusively while it publishes a set and sweeps
	// the leases that set no longer covers; Admit holds it shared from its
	// final enrolment check to the lease write. Order: enrolGate before a
	// device lock, never the reverse.
	enrolGate sync.RWMutex
	// rejectedEnrolments holds the peers of the last delivered set this
	// gateway refused (a zone it does not serve).
	rejectedEnrolments atomic.Pointer[[]EnrolmentRejection]
	// tenantPosture holds the compiled tenant posture policies, by tenant.
	tenantPosture atomic.Pointer[map[string]tenantPosture]

	admissions  atomic.Uint64
	refusals    atomic.Uint64
	lastRefusal atomic.Pointer[string]
}

// New validates the configuration and dependencies and returns a stopped
// service. A configuration this build cannot run — a data plane it does not
// offer, lease bounds, an empty pool — is ErrInvalidConfig here, not later.
func New(deps Deps, cfg Config) (*Service, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := deps.validate(cfg); err != nil {
		return nil, err
	}
	if deps.Clock == nil {
		deps.Clock = realClock{}
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return &Service{
		cfg:     cfg,
		deps:    deps,
		logger:  deps.Logger.With(slog.String("service", "vpn")),
		nonces:  make(map[string]time.Time),
		devices: newKeyLock(),
	}, nil
}

// Config returns the effective (defaulted) configuration.
func (s *Service) Config() Config {
	return s.cfg
}

// Start begins the expiry sweep. Leases already in the store (a projection
// rebuilt from the control plane) are honoured and swept like any other.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return &ErrAlreadyStarted{}
	}
	runCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})
	s.active = true
	go s.sweepLoop(runCtx, s.done)
	s.logger.Info("vpn admission service started",
		slog.String("pool", s.cfg.Pool),
		slog.Duration("lease_ttl", s.cfg.LeaseTTL),
		slog.Any("data_planes", s.cfg.DataPlanes))
	return nil
}

// Stop ends the sweep. Leases stay installed: a control-process restart must
// not drop admitted clients; the rebuilt projection resumes sweeping them.
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return &ErrNotStarted{}
	}
	s.active = false
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// Active reports whether the service is started.
func (s *Service) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Health returns the service snapshot.
func (s *Service) Health() Health {
	h := Health{
		Active:            s.Active(),
		LeasesByDataPlane: map[DataPlaneKind]int{},
		Admissions:        s.admissions.Load(),
		Refusals:          s.refusals.Load(),
	}
	if p := s.lastRefusal.Load(); p != nil {
		h.LastRefusal = *p
	}
	leases, err := s.deps.Leases.List(context.Background())
	if err != nil {
		return h
	}
	h.ActiveLeases = len(leases)
	for _, l := range leases {
		h.LeasesByDataPlane[l.DataPlane]++
	}
	return h
}

// Challenge issues a fresh nonce a client must echo in its admission or
// renewal. A nonce is single-use and expires after NonceTTL.
func (s *Service) Challenge() ([]byte, error) {
	if !s.Active() {
		return nil, &ErrNotStarted{}
	}
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &ErrInvalidRequest{Field: "nonce", Reason: "entropy unavailable: " + err.Error()}
	}
	s.mu.Lock()
	s.nonces[hex.EncodeToString(nonce)] = s.deps.Clock.Now().Add(s.cfg.NonceTTL)
	s.mu.Unlock()
	return nonce, nil
}

// consumeNonce removes an outstanding nonce and reports whether it was
// issued and still live.
func (s *Service) consumeNonce(nonce []byte) bool {
	if len(nonce) == 0 {
		return false
	}
	key := hex.EncodeToString(nonce)
	now := s.deps.Clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.nonces[key]
	if !ok {
		return false
	}
	delete(s.nonces, key)
	return now.Before(exp)
}

// sweepLoop revokes expired leases and drops stale nonces. It never sleeps;
// it waits on the clock's ticker or the context.
func (s *Service) sweepLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	tick, stop := s.deps.Clock.Tick(expirySweep)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			s.Sweep(ctx)
		}
	}
}

// Sweep revokes every lease past its expiry and forgets expired nonces. It
// is exported so a caller with its own schedule (and tests) can drive it.
func (s *Service) Sweep(ctx context.Context) {
	now := s.deps.Clock.Now()
	s.mu.Lock()
	for k, exp := range s.nonces {
		if !now.Before(exp) {
			delete(s.nonces, k)
		}
	}
	s.mu.Unlock()

	leases, err := s.deps.Leases.List(ctx)
	if err != nil {
		s.logger.Warn("vpn lease sweep: listing leases failed", slog.Any("error", err))
		return
	}
	for _, l := range leases {
		if !l.Expired(now) {
			continue
		}
		unlock := s.devices.lock(deviceKey(l.TenantID, l.DeviceID))
		// Re-read under the lock: a renewal may have landed since List.
		current, err := s.deps.Leases.Get(ctx, l.ID)
		if err == nil && current.Expired(now) {
			if err := s.revoke(ctx, current, RevokeExpired); err != nil {
				s.logger.Warn("vpn lease expiry revoke incomplete", slog.String("lease", string(l.ID)), slog.Any("error", err))
			}
		}
		unlock()
	}
}

func (s *Service) recordRefusal(reason string) {
	s.refusals.Add(1)
	r := reason
	s.lastRefusal.Store(&r)
}

func newLeaseID() (LeaseID, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", &ErrInvalidRequest{Field: "lease", Reason: "entropy unavailable: " + err.Error()}
	}
	return LeaseID(hex.EncodeToString(b)), nil
}
