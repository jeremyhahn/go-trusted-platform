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
	"errors"
	"log/slog"
	"net/netip"
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
	// Revocations counts the revoked leases by RevokeReason.
	Revocations map[RevokeReason]uint64
	// PostureViolations counts the posture rules that refused an admission
	// or a renewal, by rule name.
	PostureViolations map[string]uint64
	// Reattest is how long the renewal re-attestations took to verify.
	Reattest DurationHistogram
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

	// peerRetry holds, per hosted plane, a peer removal Restore could not
	// complete, with the rejected leases whose addresses wait on it (see
	// retryPeerReconcile). A key with a nil slice is a failed
	// reconciliation alone. Guarded by mu.
	peerRetry map[DataPlaneKind][]*Lease
	// extendOwed holds the leases whose stored deadline the host has not
	// confirmed (a failed ExtendPeer): Sweep re-sends it until the host
	// holds it. Allocated on first use. Guarded by mu.
	extendOwed map[LeaseID]struct{}
	// renewBypass holds the leases whose client was refused a renewal
	// after the new deadline was stored (a failed ExtendPeer): the client
	// still holds its old expiry, so its retry is not held to the window
	// of the stored one. A Sweep that pays the host extension leaves it;
	// only a successful Renew or a committed revocation clears it. The
	// deadline the client holds is also stored on the lease
	// (Lease.ClientExpiresAt), from which Restore rebuilds this set after
	// a restart. Allocated on first use. Guarded by mu.
	renewBypass map[LeaseID]struct{}
	// tearingDown counts, per address, the revocations whose teardown has
	// not settled: the lease may already be deleted while the peer removal
	// runs and neither releaseAddress nor owePeerRetry has run yet. Orphan
	// reclaim treats these addresses as held. Allocated on first use, like
	// peerRetry. Guarded by mu.
	tearingDown map[netip.Addr]int
	// sweepGateHook, when set by a test, runs in retryPeerReconcile after
	// its pending check and before it takes enrolGate: it parks one sweep
	// at that point while an overlapping one runs. Nil in production.
	sweepGateHook func()
	// reclaimOwed records that orphan addresses still wait to be reclaimed
	// (a reconciliation or a reclaim failed); retryPeerReconcile pays it
	// once every plane reconciles. Guarded by mu.
	reclaimOwed bool

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

	admissions        atomic.Uint64
	refusals          atomic.Uint64
	lastRefusal       atomic.Pointer[string]
	revocations       labelledCounters
	postureViolations labelledCounters
	reattest          *durationHistogram
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
		postureViolations: labelledCounters{
			limit:    maxPostureRuleLabels,
			overflow: OtherPostureRule,
		},
		reattest: newDurationHistogram(reattestBuckets),
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
		PostureViolations: s.postureViolations.snapshot(),
		Reattest:          s.reattest.snapshot(),
	}
	if p := s.lastRefusal.Load(); p != nil {
		h.LastRefusal = *p
	}
	if counts := s.revocations.snapshot(); counts != nil {
		h.Revocations = make(map[RevokeReason]uint64, len(counts))
		for reason, n := range counts {
			h.Revocations[RevokeReason(reason)] = n
		}
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
// A store with pending deletions (PendingDeleteStore) retries them first.
func (s *Service) Sweep(ctx context.Context) {
	now := s.deps.Clock.Now()
	s.mu.Lock()
	for k, exp := range s.nonces {
		if !now.Before(exp) {
			delete(s.nonces, k)
		}
	}
	s.mu.Unlock()

	s.retryPeerReconcile(ctx)
	s.retryOwedExtensions(ctx)
	if pending, ok := s.deps.Leases.(PendingDeleteStore); ok {
		if err := pending.RetryPendingDeletes(ctx); err != nil {
			s.logger.Warn("vpn lease sweep: a pending lease deletion failed again", slog.Any("error", err))
		}
	}
	leases, err := s.deps.Leases.List(ctx)
	if err != nil {
		s.logger.Warn("vpn lease sweep: listing leases failed", slog.Any("error", err))
		return
	}
	for _, l := range leases {
		if !l.Expired(now) {
			continue
		}
		// revoke needs enrolGate held; it is taken before the device lock.
		s.enrolGate.RLock()
		unlock := s.devices.lock(deviceKey(l.TenantID, l.DeviceID))
		// Re-read under the lock: a renewal may have landed since List.
		current, err := s.deps.Leases.Get(ctx, l.ID)
		if err == nil && current.Expired(now) {
			s.logger.Info("vpn.lease.expire",
				slog.String("lease", string(current.ID)),
				slog.String("device", current.DeviceID),
				slog.Time("expired_at", current.ExpiresAt))
			if err := s.revoke(ctx, current, RevokeExpired); err != nil {
				s.logger.Warn("vpn lease expiry revoke incomplete", slog.String("lease", string(l.ID)), slog.Any("error", err))
			}
		}
		unlock()
		s.enrolGate.RUnlock()
	}
}

// oweExtension records that the host has not confirmed the stored deadline
// of lease and that its client, refused the renewal, still holds its older
// deadline: Sweep re-sends the extension and the client's retry bypasses the
// renew window. The deadline the client holds (Lease.ClientExpiresAt) is
// already stored by Renew in the same write as the new deadline, so Restore
// rebuilds the bypass after a restart without a further write here.
func (s *Service) oweExtension(lease *Lease) {
	s.mu.Lock()
	if s.extendOwed == nil {
		s.extendOwed = map[LeaseID]struct{}{}
	}
	s.extendOwed[lease.ID] = struct{}{}
	s.mu.Unlock()
	s.bypassRenewal(lease.ID)
}

// bypassRenewal lets the client of lease id renew outside the renew window
// (see renewBypass).
func (s *Service) bypassRenewal(id LeaseID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.renewBypass == nil {
		s.renewBypass = map[LeaseID]struct{}{}
	}
	s.renewBypass[id] = struct{}{}
}

// confirmClientDeadline drops the stored refused-renewal mark once the
// client holds the lease's stored deadline. A failed clearing write may have
// committed (a lost response), so the mark is stored again before the failure
// is returned, and the renew bypass is granted: the refusal is then durable
// and Restore rebuilds the bypass from the stored mark. When that write fails
// too, the record is read back (readRecord): a record without the mark means the clear is
// stored and the renewal is done; otherwise the failure is returned with the
// bypass kept in memory.
func (s *Service) confirmClientDeadline(ctx context.Context, lease *Lease) error {
	if lease.ClientExpiresAt.IsZero() {
		s.clearRenewBypass(lease.ID)
		return nil
	}
	held := lease.ClientExpiresAt
	lease.ClientExpiresAt = time.Time{}
	// A failed Put may have committed before its response was lost.
	err := s.deps.Leases.Put(ctx, lease)
	if err == nil {
		s.clearRenewBypass(lease.ID)
		return nil
	}
	lease.ClientExpiresAt = held
	s.bypassRenewal(lease.ID)
	// Store the mark again so the refusal is durable whatever the clear did.
	if rErr := s.deps.Leases.Put(ctx, lease); rErr == nil {
		return err
	}
	// Both outcomes are unknown: the record decides, read from the
	// authoritative store and not from a projection that a lost answer left
	// behind. No other writer moves it, because Renew holds the device lock.
	if stored, gErr := s.readRecord(ctx, lease.ID); gErr == nil &&
		stored.ClientExpiresAt.IsZero() && stored.ExpiresAt.Equal(lease.ExpiresAt) {
		lease.ClientExpiresAt = time.Time{}
		s.clearRenewBypass(lease.ID)
		return nil
	}
	return err
}

// readRecord reads the lease from the store's authoritative record:
// GetRecorded when the store is a RecordedLeaseStore (a projection of the
// control plane), Get otherwise, because a store with no projection is its
// own record.
func (s *Service) readRecord(ctx context.Context, id LeaseID) (*Lease, error) {
	if rs, ok := s.deps.Leases.(RecordedLeaseStore); ok {
		return rs.GetRecorded(ctx, id)
	}
	return s.deps.Leases.Get(ctx, id)
}

// extensionOwed reports whether lease id waits on a deadline extension.
func (s *Service) extensionOwed(id LeaseID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.extendOwed[id]
	return ok
}

// clearExtension drops the owed extension of lease id, if any.
func (s *Service) clearExtension(id LeaseID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.extendOwed, id)
}

// renewBypassed reports whether the lease's client is owed a renewal
// outside the renew window (see renewBypass).
func (s *Service) renewBypassed(id LeaseID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.renewBypass[id]
	return ok
}

// clearRenewBypass drops the client's renewal recovery obligation: the
// client learned its deadline, or the lease is gone.
func (s *Service) clearRenewBypass(id LeaseID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.renewBypass, id)
}

// retryOwedExtensions re-sends each owed deadline extension with the stored
// deadline. The host deadline only moves forward, so a retry that races a
// renewal cannot shorten it. A lease the host already expired is revoked.
func (s *Service) retryOwedExtensions(ctx context.Context) {
	s.mu.Lock()
	ids := make([]LeaseID, 0, len(s.extendOwed))
	for id := range s.extendOwed {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		probe, err := s.deps.Leases.Get(ctx, id)
		if err != nil {
			var nf *ErrLeaseNotFound
			if errors.As(err, &nf) {
				s.clearExtension(id)
				s.clearRenewBypass(id)
			}
			continue
		}
		s.retryOwedExtension(ctx, probe)
	}
}

func (s *Service) retryOwedExtension(ctx context.Context, probe *Lease) {
	// revoke needs enrolGate held; it is taken before the device lock.
	s.enrolGate.RLock()
	defer s.enrolGate.RUnlock()
	unlock := s.devices.lock(deviceKey(probe.TenantID, probe.DeviceID))
	defer unlock()
	if !s.extensionOwed(probe.ID) {
		return
	}
	lease, err := s.deps.Leases.Get(ctx, probe.ID)
	if err != nil {
		var nf *ErrLeaseNotFound
		if errors.As(err, &nf) {
			s.clearExtension(probe.ID)
			s.clearRenewBypass(probe.ID)
		}
		return
	}
	if lease.Expired(s.deps.Clock.Now()) {
		// The expiry sweep revokes it.
		s.clearExtension(lease.ID)
		return
	}
	ext, ok := s.deps.DataPlanes[lease.DataPlane].(PeerDeadlineExtender)
	if !ok {
		s.clearExtension(lease.ID)
		return
	}
	if err := ext.ExtendPeer(ctx, lease); err != nil {
		var nf *ErrLeaseNotFound
		if errors.As(err, &nf) {
			// The host already expired the peer: the lease is dead. The
			// obligation is paid only once the store records the
			// revocation (revoke clears it then).
			rErr := s.revoke(ctx, lease, RevokeExpired)
			var unrecorded *ErrRevocationNotRecorded
			if errors.As(rErr, &unrecorded) {
				s.oweDeletion(ctx, lease)
			}
			if rErr != nil {
				s.logger.Warn("vpn lease sweep: revoking a lease the host expired failed",
					slog.String("lease", string(lease.ID)), slog.Any("error", rErr))
			}
			return
		}
		s.logger.Warn("vpn lease sweep: an owed deadline extension failed again",
			slog.String("lease", string(lease.ID)), slog.Time("expires_at", lease.ExpiresAt), slog.Any("error", err))
		return
	}
	s.clearExtension(lease.ID)
}

// oweDeletion keeps a lease the host already expired owed when the store
// could not record its revocation. The kept record is re-stored with an
// elapsed deadline, so the expiry sweep retries the deletion and a
// restart's Restore drops the lease instead of reinstalling its peer. If
// that write fails too, the extension stays owed in memory: the next Sweep
// re-sends it, the host refuses it again, and the revocation is retried.
func (s *Service) oweDeletion(ctx context.Context, lease *Lease) {
	now := s.deps.Clock.Now()
	dead := *lease
	if now.Before(dead.ExpiresAt) {
		dead.ExpiresAt = now
	}
	if err := s.deps.Leases.Put(ctx, &dead); err != nil {
		s.logger.Warn("vpn lease sweep: marking a lease the host expired as expired failed; the sweep retries",
			slog.String("lease", string(lease.ID)), slog.Any("error", err))
		s.mu.Lock()
		if s.extendOwed == nil {
			s.extendOwed = map[LeaseID]struct{}{}
		}
		s.extendOwed[lease.ID] = struct{}{}
		s.mu.Unlock()
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
