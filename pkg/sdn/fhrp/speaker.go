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

package fhrp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// idleWait is how long a run loop sleeps when its group has no timer
// (Initialize); it exists only so the select has a timer case.
const idleWait = time.Hour

// Deps are the speaker's kernel-facing dependencies.
type Deps struct {
	Transport  Transport
	Programmer Programmer
	Logger     *slog.Logger
	// Clock defaults to the wall clock.
	Clock Clock
	// Observer, when set, is told about every state transition and every
	// accepted advertisement — telemetry for the gateway snapshot, and the
	// deterministic hook the tests wait on. Calls are made from the group's
	// run loop and must not block for long.
	Observer Observer
	// Inventory, when set, records every VIP a group adds or adopts, so a
	// restart that drops the group can still delete it (Inventory.Sweep).
	Inventory *Inventory
}

// EventKind classifies an Observer notification.
type EventKind uint8

const (
	// EventTransition: the group changed state.
	EventTransition EventKind = iota + 1
	// EventAdvertisement: the group accepted a peer's advertisement.
	EventAdvertisement
	// EventTimer: a timer fired without changing state.
	EventTimer
)

// Event is one Observer notification.
type Event struct {
	Kind   EventKind
	Status GroupStatus
	// Sender is set for EventAdvertisement.
	Sender netip.Addr
	// Priority is the advertised priority for EventAdvertisement.
	Priority uint8
}

// Observer receives Events.
type Observer interface {
	GroupEvent(Event)
}

func (d Deps) validate() error {
	if d.Transport == nil {
		return &ErrTransportRequired{Dependency: "transport"}
	}
	if d.Programmer == nil {
		return &ErrTransportRequired{Dependency: "programmer"}
	}
	return nil
}

// Speaker runs every configured group. It is the gateway service: Start,
// Stop, Active and Health follow the shape of the other
// pkg/sdn/gateway/services so the gateway's handler table can build it.
type Speaker struct {
	cfg    Config
	deps   Deps
	logger *slog.Logger
	clock  Clock

	mu      sync.Mutex
	active  bool
	runners []*runner
	// pending holds the stopped runners whose VIP release failed, at Stop
	// or in the rollback of a failed Start; a later Start or Stop retries
	// their group's Shutdown until it succeeds.
	pending []*runner
	// dropped counts advertisements discarded by the §7.1 receive checks.
	dropped atomic.Uint64
}

// New validates the configuration and dependencies and builds a speaker.
func New(cfg Config, deps Deps) (*Speaker, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := deps.validate(); err != nil {
		return nil, err
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Clock == nil {
		deps.Clock = wallClock{}
	}
	return &Speaker{cfg: cfg, deps: deps, logger: deps.Logger, clock: deps.Clock}, nil
}

// GroupStatus is one group's observable state.
type GroupStatus struct {
	VRID        uint8
	Interface   string
	Family      Family
	State       State
	Priority    uint8
	Addresses   []netip.Addr
	Transitions uint64
	// NextDeadline is when the group's running timer fires (zero in
	// Initialize).
	NextDeadline time.Time
	LastError    error
	// ClaimError is the unrepaired address-claim failure; LastError can be nil while it is set.
	ClaimError error
}

// Health is the speaker's health summary.
type Health struct {
	Active  bool
	Groups  []GroupStatus
	Dropped uint64
}

// Start opens every group's socket, performs the RFC 5798 §6.4.1 startup
// and runs one loop per group. A group that cannot open its socket fails
// the start; groups already started are stopped again, and one whose VIP
// release fails in that rollback stays pending (see ReleasePending).
func (s *Speaker) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return ErrSpeakerAlreadyRunning{}
	}
	// Drain the releases an earlier Stop left outstanding first: a VIP
	// still installed would look like a pre-existing owner address.
	if err := s.retryPending(); err != nil {
		return ErrReleasePending{Cause: err}
	}
	var started []*runner
	for _, gc := range s.cfg.Groups {
		r, err := s.startGroup(ctx, gc)
		if err != nil {
			if r != nil {
				// A stale VIP it could not remove: its loops never ran,
				// and retryPending drives only its group's Shutdown.
				s.pending = append(s.pending, r)
			}
			// Roll back the groups already started; a rollback that itself
			// fails is reported beside the cause, never dropped.
			for _, sr := range started {
				if rbErr := sr.stop(s.clock.Now()); rbErr != nil {
					// Keep the runner for cleanup: its VIP is still
					// installed, and the next Start or Stop releases it.
					s.pending = append(s.pending, sr)
					err = &ErrRollbackIncomplete{Cause: err, Rollback: rbErr}
				}
			}
			return err
		}
		started = append(started, r)
	}
	s.runners = started
	s.active = true
	return nil
}

// ReleasePending reports whether a VIP release is outstanding, from a
// failed Stop, a failed startup rollback or a stale VIP that Start could
// not remove. A speaker in that state must be
// kept, not rebuilt, so its next Start or Stop can delete that VIP.
func (s *Speaker) ReleasePending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending) > 0
}

// Stop shuts every group down (§6.4.3: a master sends a priority-0
// advertisement and releases its addresses) and closes the sockets. The
// speaker is inactive afterwards even when a group fails to release a VIP;
// such a group stays pending, and a later Stop retries its release (#1716).
// Stop on an inactive speaker returns ErrSpeakerNotRunning only when no
// release is pending.
func (s *Speaker) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		if len(s.pending) == 0 {
			return ErrSpeakerNotRunning{}
		}
		return s.retryPending()
	}
	var first error
	// Retry the releases still outstanding from an earlier Stop before
	// queueing this Stop's failures, so each runner is shut down once here.
	if err := s.retryPending(); err != nil {
		first = err
	}
	for _, r := range s.runners {
		if err := r.stop(s.clock.Now()); err != nil {
			s.pending = append(s.pending, r)
			if first == nil {
				first = err
			}
		}
	}
	s.runners = nil
	s.active = false
	return first
}

// retryPending re-runs Shutdown on every runner whose release failed at an
// earlier Stop. Its loops and socket are already closed, so only the group
// is driven. Runners that still fail stay pending. s.mu must be held.
func (s *Speaker) retryPending() error {
	var first error
	still := s.pending[:0]
	for _, r := range s.pending {
		r.mu.Lock()
		err := r.group.Shutdown(s.clock.Now())
		r.mu.Unlock()
		if err != nil {
			still = append(still, r)
			if first == nil {
				first = err
			}
		}
	}
	for i := len(still); i < len(s.pending); i++ {
		s.pending[i] = nil
	}
	s.pending = still
	if len(s.pending) == 0 {
		s.pending = nil
	}
	return first
}

// Active reports whether the speaker is started.
func (s *Speaker) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Health returns the per-group status.
func (s *Speaker) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := Health{Active: s.active, Dropped: s.dropped.Load()}
	for _, r := range s.runners {
		h.Groups = append(h.Groups, r.status())
	}
	return h
}

// GroupState returns the state of one group.
func (s *Speaker) GroupState(iface string, vrid uint8) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.runners {
		if r.group.cfg.Interface == iface && r.group.cfg.VRID == vrid {
			return r.status().State, nil
		}
	}
	return StateInitialize, &ErrGroupNotFound{VRID: vrid, Interface: iface}
}

// runner owns one group: its socket, its actuator and its loop goroutine.
type runner struct {
	speaker *Speaker
	group   *Group
	conn    Conn
	dst     netip.Addr

	mu     sync.Mutex // guards group for status reads from other goroutines
	events chan event
	stopCh chan struct{}
	done   chan struct{}
	recvWG sync.WaitGroup
	cancel context.CancelFunc
	// timer is armed in startGroup, before the run loop exists, so the
	// first deadline is computed from the same instant Startup used.
	timer Timer
	// owned holds the prefixes this runner added or adopted; Release
	// deletes only these. A priority-255 owner's preexisting address is
	// never in it, so it stays, unless the inventory records that this
	// node installed it (restoreOwned); a non-owner adopts any VIP it finds (one a
	// crashed master left), so it is released on demotion and Stop (#1716).
	owned map[netip.Prefix]bool
	// stale holds prefixes of another length that dropStaleVIPs found and
	// could not delete; Release deletes them too.
	stale []netip.Prefix
}

type event struct {
	adv    *Advertisement
	sender netip.Addr
}

func (s *Speaker) startGroup(ctx context.Context, gc GroupConfig) (*runner, error) {
	r := &runner{
		speaker: s,
		dst:     gc.family().MulticastAddr(),
		events:  make(chan event, 16),
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
		owned:   make(map[netip.Prefix]bool),
	}
	// The group validates the config, so build it before opening a socket
	// and open on the source address it parsed.
	g, err := NewGroup(gc, r)
	if err != nil {
		return nil, err
	}
	r.group = g
	conn, err := s.deps.Transport.Open(gc.Interface, g.family, g.source)
	if err != nil {
		return nil, &ErrTransportFailed{VRID: gc.VRID, Interface: gc.Interface, Operation: "open", Cause: err}
	}
	r.conn = conn
	// The inventory's record comes first: an address this node installed
	// is never classified as an owner's preexisting one (Claim).
	if err := r.restoreOwned(g); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := r.dropStaleVIPs(g); err != nil {
		// Nothing is running yet: close the socket and fail the start, so
		// Start rolls back the groups already started. A stale VIP that
		// could not be removed stays recorded as a failed release, and the
		// runner is returned so Start keeps it pending for Stop or the next
		// Start to retry (Group.Shutdown releases in Initialize only when
		// releaseErr is set).
		_ = conn.Close()
		if len(r.owned) > 0 || len(r.stale) > 0 {
			g.releaseErr = err
			return r, err
		}
		return nil, err
	}
	now := s.clock.Now()
	r.mu.Lock()
	err = g.Startup(now)
	r.mu.Unlock()
	if err != nil {
		s.logger.Warn("fhrp: startup actuation failed", slog.Int("vrid", int(gc.VRID)), slog.String("interface", gc.Interface), slog.Any("error", err))
	}
	r.timer = s.clock.NewTimer(r.wait(now))
	if s.deps.Observer != nil {
		s.deps.Observer.GroupEvent(Event{Kind: EventTransition, Status: r.status()})
	}
	recvCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.recvWG.Add(1)
	go r.receive(recvCtx)
	go r.run()
	return r, nil
}

// dropStaleVIPs removes, before Startup, every VIP a non-owner finds on
// its interface: a fresh runner owns nothing, so such an address is one a
// crashed master left. A non-owner starts in Backup and, while a peer stays
// master, never claims, so a stale VIP would keep answering ARP/ND for the
// peer's address (Codex #1716 round 4). A priority-255 owner's address is
// its own and stays. Without an AddressReader nothing can be seen, so
// nothing is removed. A failed check or removal fails the start (ruling
// 673, Codex #1716 round 5): a backup that cannot prove its interface free
// of the master's VIP must not run, so the supervisor restarts the speaker
// instead of a backup answering for the VIP while Health shows no error.
// A VIP whose removal failed stays pending (see ReleasePending), and Stop
// or the next Start retries it.
func (r *runner) dropStaleVIPs(g *Group) error {
	reader, ok := r.speaker.deps.Programmer.(AddressReader)
	if !ok || g.Priority() == PriorityOwner {
		return nil
	}
	lister, lists := r.speaker.deps.Programmer.(PrefixReader)
	hw := VirtualMAC(g.family, g.cfg.VRID)
	stale := false
	for _, p := range g.prefixes {
		if !lists {
			present, err := reader.HasAddress(g.cfg.Interface, p)
			if err != nil {
				return &ErrAddressOperationFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "list", Address: p, Cause: err}
			}
			if present {
				if err := r.speaker.deps.Inventory.Record(g.cfg.Interface, g.cfg.VRID, p); err != nil {
					return err
				}
				r.owned[p] = true
				stale = true
			}
			continue
		}
		// Match by address: a crashed master may have installed the VIP
		// with the prefix length of an older configuration.
		installed, err := lister.AddressPrefixes(g.cfg.Interface, p.Addr())
		if err != nil {
			return &ErrAddressOperationFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "list", Address: p, Cause: err}
		}
		for _, q := range installed {
			if q == p {
				if err := r.speaker.deps.Inventory.Record(g.cfg.Interface, g.cfg.VRID, p); err != nil {
					return err
				}
				r.owned[p] = true
				stale = true
				continue
			}
			if err := r.speaker.deps.Programmer.DeleteAddress(g.cfg.Interface, q, hw); err != nil {
				r.stale = append(r.stale, q)
				if rerr := r.speaker.deps.Inventory.Record(g.cfg.Interface, g.cfg.VRID, q); rerr != nil {
					r.speaker.logger.Warn("fhrp: VIP inventory record failed", slog.Any("error", rerr))
				}
				return &ErrAddressOperationFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "delete", Address: q, Cause: err}
			}
		}
	}
	if stale {
		return r.Release(g)
	}
	return nil
}

// restoreOwned marks as owned every configured prefix of g the inventory
// says this node installed, so a runner restarted after a crash releases on
// demotion or Stop the VIPs its predecessor added, rather than Claim taking
// one still on the interface for a priority-255 owner's permanent address.
// Without an inventory nothing is restored.
func (r *runner) restoreOwned(g *Group) error {
	entries, err := r.speaker.deps.Inventory.Entries()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Interface != g.cfg.Interface || e.VRID != g.cfg.VRID {
			continue
		}
		for _, p := range g.prefixes {
			if p == e.Prefix {
				r.owned[p] = true
			}
		}
	}
	return nil
}

// stop ends the loops, performs the group's Shutdown and closes the socket.
func (r *runner) stop(now time.Time) error {
	close(r.stopCh)
	<-r.done
	r.mu.Lock()
	err := r.group.Shutdown(now)
	r.mu.Unlock()
	r.cancel()
	_ = r.conn.Close()
	r.recvWG.Wait()
	return err
}

func (r *runner) status() GroupStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	g := r.group
	return GroupStatus{
		VRID: g.cfg.VRID, Interface: g.cfg.Interface, Family: g.family, State: g.state,
		Priority: g.Priority(), Addresses: g.Addresses(), Transitions: g.transitions, LastError: g.lastErr,
		ClaimError:   g.claimErr,
		NextDeadline: g.NextDeadline(),
	}
}

// run is the group's single writer: timers and received advertisements
// are applied here and nowhere else.
func (r *runner) run() {
	defer close(r.done)
	clock := r.speaker.clock
	timer := r.timer
	defer timer.Stop()
	for {
		var pending Event
		var before, after State
		select {
		case <-r.stopCh:
			return
		case now := <-timer.C():
			r.mu.Lock()
			before = r.group.state
			err := r.group.Tick(now)
			after = r.group.state
			r.mu.Unlock()
			r.logErr("tick", err)
			pending = Event{Kind: EventTimer}
		case ev := <-r.events:
			now := clock.Now()
			r.mu.Lock()
			before = r.group.state
			err := r.group.HandleAdvertisement(ev.adv, ev.sender, now)
			after = r.group.state
			r.mu.Unlock()
			r.logErr("advertisement", err)
			pending = Event{Kind: EventAdvertisement, Sender: ev.sender, Priority: ev.adv.Priority}
		}
		// Re-arm before telling anyone: an observer that reacts to the
		// event (a test advancing a fake clock, a snapshot reading the
		// deadline) must see the timer already set for the new deadline.
		timer.Reset(r.wait(clock.Now()))
		r.notify(before, after, pending)
	}
}

// wait is how long until the group's next deadline, never negative and
// idleWait when the group has none.
func (r *runner) wait(now time.Time) time.Duration {
	r.mu.Lock()
	deadline := r.group.NextDeadline()
	r.mu.Unlock()
	if deadline.IsZero() {
		return idleWait
	}
	d := deadline.Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// receive applies the §7.1 receive checks and hands accepted
// advertisements to the run loop.
func (r *runner) receive(ctx context.Context) {
	defer r.recvWG.Done()
	for {
		payload, src, ttl, err := r.conn.Receive(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-r.stopCh:
				return
			default:
			}
			r.speaker.logger.Debug("fhrp: receive failed", slog.Any("error", err))
			continue
		}
		adv, ok := r.accept(payload, src, ttl)
		if !ok {
			r.speaker.dropped.Add(1)
			continue
		}
		select {
		case r.events <- event{adv: adv, sender: src}:
		case <-r.stopCh:
			return
		}
	}
}

// accept implements RFC 5798 §7.1: TTL 255, a valid version-3
// advertisement, our VRID, and — because a mismatch is a configuration
// error on the segment, not a protocol event — the same address count and
// addresses as ours.
func (r *runner) accept(payload []byte, src netip.Addr, ttl int) (*Advertisement, bool) {
	if ttl != RequiredTTL {
		return nil, false
	}
	adv, err := Unmarshal(payload, src, r.dst)
	if err != nil {
		return nil, false
	}
	r.mu.Lock()
	g := r.group
	sameVRID := adv.VRID == g.cfg.VRID
	ours := g.Addresses()
	fromSelf := src == g.source
	r.mu.Unlock()
	if !sameVRID || fromSelf {
		return nil, false
	}
	if adv.Family() != g.family {
		return nil, false
	}
	if len(adv.Addresses) != len(ours) {
		return nil, false
	}
	for i := range ours {
		if adv.Addresses[i] != ours[i] {
			return nil, false
		}
	}
	return adv, true
}

// notify tells the observer what just happened: the event itself, and a
// transition event when the state changed.
func (r *runner) notify(before, after State, ev Event) {
	obs := r.speaker.deps.Observer
	if obs == nil {
		return
	}
	ev.Status = r.status()
	obs.GroupEvent(ev)
	if before != after {
		obs.GroupEvent(Event{Kind: EventTransition, Status: ev.Status})
	}
}

func (r *runner) logErr(op string, err error) {
	if err == nil {
		return
	}
	r.speaker.logger.Warn("fhrp: group action failed", slog.String("op", op),
		slog.Int("vrid", int(r.group.cfg.VRID)), slog.String("interface", r.group.cfg.Interface), slog.Any("error", err))
}

// Actuator implementation: the runner is its group's actuator.

// Advertise implements Actuator.
func (r *runner) Advertise(g *Group, priority uint8) error {
	payload, err := g.advertisement(priority).Marshal(g.source, r.dst)
	if err != nil {
		return err
	}
	if err := r.conn.Send(payload, r.dst); err != nil {
		return &ErrTransportFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "send", Cause: err}
	}
	return nil
}

// Claim implements Actuator.
func (r *runner) Claim(g *Group) error {
	hw := VirtualMAC(g.family, g.cfg.VRID)
	if r.owned == nil {
		r.owned = make(map[netip.Prefix]bool)
	}
	reader, _ := r.speaker.deps.Programmer.(AddressReader)
	for _, p := range g.prefixes {
		// Only a priority-255 address owner holds a VIP as its own
		// permanent address. For any other group a VIP already on the
		// interface is one a crashed master left behind: adopt it
		// (AddAddress replaces idempotently) so it is released later.
		if !r.owned[p] && reader != nil && g.Priority() == PriorityOwner {
			present, err := reader.HasAddress(g.cfg.Interface, p)
			if err != nil {
				return &ErrAddressOperationFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "list", Address: p, Cause: err}
			}
			if present {
				// The owner's preexisting address: leave it in place.
				continue
			}
		}
		// Recorded before it is added, so a crash between the two leaves
		// at most an entry for an address that is not there.
		if err := r.speaker.deps.Inventory.Record(g.cfg.Interface, g.cfg.VRID, p); err != nil {
			return err
		}
		if err := r.speaker.deps.Programmer.AddAddress(g.cfg.Interface, p, hw); err != nil {
			return &ErrAddressOperationFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "add", Address: p, Cause: err}
		}
		r.owned[p] = true
	}
	for _, p := range g.prefixes {
		if err := r.speaker.deps.Programmer.Announce(g.cfg.Interface, p.Addr(), hw); err != nil {
			return &ErrAddressOperationFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "announce", Address: p, Cause: err}
		}
	}
	return nil
}

// Release implements Actuator.
func (r *runner) Release(g *Group) error {
	hw := VirtualMAC(g.family, g.cfg.VRID)
	var first error
	_, reads := r.speaker.deps.Programmer.(AddressReader)
	for _, p := range g.prefixes {
		// The owner's preexisting prefix is never ours to delete (Claim
		// adopts a stale VIP for any other group). Without an
		// AddressReader every prefix counts as owned, as before.
		if reads && !r.owned[p] {
			continue
		}
		if err := r.speaker.deps.Programmer.DeleteAddress(g.cfg.Interface, p, hw); err != nil {
			if first == nil {
				first = &ErrAddressOperationFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "delete", Address: p, Cause: err}
			}
			continue
		}
		delete(r.owned, p)
		r.forget(g, p)
	}
	// Prefixes of another length a failed stale removal left behind.
	kept := r.stale[:0]
	for _, q := range r.stale {
		if err := r.speaker.deps.Programmer.DeleteAddress(g.cfg.Interface, q, hw); err != nil {
			kept = append(kept, q)
			if first == nil {
				first = &ErrAddressOperationFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "delete", Address: q, Cause: err}
			}
			continue
		}
		r.forget(g, q)
	}
	r.stale = kept
	if len(r.stale) == 0 {
		r.stale = nil
	}
	return first
}

// forget drops a deleted VIP from the inventory. The address is already
// gone, so a failed rewrite is logged: the stale entry only makes a later
// sweep delete an absent address, which succeeds.
func (r *runner) forget(g *Group, p netip.Prefix) {
	if err := r.speaker.deps.Inventory.Forget(g.cfg.Interface, g.cfg.VRID, p); err != nil {
		r.speaker.logger.Warn("fhrp: VIP inventory forget failed", slog.Any("error", err))
	}
}
