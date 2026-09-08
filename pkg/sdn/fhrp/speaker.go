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
}

// Health is the speaker's health summary.
type Health struct {
	Active  bool
	Groups  []GroupStatus
	Dropped uint64
}

// Start opens every group's socket, performs the RFC 5798 §6.4.1 startup
// and runs one loop per group. A group that cannot open its socket fails
// the start; groups already started are stopped again.
func (s *Speaker) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return ErrSpeakerAlreadyRunning{}
	}
	var started []*runner
	for _, gc := range s.cfg.Groups {
		r, err := s.startGroup(ctx, gc)
		if err != nil {
			// Roll back the groups already started; a rollback that itself
			// fails is reported beside the cause, never dropped.
			for _, sr := range started {
				if rbErr := sr.stop(s.clock.Now()); rbErr != nil {
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

// Stop shuts every group down (§6.4.3: a master sends a priority-0
// advertisement and releases its addresses) and closes the sockets.
func (s *Speaker) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return ErrSpeakerNotRunning{}
	}
	var first error
	for _, r := range s.runners {
		if err := r.stop(s.clock.Now()); err != nil && first == nil {
			first = err
		}
	}
	s.runners = nil
	s.active = false
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
}

type event struct {
	adv    *Advertisement
	sender netip.Addr
}

func (s *Speaker) startGroup(ctx context.Context, gc GroupConfig) (*runner, error) {
	src, _ := netip.ParseAddr(gc.Source)
	family := gc.family()
	conn, err := s.deps.Transport.Open(gc.Interface, family, src)
	if err != nil {
		return nil, &ErrTransportFailed{VRID: gc.VRID, Interface: gc.Interface, Operation: "open", Cause: err}
	}
	r := &runner{
		speaker: s,
		conn:    conn,
		dst:     family.MulticastAddr(),
		events:  make(chan event, 16),
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
	}
	g, err := NewGroup(gc, r)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	r.group = g
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
	for _, p := range g.prefixes {
		if err := r.speaker.deps.Programmer.AddAddress(g.cfg.Interface, p, hw); err != nil {
			return &ErrAddressOperationFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "add", Address: p, Cause: err}
		}
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
	for _, p := range g.prefixes {
		if err := r.speaker.deps.Programmer.DeleteAddress(g.cfg.Interface, p, hw); err != nil && first == nil {
			first = &ErrAddressOperationFailed{VRID: g.cfg.VRID, Interface: g.cfg.Interface, Operation: "delete", Address: p, Cause: err}
		}
	}
	return first
}
