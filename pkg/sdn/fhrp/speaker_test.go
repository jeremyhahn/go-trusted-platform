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
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- fakes -----------------------------------------------------------------

// segment is an in-memory L2 segment: every Send is delivered to every other
// conn on it with TTL 255.
type segment struct {
	mu    sync.Mutex
	conns []*fakeConn
	// ttl overrides the delivered TTL for tests of the §7.1 check.
	ttl int
}

func newSegment() *segment { return &segment{ttl: RequiredTTL} }

type fakeTransport struct {
	seg     *segment
	openErr error
}

func (t *fakeTransport) Open(iface string, family Family, source netip.Addr) (Conn, error) {
	if t.openErr != nil {
		return nil, t.openErr
	}
	c := &fakeConn{seg: t.seg, iface: iface, source: source, inbox: make(chan delivery, 64), closed: make(chan struct{})}
	t.seg.mu.Lock()
	t.seg.conns = append(t.seg.conns, c)
	t.seg.mu.Unlock()
	return c, nil
}

type delivery struct {
	payload []byte
	src     netip.Addr
	ttl     int
}

type fakeConn struct {
	seg     *segment
	iface   string
	source  netip.Addr
	inbox   chan delivery
	closed  chan struct{}
	once    sync.Once
	sendErr error
	sent    []netip.Addr
	mu      sync.Mutex
}

func (c *fakeConn) Send(payload []byte, dst netip.Addr) error {
	if c.sendErr != nil {
		return c.sendErr
	}
	c.mu.Lock()
	c.sent = append(c.sent, dst)
	c.mu.Unlock()
	c.seg.mu.Lock()
	defer c.seg.mu.Unlock()
	for _, other := range c.seg.conns {
		if other == c {
			continue
		}
		select {
		case other.inbox <- delivery{payload: append([]byte(nil), payload...), src: c.source, ttl: c.seg.ttl}:
		default:
		}
	}
	return nil
}

func (c *fakeConn) Receive(ctx context.Context) ([]byte, netip.Addr, int, error) {
	select {
	case d := <-c.inbox:
		return d.payload, d.src, d.ttl, nil
	case <-ctx.Done():
		return nil, netip.Addr{}, 0, ctx.Err()
	case <-c.closed:
		return nil, netip.Addr{}, 0, net.ErrClosed
	}
}

func (c *fakeConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

// fakeProgrammer records address changes and signals claims.
type fakeProgrammer struct {
	mu      sync.Mutex
	addrs   map[string]net.HardwareAddr // iface/prefix -> hw
	claimed chan string
	addErr  error
	delErr  error
}

func newFakeProgrammer() *fakeProgrammer {
	return &fakeProgrammer{addrs: map[string]net.HardwareAddr{}, claimed: make(chan string, 16)}
}

func (p *fakeProgrammer) AddAddress(iface string, prefix netip.Prefix, hw net.HardwareAddr) error {
	if p.addErr != nil {
		return p.addErr
	}
	p.mu.Lock()
	p.addrs[iface+"/"+prefix.String()] = hw
	p.mu.Unlock()
	return nil
}

func (p *fakeProgrammer) DeleteAddress(iface string, prefix netip.Prefix, _ net.HardwareAddr) error {
	if p.delErr != nil {
		return p.delErr
	}
	p.mu.Lock()
	delete(p.addrs, iface+"/"+prefix.String())
	p.mu.Unlock()
	return nil
}

func (p *fakeProgrammer) Announce(iface string, addr netip.Addr, _ net.HardwareAddr) error {
	select {
	case p.claimed <- iface + "/" + addr.String():
	default:
	}
	return nil
}

func (p *fakeProgrammer) holds(iface string, prefix string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.addrs[iface+"/"+prefix]
	return ok
}

// HasAddress makes fakeProgrammer an AddressReader: an address seeded in
// addrs before Start is one the speaker found on the interface.
func (p *fakeProgrammer) HasAddress(iface string, prefix netip.Prefix) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.addrs[iface+"/"+prefix.String()]
	return ok, nil
}

// fakeClock fires timers when the test advances it.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{clock: c, deadline: c.now.Add(d), ch: make(chan time.Time, 1), armed: true}
	c.timers = append(c.timers, t)
	t.fireIfDueLocked(c.now)
	return t
}

// Advance moves the clock and fires every armed timer that is due, in
// deadline order, one at a time.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	var due []*fakeTimer
	for _, t := range c.timers {
		if t.armed && !t.deadline.After(now) {
			t.armed = false
			due = append(due, t)
		}
	}
	c.mu.Unlock()
	for _, t := range due {
		t.ch <- now
	}
}

type fakeTimer struct {
	clock    *fakeClock
	deadline time.Time
	ch       chan time.Time
	armed    bool
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := t.armed
	t.armed = false
	return was
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := t.armed
	t.deadline = t.clock.now.Add(d)
	t.armed = true
	t.fireIfDueLocked(t.clock.now)
	return was
}

// fireIfDueLocked mirrors time.Timer: a non-positive duration fires at once.
// Callers hold the clock mutex.
func (t *fakeTimer) fireIfDueLocked(now time.Time) {
	if !t.armed || t.deadline.After(now) {
		return
	}
	t.armed = false
	select {
	case t.ch <- now:
	default:
	}
}

// eventSink collects observer events on a channel.
type eventSink struct {
	ch   chan Event
	held []Event
}

func newEventSink() *eventSink { return &eventSink{ch: make(chan Event, 256)} }

func (s *eventSink) GroupEvent(ev Event) { s.ch <- ev }

// await returns the first event for which match is true, failing the test
// after the deadline without sleeping. Events that do not match are kept
// (in order) for later awaits, so two speakers' interleaved events can be
// asserted independently of the order their goroutines emitted them.
func (s *eventSink) await(t *testing.T, match func(Event) bool) Event {
	t.Helper()
	for i, ev := range s.held {
		if match(ev) {
			s.held = append(s.held[:i], s.held[i+1:]...)
			return ev
		}
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case ev := <-s.ch:
			if match(ev) {
				return ev
			}
			s.held = append(s.held, ev)
		case <-deadline.C:
			t.Fatalf("event did not arrive; %d unmatched events held", len(s.held))
			return Event{}
		}
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func speakerConfig(prio uint8, source string) Config {
	return Config{Enabled: true, Groups: []GroupConfig{{
		VRID: 20, Interface: "br-int", Priority: prio, AdvertIntervalCentiseconds: 100,
		Addresses: []string{"10.4.200.1/24"}, Source: source,
	}}}
}

// ---- tests -----------------------------------------------------------------

func TestNew_Rejects(t *testing.T) {
	seg := newSegment()
	_, err := New(Config{Groups: []GroupConfig{{}}}, Deps{Transport: &fakeTransport{seg: seg}, Programmer: newFakeProgrammer()})
	var invalid *ErrInvalidGroupConfig
	require.True(t, errors.As(err, &invalid))
	_, err = New(speakerConfig(100, "10.4.200.2"), Deps{Programmer: newFakeProgrammer()})
	var req *ErrTransportRequired
	require.True(t, errors.As(err, &req))
	_, err = New(speakerConfig(100, "10.4.200.2"), Deps{Transport: &fakeTransport{seg: seg}})
	require.True(t, errors.As(err, &req))
}

func TestSpeaker_TwoNodesElectAndFailOver(t *testing.T) {
	seg := newSegment()
	clock := newFakeClock(t0)
	sink := newEventSink()
	progA, progB := newFakeProgrammer(), newFakeProgrammer()

	a, err := New(speakerConfig(200, "10.4.200.2"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: progA, Clock: clock, Logger: quietLogger(), Observer: sink})
	require.NoError(t, err)
	b, err := New(speakerConfig(100, "10.4.200.10"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: progB, Clock: clock, Logger: quietLogger(), Observer: sink})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, a.Start(ctx))
	require.NoError(t, b.Start(ctx))
	assert.True(t, a.Active())
	require.ErrorIs(t, a.Start(ctx), ErrSpeakerAlreadyRunning{})

	// Both start as Backup (startup transitions are reported).
	sink.await(t, func(ev Event) bool {
		return ev.Kind == EventTransition && ev.Status.State == StateBackup && ev.Status.Priority == 200
	})
	sink.await(t, func(ev Event) bool {
		return ev.Kind == EventTransition && ev.Status.State == StateBackup && ev.Status.Priority == 100
	})

	// A's Master_Down_Interval: 300 cs + ((256−200)×100)/256 = 21 cs.
	clock.Advance(3210 * time.Millisecond)
	sink.await(t, func(ev Event) bool {
		return ev.Kind == EventTransition && ev.Status.State == StateMaster && ev.Status.Priority == 200
	})
	assert.Equal(t, "br-int/10.4.200.1", <-progA.claimed)
	assert.True(t, progA.holds("br-int", "10.4.200.1/24"))
	// B hears A's advertisement and stays Backup with a fresh timer.
	ev := sink.await(t, func(ev Event) bool { return ev.Kind == EventAdvertisement && ev.Status.Priority == 100 })
	assert.Equal(t, uint8(200), ev.Priority)
	assert.Equal(t, netip.MustParseAddr("10.4.200.2"), ev.Sender)
	stB, err := b.GroupState("br-int", 20)
	require.NoError(t, err)
	assert.Equal(t, StateBackup, stB)
	assert.False(t, progB.holds("br-int", "10.4.200.1/24"))

	// Both sockets are opened on the group's interface, and every
	// advertisement goes to the VRRP group address (RFC 5798 §5.1.1.2).
	advertised := 0
	for _, c := range seg.conns {
		assert.Equal(t, "br-int", c.iface)
		c.mu.Lock()
		for _, dst := range c.sent {
			assert.Equal(t, MulticastIPv4, dst)
			advertised++
		}
		c.mu.Unlock()
	}
	assert.Positive(t, advertised)

	// A keeps advertising every second; B keeps deferring.
	clock.Advance(time.Second)
	sink.await(t, func(ev Event) bool { return ev.Kind == EventAdvertisement && ev.Status.Priority == 100 })

	// A stops: priority-0 release, addresses gone; B takes over after its
	// skew time (60 cs) rather than the full master-down interval.
	require.NoError(t, a.Stop(ctx))
	assert.False(t, a.Active())
	assert.False(t, progA.holds("br-int", "10.4.200.1/24"))
	sink.await(t, func(ev Event) bool { return ev.Kind == EventAdvertisement && ev.Priority == PriorityRelease })
	clock.Advance(600 * time.Millisecond)
	sink.await(t, func(ev Event) bool {
		return ev.Kind == EventTransition && ev.Status.State == StateMaster && ev.Status.Priority == 100
	})
	<-progB.claimed
	assert.True(t, progB.holds("br-int", "10.4.200.1/24"))

	h := b.Health()
	require.Len(t, h.Groups, 1)
	assert.Equal(t, StateMaster, h.Groups[0].State)
	assert.Equal(t, uint64(2), h.Groups[0].Transitions)
	assert.False(t, h.Groups[0].NextDeadline.IsZero())

	require.NoError(t, b.Stop(ctx))
	require.ErrorIs(t, b.Stop(ctx), ErrSpeakerNotRunning{})
	assert.False(t, progB.holds("br-int", "10.4.200.1/24"))
	_, err = b.GroupState("br-int", 20)
	var nf *ErrGroupNotFound
	assert.True(t, errors.As(err, &nf))
}

func TestSpeaker_MasterYieldsToHigherPriorityPeer(t *testing.T) {
	seg := newSegment()
	clock := newFakeClock(t0)
	sink := newEventSink()
	progLow := newFakeProgrammer()
	low, err := New(speakerConfig(100, "10.4.200.10"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: progLow, Clock: clock, Logger: quietLogger(), Observer: sink})
	require.NoError(t, err)
	require.NoError(t, low.Start(context.Background()))
	clock.Advance(3600 * time.Millisecond)
	sink.await(t, func(ev Event) bool { return ev.Kind == EventTransition && ev.Status.State == StateMaster })
	<-progLow.claimed

	// A higher-priority owner joins the segment and advertises at startup.
	progHigh := newFakeProgrammer()
	ownerCfg := speakerConfig(PriorityOwner, "10.4.200.2")
	high, err := New(ownerCfg, Deps{Transport: &fakeTransport{seg: seg}, Programmer: progHigh, Clock: clock, Logger: quietLogger(), Observer: sink})
	require.NoError(t, err)
	require.NoError(t, high.Start(context.Background()))
	<-progHigh.claimed
	sink.await(t, func(ev Event) bool {
		return ev.Kind == EventTransition && ev.Status.State == StateBackup && ev.Status.Priority == 100 && ev.Status.Transitions == 3
	})
	assert.False(t, progLow.holds("br-int", "10.4.200.1/24"), "the yielding master released the addresses")
	assert.True(t, progHigh.holds("br-int", "10.4.200.1/24"))
	require.NoError(t, high.Stop(context.Background()))
	require.NoError(t, low.Stop(context.Background()))
}

func TestSpeaker_ReceiveChecksDropForeignTraffic(t *testing.T) {
	seg := newSegment()
	clock := newFakeClock(t0)
	sink := newEventSink()
	prog := newFakeProgrammer()
	s, err := New(speakerConfig(100, "10.4.200.10"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: prog, Clock: clock, Logger: quietLogger(), Observer: sink})
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()))
	defer func() { _ = s.Stop(context.Background()) }()
	sink.await(t, func(ev Event) bool { return ev.Kind == EventTransition })

	// A raw peer on the segment sends things the §7.1 checks must drop.
	peer, err := (&fakeTransport{seg: seg}).Open("br-int", FamilyIPv4, netip.MustParseAddr("10.4.200.99"))
	require.NoError(t, err)
	dst := FamilyIPv4.MulticastAddr()
	good := func(vrid uint8, list ...string) []byte {
		p, err := (&Advertisement{VRID: vrid, Priority: 250, MaxAdvertInterval: 100, Addresses: addrs(list...)}).Marshal(netip.MustParseAddr("10.4.200.99"), dst)
		require.NoError(t, err)
		return p
	}
	require.NoError(t, peer.Send(good(21, "10.4.200.1"), dst))                           // wrong VRID
	require.NoError(t, peer.Send(good(20, "10.4.200.1", "10.0.0.1"), dst))               // address list differs
	require.NoError(t, peer.Send([]byte{0x21, 20, 1, 1, 0, 100, 0, 0, 1, 2, 3, 4}, dst)) // version 2
	seg.ttl = 64
	require.NoError(t, peer.Send(good(20, "10.4.200.1"), dst)) // bad TTL
	seg.ttl = RequiredTTL
	require.NoError(t, peer.Send(good(20, "10.4.200.1"), dst)) // accepted

	ev := sink.await(t, func(ev Event) bool { return ev.Kind == EventAdvertisement })
	assert.Equal(t, uint8(250), ev.Priority)
	assert.Equal(t, uint64(4), s.Health().Dropped)
}

func TestSpeaker_OpenFailureStopsStartedGroups(t *testing.T) {
	seg := newSegment()
	prog := newFakeProgrammer()
	cfg := speakerConfig(PriorityOwner, "10.4.200.2")
	cfg.Groups = append(cfg.Groups, GroupConfig{VRID: 21, Interface: "public0", Priority: 100, Addresses: []string{"203.0.113.1/24"}, Source: "203.0.113.4"})
	tr := &failOnSecondOpen{seg: seg}
	s, err := New(cfg, Deps{Transport: tr, Programmer: prog, Logger: quietLogger()})
	require.NoError(t, err)
	err = s.Start(context.Background())
	var tf *ErrTransportFailed
	require.True(t, errors.As(err, &tf), "got %v", err)
	assert.Equal(t, "open", tf.Operation)
	assert.False(t, s.Active())
	assert.False(t, prog.holds("br-int", "10.4.200.1/24"), "the owner group that had claimed was rolled back")
}

// TestSpeaker_InvalidGroupOpensNoSocket pins that a group is validated before
// its socket is opened: a source that does not parse must be rejected, not
// handed to the transport as the zero address. New validates the config, so
// the group is corrupted afterwards to reach startGroup with it.
func TestSpeaker_InvalidGroupOpensNoSocket(t *testing.T) {
	seg := newSegment()
	s, err := New(speakerConfig(PriorityOwner, "10.4.200.2"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: newFakeProgrammer(), Logger: quietLogger()})
	require.NoError(t, err)
	s.cfg.Groups[0].Source = "not-an-address"

	err = s.Start(context.Background())
	var invalid *ErrInvalidGroupConfig
	require.True(t, errors.As(err, &invalid), "got %v", err)
	assert.Equal(t, "source", invalid.Field)
	seg.mu.Lock()
	opened := len(seg.conns)
	seg.mu.Unlock()
	assert.Zero(t, opened, "no socket is opened for a group that fails validation")
	assert.False(t, s.Active())
}

type failOnSecondOpen struct {
	seg *segment
	n   int
}

func (f *failOnSecondOpen) Open(iface string, family Family, source netip.Addr) (Conn, error) {
	f.n++
	if f.n == 2 {
		return nil, errors.New("EPERM")
	}
	return (&fakeTransport{seg: f.seg}).Open(iface, family, source)
}

// TestSpeaker_OpenFailureReportsAFailedRollback: when the rollback of an
// already-started owner group cannot release its addresses, both errors are
// reported (the errcheck finding on #589).
func TestSpeaker_OpenFailureReportsAFailedRollback(t *testing.T) {
	seg := newSegment()
	prog := newFakeProgrammer()
	prog.delErr = errors.New("EBUSY")
	cfg := speakerConfig(PriorityOwner, "10.4.200.2")
	cfg.Groups = append(cfg.Groups, GroupConfig{VRID: 21, Interface: "public0", Priority: 100, Addresses: []string{"203.0.113.1/24"}, Source: "203.0.113.4"})
	s, err := New(cfg, Deps{Transport: &failOnSecondOpen{seg: seg}, Programmer: prog, Logger: quietLogger()})
	require.NoError(t, err)
	err = s.Start(context.Background())
	var rb *ErrRollbackIncomplete
	require.True(t, errors.As(err, &rb), "got %v", err)
	var tf *ErrTransportFailed
	assert.True(t, errors.As(err, &tf), "the cause is reachable")
	var ao *ErrAddressOperationFailed
	assert.True(t, errors.As(err, &ao), "the rollback failure is reachable")
	assert.Contains(t, err.Error(), "rollback incomplete")
	assert.False(t, s.Active())
}

func TestSpeaker_ClaimFailureIsReportedInHealth(t *testing.T) {
	seg := newSegment()
	prog := newFakeProgrammer()
	prog.addErr = errors.New("netlink EPERM")
	s, err := New(speakerConfig(PriorityOwner, "10.4.200.2"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: prog, Logger: quietLogger()})
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()), "a failed claim is reported, not a failed start: the state must still advance")
	h := s.Health()
	require.Len(t, h.Groups, 1)
	assert.Equal(t, StateMaster, h.Groups[0].State)
	var ao *ErrAddressOperationFailed
	require.True(t, errors.As(h.Groups[0].LastError, &ao))
	require.NoError(t, s.Stop(context.Background()))
}

// An owner whose source is its virtual address finds that address on the
// interface before it claims: Stop must leave it there (Codex #1716 P1).
func TestSpeaker_StopKeepsThePreexistingOwnerAddress(t *testing.T) {
	seg := newSegment()
	prog := newFakeProgrammer()
	prog.addrs["br-int/10.4.200.1/24"] = nil
	s, err := New(speakerConfig(PriorityOwner, "10.4.200.1"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: prog, Logger: quietLogger()})
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()))
	require.Equal(t, StateMaster, s.Health().Groups[0].State)
	require.NoError(t, s.Stop(context.Background()))
	assert.True(t, prog.holds("br-int", "10.4.200.1/24"), "the owner's preexisting address survives Stop")
}

func TestSpeaker_StopDeletesTheAddressItAdded(t *testing.T) {
	seg := newSegment()
	prog := newFakeProgrammer()
	s, err := New(speakerConfig(PriorityOwner, "10.4.200.2"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: prog, Logger: quietLogger()})
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()))
	require.True(t, prog.holds("br-int", "10.4.200.1/24"))
	require.NoError(t, s.Stop(context.Background()))
	assert.False(t, prog.holds("br-int", "10.4.200.1/24"), "an address the speaker added is deleted on Stop")
}

func TestSpeaker_RollbackKeepsThePreexistingOwnerAddress(t *testing.T) {
	seg := newSegment()
	prog := newFakeProgrammer()
	prog.addrs["br-int/10.4.200.1/24"] = nil
	cfg := speakerConfig(PriorityOwner, "10.4.200.1")
	cfg.Groups = append(cfg.Groups, GroupConfig{VRID: 21, Interface: "public0", Priority: 100, Addresses: []string{"203.0.113.1/24"}, Source: "203.0.113.4"})
	s, err := New(cfg, Deps{Transport: &failOnSecondOpen{seg: seg}, Programmer: prog, Logger: quietLogger()})
	require.NoError(t, err)
	var tf *ErrTransportFailed
	require.True(t, errors.As(s.Start(context.Background()), &tf))
	assert.False(t, s.Active())
	assert.True(t, prog.holds("br-int", "10.4.200.1/24"), "the rollback leaves the owner's preexisting address in place")
}

// A master that crashed leaves its VIP on the interface. Only a
// priority-255 owner holds a VIP as its own address, so a restarted
// non-owner runner adopts the stale VIP and releases it on demotion and on
// Stop (Codex #1716 round 3 P1).
func TestSpeaker_AdoptsAStaleVIPAfterRestart(t *testing.T) {
	t.Run("demotion", func(t *testing.T) {
		seg := newSegment()
		clock := newFakeClock(t0)
		sink := newEventSink()
		prog := newFakeProgrammer()
		prog.addrs["br-int/10.4.200.1/24"] = nil
		s, err := New(speakerConfig(200, "10.4.200.10"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: prog, Clock: clock, Logger: quietLogger(), Observer: sink})
		require.NoError(t, err)
		require.NoError(t, s.Start(context.Background()))
		defer func() { _ = s.Stop(context.Background()) }()
		clock.Advance(3600 * time.Millisecond)
		sink.await(t, func(ev Event) bool { return ev.Kind == EventTransition && ev.Status.State == StateMaster })

		progHigh := newFakeProgrammer()
		high, err := New(speakerConfig(PriorityOwner, "10.4.200.2"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: progHigh, Clock: clock, Logger: quietLogger()})
		require.NoError(t, err)
		require.NoError(t, high.Start(context.Background()))
		defer func() { _ = high.Stop(context.Background()) }()
		sink.await(t, func(ev Event) bool {
			return ev.Kind == EventTransition && ev.Status.State == StateBackup && ev.Status.Priority == 200
		})
		assert.False(t, prog.holds("br-int", "10.4.200.1/24"), "the demoted master deleted the stale VIP it adopted")
	})
	t.Run("stop", func(t *testing.T) {
		seg := newSegment()
		clock := newFakeClock(t0)
		sink := newEventSink()
		prog := newFakeProgrammer()
		prog.addrs["br-int/10.4.200.1/24"] = nil
		s, err := New(speakerConfig(200, "10.4.200.10"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: prog, Clock: clock, Logger: quietLogger(), Observer: sink})
		require.NoError(t, err)
		require.NoError(t, s.Start(context.Background()))
		clock.Advance(3600 * time.Millisecond)
		sink.await(t, func(ev Event) bool { return ev.Kind == EventTransition && ev.Status.State == StateMaster })
		<-prog.claimed
		require.NoError(t, s.Stop(context.Background()))
		assert.False(t, prog.holds("br-int", "10.4.200.1/24"), "Stop deleted the stale VIP the master adopted")
	})
}

func TestWallClock(t *testing.T) {
	c := wallClock{}
	assert.WithinDuration(t, time.Now(), c.Now(), time.Second)
	tm := c.NewTimer(time.Hour)
	assert.True(t, tm.Stop())
	assert.False(t, tm.Reset(time.Hour))
	assert.NotNil(t, tm.C())
	tm.Stop()
}
