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
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- helpers ---------------------------------------------------------------

// errInjected is the failure the fakes in this file return.
type errInjected struct{ op string }

func (e errInjected) Error() string { return "injected " + e.op + " failure" }

// recordHandler hands every log record to a channel.
type recordHandler struct{ ch chan slog.Record }

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.ch <- r
	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }

// awaitRecord returns the first record with message msg, failing the test
// after the deadline without sleeping.
func awaitRecord(t *testing.T, ch chan slog.Record, msg string) slog.Record {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case r := <-ch:
			if r.Message == msg {
				return r
			}
		case <-deadline.C:
			t.Fatalf("log record %q did not arrive", msg)
			return slog.Record{}
		}
	}
}

func recordAttr(r slog.Record, key string) string {
	var out string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			out = a.Value.String()
			return false
		}
		return true
	})
	return out
}

// scriptedConn returns the scripted Receive results in order, then
// net.ErrClosed.
type scriptedConn struct {
	results chan delivery
	errs    chan error
}

func (c *scriptedConn) Send([]byte, netip.Addr) error { return nil }
func (c *scriptedConn) Receive(context.Context) ([]byte, netip.Addr, int, error) {
	select {
	case err := <-c.errs:
		return nil, netip.Addr{}, 0, err
	default:
	}
	select {
	case d := <-c.results:
		return d.payload, d.src, d.ttl, nil
	default:
		return nil, netip.Addr{}, 0, net.ErrClosed
	}
}
func (c *scriptedConn) Close() error { return nil }

// announceFailProgrammer programs addresses but cannot announce them.
type announceFailProgrammer struct{ added int }

func (p *announceFailProgrammer) AddAddress(string, netip.Prefix, net.HardwareAddr) error {
	p.added++
	return nil
}
func (p *announceFailProgrammer) DeleteAddress(string, netip.Prefix, net.HardwareAddr) error {
	return nil
}
func (p *announceFailProgrammer) Announce(string, netip.Addr, net.HardwareAddr) error {
	return errInjected{op: "announce"}
}

// testRunner builds a runner for one backup group with no socket or loop.
func testRunner(t *testing.T, conn Conn, prog Programmer) *runner {
	t.Helper()
	s := &Speaker{deps: Deps{Programmer: prog}, logger: quietLogger(), clock: newFakeClock(t0)}
	r := &runner{
		speaker: s,
		conn:    conn,
		dst:     FamilyIPv4.MulticastAddr(),
		events:  make(chan event, 16),
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
	}
	g, err := NewGroup(backupConfig(), r)
	require.NoError(t, err)
	r.group = g
	return r
}

func peerAdvert(t *testing.T, addrs ...string) []byte {
	t.Helper()
	adv := &Advertisement{VRID: 20, Priority: 200, MaxAdvertInterval: 100}
	for _, a := range addrs {
		adv.Addresses = append(adv.Addresses, netip.MustParseAddr(a))
	}
	payload, err := adv.Marshal(netip.MustParseAddr("10.4.200.9"), FamilyIPv4.MulticastAddr())
	require.NoError(t, err)
	return payload
}

// ---- packet ----------------------------------------------------------------

func TestUnmarshal_RejectsZeroAdvertInterval(t *testing.T) {
	src, dst := netip.MustParseAddr("10.4.200.9"), FamilyIPv4.MulticastAddr()
	buf := make([]byte, headerLen+4)
	buf[0] = Version<<4 | TypeAdvertisement
	buf[1], buf[2], buf[3] = 20, 100, 1
	copy(buf[headerLen:], netip.MustParseAddr("10.4.200.1").AsSlice())
	binary.BigEndian.PutUint16(buf[6:8], checksum(buf, src, dst))

	_, err := Unmarshal(buf, src, dst)
	var invalid *ErrInvalidPacket
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "zero advertisement interval", invalid.Reason)
}

func TestChecksum_PadsAnOddLengthMessage(t *testing.T) {
	src, dst := netip.MustParseAddr("10.4.200.9"), FamilyIPv4.MulticastAddr()
	odd := []byte{0x31, 0x14, 0x64}
	// RFC 1071 §4.1: an odd trailing byte is summed as if padded with zero;
	// the pseudo-header length still counts the unpadded message.
	padded := append(append([]byte(nil), odd...), 0)
	want := checksum(padded, src, dst)
	// Correct the length difference the pseudo-header carries (3 vs 4).
	assert.Equal(t, want+1, checksum(odd, src, dst))
}

// ---- group -----------------------------------------------------------------

func TestGroup_ShutdownReportsTheAdvertFailureFirst(t *testing.T) {
	cfg := backupConfig()
	cfg.Priority = PriorityOwner
	g, act := newGroupT(t, cfg)
	require.NoError(t, g.Startup(t0))
	require.Equal(t, StateMaster, g.State())

	act.failAdv = errInjected{op: "advertise"}
	act.failRel = errInjected{op: "release"}
	err := g.Shutdown(t0)
	assert.Equal(t, errInjected{op: "advertise"}, err)
	assert.Equal(t, err, g.LastError())
	assert.Equal(t, 1, act.releases, "the addresses are released even when the advert fails")
	assert.Equal(t, StateInitialize, g.State())
}

func TestGroup_TickIsANoOpWhenNothingIsDue(t *testing.T) {
	cases := []struct {
		name  string
		owner bool
	}{
		{name: "initialize", owner: false},
		{name: "master before the advert timer", owner: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := backupConfig()
			if tc.owner {
				cfg.Priority = PriorityOwner
			}
			g, act := newGroupT(t, cfg)
			if tc.owner {
				require.NoError(t, g.Startup(t0))
			}
			sent := len(act.adverts)
			state := g.State()
			require.NoError(t, g.Tick(t0.Add(time.Millisecond)))
			assert.Len(t, act.adverts, sent)
			assert.Equal(t, state, g.State())
		})
	}
}

func TestGroup_BecomeMasterClaimsDespiteAnAdvertFailure(t *testing.T) {
	cfg := backupConfig()
	cfg.Priority = PriorityOwner
	g, act := newGroupT(t, cfg)
	act.failAdv = errInjected{op: "advertise"}
	act.failClm = errInjected{op: "claim"}

	err := g.Startup(t0)
	var tf *ErrTransportFailed
	require.ErrorAs(t, err, &tf)
	assert.Equal(t, "advertise", tf.Operation)
	assert.Equal(t, 1, act.claims, "the addresses are claimed even when the advert fails")
	assert.Equal(t, StateMaster, g.State())
}

// ---- speaker ---------------------------------------------------------------

func TestNew_DefaultsLoggerAndClock(t *testing.T) {
	s, err := New(speakerConfig(100, "10.4.200.2"), Deps{Transport: &fakeTransport{seg: newSegment()}, Programmer: newFakeProgrammer()})
	require.NoError(t, err)
	assert.Same(t, slog.Default(), s.logger)
	assert.Equal(t, wallClock{}, s.clock)
}

func TestSpeaker_StopReportsAFailedRelease(t *testing.T) {
	prog := newFakeProgrammer()
	s, err := New(speakerConfig(PriorityOwner, "10.4.200.2"), Deps{Transport: &fakeTransport{seg: newSegment()}, Programmer: prog, Clock: newFakeClock(t0), Logger: quietLogger()})
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()))
	prog.mu.Lock()
	prog.delErr = errInjected{op: "delete"}
	prog.mu.Unlock()

	err = s.Stop(context.Background())
	var aof *ErrAddressOperationFailed
	require.ErrorAs(t, err, &aof)
	assert.Equal(t, "delete", aof.Operation)
	assert.False(t, s.Active(), "a failed release still stops the speaker")
}

func TestSpeaker_TickFailureIsLogged(t *testing.T) {
	seg := newSegment()
	clock := newFakeClock(t0)
	logs := &recordHandler{ch: make(chan slog.Record, 64)}
	s, err := New(speakerConfig(PriorityOwner, "10.4.200.2"), Deps{Transport: &fakeTransport{seg: seg}, Programmer: newFakeProgrammer(), Clock: clock, Logger: slog.New(logs)})
	require.NoError(t, err)
	require.NoError(t, s.Start(context.Background()))

	seg.mu.Lock()
	seg.conns[0].sendErr = errInjected{op: "send"}
	seg.mu.Unlock()
	clock.Advance(time.Second)

	r := awaitRecord(t, logs.ch, "fhrp: group action failed")
	assert.Equal(t, "tick", recordAttr(r, "op"))
	assert.Equal(t, "br-int", recordAttr(r, "interface"))

	// The §6.4.3 priority-0 advertisement fails on the same socket.
	var tf *ErrTransportFailed
	require.ErrorAs(t, s.Stop(context.Background()), &tf)
	assert.Equal(t, "send", tf.Operation)
}

func TestRunner_Wait(t *testing.T) {
	r := testRunner(t, &scriptedConn{}, newFakeProgrammer())
	assert.Equal(t, idleWait, r.wait(t0), "initialize has no deadline")

	require.NoError(t, r.group.Startup(t0))
	down := r.group.MasterDownInterval()
	assert.Equal(t, down, r.wait(t0))
	assert.Equal(t, time.Duration(0), r.wait(t0.Add(2*down)), "a passed deadline never waits a negative time")
}

func TestRunner_ReceiveSurvivesATransientError(t *testing.T) {
	conn := &scriptedConn{results: make(chan delivery, 1), errs: make(chan error, 1)}
	conn.errs <- errInjected{op: "receive"}
	conn.results <- delivery{payload: peerAdvert(t, "10.4.200.1"), src: netip.MustParseAddr("10.4.200.9"), ttl: RequiredTTL}
	r := testRunner(t, conn, newFakeProgrammer())

	r.recvWG.Add(1)
	r.receive(context.Background())

	require.Len(t, r.events, 1, "the advertisement after the error is still delivered")
	ev := <-r.events
	assert.Equal(t, uint8(200), ev.adv.Priority)
	assert.Equal(t, uint64(0), r.speaker.dropped.Load())
}

func TestRunner_ReceiveEndsOnStop(t *testing.T) {
	cases := []struct {
		name   string
		script func(*scriptedConn)
		events chan event
	}{
		{
			name:   "an error after stop",
			script: func(c *scriptedConn) { c.errs <- errInjected{op: "receive"} },
			events: make(chan event, 1),
		},
		{
			name: "a full event queue after stop",
			script: func(c *scriptedConn) {
				c.results <- delivery{payload: peerAdvert(t, "10.4.200.1"), src: netip.MustParseAddr("10.4.200.9"), ttl: RequiredTTL}
			},
			events: make(chan event),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &scriptedConn{results: make(chan delivery, 2), errs: make(chan error, 1)}
			tc.script(conn)
			// A second result proves receive returned rather than read on.
			conn.results <- delivery{payload: peerAdvert(t, "10.4.200.1"), src: netip.MustParseAddr("10.4.200.9"), ttl: RequiredTTL}
			r := testRunner(t, conn, newFakeProgrammer())
			r.events = tc.events
			close(r.stopCh)

			r.recvWG.Add(1)
			r.receive(context.Background())
			assert.NotEmpty(t, conn.results, "receive stops reading once stopped")
		})
	}
}

func TestRunner_AcceptRejectsForeignAddresses(t *testing.T) {
	r := testRunner(t, &scriptedConn{}, newFakeProgrammer())
	src := netip.MustParseAddr("10.4.200.9")

	_, ok := r.accept(peerAdvert(t, "10.4.200.1"), src, RequiredTTL)
	assert.True(t, ok)
	_, ok = r.accept(peerAdvert(t, "10.4.200.77"), src, RequiredTTL)
	assert.False(t, ok, "same count, different address is a misconfiguration (§7.1)")
}

func TestRunner_AdvertiseWrapsASendFailure(t *testing.T) {
	seg := newSegment()
	conn, err := (&fakeTransport{seg: seg}).Open("br-int", FamilyIPv4, netip.MustParseAddr("10.4.200.2"))
	require.NoError(t, err)
	conn.(*fakeConn).sendErr = errInjected{op: "send"}
	r := testRunner(t, conn, newFakeProgrammer())

	err = r.Advertise(r.group, 100)
	var tf *ErrTransportFailed
	require.ErrorAs(t, err, &tf)
	assert.Equal(t, "send", tf.Operation)
	assert.Equal(t, uint8(20), tf.VRID)
	assert.Equal(t, errInjected{op: "send"}, tf.Cause)
}

func TestRunner_ClaimReportsAFailedAnnouncement(t *testing.T) {
	prog := &announceFailProgrammer{}
	r := testRunner(t, &scriptedConn{}, prog)

	err := r.Claim(r.group)
	var aof *ErrAddressOperationFailed
	require.ErrorAs(t, err, &aof)
	assert.Equal(t, "announce", aof.Operation)
	assert.Equal(t, netip.MustParsePrefix("10.4.200.1/24"), aof.Address)
	assert.Equal(t, 1, prog.added, "the address is programmed before it is announced")
}

// ---- linux programmer and raw conn -----------------------------------------

func TestNetlinkProgrammer_RefusesAnInvalidPrefix(t *testing.T) {
	p := NewNetlinkProgrammer()
	ops := map[string]func(string, netip.Prefix, net.HardwareAddr) error{
		"add":    p.AddAddress,
		"delete": p.DeleteAddress,
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			// lo always exists; the zero prefix fails parsing before netlink
			// is asked to change anything.
			require.Error(t, op("lo", netip.Prefix{}, nil))
		})
	}
}
