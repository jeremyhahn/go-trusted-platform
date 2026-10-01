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

package arp

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

var (
	localMAC     = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	responderMAC = net.HardwareAddr{0x00, 0x00, 0x0c, 0x9f, 0xf0, 0x14}
	probedIP     = net.IPv4(10, 4, 200, 1)
)

// fakeSession is an in-memory ProbeSession. Nothing it does touches a
// network: replies are queued by the test and handed back in order.
type fakeSession struct {
	local    net.HardwareAddr
	replies  []*Packet
	recvErr  error
	sendErr  error
	sent     []net.IP
	closed   bool
	closeErr error
}

func (s *fakeSession) LocalHardwareAddr() net.HardwareAddr { return s.local }

func (s *fakeSession) SendProbe(target net.IP) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, target)
	return nil
}

func (s *fakeSession) Receive(time.Time) (*Packet, error) {
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	if len(s.replies) == 0 {
		return nil, ErrProbeTimeout
	}
	reply := s.replies[0]
	s.replies = s.replies[1:]
	return reply, nil
}

func (s *fakeSession) Close() error {
	s.closed = true
	return s.closeErr
}

// fakeTransport hands out a single prepared session, or an open error.
type fakeTransport struct {
	session *fakeSession
	openErr error
	opened  []string
}

func (t *fakeTransport) Open(iface string) (ProbeSession, error) {
	t.opened = append(t.opened, iface)
	if t.openErr != nil {
		return nil, t.openErr
	}
	return t.session, nil
}

func reply(sender net.HardwareAddr, ip net.IP) *Packet {
	return &Packet{
		Operation:          OperationReply,
		SenderHardwareAddr: sender,
		SenderProtocolAddr: ip,
		TargetHardwareAddr: localMAC,
		TargetProtocolAddr: ip,
	}
}

func TestDetectorCheckFreeAddress(t *testing.T) {
	session := &fakeSession{local: localMAC}
	transport := &fakeTransport{session: session}
	detector := NewDuplicateAddressDetector(transport,
		WithProbeCount(3), WithProbeInterval(time.Millisecond))

	if err := detector.Check(context.Background(), "br-int", probedIP); err != nil {
		t.Fatalf("expected a silent segment to report no conflict, got %v", err)
	}
	if len(session.sent) != 3 {
		t.Errorf("expected 3 probes (RFC 5227 PROBE_NUM), sent %d", len(session.sent))
	}
	if !session.closed {
		t.Error("expected the probe session to be closed")
	}
	if len(transport.opened) != 1 || transport.opened[0] != "br-int" {
		t.Errorf("expected the probe to bind br-int, bound %v", transport.opened)
	}
}

func TestDetectorCheckConflict(t *testing.T) {
	session := &fakeSession{
		local:   localMAC,
		replies: []*Packet{reply(responderMAC, probedIP)},
	}
	detector := NewDuplicateAddressDetector(&fakeTransport{session: session},
		WithProbeInterval(time.Millisecond))

	err := detector.Check(context.Background(), "br-int", probedIP)

	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected a *ConflictError, got %v", err)
	}
	if conflict.ResponderHardwareAddr.String() != responderMAC.String() {
		t.Errorf("expected responder %s, got %s", responderMAC, conflict.ResponderHardwareAddr)
	}
	if conflict.LocalHardwareAddr.String() != localMAC.String() {
		t.Errorf("expected local %s, got %s", localMAC, conflict.LocalHardwareAddr)
	}
	if !conflict.Address.Equal(probedIP) {
		t.Errorf("expected address %s, got %s", probedIP, conflict.Address)
	}
	if conflict.Interface != "br-int" {
		t.Errorf("expected interface br-int, got %q", conflict.Interface)
	}
	if len(session.sent) != 1 {
		t.Errorf("expected the detector to stop on the first defence, sent %d probes", len(session.sent))
	}
	if !strings.Contains(conflict.Error(), responderMAC.String()) {
		t.Errorf("expected the error text to name the responder MAC, got %q", conflict.Error())
	}
}

// TestDetectorCheckConflictFromRequest covers the second defence RFC 5227
// recognises: another host probing or announcing the same address.
func TestDetectorCheckConflictFromRequest(t *testing.T) {
	announce := &Packet{
		Operation:          OperationRequest,
		SenderHardwareAddr: responderMAC,
		SenderProtocolAddr: probedIP,
		TargetHardwareAddr: net.HardwareAddr(make([]byte, hardwareAddrLen)),
		TargetProtocolAddr: probedIP,
	}
	session := &fakeSession{local: localMAC, replies: []*Packet{announce}}
	detector := NewDuplicateAddressDetector(&fakeTransport{session: session},
		WithProbeInterval(time.Millisecond))

	var conflict *ConflictError
	if err := detector.Check(context.Background(), "br-int", probedIP); !errors.As(err, &conflict) {
		t.Fatalf("expected an ARP announcement to be a conflict, got %v", err)
	}
}

// TestDetectorCheckIgnoresOwnProbeEcho proves the guard does not report a
// conflict against itself: AF_PACKET sockets see the frames they transmit.
func TestDetectorCheckIgnoresOwnProbeEcho(t *testing.T) {
	echo := reply(localMAC, probedIP)
	session := &fakeSession{local: localMAC, replies: []*Packet{echo}}
	detector := NewDuplicateAddressDetector(&fakeTransport{session: session},
		WithProbeCount(1), WithProbeInterval(time.Millisecond))

	if err := detector.Check(context.Background(), "br-int", probedIP); err != nil {
		t.Fatalf("expected our own frame to be ignored, got %v", err)
	}
}

// TestDetectorCheckIgnoresOtherAddresses proves unrelated ARP chatter on a
// busy segment does not read as a conflict.
func TestDetectorCheckIgnoresOtherAddresses(t *testing.T) {
	other := reply(responderMAC, net.IPv4(10, 4, 200, 99))
	session := &fakeSession{local: localMAC, replies: []*Packet{other}}
	detector := NewDuplicateAddressDetector(&fakeTransport{session: session},
		WithProbeCount(1), WithProbeInterval(time.Millisecond))

	if err := detector.Check(context.Background(), "br-int", probedIP); err != nil {
		t.Fatalf("expected traffic for another address to be ignored, got %v", err)
	}
}

func TestDetectorCheckInterfaceAbsent(t *testing.T) {
	transport := &fakeTransport{openErr: errors.New("no such device")}
	detector := NewDuplicateAddressDetector(transport)

	err := detector.Check(context.Background(), "missing0", probedIP)
	if !errors.Is(err, ErrInterfaceUnavailable) {
		t.Fatalf("expected ErrInterfaceUnavailable, got %v", err)
	}
	var conflict *ConflictError
	if errors.As(err, &conflict) {
		t.Error("an unusable interface must never be reported as a conflict")
	}
}

func TestDetectorCheckInvalidInput(t *testing.T) {
	session := &fakeSession{local: localMAC}
	detector := NewDuplicateAddressDetector(&fakeTransport{session: session},
		WithProbeInterval(time.Millisecond))

	tests := map[string]struct {
		detector *DuplicateAddressDetector
		iface    string
		ip       net.IP
		want     error
	}{
		"no transport":     {NewDuplicateAddressDetector(nil), "br-int", probedIP, ErrNoProbeTransport},
		"empty interface":  {detector, "", probedIP, ErrInvalidInterface},
		"nil address":      {detector, "br-int", nil, ErrNotIPv4},
		"ipv6 address":     {detector, "br-int", net.ParseIP("fd00::1"), ErrNotIPv4},
		"unspecified ipv4": {detector, "br-int", net.IPv4zero, ErrNotIPv4},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := tc.detector.Check(context.Background(), tc.iface, tc.ip); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestDetectorCheckSendFailure(t *testing.T) {
	sendErr := errors.New("network is down")
	session := &fakeSession{local: localMAC, sendErr: sendErr}
	detector := NewDuplicateAddressDetector(&fakeTransport{session: session})

	if err := detector.Check(context.Background(), "br-int", probedIP); !errors.Is(err, sendErr) {
		t.Fatalf("expected the send failure to surface, got %v", err)
	}
}

func TestDetectorCheckReceiveFailure(t *testing.T) {
	recvErr := errors.New("socket closed")
	session := &fakeSession{local: localMAC, recvErr: recvErr}
	detector := NewDuplicateAddressDetector(&fakeTransport{session: session})

	if err := detector.Check(context.Background(), "br-int", probedIP); !errors.Is(err, recvErr) {
		t.Fatalf("expected the receive failure to surface, got %v", err)
	}
}

func TestDetectorCheckContextCancelled(t *testing.T) {
	session := &fakeSession{local: localMAC}
	detector := NewDuplicateAddressDetector(&fakeTransport{session: session})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := detector.Check(ctx, "br-int", probedIP); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(session.sent) != 0 {
		t.Error("expected no probe to be sent after cancellation")
	}
}

// TestDetectorCheckHonoursContextDeadline proves the listen window never
// outlives the caller's deadline.
func TestDetectorCheckHonoursContextDeadline(t *testing.T) {
	session := &fakeSession{local: localMAC}
	detector := NewDuplicateAddressDetector(&fakeTransport{session: session},
		WithProbeCount(2), WithProbeInterval(time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := detector.Check(ctx, "br-int", probedIP); err != nil {
		t.Fatalf("expected the deadline-bounded probe to report no conflict, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Minute {
		t.Fatalf("probe ignored the context deadline, took %s", elapsed)
	}
}

func TestDetectorWindowAndDefaults(t *testing.T) {
	detector := NewDuplicateAddressDetector(&fakeTransport{})
	if detector.probes != DefaultProbeCount || detector.interval != DefaultProbeInterval {
		t.Fatalf("expected RFC 5227 defaults, got %d probes at %s", detector.probes, detector.interval)
	}
	if want := DefaultProbeCount * DefaultProbeInterval; detector.Window() != want {
		t.Errorf("expected a %s window, got %s", want, detector.Window())
	}

	// Non-positive options are ignored rather than producing a detector
	// that probes zero times and declares every address free.
	guarded := NewDuplicateAddressDetector(&fakeTransport{}, WithProbeCount(0), WithProbeInterval(0))
	if guarded.probes != DefaultProbeCount || guarded.interval != DefaultProbeInterval {
		t.Errorf("expected non-positive options to be ignored, got %d probes at %s",
			guarded.probes, guarded.interval)
	}
}

// TestDetectorCheckSharedAddressFromGroupMAC: a VRRP virtual address
// defended by the group's virtual MAC is the redundancy group answering,
// not a conflict (epic #553 R7); the same address from any other MAC still
// is one, and an unrelated address is unaffected by the declaration.
func TestDetectorCheckSharedAddressFromGroupMAC(t *testing.T) {
	vmac := net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x01, 0x14}

	session := &fakeSession{local: localMAC, replies: []*Packet{reply(vmac, probedIP)}}
	detector := NewDuplicateAddressDetector(&fakeTransport{session: session},
		WithProbeInterval(time.Millisecond), WithSharedAddress(probedIP, vmac))
	if err := detector.Check(context.Background(), "br-int", probedIP); err != nil {
		t.Fatalf("a defence from the group's virtual MAC must not be a conflict, got %v", err)
	}

	session = &fakeSession{local: localMAC, replies: []*Packet{reply(responderMAC, probedIP)}}
	detector = NewDuplicateAddressDetector(&fakeTransport{session: session},
		WithProbeInterval(time.Millisecond), WithSharedAddress(probedIP, vmac))
	var conflict *ConflictError
	if err := detector.Check(context.Background(), "br-int", probedIP); !errors.As(err, &conflict) {
		t.Fatalf("a defence from another MAC is still a conflict, got %v", err)
	}

	other := net.IPv4(10, 4, 200, 9)
	session = &fakeSession{local: localMAC, replies: []*Packet{reply(vmac, other)}}
	detector = NewDuplicateAddressDetector(&fakeTransport{session: session},
		WithProbeInterval(time.Millisecond), WithSharedAddress(probedIP, vmac))
	if err := detector.Check(context.Background(), "br-int", other); !errors.As(err, &conflict) {
		t.Fatalf("the declaration covers only its own address, got %v", err)
	}

	// Nil inputs are ignored rather than registering an empty entry.
	detector = NewDuplicateAddressDetector(&fakeTransport{session: session}, WithSharedAddress(nil, vmac), WithSharedAddress(probedIP, nil))
	if detector.shared != nil {
		t.Fatalf("nil declarations must be ignored")
	}
}
