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
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// timeoutError is a net.Error reporting a read deadline expiry, which is how
// a real socket signals a silent probe window.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// fakePacketConn is an in-memory raw socket.
type fakePacketConn struct {
	frames      [][]byte
	written     [][]byte
	readErr     error
	writeErr    error
	deadlineErr error
	deadline    time.Time
	closed      bool
}

func (c *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	if len(c.frames) == 0 {
		return 0, nil, timeoutError{}
	}
	frame := c.frames[0]
	c.frames = c.frames[1:]
	return copy(b, frame), nil, nil
}

func (c *fakePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.written = append(c.written, append([]byte(nil), b...))
	return len(b), nil
}

func (c *fakePacketConn) SetReadDeadline(t time.Time) error {
	c.deadline = t
	return c.deadlineErr
}

func (c *fakePacketConn) Close() error {
	c.closed = true
	return nil
}

func mustFrame(t *testing.T, packet *Packet, src, dst net.HardwareAddr) []byte {
	t.Helper()
	frame, err := packet.MarshalFrame(src, dst)
	if err != nil {
		t.Fatalf("MarshalFrame: %v", err)
	}
	return frame
}

func TestPacketRoundTrip(t *testing.T) {
	original := &Packet{
		Operation:          OperationReply,
		SenderHardwareAddr: responderMAC,
		SenderProtocolAddr: probedIP,
		TargetHardwareAddr: localMAC,
		TargetProtocolAddr: net.IPv4(172, 16, 200, 2),
	}
	frame := mustFrame(t, original, responderMAC, localMAC)
	if len(frame) != frameLen {
		t.Fatalf("expected a %d-byte frame, got %d", frameLen, len(frame))
	}

	decoded, err := UnmarshalFrame(frame)
	if err != nil {
		t.Fatalf("UnmarshalFrame: %v", err)
	}
	if decoded.Operation != OperationReply {
		t.Errorf("expected an ARP reply, got opcode %d", decoded.Operation)
	}
	if !bytes.Equal(decoded.SenderHardwareAddr, responderMAC) {
		t.Errorf("expected sender %s, got %s", responderMAC, decoded.SenderHardwareAddr)
	}
	if !decoded.SenderProtocolAddr.Equal(probedIP) {
		t.Errorf("expected sender IP %s, got %s", probedIP, decoded.SenderProtocolAddr)
	}
	if !bytes.Equal(decoded.TargetHardwareAddr, localMAC) {
		t.Errorf("expected target %s, got %s", localMAC, decoded.TargetHardwareAddr)
	}
}

// TestPacketMarshalProbeDefaults proves an RFC 5227 probe carries 0.0.0.0 as
// its sender protocol address, so no receiver caches the probe as a mapping
// for the address under test.
func TestPacketMarshalProbeDefaults(t *testing.T) {
	probe := &Packet{
		Operation:          OperationRequest,
		SenderHardwareAddr: localMAC,
		TargetProtocolAddr: probedIP,
	}
	frame := mustFrame(t, probe, localMAC, broadcastHardwareAddr)

	decoded, err := UnmarshalFrame(frame)
	if err != nil {
		t.Fatalf("UnmarshalFrame: %v", err)
	}
	if !decoded.SenderProtocolAddr.Equal(net.IPv4zero) {
		t.Errorf("expected a 0.0.0.0 sender, got %s", decoded.SenderProtocolAddr)
	}
	if !bytes.Equal(decoded.TargetHardwareAddr, make([]byte, hardwareAddrLen)) {
		t.Errorf("expected a zero target MAC, got %s", decoded.TargetHardwareAddr)
	}
	if !bytes.Equal(frame[0:hardwareAddrLen], broadcastHardwareAddr) {
		t.Errorf("expected a broadcast destination, got %s", net.HardwareAddr(frame[0:hardwareAddrLen]))
	}
}

func TestPacketMarshalErrors(t *testing.T) {
	valid := &Packet{Operation: OperationRequest, TargetProtocolAddr: probedIP}

	tests := map[string]struct {
		packet *Packet
		src    net.HardwareAddr
		dst    net.HardwareAddr
		want   error
	}{
		"short source MAC":      {valid, net.HardwareAddr{0x02}, broadcastHardwareAddr, ErrInvalidMAC},
		"short destination MAC": {valid, localMAC, net.HardwareAddr{0x02}, ErrInvalidMAC},
		"short sender MAC": {
			&Packet{SenderHardwareAddr: net.HardwareAddr{0x02}, TargetProtocolAddr: probedIP},
			localMAC, broadcastHardwareAddr, ErrInvalidMAC,
		},
		"short target MAC": {
			&Packet{TargetHardwareAddr: net.HardwareAddr{0x02}, TargetProtocolAddr: probedIP},
			localMAC, broadcastHardwareAddr, ErrInvalidMAC,
		},
		"ipv6 target": {
			&Packet{TargetProtocolAddr: net.ParseIP("fd00::1")},
			localMAC, broadcastHardwareAddr, ErrNotIPv4,
		},
		"ipv6 sender": {
			&Packet{SenderProtocolAddr: net.ParseIP("fd00::1"), TargetProtocolAddr: probedIP},
			localMAC, broadcastHardwareAddr, ErrNotIPv4,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.packet.MarshalFrame(tc.src, tc.dst); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestUnmarshalFrameErrors(t *testing.T) {
	base := mustFrame(t, reply(responderMAC, probedIP), responderMAC, localMAC)

	notARP := append([]byte(nil), base...)
	binary.BigEndian.PutUint16(notARP[12:14], 0x0800)

	badHardware := append([]byte(nil), base...)
	binary.BigEndian.PutUint16(badHardware[etherHeaderLen:etherHeaderLen+2], 99)

	badProtocol := append([]byte(nil), base...)
	binary.BigEndian.PutUint16(badProtocol[etherHeaderLen+2:etherHeaderLen+4], 0x86dd)

	badLengths := append([]byte(nil), base...)
	badLengths[etherHeaderLen+4] = 8

	tests := map[string]struct {
		frame []byte
		want  error
	}{
		"short frame":    {base[:frameLen-1], ErrShortFrame},
		"not ARP":        {notARP, ErrNotARP},
		"hardware type":  {badHardware, ErrUnsupportedHardwareType},
		"protocol type":  {badProtocol, ErrUnsupportedProtocolType},
		"address length": {badLengths, ErrUnsupportedAddressLength},
		"empty":          {nil, ErrShortFrame},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalFrame(tc.frame); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestNewProbeSessionValidation(t *testing.T) {
	if _, err := NewProbeSession(nil, localMAC, nil); !errors.Is(err, ErrNilPacketConn) {
		t.Fatalf("expected ErrNilPacketConn, got %v", err)
	}
	if _, err := NewProbeSession(&fakePacketConn{}, net.HardwareAddr{0x02}, nil); !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("expected ErrInvalidMAC, got %v", err)
	}
}

func TestProbeSessionSendProbe(t *testing.T) {
	conn := &fakePacketConn{}
	session, err := NewProbeSession(conn, localMAC, nil)
	if err != nil {
		t.Fatalf("NewProbeSession: %v", err)
	}
	if got := session.LocalHardwareAddr(); !bytes.Equal(got, localMAC) {
		t.Fatalf("expected local MAC %s, got %s", localMAC, got)
	}
	if err := session.SendProbe(probedIP); err != nil {
		t.Fatalf("SendProbe: %v", err)
	}
	if len(conn.written) != 1 {
		t.Fatalf("expected one frame on the wire, got %d", len(conn.written))
	}
	decoded, err := UnmarshalFrame(conn.written[0])
	if err != nil {
		t.Fatalf("UnmarshalFrame: %v", err)
	}
	if decoded.Operation != OperationRequest {
		t.Errorf("expected an ARP request, got opcode %d", decoded.Operation)
	}
	if !decoded.TargetProtocolAddr.Equal(probedIP) {
		t.Errorf("expected the probe to target %s, got %s", probedIP, decoded.TargetProtocolAddr)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !conn.closed {
		t.Error("expected Close to release the socket")
	}
}

func TestProbeSessionSendProbeErrors(t *testing.T) {
	writeErr := errors.New("write failed")
	session, err := NewProbeSession(&fakePacketConn{writeErr: writeErr}, localMAC, nil)
	if err != nil {
		t.Fatalf("NewProbeSession: %v", err)
	}
	err = session.SendProbe(probedIP)
	if !errors.Is(err, ErrProbeSend) || !errors.Is(err, writeErr) {
		t.Fatalf("expected ErrProbeSend wrapping the cause, got %v", err)
	}

	// An IPv6 target never reaches the socket.
	if err := session.SendProbe(net.ParseIP("fd00::1")); !errors.Is(err, ErrNotIPv4) {
		t.Fatalf("expected ErrNotIPv4, got %v", err)
	}
}

func TestProbeSessionReceive(t *testing.T) {
	defence := mustFrame(t, reply(responderMAC, probedIP), responderMAC, localMAC)
	// A non-ARP frame ahead of the defence must be skipped, not mistaken
	// for a silent segment.
	noise := append([]byte(nil), defence...)
	binary.BigEndian.PutUint16(noise[12:14], 0x0800)

	conn := &fakePacketConn{frames: [][]byte{noise, defence}}
	session, err := NewProbeSession(conn, localMAC, nil)
	if err != nil {
		t.Fatalf("NewProbeSession: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	packet, err := session.Receive(deadline)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !bytes.Equal(packet.SenderHardwareAddr, responderMAC) {
		t.Errorf("expected the defence from %s, got %s", responderMAC, packet.SenderHardwareAddr)
	}
	if !conn.deadline.Equal(deadline) {
		t.Errorf("expected the read deadline to be applied, got %s", conn.deadline)
	}
}

func TestProbeSessionReceiveErrors(t *testing.T) {
	t.Run("timeout is the quiet outcome", func(t *testing.T) {
		session, err := NewProbeSession(&fakePacketConn{}, localMAC, nil)
		if err != nil {
			t.Fatalf("NewProbeSession: %v", err)
		}
		if _, err := session.Receive(time.Now()); !errors.Is(err, ErrProbeTimeout) {
			t.Fatalf("expected ErrProbeTimeout, got %v", err)
		}
	})

	t.Run("read failure surfaces", func(t *testing.T) {
		readErr := errors.New("socket closed")
		session, err := NewProbeSession(&fakePacketConn{readErr: readErr}, localMAC, nil)
		if err != nil {
			t.Fatalf("NewProbeSession: %v", err)
		}
		got := func() error { _, e := session.Receive(time.Now()); return e }()
		if !errors.Is(got, ErrProbeReceive) || !errors.Is(got, readErr) {
			t.Fatalf("expected ErrProbeReceive wrapping the cause, got %v", got)
		}
	})

	t.Run("deadline failure surfaces", func(t *testing.T) {
		deadlineErr := errors.New("bad file descriptor")
		session, err := NewProbeSession(&fakePacketConn{deadlineErr: deadlineErr}, localMAC, nil)
		if err != nil {
			t.Fatalf("NewProbeSession: %v", err)
		}
		got := func() error { _, e := session.Receive(time.Now()); return e }()
		if !errors.Is(got, ErrProbeReceive) || !errors.Is(got, deadlineErr) {
			t.Fatalf("expected ErrProbeReceive wrapping the cause, got %v", got)
		}
	})
}

// TestRawProbeTransportRejectsMissingInterface exercises the production
// transport's failure path without needing a raw socket: the interface does
// not exist, so no privilege is required to prove the error is typed.
func TestRawProbeTransportRejectsMissingInterface(t *testing.T) {
	transport := NewRawProbeTransport()

	if _, err := transport.Open(""); err == nil {
		t.Fatal("expected an empty interface name to be refused")
	}
	if _, err := transport.Open("tp-no-such-iface0"); err == nil {
		t.Fatal("expected a missing interface to be refused")
	}
}

// TestSentinelCauseErrorText proves a wrapped probe failure names both the
// sentinel and the underlying cause, which is what an operator reads in the
// bring-up log.
func TestSentinelCauseErrorText(t *testing.T) {
	cause := errors.New("operation not permitted")
	err := &SentinelCauseError{Sentinel: ErrProbeSocket, Cause: cause}

	if !errors.Is(err, ErrProbeSocket) || !errors.Is(err, cause) {
		t.Fatalf("expected the wrapper to match both errors, got %v", err)
	}
	if got := err.Error(); got != ErrProbeSocket.Error()+": "+cause.Error() {
		t.Errorf("unexpected error text %q", got)
	}
}

// TestDefendsRejectsMalformedPackets covers the guard clauses that keep a
// half-parsed frame from reading as a defence.
func TestDefendsRejectsMalformedPackets(t *testing.T) {
	tests := map[string]*Packet{
		"nil packet":       nil,
		"no sender MAC":    {Operation: OperationReply, SenderProtocolAddr: probedIP},
		"unknown opcode":   {Operation: 42, SenderHardwareAddr: responderMAC, SenderProtocolAddr: probedIP},
		"different sender": {Operation: OperationReply, SenderHardwareAddr: responderMAC, SenderProtocolAddr: net.IPv4(10, 0, 0, 1)},
	}
	for name, packet := range tests {
		t.Run(name, func(t *testing.T) {
			if defends(packet, probedIP, localMAC) {
				t.Fatal("expected the packet not to count as a defence")
			}
		})
	}
}
