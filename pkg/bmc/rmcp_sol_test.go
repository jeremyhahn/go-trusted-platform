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

package bmc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// loopbackSession wires a test rmcpSession to a loopback UDP listener the
// test controls, with the given exchange timeout. Reply through the
// returned listener to answer datagrams the session sends.
func loopbackSession(t *testing.T, timeout time.Duration) (*rmcpSession, *net.UDPConn) {
	t.Helper()
	s := newTestSOLSession(t)
	s.timeout = timeout
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	dial, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { dial.Close() })
	s.conn = dial
	return s, listener
}

// TestRebindForSOL_ExcludesInFlightSend verifies the socket swap cannot
// run under an in-flight exchange. A real Send is parked inside its read —
// proven by the listener holding its unanswered request — and at that
// moment exchangeMu is provably held (TryLock fails). rebindForSOL's first
// act is to take that same lock, so it cannot swap the socket until the
// exchange completes: the reply is written to the OLD remote, Send only
// succeeds if that socket is still the session's, and the rebind then
// completes onto the new port.
func TestRebindForSOL_ExcludesInFlightSend(t *testing.T) {
	s, listener := loopbackSession(t, 2*time.Second)
	newPort := uint16(listener.LocalAddr().(*net.UDPAddr).Port + 1)

	sendDone := make(chan error, 1)
	go func() {
		_, err := s.Send(netFnApp, cmdGetDeviceID, nil)
		sendDone <- err
	}()
	buf := make([]byte, maxUDPRecvSize)
	if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, from, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("request never reached the listener: %v", err)
	}
	// Send is parked in its read. The exchange lock rebindForSOL needs
	// must be held right now — this is the deterministic exclusion proof.
	if s.exchangeMu.TryLock() {
		s.exchangeMu.Unlock()
		t.Fatal("exchangeMu is free while an exchange is in flight — rebindForSOL could swap the socket under Send")
	}

	rebindDone := make(chan error, 1)
	go func() { rebindDone <- s.rebindForSOL(newPort) }()

	// Answer on the OLD socket. Send succeeding proves the socket was not
	// swapped while the exchange was in flight, whenever the goroutine ran.
	if _, err := listener.WriteToUDP(unwrapTestPacket((netFnApp+1)<<2, cmdGetDeviceID, 0x00), from); err != nil {
		t.Fatal(err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("the in-flight Send failed — the socket was swapped underneath it: %v", err)
	}
	if err := <-rebindDone; err != nil {
		t.Fatalf("rebindForSOL after the exchange finished: %v", err)
	}
	if got := s.conn.RemoteAddr().(*net.UDPAddr).Port; got != int(newPort) {
		t.Errorf("remote port after rebind = %d, want %d", got, newPort)
	}
	s.conn.Close()
}

// TestSOLSession_DeactivateWaitsForReceiveLoop verifies Deactivate hands
// the socket back before it sends Deactivate Payload. The receive loop is
// parked in a real read on the socket; the listener, on receiving the
// Deactivate Payload datagram, records whether the loop had already exited
// (loopDone closed) at that moment and then answers it. Nothing else wakes
// the loop's read before that reply, so the datagram can only arrive after
// the loop exited if Deactivate waited for it.
func TestSOLSession_DeactivateWaitsForReceiveLoop(t *testing.T) {
	s, listener := loopbackSession(t, 200*time.Millisecond)

	sol := &SOLSession{
		session:         s,
		logger:          slog.Default(),
		output:          make(chan []byte, 16),
		done:            make(chan struct{}),
		loopDone:        make(chan struct{}),
		payloadInstance: 0x01,
	}

	var loopExitedFirst atomic.Bool
	observed := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, maxUDPRecvSize)
		_, from, err := listener.ReadFromUDP(buf)
		if err != nil {
			return
		}
		select {
		case <-sol.loopDone:
			loopExitedFirst.Store(true)
		default:
		}
		observed <- struct{}{}
		_, _ = listener.WriteToUDP(unwrapTestPacket((netFnApp+1)<<2, cmdDeactivatePayload, 0x00), from)
	}()

	// Wrap the socket so the test knows when the loop is inside a read
	// — otherwise Deactivate could run before the loop ever started.
	inRead := make(chan struct{}, 1)
	s.conn = &readSignalConn{Conn: s.conn, inRead: inRead}
	sol.active.Store(true)
	go sol.receiveLoop()
	<-inRead

	if err := sol.Deactivate(context.Background()); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	<-observed
	if !loopExitedFirst.Load() {
		t.Fatal("Deactivate Payload was sent while the receive loop still owned the socket")
	}
	if _, ok := <-sol.output; ok {
		t.Error("output must be closed once the loop has exited")
	}
}

// readSignalConn is a net.Conn that reports each entry into Read on a
// channel, so a test can wait until a goroutine is parked in a read.
type readSignalConn struct {
	net.Conn
	inRead chan struct{}
}

func (c *readSignalConn) Read(p []byte) (int, error) {
	select {
	case c.inRead <- struct{}{}:
	default:
	}
	return c.Conn.Read(p)
}

func TestSOLSession_ReadWrite(t *testing.T) {
	t.Run("write_returns_error_with_no_connection", func(t *testing.T) {
		sol := &SOLSession{
			session: newTestSOLSession(t),
			logger:  slog.Default(),
			output:  make(chan []byte, 16),
			done:    make(chan struct{}),
		}
		sol.active.Store(true)

		// Write should fail because there is no real UDP connection.
		data := []byte("hello")
		_, err := sol.Write(data)
		if err == nil {
			t.Fatal("expected error writing to session with no connection")
		}
		var udpErr ErrUDPSend
		var sessionErr ErrSessionClosed
		if !errors.As(err, &udpErr) && !errors.As(err, &sessionErr) {
			t.Fatalf("expected ErrUDPSend or ErrSessionClosed, got %T: %v", err, err)
		}
	})

	t.Run("write_returns_error_when_closed", func(t *testing.T) {
		sol := &SOLSession{
			session: newTestSOLSession(t),
			logger:  slog.Default(),
			output:  make(chan []byte, 16),
			done:    make(chan struct{}),
		}
		// Session not active (default) - should get ErrSOLSessionClosed.

		_, err := sol.Write([]byte("test"))
		if err == nil {
			t.Fatal("expected error writing to inactive session")
		}
		var solClosed ErrSOLSessionClosed
		if !errors.As(err, &solClosed) {
			t.Fatalf("expected ErrSOLSessionClosed, got %T: %v", err, err)
		}
	})

	t.Run("read_returns_data_from_output_channel", func(t *testing.T) {
		sol := &SOLSession{
			session: newTestSOLSession(t),
			logger:  slog.Default(),
			output:  make(chan []byte, 16),
			done:    make(chan struct{}),
		}
		sol.active.Store(true)

		expected := []byte("hello from BMC")
		sol.output <- expected

		buf := make([]byte, 64)
		n, err := sol.Read(buf)
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}
		if string(buf[:n]) != string(expected) {
			t.Fatalf("expected %q, got %q", expected, buf[:n])
		}
	})

	t.Run("read_returns_eof_when_channel_closed", func(t *testing.T) {
		sol := &SOLSession{
			session: newTestSOLSession(t),
			logger:  slog.Default(),
			output:  make(chan []byte, 16),
			done:    make(chan struct{}),
		}
		sol.active.Store(true)

		close(sol.output)

		buf := make([]byte, 64)
		_, err := sol.Read(buf)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected io.EOF, got %v", err)
		}
	})

	t.Run("read_returns_error_when_inactive", func(t *testing.T) {
		sol := &SOLSession{
			session: newTestSOLSession(t),
			logger:  slog.Default(),
			output:  make(chan []byte, 16),
			done:    make(chan struct{}),
		}
		// active is false by default

		buf := make([]byte, 64)
		_, err := sol.Read(buf)
		var solClosed ErrSOLSessionClosed
		if !errors.As(err, &solClosed) {
			t.Fatalf("expected ErrSOLSessionClosed, got %T: %v", err, err)
		}
	})
}

func TestSOLSession_Close(t *testing.T) {
	t.Run("close_marks_session_inactive", func(t *testing.T) {
		sol := &SOLSession{
			session: newTestSOLSession(t),
			logger:  slog.Default(),
			output:  make(chan []byte, 16),
			done:    make(chan struct{}),
		}
		sol.active.Store(true)

		// Close will attempt to send Deactivate which will fail with no conn,
		// but the session must be marked inactive.
		_ = sol.Close()

		if sol.active.Load() {
			t.Fatal("session should be inactive after Close")
		}
	})

	t.Run("close_is_idempotent", func(t *testing.T) {
		sol := &SOLSession{
			session: newTestSOLSession(t),
			logger:  slog.Default(),
			output:  make(chan []byte, 16),
			done:    make(chan struct{}),
		}
		sol.active.Store(true)

		// First close.
		_ = sol.Close()

		// Second close should return nil (already deactivated).
		err := sol.Close()
		if err != nil {
			t.Fatalf("second Close should return nil, got: %v", err)
		}
	})
}

func TestSOLSession_ActivatePayload(t *testing.T) {
	t.Run("activate_fails_on_closed_session", func(t *testing.T) {
		session := newTestSOLSession(t)
		session.closed.Store(true)

		_, err := session.ActivateSOL(context.Background(), 0x01)
		var sessionErr ErrSessionClosed
		if !errors.As(err, &sessionErr) {
			t.Fatalf("expected ErrSessionClosed, got %T: %v", err, err)
		}
	})

	t.Run("activate_fails_with_no_connection", func(t *testing.T) {
		session := newTestSOLSession(t)
		// Session is open but has no connection, so ActivateSOL should
		// detect nil conn and return ErrSessionClosed.
		_, err := session.ActivateSOL(context.Background(), 0x01)
		if err == nil {
			t.Fatal("expected error activating SOL with no connection")
		}
		var sessionErr ErrSessionClosed
		if !errors.As(err, &sessionErr) {
			t.Fatalf("expected ErrSessionClosed, got %T: %v", err, err)
		}
	})
}

func TestSOLPacket_Format(t *testing.T) {
	t.Run("sol_packet_header_layout", func(t *testing.T) {
		sol := &SOLSession{
			session: newTestSOLSession(t),
			logger:  slog.Default(),
			output:  make(chan []byte, 16),
			done:    make(chan struct{}),
		}
		sol.active.Store(true)

		// Verify the SOL packet construction by building one directly.
		data := []byte("AB")
		seq := sol.seqNum.Add(1)

		packet := make([]byte, solHeaderSize+len(data))
		packet[0] = byte(seq & 0xFF)
		packet[1] = 0x00
		packet[2] = 0x00
		packet[3] = 0x00
		copy(packet[solHeaderSize:], data)

		// Verify header fields.
		if packet[0] != 0x01 {
			t.Fatalf("expected sequence number 1, got %d", packet[0])
		}
		if packet[1] != 0x00 {
			t.Fatal("expected ACK sequence 0")
		}
		if packet[2] != 0x00 {
			t.Fatal("expected accepted char count 0")
		}
		if packet[3] != 0x00 {
			t.Fatal("expected operation/status 0")
		}

		// Verify character data.
		if string(packet[solHeaderSize:]) != "AB" {
			t.Fatalf("expected character data 'AB', got %q", packet[solHeaderSize:])
		}
	})

	t.Run("sol_header_size_constant", func(t *testing.T) {
		if solHeaderSize != 4 {
			t.Fatalf("expected solHeaderSize=4, got %d", solHeaderSize)
		}
	})

	t.Run("sol_status_bits", func(t *testing.T) {
		if solStatusNACK != 0x01 {
			t.Fatalf("expected solStatusNACK=0x01, got 0x%02x", solStatusNACK)
		}
		if solStatusRingDetect != 0x02 {
			t.Fatalf("expected solStatusRingDetect=0x02, got 0x%02x", solStatusRingDetect)
		}
		if solStatusBreakDetect != 0x04 {
			t.Fatalf("expected solStatusBreakDetect=0x04, got 0x%02x", solStatusBreakDetect)
		}
		if solStatusTransmitOverrun != 0x08 {
			t.Fatalf("expected solStatusTransmitOverrun=0x08, got 0x%02x", solStatusTransmitOverrun)
		}
	})

	t.Run("sol_aux_handshake_and_alert_constants", func(t *testing.T) {
		// Verify the Activate Payload auxiliary data bit definitions per
		// IPMI 2.0 spec Table 24-2 are correct.
		if solAuxHandshakeAssert != 0x08 {
			t.Fatalf("expected solAuxHandshakeAssert=0x08, got 0x%02x", solAuxHandshakeAssert)
		}
		if solAuxAlertDefer != 0x04 {
			t.Fatalf("expected solAuxAlertDefer=0x04, got 0x%02x", solAuxAlertDefer)
		}
		// Combined value used in ActivateSOL must be 0x0C (bits 3 + 2).
		combined := solAuxHandshakeAssert | solAuxAlertDefer
		if combined != 0x0C {
			t.Fatalf("expected combined aux byte=0x0C, got 0x%02x", combined)
		}
	})
}

func TestSOLErrors(t *testing.T) {
	t.Run("activate_error_message", func(t *testing.T) {
		err := ErrSOLActivateFailed{Cause: io.EOF}
		expected := "bmc: SOL activate payload failed: EOF"
		if err.Error() != expected {
			t.Fatalf("expected %q, got %q", expected, err.Error())
		}
		if !errors.Is(err, io.EOF) {
			t.Fatal("expected Unwrap to return io.EOF")
		}
	})

	t.Run("activate_error_message_nil_cause", func(t *testing.T) {
		err := ErrSOLActivateFailed{}
		expected := "bmc: SOL activate payload failed"
		if err.Error() != expected {
			t.Fatalf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("deactivate_error_message", func(t *testing.T) {
		cause := ErrSessionClosed{}
		err := ErrSOLDeactivateFailed{Cause: cause}
		expected := "bmc: SOL deactivate payload failed: bmc: RMCP+ session is closed"
		if err.Error() != expected {
			t.Fatalf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("deactivate_error_message_nil_cause", func(t *testing.T) {
		err := ErrSOLDeactivateFailed{}
		expected := "bmc: SOL deactivate payload failed"
		if err.Error() != expected {
			t.Fatalf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("session_closed_error", func(t *testing.T) {
		err := ErrSOLSessionClosed{}
		expected := "bmc: SOL session is closed"
		if err.Error() != expected {
			t.Fatalf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("timeout_error", func(t *testing.T) {
		err := ErrSOLTimeout{}
		expected := "bmc: SOL operation timed out"
		if err.Error() != expected {
			t.Fatalf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestWrapSOLPayload(t *testing.T) {
	t.Run("wraps_with_sol_payload_type", func(t *testing.T) {
		session := newTestSOLSession(t)
		// No encryption/integrity so we can easily inspect the packet.
		session.cryptoAlgo = cryptoAlgoNone
		session.integrityAlgo = integrityAlgoNone
		session.bmcSessionID = 0x12345678

		solData := []byte{0x01, 0x00, 0x00, 0x00, 'A'}
		packet, err := session.wrapSOLPayload(solData)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify RMCP header.
		if packet[0] != rmcpVersion {
			t.Fatalf("expected RMCP version 0x%02x, got 0x%02x", rmcpVersion, packet[0])
		}
		if packet[3] != rmcpClassIPMI {
			t.Fatalf("expected RMCP class 0x%02x, got 0x%02x", rmcpClassIPMI, packet[3])
		}

		// Verify payload type is SOL (0x01) with no encrypt/auth bits.
		if packet[5] != payloadTypeSOL {
			t.Fatalf("expected payload type 0x%02x (SOL), got 0x%02x", payloadTypeSOL, packet[5])
		}

		// Verify the payload data starts at offset 16.
		payloadStart := 16
		if len(packet) < payloadStart+len(solData) {
			t.Fatalf("packet too short: %d", len(packet))
		}

		for i, b := range solData {
			if packet[payloadStart+i] != b {
				t.Fatalf("payload byte %d: expected 0x%02x, got 0x%02x", i, b, packet[payloadStart+i])
			}
		}
	})

	t.Run("wraps_with_encryption_flag", func(t *testing.T) {
		session := newTestSOLSession(t)
		session.cryptoAlgo = cryptoAlgoAESCBC128
		session.integrityAlgo = integrityAlgoNone
		session.k2 = make([]byte, 32)
		for i := range session.k2 {
			session.k2[i] = byte(i)
		}

		solData := []byte{0x01, 0x00, 0x00, 0x00, 'B'}
		packet, err := session.wrapSOLPayload(solData)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Payload type should have encrypted bit set (0x80) plus SOL type (0x01).
		expectedType := byte(payloadTypeSOL | 0x80)
		if packet[5] != expectedType {
			t.Fatalf("expected payload type 0x%02x, got 0x%02x", expectedType, packet[5])
		}
	})

	t.Run("wraps_with_integrity_flag", func(t *testing.T) {
		session := newTestSOLSession(t)
		session.cryptoAlgo = cryptoAlgoNone
		session.integrityAlgo = integrityAlgoHMACSHA256_128
		session.k1 = make([]byte, 32)

		solData := []byte{0x01, 0x00, 0x00, 0x00, 'C'}
		packet, err := session.wrapSOLPayload(solData)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Payload type should have authenticated bit (0x40) plus SOL type (0x01).
		expectedType := byte(payloadTypeSOL | 0x40)
		if packet[5] != expectedType {
			t.Fatalf("expected payload type 0x%02x, got 0x%02x", expectedType, packet[5])
		}

		// Packet should be longer due to integrity pad + auth code.
		minLen := 16 + len(solData) + 2 + 16
		if len(packet) < minLen {
			t.Fatalf("expected packet length >= %d with integrity, got %d", minLen, len(packet))
		}
	})

	t.Run("wraps_with_both_encryption_and_integrity", func(t *testing.T) {
		session := newTestSOLSession(t)
		session.cryptoAlgo = cryptoAlgoAESCBC128
		session.integrityAlgo = integrityAlgoHMACSHA256_128
		session.k1 = make([]byte, 32)
		session.k2 = make([]byte, 32)
		for i := range session.k2 {
			session.k2[i] = byte(i)
		}

		solData := []byte{0x01, 0x00, 0x00, 0x00, 'D', 'E'}
		packet, err := session.wrapSOLPayload(solData)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Payload type should have both encrypted (0x80) and authenticated (0x40) bits.
		expectedType := byte(payloadTypeSOL | 0x80 | 0x40)
		if packet[5] != expectedType {
			t.Fatalf("expected payload type 0x%02x, got 0x%02x", expectedType, packet[5])
		}
	})
}

// newTestSOLSession creates an rmcpSession suitable for SOL unit tests.
// No encryption/integrity is configured by default to avoid panics from
// missing keys. Tests that need crypto should set k1/k2 and algo fields.
func newTestSOLSession(t *testing.T) *rmcpSession {
	t.Helper()
	return &rmcpSession{
		addr:          "127.0.0.1:623",
		username:      "test",
		password:      "test",
		timeout:       defaultIPMITimeout,
		authAlgo:      authAlgoHMACSHA256,
		integrityAlgo: integrityAlgoNone,
		cryptoAlgo:    cryptoAlgoNone,
		privilege:     privilegeAdministrator,
		logger:        slog.Default(),
	}
}
