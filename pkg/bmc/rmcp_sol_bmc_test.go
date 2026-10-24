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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// solTestTimeout bounds every socket read in these tests. The receive loop
// re-polls on this interval, so Deactivate returns within one timeout.
const solTestTimeout = 250 * time.Millisecond

// solReadPayload reads one datagram the console sent and returns its
// unauthenticated payload plus the sender address.
func solReadPayload(t *testing.T, conn *net.UDPConn, payloadType byte) ([]byte, *net.UDPAddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxUDPRecvSize)
	n, from, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("fake BMC read: %v", err)
	}
	payload, err := extractUnauthPayload(buf[:n], payloadType)
	if err != nil {
		t.Fatalf("fake BMC parse: %v", err)
	}
	return append([]byte(nil), payload...), from
}

// solIPMIResponse builds an App netFn response the session's Send accepts:
// the command echo, a completion code and the response data.
func solIPMIResponse(cmd, completion byte, data []byte) []byte {
	msg := []byte{0x81, (netFnApp + 1) << 2, 0x00, 0x20, 0x00, cmd, completion}
	msg[2] = ipmiChecksum(msg[0:2])
	msg = append(msg, data...)
	msg = append(msg, ipmiChecksum(msg[3:]))
	return buildRMCPPlusUnauthPacket(payloadTypeIPMI, 0x12345678, 1, msg)
}

// solActivateData is an Activate Payload response body (IPMI 2.0 Table
// 24-3) advertising the given SOL UDP port.
func solActivateData(port uint16) []byte {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint16(data[4:6], 0x00C8)
	binary.LittleEndian.PutUint16(data[6:8], 0x00C8)
	binary.LittleEndian.PutUint16(data[8:10], port)
	binary.LittleEndian.PutUint16(data[10:12], 0xFFFF)
	return data
}

// solDataPacket is a BMC-to-console SOL packet carrying chars.
func solDataPacket(seq byte, chars []byte) []byte {
	payload := append([]byte{seq, 0x00, 0x00, 0x00}, chars...)
	return buildRMCPPlusUnauthPacket(payloadTypeSOL, 0x12345678, uint32(seq), payload)
}

// activateOverLoopback activates SOL on s, answering the Activate Payload
// request on listener with the given completion code and data.
func activateOverLoopback(t *testing.T, s *rmcpSession, listener *net.UDPConn, completion byte, data []byte) (*SOLSession, []byte, error) {
	t.Helper()
	type result struct {
		sol *SOLSession
		err error
	}
	done := make(chan result, 1)
	go func() {
		sol, err := s.ActivateSOL(context.Background(), 0)
		done <- result{sol, err}
	}()
	req, from := solReadPayload(t, listener, payloadTypeIPMI)
	if _, err := listener.WriteToUDP(solIPMIResponse(cmdActivatePayload, completion, data), from); err != nil {
		t.Fatal(err)
	}
	r := <-done
	return r.sol, req, r.err
}

// TestActivateSOL_FullConsoleExchange drives a whole console session against
// a loopback BMC: activation rebinds to the advertised SOL port, BMC data is
// ACKed and delivered, console writes and breaks carry the ACK state, and
// Deactivate releases the payload instance that was activated.
func TestActivateSOL_FullConsoleExchange(t *testing.T) {
	s, listener := loopbackSession(t, solTestTimeout)
	solPort, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { solPort.Close() })
	port := uint16(solPort.LocalAddr().(*net.UDPAddr).Port)

	sol, req, err := activateOverLoopback(t, s, listener, 0x00, solActivateData(port))
	if err != nil {
		t.Fatalf("ActivateSOL: %v", err)
	}
	t.Cleanup(func() { s.conn.Close() })

	// IPMI message: rsAddr, netFn, chk, rqAddr, rqSeq, cmd, data...
	wantReq := []byte{payloadTypeSOL, solPayloadInstanceDefault, solAuxHandshakeAssert | solAuxAlertDefer, 0, 0, 0}
	if req[5] != cmdActivatePayload || !bytes.Equal(req[6:12], wantReq) {
		t.Fatalf("activate request cmd=%#x data=%x, want cmd=%#x data=%x", req[5], req[6:12], cmdActivatePayload, wantReq)
	}
	if got := sol.PayloadInstance(); got != solPayloadInstanceDefault {
		t.Errorf("PayloadInstance() = %d, want %d", got, solPayloadInstanceDefault)
	}
	if got := s.conn.RemoteAddr().(*net.UDPAddr).Port; got != int(port) {
		t.Fatalf("session remote port = %d, want the advertised SOL port %d", got, port)
	}
	client := s.conn.LocalAddr().(*net.UDPAddr)
	send := func(packet []byte) {
		t.Helper()
		if _, err := solPort.WriteToUDP(packet, client); err != nil {
			t.Fatal(err)
		}
	}
	expectSOL := func(want []byte) {
		t.Helper()
		got, _ := solReadPayload(t, solPort, payloadTypeSOL)
		if !bytes.Equal(got, want) {
			t.Fatalf("console sent SOL payload %x, want %x", got, want)
		}
	}

	// BMC data: ACKed with its sequence number and character count, then
	// delivered to Read.
	send(solDataPacket(1, []byte("hi")))
	expectSOL([]byte{0x00, 0x01, 0x02, 0x00})
	buf := make([]byte, 16)
	n, err := sol.Read(buf)
	if err != nil || string(buf[:n]) != "hi" {
		t.Fatalf("Read = %q, %v; want \"hi\"", buf[:n], err)
	}
	if got := sol.BytesReceived(); got != 2 {
		t.Errorf("BytesReceived() = %d, want 2", got)
	}

	// Console data carries its own sequence and the last BMC ACK state.
	if n, err := sol.Write([]byte("ok")); err != nil || n != 2 {
		t.Fatalf("Write = %d, %v; want 2, nil", n, err)
	}
	expectSOL([]byte{0x01, 0x01, 0x02, 0x00, 'o', 'k'})
	if err := sol.SendBreak(); err != nil {
		t.Fatalf("SendBreak: %v", err)
	}
	expectSOL([]byte{0x02, 0x01, 0x02, 0x10})

	// Non-SOL and truncated packets are dropped; an ACK-only packet is
	// ACKed but produces no output; a sequence-0 packet is delivered
	// without an ACK.
	send(buildRMCPPlusUnauthPacket(payloadTypeIPMI, 0x12345678, 9, []byte{1, 2, 3, 4, 5}))
	send(buildRMCPPlusUnauthPacket(payloadTypeSOL, 0x12345678, 9, []byte{1, 2, 3}))
	send(solDataPacket(3, nil))
	expectSOL([]byte{0x00, 0x03, 0x00, 0x00})
	send(solDataPacket(0, []byte("z")))
	n, err = sol.Read(buf)
	if err != nil || string(buf[:n]) != "z" {
		t.Fatalf("Read = %q, %v; want \"z\" (dropped packets must not reach the output)", buf[:n], err)
	}

	deactivated := make(chan error, 1)
	go func() { deactivated <- sol.Close() }()
	req, from := solReadPayload(t, solPort, payloadTypeIPMI)
	if req[5] != cmdDeactivatePayload || req[6] != payloadTypeSOL || req[7] != solPayloadInstanceDefault {
		t.Fatalf("deactivate request cmd=%#x type=%#x instance=%#x", req[5], req[6], req[7])
	}
	if _, err := solPort.WriteToUDP(solIPMIResponse(cmdDeactivatePayload, 0x00, nil), from); err != nil {
		t.Fatal(err)
	}
	if err := <-deactivated; err != nil {
		t.Fatalf("Close: %v", err)
	}

	var closedErr ErrSOLSessionClosed
	if _, err := sol.Read(buf); !errors.As(err, &closedErr) {
		t.Errorf("Read after Close = %v, want ErrSOLSessionClosed", err)
	}
	if _, err := sol.Write([]byte("x")); !errors.As(err, &closedErr) {
		t.Errorf("Write after Close = %v, want ErrSOLSessionClosed", err)
	}
	if err := sol.SendBreak(); !errors.As(err, &closedErr) {
		t.Errorf("SendBreak after Close = %v, want ErrSOLSessionClosed", err)
	}
	if err := sol.Deactivate(context.Background()); err != nil {
		t.Errorf("second Deactivate = %v, want nil (idempotent)", err)
	}
}

// TestActivateSOL_PortZeroKeepsSessionSocket verifies a BMC that advertises
// no SOL port keeps the session on its RMCP+ socket.
func TestActivateSOL_PortZeroKeepsSessionSocket(t *testing.T) {
	s, listener := loopbackSession(t, solTestTimeout)
	original := s.conn
	sol, _, err := activateOverLoopback(t, s, listener, 0x00, solActivateData(0))
	if err != nil {
		t.Fatalf("ActivateSOL: %v", err)
	}
	if s.conn != original {
		t.Error("port 0 must not rebind the session socket")
	}
	// Mark the session closed so Deactivate skips the wire exchange.
	s.closed.Store(true)
	if err := sol.Deactivate(context.Background()); err != nil {
		t.Fatalf("Deactivate on a closed session: %v", err)
	}
}

func TestActivateSOL_Errors(t *testing.T) {
	tests := []struct {
		name       string
		completion byte
		data       []byte
		check      func(t *testing.T, cause error)
	}{
		{
			name:       "completion code",
			completion: 0xC1,
			check: func(t *testing.T, cause error) {
				var cc ErrCompletionCode
				if !errors.As(cause, &cc) || cc.Code != 0xC1 || cc.Command != cmdActivatePayload {
					t.Errorf("cause = %v, want ErrCompletionCode 0xC1 for Activate Payload", cause)
				}
			},
		},
		{
			name: "short response",
			data: []byte{0, 0, 0, 0},
			check: func(t *testing.T, cause error) {
				var short ErrPacketTooShort
				if !errors.As(cause, &short) || short.Expected != 12 || short.Actual != 4 {
					t.Errorf("cause = %v, want ErrPacketTooShort{12, 4}", cause)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, listener := loopbackSession(t, solTestTimeout)
			sol, _, err := activateOverLoopback(t, s, listener, tt.completion, tt.data)
			if sol != nil {
				t.Fatal("a failed activation must not return a session")
			}
			var activateErr ErrSOLActivateFailed
			if !errors.As(err, &activateErr) {
				t.Fatalf("err = %v, want ErrSOLActivateFailed", err)
			}
			if activateErr.Error() == "" || errors.Unwrap(activateErr) == nil {
				t.Error("ErrSOLActivateFailed must describe and wrap its cause")
			}
			tt.check(t, activateErr.Cause)
		})
	}
}

func TestSOLSession_DeactivateReportsBMCRefusal(t *testing.T) {
	s, listener := loopbackSession(t, solTestTimeout)
	released := 0
	sol := &SOLSession{
		session:         s,
		logger:          s.logger,
		output:          make(chan []byte, 1),
		done:            make(chan struct{}),
		payloadInstance: 0x02,
		release:         func() { released++ },
	}
	sol.active.Store(true)

	errc := make(chan error, 1)
	go func() { errc <- sol.Deactivate(context.Background()) }()
	req, from := solReadPayload(t, listener, payloadTypeIPMI)
	if req[7] != 0x02 {
		t.Errorf("deactivate instance = %d, want the activated instance 2", req[7])
	}
	if _, err := listener.WriteToUDP(solIPMIResponse(cmdDeactivatePayload, 0x80, nil), from); err != nil {
		t.Fatal(err)
	}
	err := <-errc
	var deactivateErr ErrSOLDeactivateFailed
	if !errors.As(err, &deactivateErr) {
		t.Fatalf("err = %v, want ErrSOLDeactivateFailed", err)
	}
	var cc ErrCompletionCode
	if !errors.As(err, &cc) || cc.Code != 0x80 {
		t.Errorf("cause = %v, want ErrCompletionCode 0x80", err)
	}
	if released != 1 {
		t.Errorf("release ran %d times, want 1 even when the BMC refuses", released)
	}
}

func TestSOLSession_WriteReportsSendFailure(t *testing.T) {
	s := newTestSOLSession(t) // no connection
	sol := &SOLSession{session: s, logger: s.logger}
	sol.active.Store(true)

	n, err := sol.Write([]byte("x"))
	var closed ErrSessionClosed
	if n != 0 || !errors.As(err, &closed) {
		t.Fatalf("Write = %d, %v; want 0, ErrSessionClosed", n, err)
	}
}

func TestSOLSession_ReadReturnsEOFWhenLoopEnds(t *testing.T) {
	sol := &SOLSession{output: make(chan []byte)}
	sol.active.Store(true)
	close(sol.output)

	if _, err := sol.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read = %v, want io.EOF", err)
	}
}

func TestRebindForSOL_Errors(t *testing.T) {
	t.Run("no connection", func(t *testing.T) {
		var closed ErrSessionClosed
		if err := newTestSOLSession(t).rebindForSOL(7000); !errors.As(err, &closed) {
			t.Fatalf("err = %v, want ErrSessionClosed", err)
		}
	})
	t.Run("non-UDP transport", func(t *testing.T) {
		s := newTestSOLSession(t)
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		s.conn = client
		var sendErr ErrUDPSend
		if err := s.rebindForSOL(7000); !errors.As(err, &sendErr) {
			t.Fatalf("err = %v, want ErrUDPSend", err)
		}
		if s.conn != client {
			t.Error("a failed rebind must leave the session socket in place")
		}
	})
}

func TestSendSOLMessage_Errors(t *testing.T) {
	t.Run("no connection", func(t *testing.T) {
		s := newTestSOLSession(t)
		var closed ErrSessionClosed
		if err := s.sendSOLMessage([]byte{0, 0, 0, 0}); !errors.As(err, &closed) {
			t.Fatalf("err = %v, want ErrSessionClosed", err)
		}
	})
	t.Run("session closed", func(t *testing.T) {
		s, _ := loopbackSession(t, solTestTimeout)
		s.closed.Store(true)
		var closed ErrSessionClosed
		if err := s.sendSOLMessage([]byte{0, 0, 0, 0}); !errors.As(err, &closed) {
			t.Fatalf("err = %v, want ErrSessionClosed", err)
		}
	})
	t.Run("socket closed", func(t *testing.T) {
		s, _ := loopbackSession(t, solTestTimeout)
		s.conn.Close()
		var sendErr ErrUDPSend
		if err := s.sendSOLMessage([]byte{0, 0, 0, 0}); !errors.As(err, &sendErr) {
			t.Fatalf("err = %v, want ErrUDPSend", err)
		}
	})
}

func TestReceiveSOLMessage_Errors(t *testing.T) {
	valid := solDataPacket(1, []byte("a"))
	badVersion := append([]byte(nil), valid...)
	badVersion[0] = 0x07
	overlong := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint16(overlong[14:16], 200)
	unsignedAuth := append([]byte(nil), valid...)
	unsignedAuth[5] |= 0x40
	shortCipher := append([]byte(nil), valid...)
	shortCipher[5] |= 0x80

	tests := []struct {
		name   string
		packet []byte
		setup  func(s *rmcpSession)
		check  func(err error) bool
	}{
		{"short packet", []byte{0x06, 0, 0, 0x07}, nil, func(err error) bool {
			var e ErrPacketTooShort
			return errors.As(err, &e) && e.Expected == 16 && e.Actual == 4
		}},
		{"bad RMCP header", badVersion, nil, func(err error) bool {
			var e ErrPacketTooShort
			return errors.As(err, &e)
		}},
		{"payload length past packet", overlong, nil, func(err error) bool {
			var e ErrPacketTooShort
			return errors.As(err, &e) && e.Expected == 216 && e.Actual == len(overlong)
		}},
		{"integrity failure", unsignedAuth, func(s *rmcpSession) {
			s.integrityAlgo = integrityAlgoHMACSHA1_96
			s.k1 = bytes.Repeat([]byte{0x11}, 20)
		}, func(err error) bool {
			var e ErrIntegrityCheckFailed
			return errors.As(err, &e)
		}},
		{"undecryptable payload", shortCipher, func(s *rmcpSession) {
			s.cryptoAlgo = cryptoAlgoAESCBC128
			s.k2 = bytes.Repeat([]byte{0x22}, 20)
		}, func(err error) bool {
			var e ErrDecryptFailed
			return errors.As(err, &e)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, listener := loopbackSession(t, solTestTimeout)
			if tt.setup != nil {
				tt.setup(s)
			}
			if _, err := listener.WriteToUDP(tt.packet, s.conn.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			_, _, err := s.receiveSOLMessage()
			if !tt.check(err) {
				t.Fatalf("receiveSOLMessage err = %v (%T)", err, err)
			}
		})
	}

	t.Run("no connection", func(t *testing.T) {
		var closed ErrSessionClosed
		if _, _, err := newTestSOLSession(t).receiveSOLMessage(); !errors.As(err, &closed) {
			t.Fatalf("err = %v, want ErrSessionClosed", err)
		}
	})
	t.Run("session closed", func(t *testing.T) {
		s, _ := loopbackSession(t, solTestTimeout)
		s.closed.Store(true)
		var closed ErrSessionClosed
		if _, _, err := s.receiveSOLMessage(); !errors.As(err, &closed) {
			t.Fatalf("err = %v, want ErrSessionClosed", err)
		}
	})
	t.Run("read timeout", func(t *testing.T) {
		s, _ := loopbackSession(t, 20*time.Millisecond)
		var recvErr ErrUDPRecv
		if _, _, err := s.receiveSOLMessage(); !errors.As(err, &recvErr) {
			t.Fatalf("err = %v, want ErrUDPRecv", err)
		}
	})
	t.Run("socket closed", func(t *testing.T) {
		s, _ := loopbackSession(t, solTestTimeout)
		s.conn.Close()
		var recvErr ErrUDPRecv
		if _, _, err := s.receiveSOLMessage(); !errors.As(err, &recvErr) {
			t.Fatalf("err = %v, want ErrUDPRecv", err)
		}
	})
}

// TestReceiveSOLMessage_AuthenticatedEncryptedRoundTrip proves a SOL packet
// wrapped with HMAC-SHA1-96 integrity and AES-CBC-128 confidentiality is
// verified and decrypted back to the original SOL bytes by a peer holding
// the same session keys.
func TestReceiveSOLMessage_AuthenticatedEncryptedRoundTrip(t *testing.T) {
	keyed := func(s *rmcpSession) {
		s.integrityAlgo = integrityAlgoHMACSHA1_96
		s.cryptoAlgo = cryptoAlgoAESCBC128
		s.k1 = bytes.Repeat([]byte{0x11}, 20)
		s.k2 = bytes.Repeat([]byte{0x22}, 20)
	}
	sender := newTestSOLSession(t)
	keyed(sender)
	receiver, listener := loopbackSession(t, solTestTimeout)
	keyed(receiver)

	solData := []byte{0x05, 0x00, 0x00, 0x00, 'b', 'o', 'o', 't'}
	packet, err := sender.wrapSOLPayload(solData)
	if err != nil {
		t.Fatalf("wrapSOLPayload: %v", err)
	}
	if bytes.Contains(packet, []byte("boot")) {
		t.Fatal("confidential SOL packet carries plaintext")
	}
	if _, err := listener.WriteToUDP(packet, receiver.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	payload, payloadType, err := receiver.receiveSOLMessage()
	if err != nil {
		t.Fatalf("receiveSOLMessage: %v", err)
	}
	if payloadType != payloadTypeSOL || !bytes.Equal(payload, solData) {
		t.Fatalf("got type %#x payload %x, want %#x %x", payloadType, payload, payloadTypeSOL, solData)
	}

	// The same packet with one flipped ciphertext byte fails integrity.
	packet[20] ^= 0xFF
	if _, err := listener.WriteToUDP(packet, receiver.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	var integrityErr ErrIntegrityCheckFailed
	if _, _, err := receiver.receiveSOLMessage(); !errors.As(err, &integrityErr) {
		t.Fatalf("tampered packet err = %v, want ErrIntegrityCheckFailed", err)
	}
}
