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
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// debugLogSession returns a loopback session whose logger writes every
// record, Debug included, to the returned buffer.
func debugLogSession(t *testing.T) (*rmcpSession, *net.UDPConn, *bytes.Buffer) {
	t.Helper()
	s, listener := loopbackSession(t, 2*time.Second)
	var logs bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return s, listener, &logs
}

// TestSendRecv_ResponseBytesNeverReachTheLog: sendRecv carries the RAKP
// exchange, and RAKP message 2 holds an HMAC keyed by the BMC user's
// password, which is enough to recover the password offline. The received
// datagram is logged by length only, at every level.
func TestSendRecv_ResponseBytesNeverReachTheLog(t *testing.T) {
	s, listener, logs := debugLogSession(t)
	rakp2 := []byte("rakp2-key-exchange-auth-code-0123456789")

	served := make(chan error, 1)
	go func() {
		buf := make([]byte, maxUDPRecvSize)
		_, peer, err := listener.ReadFromUDP(buf)
		if err != nil {
			served <- err
			return
		}
		_, err = listener.WriteToUDP(rakp2, peer)
		served <- err
	}()

	resp, err := s.sendRecv([]byte{0x06, 0x00, 0xff, 0x07})
	if err != nil {
		t.Fatalf("sendRecv: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("loopback BMC: %v", err)
	}
	if !bytes.Equal(resp, rakp2) {
		t.Fatalf("sendRecv returned %x, want %x", resp, rakp2)
	}

	logged := logs.String()
	if !strings.Contains(logged, "bmc: recv") {
		t.Fatalf("the receive is no longer logged at all: %q", logged)
	}
	if strings.Contains(logged, hex.EncodeToString(rakp2)) || strings.Contains(logged, string(rakp2)) {
		t.Errorf("the received datagram reached the log: %q", logged)
	}
}

// TestSendRecv_ReadFailureLogsNothingAndIsTyped: a receive that times out
// returns ErrUDPRecv and writes no receive record.
func TestSendRecv_ReadFailureLogsNothingAndIsTyped(t *testing.T) {
	s, _, logs := debugLogSession(t)
	s.timeout = 50 * time.Millisecond

	_, err := s.sendRecv([]byte{0x06, 0x00, 0xff, 0x07})
	var recvErr ErrUDPRecv
	if !errors.As(err, &recvErr) {
		t.Fatalf("sendRecv with no responder: got %v, want ErrUDPRecv", err)
	}
	if strings.Contains(logs.String(), "bmc: recv") {
		t.Errorf("a failed receive was logged as received: %q", logs.String())
	}
}
