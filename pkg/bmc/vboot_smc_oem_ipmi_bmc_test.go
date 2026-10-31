package bmc

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"
)

func TestOpenRMCPSession_NoBMC(t *testing.T) {
	// Bind then release a UDP port so nothing answers the handshake.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatalf("close udp: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	config := &Config{Address: "127.0.0.1", Port: port, Protocol: ProtocolIPMI, Username: "ADMIN"}

	// rmcpSession logs unconditionally, so it needs a real logger.
	session, err := openRMCPSession(ctx, config, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("openRMCPSession succeeded with no BMC listening")
	}
	if session != nil {
		t.Fatalf("session = %v, want nil when the handshake fails", session)
	}
}
