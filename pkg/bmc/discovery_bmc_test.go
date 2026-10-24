package bmc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// rmcpResponder answers RMCP presence pings on a loopback UDP socket with
// the given reply and points ipmiProbePort at it for the test. The ping
// it received is delivered on the returned channel.
func rmcpResponder(t *testing.T, reply []byte) <-chan []byte {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("split %s: %v", conn.LocalAddr(), err)
	}
	saved := ipmiProbePort
	ipmiProbePort = port
	t.Cleanup(func() { ipmiProbePort = saved })

	pings := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			close(pings)
			return
		}
		pings <- append([]byte(nil), buf[:n]...)
		if _, err := conn.WriteTo(reply, peer); err != nil {
			return
		}
	}()
	return pings
}

// closedTCPPort returns a loopback port nothing listens on, so a dial is
// refused at once instead of timing out.
func closedTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

func setRedfishProbePort(t *testing.T, port int) {
	t.Helper()
	saved := redfishProbePort
	redfishProbePort = port
	t.Cleanup(func() { redfishProbePort = saved })
}

func serverPort(t *testing.T, server *httptest.Server) int {
	t.Helper()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split %s: %v", server.Listener.Addr(), err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q: %v", port, err)
	}
	return n
}

// asfPong is an ASF Presence Pong (message type 0x40) as a BMC sends it.
var asfPong = []byte{0x06, 0x00, 0xFF, 0x06, 0x00, 0x00, 0x11, 0xBE, 0x40, 0x00, 0x00, 0x10}

func TestProbeIPMI_PresencePong(t *testing.T) {
	pings := rmcpResponder(t, asfPong)

	if !probeIPMI(context.Background(), "127.0.0.1", time.Second) {
		t.Fatal("probeIPMI = false, want true for a BMC answering the presence ping")
	}
	ping := <-pings
	if len(ping) != 12 || ping[3] != 0x06 || ping[8] != 0x80 {
		t.Fatalf("ping = % x, want an ASF Presence Ping (class 0x06, type 0x80)", ping)
	}
}

func TestProbeIPMI_EmptyReply(t *testing.T) {
	rmcpResponder(t, []byte{})

	if probeIPMI(context.Background(), "127.0.0.1", time.Second) {
		t.Fatal("probeIPMI = true, want false for a zero-length datagram")
	}
}

func TestProbeIPMI_DialFails(t *testing.T) {
	saved := ipmiProbePort
	ipmiProbePort = "99999"
	t.Cleanup(func() { ipmiProbePort = saved })

	if probeIPMI(context.Background(), "127.0.0.1", 100*time.Millisecond) {
		t.Fatal("probeIPMI = true, want false when the dial fails")
	}
}

func TestDetectProtocol_IPMIOnly(t *testing.T) {
	setRedfishProbePort(t, closedTCPPort(t))
	rmcpResponder(t, asfPong)

	if got := DetectProtocol(context.Background(), "127.0.0.1", time.Second); got != ProtocolIPMI {
		t.Fatalf("DetectProtocol = %q, want %q", got, ProtocolIPMI)
	}
}

func TestDetectProtocol_RedfishUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	setRedfishProbePort(t, serverPort(t, server))

	// The httptest certificate does not chain to the system roots: the
	// failed verification still proves a TLS service answered.
	if got := DetectProtocol(context.Background(), "127.0.0.1", time.Second); got != ProtocolRedfish {
		t.Fatalf("DetectProtocol = %q, want %q", got, ProtocolRedfish)
	}
}

func TestProbeRedfish_NotRedfish(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(plain.Close)

	tests := []struct {
		name    string
		address string
		port    int
	}{
		// A plain-HTTP listener fails the handshake with an error that
		// is not a certificate verification failure.
		{"plain HTTP listener", "127.0.0.1", serverPort(t, plain)},
		{"address that is not a host", "bad host", 443},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRedfishProbePort(t, tt.port)
			if probeRedfish(context.Background(), tt.address, time.Second) {
				t.Fatal("probeRedfish = true, want false")
			}
		})
	}
}

func TestIsCertVerificationError(t *testing.T) {
	leaf := &x509.Certificate{}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"tls verification error", &tls.CertificateVerificationError{Err: errors.New("bad chain")}, true},
		{"unknown authority", x509.UnknownAuthorityError{Cert: leaf}, true},
		{"hostname mismatch", x509.HostnameError{Certificate: leaf, Host: "bmc"}, true},
		{"expired certificate", x509.CertificateInvalidError{Cert: leaf, Reason: x509.Expired}, true},
		{"wrapped hostname mismatch", fmt.Errorf("dial: %w", x509.HostnameError{Certificate: leaf, Host: "bmc"}), true},
		{"connection refused", errors.New("connection refused"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCertVerificationError(tt.err); got != tt.want {
				t.Fatalf("isCertVerificationError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
