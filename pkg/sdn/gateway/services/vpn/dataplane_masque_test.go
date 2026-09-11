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

package vpn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

// fakeDevice is an in-memory PacketDevice: toDevice receives what the plane
// writes toward the host, fromDevice feeds packets the host sends back.
type fakeDevice struct {
	toDevice   chan []byte
	fromDevice chan []byte
	closed     chan struct{}
	writeErr   atomic.Pointer[error]
}

func (d *fakeDevice) failWrites(err error) { d.writeErr.Store(&err) }

func newFakeDevice() *fakeDevice {
	return &fakeDevice{
		toDevice:   make(chan []byte, 8),
		fromDevice: make(chan []byte, 8),
		closed:     make(chan struct{}),
	}
}

func (d *fakeDevice) Read(p []byte) (int, error) {
	select {
	case pkt := <-d.fromDevice:
		return copy(p, pkt), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *fakeDevice) Write(p []byte) (int, error) {
	if err := d.writeErr.Load(); err != nil {
		return 0, *err
	}
	select {
	case d.toDevice <- append([]byte(nil), p...):
		return len(p), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *fakeDevice) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

// testPKI is a throwaway CA with a server and client certificate, so the
// round trip runs over the mTLS the plane requires.
type testPKI struct {
	pool       *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vpn-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	issue := func(cn string, serial int64, usage x509.ExtKeyUsage, dns []string) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			DNSNames:     dns,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	}
	return &testPKI{
		pool:       pool,
		serverCert: issue("localhost", 2, x509.ExtKeyUsageServerAuth, []string{"localhost"}),
		clientCert: issue("mini-99", 3, x509.ExtKeyUsageClientAuth, nil),
	}
}

func (p *testPKI) serverTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{p.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.pool,
		MinVersion:   tls.VersionTLS13,
	}
}

func (p *testPKI) clientTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      p.pool,
		ServerName:   "localhost",
		NextProtos:   []string{http3.NextProtoH3},
		MinVersion:   tls.VersionTLS13,
	}
}

func fingerprint(cert tls.Certificate) []byte {
	sum := sha256.Sum256(cert.Certificate[0])
	return sum[:]
}

func masqueLease(id LeaseID, addr string, cert tls.Certificate) *Lease {
	return &Lease{
		ID: id, DeviceID: "mini-99", TenantID: "t1",
		Address:   netip.MustParsePrefix(addr),
		DataPlane: DataPlaneMASQUE,
		Keys:      PeerKeys{ClientCertificateSHA256: fingerprint(cert)},
	}
}

// masqueHarness is a started plane on a loopback socket with the template
// its own port implies.
type masqueHarness struct {
	plane *masquePlane
	dev   *fakeDevice
	pki   *testPKI
	tmpl  *uritemplate.Template
	addr  *net.UDPAddr
}

func newMASQUEHarness(t *testing.T, routes ...netip.Prefix) *masqueHarness {
	t.Helper()
	if len(routes) == 0 {
		routes = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	}
	pki := newTestPKI(t)
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	addr := sock.LocalAddr().(*net.UDPAddr)
	raw := fmt.Sprintf("https://localhost:%d/.well-known/masque/ip/", addr.Port)
	dev := newFakeDevice()
	plane, err := newMASQUEPlane(MASQUEConfig{
		Template: raw,
		TLS:      pki.serverTLS(),
		Routes:   routes,
	}, dev, nil, sock)
	require.NoError(t, err)
	require.NoError(t, plane.Start(context.Background()))
	t.Cleanup(func() { _ = plane.Stop(context.Background()) })
	return &masqueHarness{plane: plane, dev: dev, pki: pki, tmpl: uritemplate.MustNew(raw), addr: addr}
}

// dial opens a CONNECT-IP session as cert. It returns the client side of the
// session, or the error the server answered with.
func (h *masqueHarness) dial(t *testing.T, cert tls.Certificate) (*connectip.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = udp.Close() })
	qc, err := quic.Dial(ctx, udp, h.addr, h.pki.clientTLS(cert), &quic.Config{EnableDatagrams: true})
	if err != nil {
		return nil, err
	}
	tr := &http3.Transport{EnableDatagrams: true}
	t.Cleanup(func() { _ = tr.Close() })
	conn, _, err := connectip.Dial(ctx, tr.NewClientConn(qc), h.tmpl)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, nil
}

// ipv4Packet builds a minimal, well-formed IPv4 packet with a TTL the
// CONNECT-IP encapsulation can decrement.
func ipv4Packet(src, dst string, payload ...byte) []byte {
	pkt := make([]byte, 20, 20+len(payload))
	pkt[0] = 0x45
	total := 20 + len(payload)
	pkt[2], pkt[3] = byte(total>>8), byte(total)
	pkt[8] = 64 // TTL
	pkt[9] = 253
	copy(pkt[12:16], netip.MustParseAddr(src).AsSlice())
	copy(pkt[16:20], netip.MustParseAddr(dst).AsSlice())
	return append(pkt, payload...)
}

func TestMASQUEPlane_RoundTrip(t *testing.T) {
	h := newMASQUEHarness(t, netip.MustParsePrefix("192.168.1.0/24"))
	lease := masqueLease("l1", "10.9.0.23/32", h.pki.clientCert)
	require.NoError(t, h.plane.InstallPeer(context.Background(), lease))

	client, err := h.dial(t, h.pki.clientCert)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The plane assigns exactly the lease address and advertises the
	// configured routes as RFC 9484 address ranges.
	prefixes, err := client.LocalPrefixes(ctx)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.9.0.23/32")}, prefixes)
	routes, err := client.Routes(ctx)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	assert.Equal(t, "192.168.1.0", routes[0].StartIP.String())
	assert.Equal(t, "192.168.1.255", routes[0].EndIP.String())

	// Client → device.
	_, err = client.WritePacket(ipv4Packet("10.9.0.23", "192.168.1.5", 0xAA))
	require.NoError(t, err)
	select {
	case got := <-h.dev.toDevice:
		src, dst, ok := packetAddresses(got)
		require.True(t, ok)
		assert.Equal(t, "10.9.0.23", src.String())
		assert.Equal(t, "192.168.1.5", dst.String())
		assert.Equal(t, byte(0xAA), got[len(got)-1])
	case <-ctx.Done():
		t.Fatal("packet never reached the device")
	}

	// Device → client, routed by destination address.
	h.dev.fromDevice <- ipv4Packet("192.168.1.5", "10.9.0.23", 0xBB)
	buf := make([]byte, 1500)
	n, err := client.ReadPacket(buf)
	require.NoError(t, err)
	src, dst, ok := packetAddresses(buf[:n])
	require.True(t, ok)
	assert.Equal(t, "192.168.1.5", src.String())
	assert.Equal(t, "10.9.0.23", dst.String())
	assert.Equal(t, byte(0xBB), buf[n-1])
}

func TestMASQUEPlane_RefusesSessionWithoutALease(t *testing.T) {
	h := newMASQUEHarness(t)
	// No lease installed at all: the certificate is valid, the session is
	// still refused.
	_, err := h.dial(t, h.pki.clientCert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")

	// A lease for a different certificate does not admit this one.
	other := newTestPKI(t)
	require.NoError(t, h.plane.InstallPeer(context.Background(), masqueLease("l1", "10.9.0.23/32", other.clientCert)))
	_, err = h.dial(t, h.pki.clientCert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestMASQUEPlane_DropsSpoofedSourceAddress(t *testing.T) {
	h := newMASQUEHarness(t)
	require.NoError(t, h.plane.InstallPeer(context.Background(), masqueLease("l1", "10.9.0.23/32", h.pki.clientCert)))
	client, err := h.dial(t, h.pki.clientCert)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.LocalPrefixes(ctx)
	require.NoError(t, err)

	// Sourced from an address this lease does not hold: dropped before it
	// reaches the host, and the session survives to carry the next
	// legitimate packet.
	_, err = client.WritePacket(ipv4Packet("10.9.0.99", "192.168.1.5", 0xAA))
	require.NoError(t, err)
	_, err = client.WritePacket(ipv4Packet("10.9.0.23", "192.168.1.5", 0xBB))
	require.NoError(t, err)
	select {
	case got := <-h.dev.toDevice:
		assert.Equal(t, byte(0xBB), got[len(got)-1], "the spoofed packet was forwarded")
	case <-ctx.Done():
		t.Fatal("no packet reached the device")
	}
}

func TestMASQUEPlane_RemovePeerClosesTheSession(t *testing.T) {
	h := newMASQUEHarness(t)
	require.NoError(t, h.plane.InstallPeer(context.Background(), masqueLease("l1", "10.9.0.23/32", h.pki.clientCert)))
	client, err := h.dial(t, h.pki.clientCert)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.LocalPrefixes(ctx)
	require.NoError(t, err)

	require.NoError(t, h.plane.RemovePeer(context.Background(), "l1"))
	buf := make([]byte, 1500)
	_, err = client.ReadPacket(buf)
	require.Error(t, err, "the client's session must end when the lease is revoked")

	// A packet for the revoked address now goes nowhere, and the plane
	// keeps running.
	h.dev.fromDevice <- ipv4Packet("192.168.1.5", "10.9.0.23", 0xBB)
	require.NoError(t, h.plane.RemovePeer(context.Background(), "l1"))
}

func TestMASQUEPlane_ReconnectReplacesTheSession(t *testing.T) {
	h := newMASQUEHarness(t)
	require.NoError(t, h.plane.InstallPeer(context.Background(), masqueLease("l1", "10.9.0.23/32", h.pki.clientCert)))
	first, err := h.dial(t, h.pki.clientCert)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = first.LocalPrefixes(ctx)
	require.NoError(t, err)

	second, err := h.dial(t, h.pki.clientCert)
	require.NoError(t, err)
	_, err = second.LocalPrefixes(ctx)
	require.NoError(t, err)

	buf := make([]byte, 1500)
	_, err = first.ReadPacket(buf)
	require.Error(t, err, "the first session must be closed when the client reconnects")

	h.dev.fromDevice <- ipv4Packet("192.168.1.5", "10.9.0.23", 0xCC)
	n, err := second.ReadPacket(buf)
	require.NoError(t, err)
	assert.Equal(t, byte(0xCC), buf[n-1])
}

func TestMASQUEPlane_InstallRefusals(t *testing.T) {
	h := newMASQUEHarness(t)
	ctx := context.Background()
	var keyErr *ErrPeerKeyInvalid
	var reqErr *ErrInvalidRequest
	var conflict *ErrPeerConflict

	assert.True(t, errors.As(h.plane.InstallPeer(ctx, nil), &reqErr))
	assert.True(t, errors.As(h.plane.InstallPeer(ctx, &Lease{ID: "l1", Address: netip.MustParsePrefix("10.9.0.23/32")}), &keyErr),
		"a lease with no client fingerprint cannot be bound")
	bad := masqueLease("l1", "10.9.0.0/24", h.pki.clientCert)
	assert.True(t, errors.As(h.plane.InstallPeer(ctx, bad), &keyErr), "a lease must be a single host address")

	require.NoError(t, h.plane.InstallPeer(ctx, masqueLease("l1", "10.9.0.23/32", h.pki.clientCert)))
	// Same certificate, different lease id.
	assert.True(t, errors.As(h.plane.InstallPeer(ctx, masqueLease("l2", "10.9.0.24/32", h.pki.clientCert)), &conflict))
	// Same address, different certificate.
	other := newTestPKI(t)
	assert.True(t, errors.As(h.plane.InstallPeer(ctx, masqueLease("l3", "10.9.0.23/32", other.clientCert)), &conflict))
	// Re-installing the same lease id is a replacement, not a conflict.
	require.NoError(t, h.plane.InstallPeer(ctx, masqueLease("l1", "10.9.0.25/32", h.pki.clientCert)))
	require.NoError(t, h.plane.InstallPeer(ctx, masqueLease("l3", "10.9.0.23/32", other.clientCert)),
		"the replaced lease must release its address")
}

func TestMASQUEPlane_Lifecycle(t *testing.T) {
	pki := newTestPKI(t)
	dev := newFakeDevice()
	plane, err := newMASQUEPlane(MASQUEConfig{
		BindHost: "127.0.0.1",
		Template: "https://localhost:14433/.well-known/masque/ip/",
		TLS:      pki.serverTLS(),
		Routes:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}, dev, nil, nil)
	require.NoError(t, err)
	ctx := context.Background()

	var notStarted *ErrDataPlaneNotStarted
	assert.True(t, errors.As(plane.InstallPeer(ctx, masqueLease("l1", "10.9.0.23/32", pki.clientCert)), &notStarted))
	assert.Nil(t, plane.LocalAddr())

	require.NoError(t, plane.Start(ctx))
	require.NoError(t, plane.Start(ctx), "Start is idempotent")
	require.NotNil(t, plane.LocalAddr())
	require.NoError(t, plane.InstallPeer(ctx, masqueLease("l1", "10.9.0.23/32", pki.clientCert)))

	require.NoError(t, plane.Stop(ctx))
	require.NoError(t, plane.Stop(ctx), "Stop is idempotent")
	require.NoError(t, plane.RemovePeer(ctx, "l1"))
}

func TestMASQUEConfig_Validate(t *testing.T) {
	pki := newTestPKI(t)
	valid := MASQUEConfig{
		Template: "https://localhost:4433/.well-known/masque/ip/",
		TLS:      pki.serverTLS(),
		Routes:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}
	dev := newFakeDevice()

	cases := map[string]struct {
		mutate func(*MASQUEConfig)
		field  string
	}{
		"no template": {func(c *MASQUEConfig) { c.Template = "" }, "masque.template"},
		"no tls":      {func(c *MASQUEConfig) { c.TLS = nil }, "masque.tls"},
		"no certificate": {func(c *MASQUEConfig) {
			c.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13}
		}, "masque.tls"},
		"no client auth": {func(c *MASQUEConfig) {
			c.TLS = &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS13}
		}, "masque.tls"},
		"port out of range": {func(c *MASQUEConfig) { c.Port = 70000 }, "masque.port"},
		"invalid route":     {func(c *MASQUEConfig) { c.Routes = []netip.Prefix{{}} }, "masque.routes"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			cfg.TLS = pki.serverTLS()
			tc.mutate(&cfg)
			_, err := newMASQUEPlane(cfg, dev, nil, nil)
			var invalid *ErrInvalidConfig
			require.True(t, errors.As(err, &invalid), "err = %v", err)
			assert.Equal(t, tc.field, invalid.Field)
		})
	}

	t.Run("template without a path", func(t *testing.T) {
		cfg := valid
		cfg.Template = "https://localhost:4433"
		_, err := newMASQUEPlane(cfg, dev, nil, nil)
		var invalid *ErrInvalidConfig
		require.True(t, errors.As(err, &invalid))
		assert.Equal(t, "masque.template", invalid.Field)
	})
	t.Run("template that is not a URI template", func(t *testing.T) {
		cfg := valid
		cfg.Template = "https://localhost:4433/{unclosed"
		_, err := newMASQUEPlane(cfg, dev, nil, nil)
		var invalid *ErrInvalidConfig
		require.True(t, errors.As(err, &invalid))
	})
	t.Run("no device", func(t *testing.T) {
		_, err := NewMASQUEPlane(valid, nil, nil)
		var missing *ErrDepsMissing
		assert.True(t, errors.As(err, &missing))
	})
	t.Run("bind failure is reported", func(t *testing.T) {
		cfg := valid
		cfg.BindHost = "no-such-host.invalid"
		plane, err := newMASQUEPlane(cfg, newFakeDevice(), nil, nil)
		require.NoError(t, err)
		var unavailable *ErrDataPlaneUnavailable
		assert.True(t, errors.As(plane.Start(context.Background()), &unavailable))
	})
}

func TestMASQUEPlane_KindIsOfferedInEveryBuild(t *testing.T) {
	assert.True(t, DataPlaneMASQUE.Known())
	h := newMASQUEHarness(t)
	assert.Equal(t, DataPlaneMASQUE, h.plane.Kind())
}

func TestMASQUEPlane_RefusesARequestThatIsNotConnectIP(t *testing.T) {
	h := newMASQUEHarness(t)
	tr := &http3.Transport{TLSClientConfig: h.pki.clientTLS(h.pki.clientCert), EnableDatagrams: true}
	defer tr.Close()
	client := &http.Client{Transport: tr}
	rsp, err := client.Get(fmt.Sprintf("https://localhost:%d/.well-known/masque/ip/", h.addr.Port))
	require.NoError(t, err)
	defer rsp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, rsp.StatusCode,
		"a plain request on the CONNECT-IP route must be refused, not proxied")
}

func TestMASQUEPlane_DeviceWriteFailureEndsTheSession(t *testing.T) {
	h := newMASQUEHarness(t)
	require.NoError(t, h.plane.InstallPeer(context.Background(), masqueLease("l1", "10.9.0.23/32", h.pki.clientCert)))
	client, err := h.dial(t, h.pki.clientCert)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.LocalPrefixes(ctx)
	require.NoError(t, err)

	h.dev.failWrites(errors.New("device gone"))
	_, err = client.WritePacket(ipv4Packet("10.9.0.23", "192.168.1.5", 0xAA))
	require.NoError(t, err)

	buf := make([]byte, 1500)
	_, err = client.ReadPacket(buf)
	require.Error(t, err, "the session must end when the host device cannot be written to")
}

func TestMASQUEPlane_DropsDeviceTrafficWithNoSession(t *testing.T) {
	h := newMASQUEHarness(t)
	require.NoError(t, h.plane.InstallPeer(context.Background(), masqueLease("l1", "10.9.0.23/32", h.pki.clientCert)))
	client, err := h.dial(t, h.pki.clientCert)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.LocalPrefixes(ctx)
	require.NoError(t, err)

	// Neither of these can be delivered: one does not parse, the other is
	// addressed to no lease. Both are dropped and the plane keeps running.
	h.dev.fromDevice <- []byte{0x00, 0x01}
	h.dev.fromDevice <- ipv4Packet("192.168.1.5", "10.9.0.99", 0xAA)
	h.dev.fromDevice <- ipv4Packet("192.168.1.5", "10.9.0.23", 0xBB)

	buf := make([]byte, 1500)
	n, err := client.ReadPacket(buf)
	require.NoError(t, err)
	assert.Equal(t, byte(0xBB), buf[n-1], "an undeliverable packet must not be forwarded to another session")
}

func TestMASQUEPlane_StopIsTerminal(t *testing.T) {
	h := newMASQUEHarness(t)
	require.NoError(t, h.plane.Stop(context.Background()))
	var unavailable *ErrDataPlaneUnavailable
	err := h.plane.Start(context.Background())
	require.True(t, errors.As(err, &unavailable),
		"a stopped plane must refuse to restart: its host device cannot be reopened")
	assert.Contains(t, err.Error(), "cannot be restarted")
}
