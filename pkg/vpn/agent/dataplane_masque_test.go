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

package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// packetWait bounds how long a test waits for a packet to cross the loopback
// session; it is a failure deadline, never a pause.
const packetWait = 10 * time.Second

// fakePackets is a packet device in memory: what the host sends is read from
// fromHost, what the device delivers lands on toHost. It stands in for the
// client TUN and for the gateway's device.
type fakePackets struct {
	fromHost chan []byte
	toHost   chan []byte
	closed   chan struct{}
	once     sync.Once
}

func newFakePackets() *fakePackets {
	return &fakePackets{fromHost: make(chan []byte, 8), toHost: make(chan []byte, 8), closed: make(chan struct{})}
}

func (d *fakePackets) Read(p []byte) (int, error) {
	select {
	case pkt := <-d.fromHost:
		return copy(p, pkt), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *fakePackets) Write(p []byte) (int, error) {
	select {
	case d.toHost <- append([]byte(nil), p...):
		return len(p), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *fakePackets) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func (d *fakePackets) isClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

func receive(t *testing.T, packets <-chan []byte) []byte {
	t.Helper()
	select {
	case pkt := <-packets:
		return pkt
	case <-time.After(packetWait):
		t.Fatal("no packet crossed the session")
		return nil
	}
}

func ipv4Packet(src, dst string) []byte {
	pkt := make([]byte, 24)
	pkt[0] = 0x45
	pkt[3] = byte(len(pkt))
	pkt[8] = 64 // TTL
	pkt[9] = 253
	copy(pkt[12:16], netip.MustParseAddr(src).AsSlice())
	copy(pkt[16:20], netip.MustParseAddr(dst).AsSlice())
	copy(pkt[20:], "ping")
	return pkt
}

// assertForwarded checks got is sent after one hop: the same addresses and
// payload, the TTL one hop lower (connect-ip-go decrements it and rewrites
// the header checksum).
func assertForwarded(t *testing.T, sent, got []byte) {
	t.Helper()
	require.Len(t, got, len(sent))
	assert.Equal(t, sent[12:], got[12:], "addresses and payload")
	assert.Equal(t, sent[8]-1, got[8], "TTL")
}

// masqueGateway is the gateway's own MASQUE plane on loopback, the far end
// of every session these tests open.
type masqueGateway struct {
	plane    gwvpn.ManagedDataPlane
	dev      *fakePackets
	roots    *x509.CertPool
	template string
	client   tls.Certificate
}

func newMASQUEGateway(t *testing.T) *masqueGateway {
	t.Helper()
	server := selfSignedCertificate(t, "localhost", x509.ExtKeyUsageServerAuth, "localhost")
	client := deviceCertificate(t, "mini-99")
	roots := x509.NewCertPool()
	roots.AddCert(server.Leaf)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(client.Leaf)

	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := sock.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, sock.Close())

	template := fmt.Sprintf("https://localhost:%d/.well-known/masque/ip/", port)
	dev := newFakePackets()
	plane, err := gwvpn.NewMASQUEPlane(gwvpn.MASQUEConfig{
		BindHost: "127.0.0.1",
		Port:     port,
		Template: template,
		TLS: &tls.Config{
			Certificates: []tls.Certificate{server},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
			MinVersion:   tls.VersionTLS13,
		},
		Routes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
	}, dev, nil)
	require.NoError(t, err)
	require.NoError(t, plane.Start(context.Background()))
	t.Cleanup(func() { assert.NoError(t, plane.Stop(context.Background())) })
	return &masqueGateway{plane: plane, dev: dev, roots: roots, template: template, client: client}
}

// admit installs the lease the gateway would have admitted the client under.
func (g *masqueGateway) admit(t *testing.T, address string) {
	t.Helper()
	sum := sha256.Sum256(g.client.Certificate[0])
	require.NoError(t, g.plane.InstallPeer(context.Background(), &gwvpn.Lease{
		ID:        "l-1",
		DeviceID:  "mini-99",
		TenantID:  "t1",
		Address:   netip.MustParsePrefix(address),
		DataPlane: gwvpn.DataPlaneMASQUE,
		Keys:      gwvpn.PeerKeys{ClientCertificateSHA256: sum[:]},
	}))
}

func (g *masqueGateway) lease() *gwvpn.LeaseWire {
	return &gwvpn.LeaseWire{
		ID:        "l-1",
		Address:   "10.8.0.2/32",
		DataPlane: gwvpn.DataPlaneMASQUE,
		Endpoint: gwvpn.EndpointWire{MASQUE: &gwvpn.MASQUEEndpointWire{
			Template: g.template,
			Routes:   []string{"10.20.0.0/16"},
		}},
	}
}

// fakeTUNs opens a fakePackets for every TUN the plane asks for, and records
// the configuration it asked with.
type fakeTUNs struct {
	err     error
	configs []tunnel.TUNConfig
	devs    []*fakePackets
}

func (f *fakeTUNs) open(cfg tunnel.TUNConfig) (packetDevice, error) {
	f.configs = append(f.configs, cfg)
	if f.err != nil {
		return nil, f.err
	}
	dev := newFakePackets()
	f.devs = append(f.devs, dev)
	return dev, nil
}

func (g *masqueGateway) clientPlane(t *testing.T) (*masquePlane, *fakeTUNs) {
	t.Helper()
	tuns := &fakeTUNs{}
	plane := newMASQUEPlane(func() (tls.Certificate, error) { return g.client, nil }, g.roots, tuns.open, nil)
	t.Cleanup(func() { assert.NoError(t, plane.Down(context.Background(), Session{})) })
	return plane, tuns
}

func TestMASQUEPlane_CarriesPacketsBetweenTheTUNAndTheGateway(t *testing.T) {
	gw := newMASQUEGateway(t)
	gw.admit(t, "10.8.0.2/32")
	plane, tuns := gw.clientPlane(t)

	session, err := plane.Up(context.Background(), gw.lease())

	require.NoError(t, err)
	assert.Equal(t, Session{Interface: "vpn-masque0"}, session)
	require.Len(t, tuns.configs, 1)
	assert.Equal(t, tunnel.TUNConfig{
		Name:      "vpn-masque0",
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")},
		Routes:    []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
	}, tuns.configs[0])
	tun := tuns.devs[0]

	out := ipv4Packet("10.8.0.2", "10.20.0.5")
	tun.fromHost <- out
	assertForwarded(t, out, receive(t, gw.dev.toHost))

	in := ipv4Packet("10.20.0.5", "10.8.0.2")
	gw.dev.fromHost <- in
	assertForwarded(t, in, receive(t, tun.toHost))

	require.NoError(t, plane.Down(context.Background(), session))
	assert.True(t, tun.isClosed(), "Down closes the TUN")
	assert.Nil(t, plane.active.Load())
	assert.NoError(t, plane.Down(context.Background(), session), "a second Down finds nothing")
}

func TestMASQUEPlane_TheGatewayEndingTheSessionClosesTheTUN(t *testing.T) {
	gw := newMASQUEGateway(t)
	gw.admit(t, "10.8.0.2/32")
	plane, tuns := gw.clientPlane(t)
	_, err := plane.Up(context.Background(), gw.lease())
	require.NoError(t, err)

	require.NoError(t, gw.plane.RemovePeer(context.Background(), "l-1"))

	select {
	case <-tuns.devs[0].closed:
	case <-time.After(packetWait):
		t.Fatal("the TUN outlived the session")
	}
	assert.NoError(t, plane.Down(context.Background(), Session{Interface: MASQUEInterface}))
}

func TestMASQUEPlane_ASessionTheGatewayRefusesLeavesNothingBehind(t *testing.T) {
	gw := newMASQUEGateway(t)
	plane, tuns := gw.clientPlane(t)

	_, err := plane.Up(context.Background(), gw.lease())

	var refused *ErrSessionRefused
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, 403, refused.Status)
	assert.Empty(t, tuns.configs, "no TUN for a refused session")
	assert.Nil(t, plane.active.Load())
}

func TestMASQUEPlane_RefusesAnAddressTheGatewayDidNotAssign(t *testing.T) {
	gw := newMASQUEGateway(t)
	gw.admit(t, "10.8.0.9/32")
	plane, tuns := gw.clientPlane(t)

	_, err := plane.Up(context.Background(), gw.lease())

	var notAssigned *ErrAddressNotAssigned
	require.ErrorAs(t, err, &notAssigned)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.8.0.9/32")}, notAssigned.Assigned)
	assert.Empty(t, tuns.configs)
	assert.Nil(t, plane.active.Load())
}

func TestMASQUEPlane_AGatewayOutsideTheRootsIsUnreachable(t *testing.T) {
	gw := newMASQUEGateway(t)
	gw.admit(t, "10.8.0.2/32")
	gw.roots = x509.NewCertPool()
	plane, tuns := gw.clientPlane(t)

	_, err := plane.Up(context.Background(), gw.lease())

	var unreachable *ErrGatewayUnreachable
	require.ErrorAs(t, err, &unreachable)
	assert.Equal(t, gw.template[len("https://"):len(gw.template)-len("/.well-known/masque/ip/")], unreachable.Gateway)
	assert.Empty(t, tuns.configs)
}

func TestMASQUEPlane_ATUNThatFailsClosesTheSession(t *testing.T) {
	gw := newMASQUEGateway(t)
	gw.admit(t, "10.8.0.2/32")
	plane, tuns := gw.clientPlane(t)
	tuns.err = &tunnel.ErrTunnelCreateFailed{Name: MASQUEInterface, Cause: &errFake{"link add"}}

	_, err := plane.Up(context.Background(), gw.lease())

	assert.ErrorIs(t, err, tuns.err)
	assert.Nil(t, plane.active.Load())

	tuns.err = nil
	_, err = plane.Up(context.Background(), gw.lease())
	assert.NoError(t, err, "nothing is left behind to stop the next session")
}

func TestMASQUEPlane_UpWhileConnectedIsRefused(t *testing.T) {
	gw := newMASQUEGateway(t)
	gw.admit(t, "10.8.0.2/32")
	plane, tuns := gw.clientPlane(t)
	_, err := plane.Up(context.Background(), gw.lease())
	require.NoError(t, err)

	_, err = plane.Up(context.Background(), gw.lease())

	var already *ErrAlreadyConnected
	require.ErrorAs(t, err, &already)
	assert.Len(t, tuns.configs, 1, "the second Up dials nothing")
	assert.False(t, tuns.devs[0].isClosed(), "the first tunnel is untouched")
}

func TestMASQUEPlane_UpReportsACertificateItCannotLoad(t *testing.T) {
	noCert := &ErrNoCertificate{}
	tuns := &fakeTUNs{}
	plane := newMASQUEPlane(func() (tls.Certificate, error) { return tls.Certificate{}, noCert }, nil, tuns.open, nil)
	lease := (&masqueGateway{template: "https://gw.example/.well-known/masque/ip/"}).lease()

	_, err := plane.Up(context.Background(), lease)

	assert.ErrorIs(t, err, noCert)
	assert.Empty(t, tuns.configs)
}

func TestMASQUEPlane_UpRefusesALeaseItCannotUse(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(l *gwvpn.LeaseWire)
	}{
		{"no endpoint", func(l *gwvpn.LeaseWire) { l.Endpoint.MASQUE = nil }},
		{"template not a template", func(l *gwvpn.LeaseWire) { l.Endpoint.MASQUE.Template = "https://gw.example/{" }},
		{"template with variables", func(l *gwvpn.LeaseWire) { l.Endpoint.MASQUE.Template = "https://gw.example/ip/{target}/" }},
		{"template not a URL", func(l *gwvpn.LeaseWire) { l.Endpoint.MASQUE.Template = "https://gw.example:port/ip/" }},
		{"template not https", func(l *gwvpn.LeaseWire) { l.Endpoint.MASQUE.Template = "http://gw.example/ip/" }},
		{"template without a host", func(l *gwvpn.LeaseWire) { l.Endpoint.MASQUE.Template = "https:///ip/" }},
		{"address not a prefix", func(l *gwvpn.LeaseWire) { l.Address = "10.8.0.2" }},
		{"no routes", func(l *gwvpn.LeaseWire) { l.Endpoint.MASQUE.Routes = nil }},
		{"route not a prefix", func(l *gwvpn.LeaseWire) { l.Endpoint.MASQUE.Routes = []string{"zone-b"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialled := false
			plane := newMASQUEPlane(func() (tls.Certificate, error) {
				dialled = true
				return tls.Certificate{}, nil
			}, nil, (&fakeTUNs{}).open, nil)
			lease := (&masqueGateway{template: "https://gw.example/.well-known/masque/ip/"}).lease()
			tt.mutate(lease)

			_, err := plane.Up(context.Background(), lease)

			var unusable *ErrLeaseUnusable
			require.ErrorAs(t, err, &unusable)
			assert.Equal(t, gwvpn.DataPlaneMASQUE, unusable.Kind)
			assert.False(t, dialled, "a lease is checked before anything is dialled")
		})
	}
}

func TestMASQUEEndpointOf_DefaultsToTheHTTPSPort(t *testing.T) {
	lease := (&masqueGateway{template: "https://gw.example/.well-known/masque/ip/"}).lease()

	ep, err := masqueEndpointOf(lease)

	require.NoError(t, err)
	assert.Equal(t, "gw.example:443", ep.authority)
	assert.Equal(t, "gw.example", ep.serverName)
}

func TestMASQUEPlane_PrepareCarriesNoKey(t *testing.T) {
	plane := NewMASQUEPlane(func() (tls.Certificate, error) { return tls.Certificate{}, nil }, nil, nil)

	peer, err := plane.Prepare(context.Background())

	require.NoError(t, err)
	assert.Equal(t, gwvpn.PeerWire{}, peer)
	assert.Equal(t, gwvpn.DataPlaneMASQUE, plane.Kind())
	assert.NoError(t, plane.Down(context.Background(), Session{Interface: MASQUEInterface}), "a tunnel another process held is gone already")
}

func TestOpenHostTUN_ReportsAConfigurationTheKernelWouldRefuse(t *testing.T) {
	dev, err := openHostTUN(tunnel.TUNConfig{})

	var invalid *tunnel.ErrInvalidTunnelConfig
	assert.ErrorAs(t, err, &invalid)
	assert.Nil(t, dev, "no typed-nil device")
}

func TestMASQUEErrors_NameTheGatewayAndTheAddresses(t *testing.T) {
	assert.Equal(t, "gateway gw.example:443 refused the MASQUE session: HTTP 403",
		(&ErrSessionRefused{Gateway: "gw.example:443", Status: 403}).Error())
	assert.Equal(t, "data plane masque: the gateway assigned [10.8.0.9/32], not the lease address 10.8.0.2/32",
		(&ErrAddressNotAssigned{
			Kind:     gwvpn.DataPlaneMASQUE,
			Lease:    netip.MustParsePrefix("10.8.0.2/32"),
			Assigned: []netip.Prefix{netip.MustParsePrefix("10.8.0.9/32")},
		}).Error())
}
