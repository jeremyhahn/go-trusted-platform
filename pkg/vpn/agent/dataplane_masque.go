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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// MASQUEInterface is the TUN the MASQUE plane carries the tunnel on.
const MASQUEInterface = "vpn-masque0"

// masqueSetupTimeout bounds how long the gateway has, once it accepted the
// CONNECT-IP request, to assign the session its address and routes.
const masqueSetupTimeout = 30 * time.Second

// masqueMaxPacket is the largest IP packet either direction moves.
const masqueMaxPacket = 1 << 16

// packetDevice is the host side of the tunnel; *tunnel.TUN satisfies it.
type packetDevice interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

type openTUNFunc func(cfg tunnel.TUNConfig) (packetDevice, error)

// masquePlane is the client side of MASQUE CONNECT-IP (RFC 9484): an HTTP/3
// session to the gateway, presenting the certificate the lease was admitted
// under, and a host TUN carrying the session's packets. A TUN lives only as
// long as the process that opened it, so the tunnel lives in the process
// that connected.
type masquePlane struct {
	certificate func() (tls.Certificate, error)
	roots       *x509.CertPool
	openTUN     openTUNFunc
	logger      *slog.Logger
	active      atomic.Pointer[masqueTunnel]
}

// NewMASQUEPlane returns the MASQUE CONNECT-IP plane. certificate is the
// device certificate the admission presented; roots verify the gateway, the
// system roots when nil.
func NewMASQUEPlane(certificate func() (tls.Certificate, error), roots *x509.CertPool, logger *slog.Logger) DataPlane {
	return newMASQUEPlane(certificate, roots, openHostTUN, logger)
}

func newMASQUEPlane(certificate func() (tls.Certificate, error), roots *x509.CertPool, openTUN openTUNFunc, logger *slog.Logger) *masquePlane {
	if logger == nil {
		logger = slog.Default()
	}
	return &masquePlane{certificate: certificate, roots: roots, openTUN: openTUN, logger: logger}
}

func openHostTUN(cfg tunnel.TUNConfig) (packetDevice, error) {
	dev, err := tunnel.OpenTUN(cfg)
	if err != nil {
		return nil, err
	}
	return dev, nil
}

func (p *masquePlane) Kind() gwvpn.DataPlaneKind { return gwvpn.DataPlaneMASQUE }

// Prepare returns no key: the gateway binds the session to the certificate
// the admission was made under.
func (p *masquePlane) Prepare(context.Context) (gwvpn.PeerWire, error) {
	return gwvpn.PeerWire{}, nil
}

// Up opens the CONNECT-IP session the lease names, checks the gateway
// assigned the lease's address, and carries the session on a TUN addressed
// with it and routing the lease's routes.
func (p *masquePlane) Up(ctx context.Context, lease *gwvpn.LeaseWire) (Session, error) {
	ep, err := masqueEndpointOf(lease)
	if err != nil {
		return Session{}, err
	}
	if p.active.Load() != nil {
		return Session{}, &ErrAlreadyConnected{Gateway: ep.authority, LeaseID: lease.ID}
	}
	t, err := p.dial(ctx, ep)
	if err != nil {
		return Session{}, err
	}
	if !p.active.CompareAndSwap(nil, t) {
		return Session{}, errors.Join(&ErrAlreadyConnected{Gateway: ep.authority, LeaseID: lease.ID}, t.close())
	}
	t.start()
	return Session{Interface: MASQUEInterface}, nil
}

// Down closes the session and the TUN. A tunnel held by another process
// ended with it, so there is nothing here to tear down.
func (p *masquePlane) Down(context.Context, Session) error {
	t := p.active.Swap(nil)
	if t == nil {
		return nil
	}
	return t.close()
}

func (p *masquePlane) dial(ctx context.Context, ep masqueEndpoint) (*masqueTunnel, error) {
	cert, err := p.certificate()
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      p.roots,
		ServerName:   ep.serverName,
		NextProtos:   []string{http3.NextProtoH3},
		MinVersion:   tls.VersionTLS13,
	}
	qc, err := quic.DialAddr(ctx, ep.authority, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return nil, &ErrGatewayUnreachable{Gateway: ep.authority, Cause: err}
	}
	t := &masqueTunnel{quic: qc, logger: p.logger}
	if err := t.open(ctx, ep, p.openTUN); err != nil {
		return nil, errors.Join(err, t.close())
	}
	return t, nil
}

// masqueEndpoint is what Up needs from the lease, checked before anything
// is dialled.
type masqueEndpoint struct {
	template   *uritemplate.Template
	authority  string
	serverName string
	address    netip.Prefix
	routes     []netip.Prefix
}

func masqueEndpointOf(lease *gwvpn.LeaseWire) (masqueEndpoint, error) {
	kind := gwvpn.DataPlaneMASQUE
	ep := lease.Endpoint.MASQUE
	if ep == nil {
		return masqueEndpoint{}, &ErrLeaseUnusable{Kind: kind, Reason: "the lease names no MASQUE endpoint"}
	}
	tmpl, err := uritemplate.New(ep.Template)
	if err != nil {
		return masqueEndpoint{}, &ErrLeaseUnusable{Kind: kind, Reason: "template " + ep.Template + " is not a URI template", Cause: err}
	}
	if len(tmpl.Varnames()) > 0 {
		return masqueEndpoint{}, &ErrLeaseUnusable{Kind: kind, Reason: "template " + ep.Template + " asks for IP flow forwarding"}
	}
	u, err := url.Parse(tmpl.Raw())
	if err != nil {
		return masqueEndpoint{}, &ErrLeaseUnusable{Kind: kind, Reason: "template " + ep.Template + " is not a URL", Cause: err}
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return masqueEndpoint{}, &ErrLeaseUnusable{Kind: kind, Reason: "template " + ep.Template + " is not an https URL"}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	address, err := leaseAddress(kind, lease)
	if err != nil {
		return masqueEndpoint{}, err
	}
	routes, err := leaseRoutes(kind, ep.Routes)
	if err != nil {
		return masqueEndpoint{}, err
	}
	return masqueEndpoint{
		template:   tmpl,
		authority:  net.JoinHostPort(u.Hostname(), port),
		serverName: u.Hostname(),
		address:    address,
		routes:     routes,
	}, nil
}

// masqueTunnel is one CONNECT-IP session and the TUN carrying it.
type masqueTunnel struct {
	quic   *quic.Conn
	conn   *connectip.Conn
	dev    packetDevice
	logger *slog.Logger

	pumps     sync.WaitGroup
	closing   atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// open requests the session, waits for the gateway's address assignment and
// route advertisement, and opens the TUN.
func (t *masqueTunnel) open(ctx context.Context, ep masqueEndpoint, openTUN openTUNFunc) error {
	setup, cancel := context.WithTimeout(ctx, masqueSetupTimeout)
	defer cancel()
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(t.quic)
	conn, rsp, err := connectip.Dial(setup, cc, ep.template)
	if err != nil {
		if rsp != nil {
			return &ErrSessionRefused{Gateway: ep.authority, Status: rsp.StatusCode}
		}
		return &ErrGatewayUnreachable{Gateway: ep.authority, Cause: err}
	}
	t.conn = conn
	assigned, err := conn.LocalPrefixes(setup)
	if err != nil {
		return &ErrGatewayUnreachable{Gateway: ep.authority, Cause: err}
	}
	if !slices.ContainsFunc(assigned, func(a netip.Prefix) bool { return a.Addr() == ep.address.Addr() }) {
		return &ErrAddressNotAssigned{Kind: gwvpn.DataPlaneMASQUE, Lease: ep.address, Assigned: assigned}
	}
	// A packet sent before the routes arrive is dropped, so the TUN opens
	// only once the session can carry it.
	if _, err := conn.Routes(setup); err != nil {
		return &ErrGatewayUnreachable{Gateway: ep.authority, Cause: err}
	}
	dev, err := openTUN(tunnel.TUNConfig{Name: MASQUEInterface, Addresses: []netip.Prefix{ep.address}, Routes: ep.routes})
	if err != nil {
		return err
	}
	t.dev = dev
	return nil
}

func (t *masqueTunnel) start() {
	t.pumps.Add(2)
	go t.pump("to-gateway", t.toGateway)
	go t.pump("from-gateway", t.fromGateway)
}

// pump moves one direction until it fails, then shuts the tunnel so the
// other direction ends too.
func (t *masqueTunnel) pump(direction string, move func() error) {
	defer t.pumps.Done()
	err := move()
	if !t.closing.Load() {
		t.logger.Warn("vpn.masque.session.ended", slog.String("direction", direction), slog.Any("error", err))
	}
	if err := t.shut(); err != nil {
		t.logger.Warn("vpn.masque.tun.close", slog.Any("error", err))
	}
}

func (t *masqueTunnel) toGateway() error {
	buf := make([]byte, masqueMaxPacket)
	for {
		n, err := t.dev.Read(buf)
		if err != nil {
			return err
		}
		icmp, err := t.conn.WritePacket(buf[:n])
		if err != nil {
			return err
		}
		if len(icmp) > 0 {
			if _, err := t.dev.Write(icmp); err != nil {
				return err
			}
		}
	}
}

func (t *masqueTunnel) fromGateway() error {
	buf := make([]byte, masqueMaxPacket)
	for {
		n, err := t.conn.ReadPacket(buf)
		if err != nil {
			return err
		}
		if _, err := t.dev.Write(buf[:n]); err != nil {
			return err
		}
	}
}

// shut closes the session, the connection and the TUN, once. Only the TUN's
// error is returned: it is the host state Down answers for, while a session
// the gateway already ended reports errors on close that mean nothing.
func (t *masqueTunnel) shut() error {
	t.closeOnce.Do(func() {
		t.closing.Store(true)
		if t.conn != nil {
			if err := t.conn.Close(); err != nil {
				t.logger.Debug("vpn.masque.session.close", slog.Any("error", err))
			}
		}
		if err := t.quic.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), ""); err != nil {
			t.logger.Debug("vpn.masque.conn.close", slog.Any("error", err))
		}
		if t.dev != nil {
			t.closeErr = t.dev.Close()
		}
	})
	return t.closeErr
}

// close shuts the tunnel and waits for both directions to stop.
func (t *masqueTunnel) close() error {
	err := t.shut()
	t.pumps.Wait()
	return err
}
