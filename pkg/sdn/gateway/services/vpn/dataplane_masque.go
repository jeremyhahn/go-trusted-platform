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
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// DefaultMASQUETemplate is the RFC 9484 URI template the plane serves when
// the configuration names none. The host and port are substituted from the
// listener before the template is parsed.
const DefaultMASQUETemplate = "https://{host}:{port}/.well-known/masque/ip/"

// masqueMaxPacket bounds one IP packet read from the device. It is the
// largest datagram a CONNECT-IP session carries.
const masqueMaxPacket = 1500

// MASQUEConfig is the MASQUE CONNECT-IP plane's configuration. The
// template, bind point and TLS identity come from the gateway; the routes
// are the platform prefixes an admitted client may reach, which the zone
// matrix compiles.
type MASQUEConfig struct {
	// BindHost and Port are the HTTP/3 listener's bind point.
	BindHost string
	Port     int
	// Template is the RFC 9484 URI template clients request. Its host must
	// be the name clients use in :authority; its path is the route served.
	Template string
	// TLS is the listener's identity. Client certificates are required:
	// the plane binds a session to the lease admitted under that exact
	// certificate.
	TLS *tls.Config
	// Routes are the prefixes advertised to an admitted client.
	Routes []netip.Prefix
}

func (c MASQUEConfig) validate() error {
	if c.Template == "" {
		return &ErrInvalidConfig{Field: "masque.template", Reason: "required"}
	}
	if c.TLS == nil || len(c.TLS.Certificates) == 0 && c.TLS.GetCertificate == nil {
		return &ErrInvalidConfig{Field: "masque.tls", Reason: "a server certificate is required"}
	}
	if c.TLS.ClientAuth != tls.RequireAndVerifyClientCert {
		return &ErrInvalidConfig{Field: "masque.tls", Reason: "client certificates must be required and verified"}
	}
	if c.Port < 0 || c.Port > 65535 {
		return &ErrInvalidConfig{Field: "masque.port", Reason: "must be 0-65535"}
	}
	return validateMASQUERoutes(c.Routes)
}

// PacketDevice is the host-side end of the MASQUE plane: a layer-3 device
// whose packets the plane forwards. *tunnel.TUN satisfies it.
type PacketDevice interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// masqueSession is one live CONNECT-IP session bound to a lease.
type masqueSession struct {
	leaseID LeaseID
	address netip.Addr
	conn    *connectip.Conn
	done    chan struct{}
	once    sync.Once
}

func (s *masqueSession) close() error {
	var err error
	s.once.Do(func() {
		err = s.conn.Close()
		close(s.done)
	})
	return err
}

// masqueBinding is an installed lease waiting for, or holding, a session.
// It keeps the lease's identity, not the caller's Lease pointer: the lease
// record belongs to the service and may be rewritten by a renewal.
type masqueBinding struct {
	leaseID LeaseID
	address netip.Addr
	// fingerprint is the SHA-256 of the client certificate the lease was
	// admitted under; a session presenting it is this lease's session.
	fingerprint [sha256.Size]byte
	session     *masqueSession
}

// masquePlane is the FIPS data plane: CONNECT-IP (RFC 9484) over HTTP/3,
// carrying IP packets as HTTP datagrams (RFC 9297, RFC 9221) on the QUIC
// stack the platform already ships. It installs no kernel peer — a lease is
// a binding from a client certificate to an address, and the session that
// presents that certificate gets that address assigned.
type masquePlane struct {
	cfg    MASQUEConfig
	dev    PacketDevice
	logger *slog.Logger
	// listener, when set, is the packet socket Start serves on instead of
	// binding cfg.BindHost:cfg.Port itself.
	listener net.PacketConn

	template *uritemplate.Template
	path     string

	mu       sync.Mutex
	started  bool
	stopped  bool
	server   *http3.Server
	conn     net.PacketConn
	bindings map[LeaseID]*masqueBinding
	byPrint  map[[sha256.Size]byte]*masqueBinding
	byAddr   map[netip.Addr]*masqueBinding

	wg   sync.WaitGroup
	stop chan struct{}
}

// NewMASQUEPlane returns the MASQUE CONNECT-IP data plane forwarding
// between dev and its sessions.
func NewMASQUEPlane(cfg MASQUEConfig, dev PacketDevice, logger *slog.Logger) (ManagedDataPlane, error) {
	return newMASQUEPlane(cfg, dev, logger, nil)
}

func newMASQUEPlane(cfg MASQUEConfig, dev PacketDevice, logger *slog.Logger, listener net.PacketConn) (*masquePlane, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, &ErrDepsMissing{Dep: "PacketDevice"}
	}
	if logger == nil {
		logger = slog.Default()
	}
	tmpl, err := uritemplate.New(cfg.Template)
	if err != nil {
		return nil, &ErrInvalidConfig{Field: "masque.template", Reason: "not a URI template: " + err.Error()}
	}
	u, err := url.Parse(tmpl.Raw())
	if err != nil {
		return nil, &ErrInvalidConfig{Field: "masque.template", Reason: "not a URI: " + err.Error()}
	}
	if u.Path == "" {
		return nil, &ErrInvalidConfig{Field: "masque.template", Reason: "template has no path to serve"}
	}
	return &masquePlane{
		cfg:      cfg,
		dev:      dev,
		logger:   logger,
		listener: listener,
		template: tmpl,
		path:     u.Path,
		bindings: make(map[LeaseID]*masqueBinding),
		byPrint:  make(map[[sha256.Size]byte]*masqueBinding),
		byAddr:   make(map[netip.Addr]*masqueBinding),
	}, nil
}

func (p *masquePlane) Kind() DataPlaneKind { return DataPlaneMASQUE }

// Start binds the listener, serves the CONNECT-IP route and starts
// forwarding packets the device delivers.
func (p *masquePlane) Start(_ context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return nil
	}
	if p.stopped {
		// Stop closed the host device, and a TUN descriptor cannot be
		// reopened. A restarted gateway builds a new plane.
		return &ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Reason: "the plane has been stopped and cannot be restarted"}
	}
	conn := p.listener
	if conn == nil {
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(p.cfg.BindHost, strconv.Itoa(p.cfg.Port)))
		if err != nil {
			return &ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Cause: err}
		}
		udp, err := net.ListenUDP("udp", addr)
		if err != nil {
			return &ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Cause: err}
		}
		conn = udp
	}
	mux := http.NewServeMux()
	mux.HandleFunc(p.path, p.handleConnectIP)
	p.conn = conn
	p.server = &http3.Server{Handler: mux, EnableDatagrams: true, TLSConfig: p.cfg.TLS}
	p.stop = make(chan struct{})
	p.started = true
	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		if err := p.server.Serve(conn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			p.logger.Error("vpn.masque.serve", slog.Any("error", err))
		}
	}()
	go func() {
		defer p.wg.Done()
		p.forwardFromDevice()
	}()
	p.logger.Info("vpn.masque.start", slog.String("listen", conn.LocalAddr().String()), slog.String("path", p.path))
	return nil
}

// Stop closes every session, the listener and the device.
func (p *masquePlane) Stop(_ context.Context) error {
	p.mu.Lock()
	if !p.started {
		p.mu.Unlock()
		return nil
	}
	p.started = false
	p.stopped = true
	server, stop := p.server, p.stop
	sessions := make([]*masqueSession, 0, len(p.bindings))
	for _, b := range p.bindings {
		if b.session != nil {
			sessions = append(sessions, b.session)
			b.session = nil
		}
	}
	p.bindings = make(map[LeaseID]*masqueBinding)
	p.byPrint = make(map[[sha256.Size]byte]*masqueBinding)
	p.byAddr = make(map[netip.Addr]*masqueBinding)
	p.mu.Unlock()

	close(stop)
	for _, s := range sessions {
		_ = s.close()
	}
	var err error
	if cerr := server.Close(); cerr != nil {
		err = cerr
	}
	// Closing the device unblocks the forwarding goroutine's Read.
	if derr := p.dev.Close(); derr != nil && err == nil {
		err = derr
	}
	p.wg.Wait()
	p.logger.Info("vpn.masque.stop")
	if err != nil {
		return &ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Cause: err}
	}
	return nil
}

// LocalAddr reports the listener's address once Start has bound it.
func (p *masquePlane) LocalAddr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		return nil
	}
	return p.conn.LocalAddr()
}

// InstallPeer binds the lease's address to the client certificate the
// admission ran under. No packet flows until that client opens a CONNECT-IP
// session; nothing else can claim the address in the meantime.
func (p *masquePlane) InstallPeer(_ context.Context, lease *Lease) error {
	if lease == nil {
		return &ErrInvalidRequest{Field: "lease", Reason: "required"}
	}
	if len(lease.Keys.ClientCertificateSHA256) != sha256.Size {
		return &ErrPeerKeyInvalid{Kind: DataPlaneMASQUE, Reason: "the lease carries no client certificate fingerprint"}
	}
	if !lease.Address.IsValid() || !lease.Address.IsSingleIP() {
		return &ErrPeerKeyInvalid{Kind: DataPlaneMASQUE, Reason: "lease address must be a single host address"}
	}
	var print [sha256.Size]byte
	copy(print[:], lease.Keys.ClientCertificateSHA256)

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return &ErrDataPlaneNotStarted{Kind: DataPlaneMASQUE}
	}
	addr := lease.Address.Addr()
	if existing, ok := p.byPrint[print]; ok && existing.leaseID != lease.ID {
		return &ErrPeerConflict{Kind: DataPlaneMASQUE, LeaseID: lease.ID, Existing: existing.leaseID, Reason: "the client certificate already holds a lease"}
	}
	if existing, ok := p.byAddr[addr]; ok && existing.leaseID != lease.ID {
		return &ErrPeerConflict{Kind: DataPlaneMASQUE, LeaseID: lease.ID, Existing: existing.leaseID, Reason: "the address is already bound"}
	}
	if prev, ok := p.bindings[lease.ID]; ok {
		p.dropLocked(prev)
	}
	b := &masqueBinding{leaseID: lease.ID, address: addr, fingerprint: print}
	p.bindings[lease.ID] = b
	p.byPrint[print] = b
	p.byAddr[addr] = b
	p.logger.Info("vpn.masque.peer.install", slog.String("lease", string(lease.ID)), slog.String("address", lease.Address.String()))
	return nil
}

// RemovePeer drops the binding and closes the session holding it, if any. A
// lease this plane never installed is not an error.
func (p *masquePlane) RemovePeer(_ context.Context, leaseID LeaseID) error {
	p.mu.Lock()
	b, ok := p.bindings[leaseID]
	if !ok {
		p.mu.Unlock()
		return nil
	}
	session := b.session
	p.dropLocked(b)
	p.mu.Unlock()

	if session != nil {
		if err := session.close(); err != nil {
			return &ErrDataPlaneUnavailable{Kind: DataPlaneMASQUE, Cause: err}
		}
	}
	p.logger.Info("vpn.masque.peer.remove", slog.String("lease", string(leaseID)))
	return nil
}

// dropLocked removes a binding from every index. Caller holds p.mu.
func (p *masquePlane) dropLocked(b *masqueBinding) {
	delete(p.bindings, b.leaseID)
	delete(p.byPrint, b.fingerprint)
	delete(p.byAddr, b.address)
	b.session = nil
}

// handleConnectIP serves one CONNECT-IP request: it accepts the session only
// for a client certificate an installed lease was admitted under, assigns
// that lease's address, advertises the configured routes and pumps packets
// until either end closes.
func (p *masquePlane) handleConnectIP(w http.ResponseWriter, r *http.Request) {
	req, err := connectip.ParseRequest(r, p.template)
	if err != nil {
		status := http.StatusBadRequest
		var parseErr *connectip.RequestParseError
		if errors.As(err, &parseErr) {
			status = parseErr.HTTPStatus
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	b, ok := p.bindingFor(r.TLS)
	if !ok {
		p.logger.Warn("vpn.masque.session.refused", slog.String("reason", "no lease for the presented client certificate"))
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	conn, err := (&connectip.Proxy{}).Proxy(w, req)
	if err != nil {
		p.logger.Warn("vpn.masque.session.refused", slog.String("lease", string(b.leaseID)), slog.Any("error", err))
		return
	}
	session := &masqueSession{leaseID: b.leaseID, address: b.address, conn: conn, done: make(chan struct{})}
	if !p.attach(b.leaseID, session) {
		_ = session.close()
		return
	}
	defer func() {
		_ = session.close()
		p.detach(session)
	}()
	ctx := r.Context()
	if err := conn.AssignAddresses(ctx, []netip.Prefix{netip.PrefixFrom(b.address, b.address.BitLen())}); err != nil {
		p.logger.Warn("vpn.masque.session.assign", slog.String("lease", string(b.leaseID)), slog.Any("error", err))
		return
	}
	if routes := p.advertisedRoutes(); len(routes) > 0 {
		if err := conn.AdvertiseRoute(ctx, routes); err != nil {
			p.logger.Warn("vpn.masque.session.routes", slog.String("lease", string(b.leaseID)), slog.Any("error", err))
			return
		}
	}
	p.logger.Info("vpn.masque.session.open", slog.String("lease", string(b.leaseID)), slog.String("address", b.address.String()))
	p.forwardToDevice(session)
	p.logger.Info("vpn.masque.session.close", slog.String("lease", string(session.leaseID)))
}

// bindingFor resolves the lease bound to the client certificate a session
// presented. A session with no client certificate is refused.
func (p *masquePlane) bindingFor(state *tls.ConnectionState) (*masqueBinding, bool) {
	if state == nil || len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return nil, false
	}
	print := sha256.Sum256(state.PeerCertificates[0].Raw)
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.byPrint[print]
	return b, ok
}

// attach makes session the lease's session, closing any session the lease
// already had: one device per lease, and a reconnect wins.
func (p *masquePlane) attach(leaseID LeaseID, session *masqueSession) bool {
	p.mu.Lock()
	b, ok := p.bindings[leaseID]
	if !ok || !p.started {
		p.mu.Unlock()
		return false
	}
	previous := b.session
	b.session = session
	p.mu.Unlock()
	if previous != nil {
		_ = previous.close()
	}
	return true
}

// detach clears the lease's session if it is still this one.
func (p *masquePlane) detach(session *masqueSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if b, ok := p.bindings[session.leaseID]; ok && b.session == session {
		b.session = nil
	}
}

func (p *masquePlane) advertisedRoutes() []connectip.IPRoute {
	routes := make([]connectip.IPRoute, 0, len(p.cfg.Routes))
	for _, r := range p.cfg.Routes {
		start, end := prefixRange(r)
		routes = append(routes, connectip.IPRoute{StartIP: start, EndIP: end})
	}
	return routes
}

// forwardToDevice carries packets from one session to the device. A packet
// whose source is not the lease address is dropped: a client may source
// traffic only from the address it was leased.
func (p *masquePlane) forwardToDevice(session *masqueSession) {
	buf := make([]byte, masqueMaxPacket)
	for {
		n, err := session.conn.ReadPacket(buf)
		if err != nil {
			return
		}
		if !allowedSource(buf[:n], session.address) {
			p.logger.Warn("vpn.masque.packet.dropped",
				slog.String("lease", string(session.leaseID)), slog.String("reason", "source address is not the lease address"))
			continue
		}
		if _, err := p.dev.Write(buf[:n]); err != nil {
			p.logger.Warn("vpn.masque.device.write", slog.String("lease", string(session.leaseID)), slog.Any("error", err))
			return
		}
	}
}

// forwardFromDevice carries packets the device delivers to the session
// holding the destination address. A packet for an address no session holds
// is dropped.
func (p *masquePlane) forwardFromDevice() {
	buf := make([]byte, masqueMaxPacket)
	for {
		n, err := p.dev.Read(buf)
		if err != nil {
			return
		}
		select {
		case <-p.stop:
			return
		default:
		}
		_, dst, ok := packetAddresses(buf[:n])
		if !ok {
			continue
		}
		session := p.sessionFor(dst)
		if session == nil {
			continue
		}
		if _, err := session.conn.WritePacket(buf[:n]); err != nil {
			p.logger.Warn("vpn.masque.session.write", slog.String("lease", string(session.leaseID)), slog.Any("error", err))
		}
	}
}

func (p *masquePlane) sessionFor(dst netip.Addr) *masqueSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.byAddr[dst]
	if !ok || b.session == nil {
		return nil
	}
	return b.session
}
