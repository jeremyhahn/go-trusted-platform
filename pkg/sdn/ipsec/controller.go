// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ipsec

import (
	"context"
	"crypto/x509"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// Admitter decides whether a remote VTEP may carry a VNI. It is the
// overlay's modes.VTEPAdmitter, restated here because that package imports
// this one's parent.
type Admitter interface {
	AdmitVTEP(ctx context.Context, vni uint32, vtep netip.Addr) error
}

// Dropper is the kernel half of an eviction: it drops a peer's packets on
// the fabric, IKE included, whatever charon holds.
type Dropper interface {
	Drop(ctx context.Context, peer netip.Addr) error
	Undrop(ctx context.Context, peer netip.Addr) error
}

// settings are the connection parameters fixed by the configuration.
type settings struct {
	local        netip.Addr
	reauthTime   time.Duration
	replayWindow uint32
}

// Controller keeps charon's connections equal to the overlay's peers: the
// static peers, plus every VTEP an admitted Type-3 route names, minus the
// evicted. It loads a connection when a peer appears and unloads it when
// the peer goes. Each attach also loads the node's tunnel identity and the
// CRLs pushed to it, which charon checks peers against.
//
// Charon may be absent: the controller then only records the peers and
// CRLs, and Attach pushes them all once a session is up again. The
// fail-closed filter keeps the fabric dark in the meantime.
type Controller struct {
	cfg      settings
	admitter Admitter
	dropper  Dropper
	identity IdentityProvider
	now      func() time.Time

	mu      sync.Mutex
	static  map[netip.Addr]struct{}
	routed  map[netip.Addr]map[uint32]struct{} // VTEP → the VNIs whose routes name it
	evicted map[netip.Addr]struct{}
	loaded  map[netip.Addr]struct{}         // connections charon holds
	crls    map[string]*x509.RevocationList // issuer → its newest CRL
	cert    *x509.Certificate               // the tunnel certificate last loaded
	cmd     Session                         // nil while detached
}

// NewController builds the controller for an enabled configuration.
func NewController(cfg *Config, admitter Admitter, dropper Dropper, identity IdentityProvider) (*Controller, error) {
	local, err := enabledLocal(cfg)
	if err != nil {
		return nil, err
	}
	if admitter == nil || dropper == nil || identity == nil {
		return nil, ErrMissingDependency
	}
	peers, err := cfg.Peers()
	if err != nil {
		return nil, err
	}
	c := &Controller{
		cfg: settings{
			local:        local,
			reauthTime:   cfg.ReauthTime(),
			replayWindow: cfg.EffectiveReplayWindow(),
		},
		admitter: admitter,
		dropper:  dropper,
		identity: identity,
		now:      time.Now,
		static:   make(map[netip.Addr]struct{}, len(peers)),
		routed:   make(map[netip.Addr]map[uint32]struct{}),
		evicted:  make(map[netip.Addr]struct{}),
		loaded:   make(map[netip.Addr]struct{}),
		crls:     make(map[string]*x509.RevocationList),
	}
	for _, p := range peers {
		c.static[p] = struct{}{}
	}
	return c, nil
}

// Attach makes sess the controller's session with charon and brings charon
// to the controller's state, in order: the tunnel identity, the CRLs, then
// the connections. Every peer's connection is loaded afresh, and any
// controller connection charon holds for a peer that is gone is unloaded.
//
// A failure to load the identity or the CRLs, or to list charon's
// connections, leaves the controller detached and is returned as an
// OpError: charon cannot authenticate peers safely without them. Peers
// whose connection fails to load leave it attached; their PeerErrors are
// returned together.
func (c *Controller) Attach(ctx context.Context, sess Session) error {
	if sess == nil {
		return ErrMissingDependency
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cmd = nil
	c.loaded = make(map[netip.Addr]struct{})

	if err := c.loadIdentity(ctx, sess); err != nil {
		return err
	}
	for _, crl := range c.crls {
		if err := loadCRL(ctx, sess, crl); err != nil {
			return err
		}
	}
	held, err := heldConns(ctx, sess)
	if err != nil {
		return err
	}
	c.cmd = sess

	var errs []error
	for _, peer := range held {
		if !c.wanted(peer) {
			errs = append(errs, c.unload(ctx, peer))
		}
	}
	for _, peer := range c.peers() {
		errs = append(errs, c.load(ctx, peer))
	}
	return errors.Join(errs...)
}

// loadIdentity loads the tunnel certificate, its CA chain and the token key
// into sess. Callers hold mu.
func (c *Controller) loadIdentity(ctx context.Context, sess Session) error {
	id, err := c.identity.TunnelIdentity(ctx)
	if err != nil {
		return &OpError{Op: "identity", Err: err}
	}
	if err := id.validate(c.cfg.local); err != nil {
		return &OpError{Op: "identity", Err: err}
	}
	for i, cert := range id.Chain {
		kind := CredentialAuthority
		if i == 0 {
			kind = CredentialEndEntity
		}
		if err := sess.LoadCert(ctx, Credential{Kind: kind, DER: cert.Raw}); err != nil {
			return &OpError{Op: "load-cert", Err: err}
		}
	}
	if err := sess.LoadToken(ctx, id.Token, id.PIN); err != nil {
		return &OpError{Op: "load-token", Err: err}
	}
	c.cert = id.Chain[0]
	return nil
}

// loadCRL loads one CRL into sess.
func loadCRL(ctx context.Context, sess Session, crl *x509.RevocationList) error {
	if err := sess.LoadCert(ctx, Credential{Kind: CredentialCRL, DER: crl.Raw}); err != nil {
		return &OpError{Op: "load-cert x509crl", Err: err}
	}
	return nil
}

// PushCRL takes a CRL pushed down the controller stream. It is kept, as
// its issuer's newest, and loaded into charon now if a session is up and
// on every later attach. charon never fetches CRLs itself, and every peer
// connection checks revocation strictly. A CRL no newer than the one held
// for its issuer is ignored.
func (c *Controller) PushCRL(ctx context.Context, der []byte) error {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return &OpError{Op: "parse crl", Err: err}
	}
	issuer := string(crl.RawIssuer) + string(crl.AuthorityKeyId)
	c.mu.Lock()
	defer c.mu.Unlock()
	if held, ok := c.crls[issuer]; ok && !supersedes(crl, held) {
		return nil
	}
	c.crls[issuer] = crl
	if c.cmd == nil {
		return nil
	}
	return loadCRL(ctx, c.cmd, crl)
}

// supersedes reports whether next replaces prev: a higher CRL number, or
// a later thisUpdate when either lacks one.
func supersedes(next, prev *x509.RevocationList) bool {
	if next.Number != nil && prev.Number != nil {
		return next.Number.Cmp(prev.Number) > 0
	}
	return next.ThisUpdate.After(prev.ThisUpdate)
}

// Detach drops the session, after charon went away. Peers and CRLs keep
// being tracked and are pushed by the next Attach.
func (c *Controller) Detach() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cmd = nil
	c.loaded = make(map[netip.Addr]struct{})
}

// attached reports whether a session is up.
func (c *Controller) attached() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmd != nil
}

// Status is the controller's state for the ipsec status.
type Status struct {
	// Attached is true while a charon session is up.
	Attached bool
	// Peers are the VTEPs with a connection, in address order.
	Peers []netip.Addr
	// Evicted are the evicted VTEPs, in address order.
	Evicted []netip.Addr
	// CRLs is how many issuers' CRLs are held.
	CRLs int
	// Certificate is the renewal state of the tunnel certificate last
	// loaded; nil before the first attach.
	Certificate *CertificateStatus
}

// Status returns the controller's state.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Status{
		Attached: c.cmd != nil,
		Peers:    c.peers(),
		Evicted:  slices.SortedFunc(maps.Keys(c.evicted), netip.Addr.Compare),
		CRLs:     len(c.crls),
	}
	if c.cert != nil {
		s.Certificate = certificateStatus(c.cert, c.now())
	}
	return s
}

// HandleEVPNRoute follows the Type-3 routes: a VTEP is a peer while any
// admitted route names it. It is a bgp.EVPNRouteHandler. A VTEP the
// admitter refuses is not a peer, and the refusal is returned.
func (c *Controller) HandleEVPNRoute(ctx context.Context, route *bgp.EVPNRouteData) error {
	if route == nil || route.Type != bgp.EVPNTypeInclusiveMulticast || route.IMET == nil {
		return nil
	}
	vni, vtep := route.IMET.VNI, route.IMET.VTEPIP.Unmap()
	if !c.candidate(vtep) {
		return nil
	}
	if route.IsWithdraw {
		return c.withdraw(ctx, vni, vtep)
	}
	if err := c.admitter.AdmitVTEP(ctx, vni, vtep); err != nil {
		return &PeerError{Peer: vtep, Op: "admit", Err: err}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	vnis, known := c.routed[vtep]
	if !known {
		vnis = make(map[uint32]struct{})
		c.routed[vtep] = vnis
	}
	vnis[vni] = struct{}{}
	return c.sync(ctx, vtep)
}

func (c *Controller) withdraw(ctx context.Context, vni uint32, vtep netip.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	vnis, known := c.routed[vtep]
	if !known {
		return nil
	}
	delete(vnis, vni)
	if len(vnis) == 0 {
		delete(c.routed, vtep)
	}
	return c.sync(ctx, vtep)
}

// candidate reports whether vtep can be a peer at all: a unicast address
// of the local family other than the local address. Routes naming anything
// else are not this controller's to act on.
func (c *Controller) candidate(vtep netip.Addr) bool {
	return vtep.IsGlobalUnicast() && vtep.Zone() == "" &&
		vtep.Is4() == c.cfg.local.Is4() && vtep != c.cfg.local
}

// Evict cuts peer off: its packets are dropped in the kernel, its
// connection is unloaded so no trap re-initiates it, and its IKE_SAs are
// torn down. It stays evicted, whatever routes name it, until Readmit.
// The kernel drop is applied first and holds even when charon is absent.
func (c *Controller) Evict(ctx context.Context, peer netip.Addr) error {
	peer = peer.Unmap()
	if !c.candidate(peer) {
		return &PeerError{Peer: peer, Op: "evict", Err: ErrInvalidAddress}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evicted[peer] = struct{}{}
	if err := c.dropper.Drop(ctx, peer); err != nil {
		return &PeerError{Peer: peer, Op: "drop", Err: err}
	}
	if c.cmd == nil {
		return nil
	}
	if _, loaded := c.loaded[peer]; loaded {
		if err := c.unload(ctx, peer); err != nil {
			return err
		}
	}
	return c.terminate(ctx, peer)
}

// Readmit lifts an eviction: the kernel drop goes, and the connection is
// loaded again if the peer is still static or routed.
func (c *Controller) Readmit(ctx context.Context, peer netip.Addr) error {
	peer = peer.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.evicted[peer]; !ok {
		return &PeerError{Peer: peer, Op: "readmit", Err: ErrNotEvicted}
	}
	if err := c.dropper.Undrop(ctx, peer); err != nil {
		return &PeerError{Peer: peer, Op: "undrop", Err: err}
	}
	delete(c.evicted, peer)
	return c.sync(ctx, peer)
}

// Peers returns the current peers in address order.
func (c *Controller) Peers() []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peers()
}

// HandleEvent checks an ike-updown event: an IKE_SA of a controller
// connection that came up must have authenticated its peer as the address
// it runs to. One that did not is terminated and reported as an
// IdentityMismatchError. charon already pins the remote identity per
// connection; this check holds that pin to account.
func (c *Controller) HandleEvent(ctx context.Context, ev IKEUpdown) error {
	if !ev.Up {
		return nil
	}
	var errs []error
	for name, sa := range ev.SAs {
		errs = append(errs, c.checkIdentity(ctx, name, sa))
	}
	return errors.Join(errs...)
}

func (c *Controller) checkIdentity(ctx context.Context, name string, sa IKESA) error {
	peer, ours := connPeer(name)
	if !ours {
		return nil
	}
	if host, err := netip.ParseAddr(sa.RemoteHost); err == nil && host.Unmap() == peer && sa.RemoteID == peer.String() {
		return nil
	}

	mismatch := &IdentityMismatchError{Conn: name, RemoteHost: sa.RemoteHost, RemoteID: sa.RemoteID}
	if sa.UniqueID == "" {
		return mismatch
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd == nil {
		return mismatch
	}
	if err := c.terminateSA(ctx, peer, sa.UniqueID); err != nil {
		return errors.Join(mismatch, err)
	}
	return mismatch
}

// peers lists static and routed VTEPs that are not evicted. Callers hold mu.
func (c *Controller) peers() []netip.Addr {
	out := make([]netip.Addr, 0, len(c.static)+len(c.routed))
	for p := range c.static {
		if c.wanted(p) {
			out = append(out, p)
		}
	}
	for p := range c.routed {
		if _, static := c.static[p]; !static && c.wanted(p) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// wanted reports whether peer should have a connection. Callers hold mu.
func (c *Controller) wanted(peer netip.Addr) bool {
	if _, evicted := c.evicted[peer]; evicted {
		return false
	}
	_, static := c.static[peer]
	_, routed := c.routed[peer]
	return static || routed
}

// sync loads or unloads peer's connection to match whether it is wanted.
// Callers hold mu.
func (c *Controller) sync(ctx context.Context, peer netip.Addr) error {
	_, loaded := c.loaded[peer]
	switch want := c.wanted(peer); {
	case c.cmd == nil || want == loaded:
		return nil
	case want:
		return c.load(ctx, peer)
	default:
		return c.unload(ctx, peer)
	}
}

// load pushes peer's connection. Callers hold mu and a session.
func (c *Controller) load(ctx context.Context, peer netip.Addr) error {
	if err := c.cmd.LoadConn(ctx, connName(peer), c.cfg.connection(peer)); err != nil {
		return &PeerError{Peer: peer, Op: "load-conn", Err: err}
	}
	c.loaded[peer] = struct{}{}
	return nil
}

// unload removes peer's connection and its trap. Callers hold mu and a
// session.
func (c *Controller) unload(ctx context.Context, peer netip.Addr) error {
	if err := c.cmd.UnloadConn(ctx, connName(peer)); err != nil {
		return &PeerError{Peer: peer, Op: "unload-conn", Err: err}
	}
	delete(c.loaded, peer)
	return nil
}

// terminate tears down every IKE_SA of peer's connection. Callers hold mu
// and a session.
func (c *Controller) terminate(ctx context.Context, peer netip.Addr) error {
	ids, err := c.cmd.IKESAs(ctx, connName(peer))
	if err != nil {
		return &PeerError{Peer: peer, Op: "list-sas", Err: err}
	}
	var errs []error
	for _, id := range ids {
		errs = append(errs, c.terminateSA(ctx, peer, id))
	}
	return errors.Join(errs...)
}

// terminateSA destroys one IKE_SA without waiting for the peer to confirm
// the delete. Callers hold mu and a session.
func (c *Controller) terminateSA(ctx context.Context, peer netip.Addr, uniqueID string) error {
	if err := c.cmd.TerminateIKE(ctx, uniqueID); err != nil {
		return &PeerError{Peer: peer, Op: "terminate", Err: err}
	}
	return nil
}

// heldConns lists the peers of the controller connections sess holds.
func heldConns(ctx context.Context, sess Session) ([]netip.Addr, error) {
	names, err := sess.Conns(ctx)
	if err != nil {
		return nil, &OpError{Op: "get-conns", Err: err}
	}
	var out []netip.Addr
	for _, name := range names {
		if peer, ours := connPeer(name); ours {
			out = append(out, peer)
		}
	}
	return out, nil
}
