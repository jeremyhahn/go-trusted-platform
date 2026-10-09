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
	"bytes"
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
	retry    chan struct{} // signalled when work failed and Converge must retry it

	mu           sync.Mutex
	static       map[netip.Addr]struct{}
	routed       map[netip.Addr]map[uint32]struct{} // VTEP → the VNIs whose routes name it
	evicted      map[netip.Addr]struct{}
	dropPending  map[netip.Addr]struct{}            // evicted VTEPs whose kernel drop failed
	loaded       map[netip.Addr]struct{}            // connections charon holds
	unsynced     map[netip.Addr]struct{}            // peers charon does not hold as wanted
	auditPending bool                               // charon's IKE_SAs need an audit
	crls         map[crlIssuer]*x509.RevocationList // issuer → its newest CRL
	unloadedCRLs map[crlIssuer]struct{}             // issuers whose held CRL charon failed to load
	pendingCRLs  map[crlIssuer]*x509.RevocationList // issuer → its newest CRL awaiting a tunnel identity
	cert         *x509.Certificate                  // the tunnel certificate last loaded
	cmd          Session                            // nil while detached
}

// maxPendingCRLs bounds the CRLs queued while no tunnel identity exists to
// verify them against. A chain has an intermediate and a root, so a
// handful of issuers covers a renewal in flight.
const maxPendingCRLs = 8

// crlIssuer identifies the issuer of a CRL: its name and, when the CRL
// carries one, its key.
type crlIssuer struct {
	name  string
	keyID string
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
		admitter:     admitter,
		dropper:      dropper,
		identity:     identity,
		now:          time.Now,
		retry:        make(chan struct{}, 1),
		static:       make(map[netip.Addr]struct{}, len(peers)),
		routed:       make(map[netip.Addr]map[uint32]struct{}),
		evicted:      make(map[netip.Addr]struct{}),
		dropPending:  make(map[netip.Addr]struct{}),
		loaded:       make(map[netip.Addr]struct{}),
		unsynced:     make(map[netip.Addr]struct{}),
		crls:         make(map[crlIssuer]*x509.RevocationList),
		unloadedCRLs: make(map[crlIssuer]struct{}),
		pendingCRLs:  make(map[crlIssuer]*x509.RevocationList),
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
// whose connection fails to load or unload leave it attached; their
// PeerErrors are returned together, and Converge retries them.
//
// Last, every IKE_SA charon holds is audited (see Audit), so an SA that
// came up while the controller was detached, or one of a peer evicted
// meanwhile, does not outlive the attach.
func (c *Controller) Attach(ctx context.Context, sess Session) error {
	if sess == nil {
		return ErrMissingDependency
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cmd = nil
	c.loaded = make(map[netip.Addr]struct{})
	c.unsynced = make(map[netip.Addr]struct{})

	id, err := c.loadIdentity(ctx, sess)
	if err != nil {
		return err
	}
	// The CRLs queued while there was no identity are verified against
	// this one; those it refuses are dropped and reported.
	errs := c.admitPending(ctx, id.Chain[1:])
	for _, crl := range c.crls {
		if err := loadCRL(ctx, sess, crl); err != nil {
			return err
		}
	}
	clear(c.unloadedCRLs)
	held, err := heldConns(ctx, sess)
	if err != nil {
		return err
	}
	c.cmd = sess

	for _, peer := range held {
		if !c.wanted(peer) {
			// Held by charon, so settle unloads it.
			c.loaded[peer] = struct{}{}
			errs = append(errs, c.settle(ctx, peer, false))
		}
	}
	for _, peer := range c.peers() {
		errs = append(errs, c.settle(ctx, peer, false))
	}
	errs = append(errs, c.audit(ctx))
	return errors.Join(errs...)
}

// loadIdentity loads the tunnel certificate, its CA chain and the token key
// into sess, and returns the identity loaded. Callers hold mu.
func (c *Controller) loadIdentity(ctx context.Context, sess Session) (*TunnelIdentity, error) {
	id, err := c.currentIdentity(ctx)
	if err != nil {
		return nil, err
	}
	for i, cert := range id.Chain {
		kind := CredentialAuthority
		if i == 0 {
			kind = CredentialEndEntity
		}
		if err := sess.LoadCert(ctx, Credential{Kind: kind, DER: cert.Raw}); err != nil {
			return nil, &OpError{Op: "load-cert", Err: err}
		}
	}
	if err := sess.LoadToken(ctx, id.Token, id.PIN); err != nil {
		return nil, &OpError{Op: "load-token", Err: err}
	}
	c.cert = id.Chain[0]
	return id, nil
}

// loadCRL loads one CRL into sess.
func loadCRL(ctx context.Context, sess Session, crl *x509.RevocationList) error {
	if err := sess.LoadCert(ctx, Credential{Kind: CredentialCRL, DER: crl.Raw}); err != nil {
		return &OpError{Op: "load-cert x509crl", Err: err}
	}
	return nil
}

// PushCRL takes a pushed CRL (Service reads them from crl-files). It is kept, as
// its issuer's newest, and loaded into charon now if a session is up and
// on every later attach. charon never fetches CRLs itself, and every peer
// connection checks revocation strictly. A CRL no newer than the one held
// for its issuer is ignored, unless charon failed to load the held one. A
// load that fails is retried by Converge.
//
// A CRL must be signed by a CA of the tunnel identity the provider holds
// now, so a renewal under a new intermediate is followed at once, and its
// NextUpdate must be in the future; one that is not is refused with an
// OpError and the CRL held for its issuer stays. While the provider has no
// valid identity, a current CRL is queued instead, and verified against
// the identity of the next Attach, or of the next PushCRL that finds one.
func (c *Controller) PushCRL(ctx context.Context, der []byte) error {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return &OpError{Op: "parse crl", Err: err}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	id, err := c.currentIdentity(ctx)
	if err != nil {
		return c.queueCRL(crl)
	}
	cas := id.Chain[1:]
	errs := c.admitPending(ctx, cas)
	errs = append(errs, c.admitCRL(ctx, crl, cas))
	return errors.Join(errs...)
}

// currentIdentity returns the identity the provider holds now, validated.
func (c *Controller) currentIdentity(ctx context.Context) (*TunnelIdentity, error) {
	id, err := c.identity.TunnelIdentity(ctx)
	if err != nil {
		return nil, &OpError{Op: "identity", Err: err}
	}
	if err := id.validate(c.cfg.local); err != nil {
		return nil, &OpError{Op: "identity", Err: err}
	}
	return id, nil
}

// queueCRL keeps crl until there is an identity to verify it against. Only
// its currency can be checked now. The queue keeps the newest CRL per
// issuer, for at most maxPendingCRLs issuers. Callers hold mu.
func (c *Controller) queueCRL(crl *x509.RevocationList) error {
	if !current(crl, c.now()) {
		return &OpError{Op: "verify crl", Err: ErrCRLStale}
	}
	issuer := issuerOf(crl)
	queued, ok := c.pendingCRLs[issuer]
	if ok && !supersedes(crl, queued) {
		return nil
	}
	if !ok && len(c.pendingCRLs) >= maxPendingCRLs {
		return &OpError{Op: "queue crl", Err: ErrCRLQueueFull}
	}
	c.pendingCRLs[issuer] = crl
	return nil
}

// admitPending empties the queue through admitCRL and returns the errors
// of the CRLs it refused, which are dropped. Callers hold mu.
func (c *Controller) admitPending(ctx context.Context, cas []*x509.Certificate) []error {
	var errs []error
	for issuer, crl := range c.pendingCRLs {
		delete(c.pendingCRLs, issuer)
		errs = append(errs, c.admitCRL(ctx, crl, cas))
	}
	return errs
}

// admitCRL verifies crl against cas and holds it if it supersedes the CRL
// held for its issuer, loading it into charon when a session is up. A CRL
// no newer than the one held is ignored, unless charon failed to load the
// held one: that is loaded again. Callers hold mu.
func (c *Controller) admitCRL(ctx context.Context, crl *x509.RevocationList, cas []*x509.Certificate) error {
	if err := verifyCRL(crl, cas, c.now()); err != nil {
		return &OpError{Op: "verify crl", Err: err}
	}
	issuer := issuerOf(crl)
	if held, ok := c.crls[issuer]; ok && !supersedes(crl, held) {
		if _, unloaded := c.unloadedCRLs[issuer]; !unloaded {
			return nil
		}
	} else {
		c.crls[issuer] = crl
	}
	return c.loadHeldCRL(ctx, issuer)
}

// loadHeldCRL loads the CRL held for issuer into charon. A failure is held
// as pending for Converge. While detached there is nothing to load: Attach
// loads every held CRL. Callers hold mu.
func (c *Controller) loadHeldCRL(ctx context.Context, issuer crlIssuer) error {
	if c.cmd == nil {
		return nil
	}
	if err := loadCRL(ctx, c.cmd, c.crls[issuer]); err != nil {
		c.unloadedCRLs[issuer] = struct{}{}
		c.signal()
		return err
	}
	delete(c.unloadedCRLs, issuer)
	return nil
}

// issuerOf is the issuer a CRL is held under.
func issuerOf(crl *x509.RevocationList) crlIssuer {
	return crlIssuer{name: string(crl.RawIssuer), keyID: string(crl.AuthorityKeyId)}
}

// current reports whether crl is still current at now.
func current(crl *x509.RevocationList, now time.Time) bool {
	return !crl.NextUpdate.IsZero() && now.Before(crl.NextUpdate)
}

// verifyCRL checks a CRL before it is held: it must be current at now, and
// signed by one of cas. charon checks revocation strictly, so a stale CRL
// fails every peer of its issuer, and an unsigned one is not to be trusted
// at all; either is refused, and the CRL held stays.
func verifyCRL(crl *x509.RevocationList, cas []*x509.Certificate, now time.Time) error {
	if !current(crl, now) {
		return ErrCRLStale
	}
	for _, ca := range cas {
		if bytes.Equal(ca.RawSubject, crl.RawIssuer) && crl.CheckSignatureFrom(ca) == nil {
			return nil
		}
	}
	return ErrCRLUntrusted
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
	// The next Attach loads every held CRL.
	clear(c.unloadedCRLs)
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
	// DropPending are the evicted VTEPs whose kernel drop is not in place:
	// it failed, and Converge retries it. Their traffic is only cut off by
	// the connection being gone.
	DropPending []netip.Addr
	// Unsynced are the peers whose connection or IKE_SAs charon does not
	// hold as wanted yet, in address order; Converge retries them.
	Unsynced []netip.Addr
	// AuditPending is true while charon's IKE_SAs await an audit that
	// failed or could not run.
	AuditPending bool
	// CRLs is how many issuers' CRLs are held.
	CRLs int
	// UnloadedCRLs is how many issuers' held CRLs the attached charon failed
	// to load; Converge retries them. Until one loads, charon checks that
	// issuer's peers against the CRL it held before, or none.
	UnloadedCRLs int
	// PendingCRLs is how many issuers' CRLs wait for a tunnel identity to
	// be verified against; the next Attach verifies them.
	PendingCRLs int
	// Certificate is the renewal state of the tunnel certificate last
	// loaded; nil before the first attach.
	Certificate *CertificateStatus
}

// Status returns the controller's state.
func (c *Controller) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Status{
		Attached:     c.cmd != nil,
		Peers:        c.peers(),
		Evicted:      slices.SortedFunc(maps.Keys(c.evicted), netip.Addr.Compare),
		DropPending:  slices.SortedFunc(maps.Keys(c.dropPending), netip.Addr.Compare),
		Unsynced:     slices.SortedFunc(maps.Keys(c.unsynced), netip.Addr.Compare),
		AuditPending: c.auditPending,
		CRLs:         len(c.crls),
		UnloadedCRLs: len(c.unloadedCRLs),
		PendingCRLs:  len(c.pendingCRLs),
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
	return c.settle(ctx, vtep, false)
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
	return c.settle(ctx, vtep, false)
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
//
// Every step is attempted even when an earlier one fails, and the failures
// are returned together. A failed step is not undone: the peer stays
// evicted, Status reports what is still pending (DropPending, Unsynced),
// and Converge retries it.
func (c *Controller) Evict(ctx context.Context, peer netip.Addr) error {
	peer = peer.Unmap()
	if !c.candidate(peer) {
		return &PeerError{Peer: peer, Op: "evict", Err: ErrInvalidAddress}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evicted[peer] = struct{}{}
	// Every step runs whatever the one before did: a failed drop must not
	// leave the peer's connection and SAs up.
	return errors.Join(c.drop(ctx, peer), c.settle(ctx, peer, true))
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
	// A drop that never went in has nothing to lift.
	if _, pending := c.dropPending[peer]; !pending {
		if err := c.dropper.Undrop(ctx, peer); err != nil {
			return &PeerError{Peer: peer, Op: "undrop", Err: err}
		}
	}
	delete(c.dropPending, peer)
	delete(c.evicted, peer)
	return c.settle(ctx, peer, false)
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
// connection; this check holds that pin to account. An SA that came up for
// an evicted peer is terminated too.
//
// An event marked Lost means others may have been missed, so every SA
// charon holds is audited instead (see Audit).
func (c *Controller) HandleEvent(ctx context.Context, ev IKEUpdown) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ev.Lost {
		// The audit covers the event's own SAs too.
		return c.audit(ctx)
	}
	if !ev.Up {
		return nil
	}
	var errs []error
	for name, sa := range ev.SAs {
		errs = append(errs, c.checkSA(ctx, name, sa))
	}
	return errors.Join(errs...)
}

// Audit checks every IKE_SA charon holds, as HandleEvent checks one that
// comes up: an SA of a controller connection is terminated when its peer
// is evicted, or did not authenticate as the address the connection runs
// to. Attach runs it, and so does HandleEvent for an event marked Lost, so
// no SA escapes the check because its ike-updown was missed. An audit that
// cannot list the SAs, or fails to end one, is retried by Converge.
func (c *Controller) Audit(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.audit(ctx)
}

func (c *Controller) audit(ctx context.Context) error {
	if c.cmd == nil {
		// Attach audits.
		return nil
	}
	c.auditPending = false
	held, err := c.cmd.IKESAs(ctx, "")
	if err != nil {
		c.auditPending = true
		c.signal()
		return &OpError{Op: "list-sas", Err: err}
	}
	var errs []error
	for _, h := range held {
		errs = append(errs, c.checkSA(ctx, h.Conn, h.SA))
	}
	return errors.Join(errs...)
}

// Converge retries what failed before: kernel drops of evicted peers, then,
// while attached, the CRLs charon failed to load, the peers charon does not
// hold as wanted, and a pending audit. Whatever fails again stays pending
// and signals another retry. It returns the failures together.
func (c *Controller) Converge(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var errs []error
	for _, peer := range slices.SortedFunc(maps.Keys(c.dropPending), netip.Addr.Compare) {
		errs = append(errs, c.drop(ctx, peer))
	}
	for _, issuer := range slices.Collect(maps.Keys(c.unloadedCRLs)) {
		errs = append(errs, c.loadHeldCRL(ctx, issuer))
	}
	for _, peer := range slices.SortedFunc(maps.Keys(c.unsynced), netip.Addr.Compare) {
		errs = append(errs, c.settle(ctx, peer, false))
	}
	if c.auditPending {
		errs = append(errs, c.audit(ctx))
	}
	return errors.Join(errs...)
}

// drop applies the kernel drop for an evicted peer. A failure is held as
// pending for Converge.
func (c *Controller) drop(ctx context.Context, peer netip.Addr) error {
	if err := c.dropper.Drop(ctx, peer); err != nil {
		c.dropPending[peer] = struct{}{}
		c.signal()
		return &PeerError{Peer: peer, Op: "drop", Err: err}
	}
	delete(c.dropPending, peer)
	return nil
}

// signal tells whoever runs Converge that work is pending. It never blocks:
// one pending signal stands for any number.
func (c *Controller) signal() {
	select {
	case c.retry <- struct{}{}:
	default:
	}
}

// checkSA checks one IKE_SA of connection name, and terminates it when its
// peer is evicted or did not prove its identity. An SA of a connection the
// controller does not own is left alone. A mismatch is returned as an
// IdentityMismatchError whether or not the SA could be ended; a failure to
// end one leaves an audit pending. The caller holds mu.
func (c *Controller) checkSA(ctx context.Context, name string, sa IKESA) error {
	peer, ours := connPeer(name)
	if !ours {
		return nil
	}
	var reason error
	if _, evicted := c.evicted[peer]; !evicted {
		if host, err := netip.ParseAddr(sa.RemoteHost); err == nil && host.Unmap() == peer && sa.RemoteID == peer.String() {
			return nil
		}
		reason = &IdentityMismatchError{Conn: name, RemoteHost: sa.RemoteHost, RemoteID: sa.RemoteID}
	}
	if c.cmd == nil || sa.UniqueID == "" {
		return reason
	}
	if err := c.terminateSA(ctx, peer, sa.UniqueID); err != nil {
		c.auditPending = true
		c.signal()
		return errors.Join(reason, err)
	}
	return reason
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
// settle brings charon to the wanted state for peer, as sync does, and ends
// the IKE_SAs of an evicted peer when cut is set or an earlier attempt
// failed. A peer that fails is recorded as unsynced and Converge retries
// it. While detached there is nothing to settle: Attach does it.
func (c *Controller) settle(ctx context.Context, peer netip.Addr, cut bool) error {
	if c.cmd == nil {
		return nil
	}
	_, evicted := c.evicted[peer]
	_, retrying := c.unsynced[peer]
	err := c.sync(ctx, peer)
	if evicted && (cut || retrying) {
		err = errors.Join(err, c.terminate(ctx, peer))
	}
	if err != nil {
		c.unsynced[peer] = struct{}{}
		c.signal()
		return err
	}
	delete(c.unsynced, peer)
	return nil
}

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
	held, err := c.cmd.IKESAs(ctx, connName(peer))
	if err != nil {
		return &PeerError{Peer: peer, Op: "list-sas", Err: err}
	}
	var errs []error
	for _, h := range held {
		errs = append(errs, c.terminateSA(ctx, peer, h.SA.UniqueID))
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
