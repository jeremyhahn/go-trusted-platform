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
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/vici"
)

// Admitter decides whether a remote VTEP may carry a VNI. It is the
// overlay's modes.VTEPAdmitter, restated here because that package imports
// this one's parent.
type Admitter interface {
	AdmitVTEP(ctx context.Context, vni uint32, vtep netip.Addr) error
}

// Commander issues VICI commands. *vici.Conn implements it.
type Commander interface {
	Call(ctx context.Context, command string, req *vici.Message) (*vici.Message, error)
	CallStreaming(ctx context.Context, command, event string, req *vici.Message, fn func(*vici.Message) error) (*vici.Message, error)
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
// the peer goes.
//
// Charon may be absent: the controller then only records the peers, and
// Attach pushes them all once a session is up again. The fail-closed
// filter keeps the fabric dark in the meantime.
type Controller struct {
	cfg      settings
	admitter Admitter
	dropper  Dropper

	mu      sync.Mutex
	static  map[netip.Addr]struct{}
	routed  map[netip.Addr]map[uint32]struct{} // VTEP → the VNIs whose routes name it
	evicted map[netip.Addr]struct{}
	loaded  map[netip.Addr]struct{} // connections charon holds
	cmd     Commander               // nil while detached
}

// NewController builds the controller for an enabled configuration.
func NewController(cfg *Config, admitter Admitter, dropper Dropper) (*Controller, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, ErrNotEnabled
	}
	if admitter == nil || dropper == nil {
		return nil, ErrMissingDependency
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	local, err := cfg.Local()
	if err != nil {
		return nil, err
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
		static:   make(map[netip.Addr]struct{}, len(peers)),
		routed:   make(map[netip.Addr]map[uint32]struct{}),
		evicted:  make(map[netip.Addr]struct{}),
		loaded:   make(map[netip.Addr]struct{}),
	}
	for _, p := range peers {
		c.static[p] = struct{}{}
	}
	return c, nil
}

// Attach makes cmd the controller's session with charon and brings
// charon's connections to the peer set: every peer's connection is loaded
// afresh, and any controller connection charon holds for a peer that is
// gone is unloaded.
func (c *Controller) Attach(ctx context.Context, cmd Commander) error {
	if cmd == nil {
		return ErrMissingDependency
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cmd = cmd
	c.loaded = make(map[netip.Addr]struct{})

	held, err := c.heldConns(ctx)
	if err != nil {
		return err
	}
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

// Detach drops the session, after charon went away. Peers keep being
// tracked and are pushed by the next Attach.
func (c *Controller) Detach() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cmd = nil
	c.loaded = make(map[netip.Addr]struct{})
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
func (c *Controller) HandleEvent(ctx context.Context, ev vici.Event) error {
	if ev.Name != "ike-updown" || ev.Message == nil {
		return nil
	}
	var errs []error
	for _, name := range ev.Message.Keys() {
		sa, ok := ev.Message.Section(name)
		if !ok {
			continue
		}
		if err := c.checkIdentity(ctx, name, sa); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Controller) checkIdentity(ctx context.Context, name string, sa *vici.Message) error {
	peer, ours := connPeer(name)
	if up, _ := sa.Value("up"); !ours || up != "yes" {
		return nil
	}
	host, _ := sa.Value("remote-host")
	id, _ := sa.Value("remote-id")
	if hostAddr, err := netip.ParseAddr(host); err == nil && hostAddr.Unmap() == peer && id == peer.String() {
		return nil
	}

	mismatch := &IdentityMismatchError{Conn: name, RemoteHost: host, RemoteID: id}
	uniqueID, ok := sa.Value("uniqueid")
	if !ok {
		return mismatch
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd == nil {
		return mismatch
	}
	if err := c.terminateSA(ctx, peer, uniqueID); err != nil {
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
	req := vici.NewMessage()
	req.SetSection(connName(peer), c.cfg.connection(peer))
	if _, err := c.cmd.Call(ctx, "load-conn", req); err != nil {
		return &PeerError{Peer: peer, Op: "load-conn", Err: err}
	}
	c.loaded[peer] = struct{}{}
	return nil
}

// unload removes peer's connection and its trap. Callers hold mu and a
// session.
func (c *Controller) unload(ctx context.Context, peer netip.Addr) error {
	req := vici.NewMessage()
	req.SetValue("name", connName(peer))
	if _, err := c.cmd.Call(ctx, "unload-conn", req); err != nil {
		return &PeerError{Peer: peer, Op: "unload-conn", Err: err}
	}
	delete(c.loaded, peer)
	return nil
}

// terminate tears down every IKE_SA of peer's connection. Callers hold mu
// and a session.
func (c *Controller) terminate(ctx context.Context, peer netip.Addr) error {
	req := vici.NewMessage()
	req.SetValue("ike", connName(peer))
	req.SetValue("noblock", "yes")
	var ids []string
	collect := func(ev *vici.Message) error {
		for _, name := range ev.Keys() {
			if sa, ok := ev.Section(name); ok {
				if id, ok := sa.Value("uniqueid"); ok {
					ids = append(ids, id)
				}
			}
		}
		return nil
	}
	if _, err := c.cmd.CallStreaming(ctx, "list-sas", "list-sa", req, collect); err != nil {
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
	req := vici.NewMessage()
	req.SetValue("ike-id", uniqueID)
	req.SetValue("force", "yes")
	if _, err := c.cmd.Call(ctx, "terminate", req); err != nil {
		return &PeerError{Peer: peer, Op: "terminate", Err: err}
	}
	return nil
}

// heldConns lists the peers of the controller connections charon holds.
// Callers hold mu and a session.
func (c *Controller) heldConns(ctx context.Context) ([]netip.Addr, error) {
	resp, err := c.cmd.Call(ctx, "get-conns", vici.NewMessage())
	if err != nil {
		return nil, &OpError{Op: "get-conns", Err: err}
	}
	names, _ := resp.List("conns")
	var out []netip.Addr
	for _, name := range names {
		if peer, ours := connPeer(name); ours {
			out = append(out, peer)
		}
	}
	return out, nil
}
