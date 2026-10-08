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
	"maps"
	"net/netip"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/vici"
)

var errInjected = errors.New("injected failure")

// fakeCharon models the part of charon the controller drives: the loaded
// connections and the IKE_SAs of each.
type fakeCharon struct {
	conns    map[string]*vici.Message
	sas      map[string][]string // connection → IKE_SA unique IDs
	commands []string
	killed   []string // terminated IKE_SA unique IDs
	fail     map[string]error
}

func newFakeCharon(held ...string) *fakeCharon {
	f := &fakeCharon{conns: make(map[string]*vici.Message), sas: make(map[string][]string), fail: make(map[string]error)}
	for _, name := range held {
		f.conns[name] = vici.NewMessage()
	}
	return f
}

func (f *fakeCharon) Call(_ context.Context, command string, req *vici.Message) (*vici.Message, error) {
	f.commands = append(f.commands, command)
	if err := f.fail[command]; err != nil {
		return nil, err
	}
	resp := vici.NewMessage()
	switch command {
	case "load-conn":
		for _, name := range req.Keys() {
			f.conns[name], _ = req.Section(name)
		}
	case "unload-conn":
		name, _ := req.Value("name")
		if _, ok := f.conns[name]; !ok {
			return nil, &vici.CommandError{Command: command, Message: "configuration not found"}
		}
		delete(f.conns, name)
	case "get-conns":
		resp.SetList("conns", slices.Sorted(maps.Keys(f.conns))...)
	case "terminate":
		id, _ := req.Value("ike-id")
		if force, _ := req.Value("force"); force != "yes" {
			return nil, &vici.CommandError{Command: command, Message: "terminate without force"}
		}
		f.killed = append(f.killed, id)
	}
	return resp, nil
}

func (f *fakeCharon) CallStreaming(_ context.Context, command, _ string, req *vici.Message, fn func(*vici.Message) error) (*vici.Message, error) {
	f.commands = append(f.commands, command)
	if err := f.fail[command]; err != nil {
		return nil, err
	}
	name, _ := req.Value("ike")
	for _, id := range f.sas[name] {
		sa := vici.NewMessage()
		sa.SetValue("uniqueid", id)
		ev := vici.NewMessage()
		ev.SetSection(name, sa)
		if err := fn(ev); err != nil {
			return nil, err
		}
	}
	return vici.NewMessage(), nil
}

func (f *fakeCharon) loaded() []string {
	return slices.Sorted(maps.Keys(f.conns))
}

type fakeAdmitter struct {
	refuse map[netip.Addr]error
}

func (a *fakeAdmitter) AdmitVTEP(_ context.Context, _ uint32, vtep netip.Addr) error {
	return a.refuse[vtep]
}

type fakeDropper struct {
	dropped map[netip.Addr]struct{}
	fail    error
}

func (d *fakeDropper) Drop(_ context.Context, peer netip.Addr) error {
	if d.fail != nil {
		return d.fail
	}
	d.dropped[peer] = struct{}{}
	return nil
}

func (d *fakeDropper) Undrop(_ context.Context, peer netip.Addr) error {
	if d.fail != nil {
		return d.fail
	}
	delete(d.dropped, peer)
	return nil
}

type harness struct {
	ctl      *Controller
	charon   *fakeCharon
	admitter *fakeAdmitter
	dropper  *fakeDropper
}

// newHarness builds a controller for validConfig (static peers 10.20.0.1
// and 10.20.0.2) attached to an empty charon.
func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		charon:   newFakeCharon(),
		admitter: &fakeAdmitter{refuse: make(map[netip.Addr]error)},
		dropper:  &fakeDropper{dropped: make(map[netip.Addr]struct{})},
	}
	ctl, err := NewController(validConfig(), h.admitter, h.dropper)
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	h.ctl = ctl
	if err := ctl.Attach(context.Background(), h.charon); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	return h
}

func imet(vni uint32, vtep string, withdraw bool) *bgp.EVPNRouteData {
	return &bgp.EVPNRouteData{
		Type:       bgp.EVPNTypeInclusiveMulticast,
		IMET:       &bgp.IMETEntry{VNI: vni, VTEPIP: netip.MustParseAddr(vtep)},
		IsWithdraw: withdraw,
	}
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestNewControllerRejects(t *testing.T) {
	admitter, dropper := &fakeAdmitter{}, &fakeDropper{}
	invalid := validConfig()
	invalid.Token.Handle = ""
	tests := []struct {
		name     string
		cfg      *Config
		admitter Admitter
		dropper  Dropper
		want     error
	}{
		{"absent section", nil, admitter, dropper, ErrNotEnabled},
		{"disabled section", &Config{}, admitter, dropper, ErrNotEnabled},
		{"no admitter", validConfig(), nil, dropper, ErrMissingDependency},
		{"no dropper", validConfig(), admitter, nil, ErrMissingDependency},
		{"invalid section", invalid, admitter, dropper, ErrRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewController(tt.cfg, tt.admitter, tt.dropper); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAttachLoadsStaticPeersAndPrunesStale(t *testing.T) {
	ctl, err := NewController(validConfig(), &fakeAdmitter{}, &fakeDropper{})
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	// charon outlived a platformd that knew 10.20.0.9; someone else's
	// connection sits beside it.
	charon := newFakeCharon("vtep-10.20.0.9", "vtep-10.20.0.1", "operator-test")
	if err := ctl.Attach(context.Background(), charon); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	want := []string{"operator-test", "vtep-10.20.0.1", "vtep-10.20.0.2"}
	if got := charon.loaded(); !slices.Equal(got, want) {
		t.Fatalf("charon holds %v, want %v", got, want)
	}

	if err := ctl.Attach(context.Background(), nil); !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("Attach(nil): err = %v", err)
	}
}

func TestAttachReportsEveryFailure(t *testing.T) {
	ctl, err := NewController(validConfig(), &fakeAdmitter{}, &fakeDropper{})
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	charon := newFakeCharon()
	charon.fail["load-conn"] = &vici.CommandError{Command: "load-conn", Message: "proposal unknown"}
	err = ctl.Attach(context.Background(), charon)
	var peerErr *PeerError
	if !errors.As(err, &peerErr) || peerErr.Op != "load-conn" {
		t.Fatalf("err = %v, want a load-conn PeerError", err)
	}
	if got := len(slices.DeleteFunc(slices.Clone(charon.commands), func(c string) bool { return c != "load-conn" })); got != 2 {
		t.Fatalf("load-conn tried %d times, want once per static peer", got)
	}

	charon = newFakeCharon()
	charon.fail["get-conns"] = errInjected
	var opErr *OpError
	if err := ctl.Attach(context.Background(), charon); !errors.As(err, &opErr) || !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want a get-conns OpError", err)
	}
}

func TestRoutesFollowTheVTEP(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const peer = "vtep-10.20.0.30"

	steps := []struct {
		route  *bgp.EVPNRouteData
		loaded bool
	}{
		{imet(100, "10.20.0.30", false), true},
		{imet(200, "10.20.0.30", false), true},
		{imet(100, "10.20.0.30", true), true}, // VNI 200 still names it
		{imet(200, "10.20.0.30", true), false},
		{imet(200, "10.20.0.30", true), false}, // a repeat withdrawal is a no-op
	}
	for i, step := range steps {
		if err := h.ctl.HandleEVPNRoute(ctx, step.route); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if _, loaded := h.charon.conns[peer]; loaded != step.loaded {
			t.Fatalf("step %d: loaded = %v, want %v", i, loaded, step.loaded)
		}
	}
}

func TestRouteWithdrawalKeepsStaticPeer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, withdraw := range []bool{false, true} {
		if err := h.ctl.HandleEVPNRoute(ctx, imet(100, "10.20.0.1", withdraw)); err != nil {
			t.Fatalf("route (withdraw=%v): %v", withdraw, err)
		}
	}
	if _, ok := h.charon.conns["vtep-10.20.0.1"]; !ok {
		t.Fatal("a route withdrawal unloaded a static peer")
	}
}

func TestRefusedVTEPIsNotAPeer(t *testing.T) {
	h := newHarness(t)
	h.admitter.refuse[addr("10.20.0.30")] = errInjected

	err := h.ctl.HandleEVPNRoute(context.Background(), imet(100, "10.20.0.30", false))
	var peerErr *PeerError
	if !errors.As(err, &peerErr) || peerErr.Op != "admit" || !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want the admitter's refusal", err)
	}
	if _, loaded := h.charon.conns["vtep-10.20.0.30"]; loaded {
		t.Fatal("a refused VTEP got a connection")
	}
}

func TestRoutesThatNameNoPeerAreIgnored(t *testing.T) {
	h := newHarness(t)
	before := h.charon.loaded()
	routes := []*bgp.EVPNRouteData{
		nil,
		{Type: bgp.EVPNTypeInclusiveMulticast},
		{Type: bgp.EVPNTypeMACIPAdvertisement, MACIP: &bgp.MACIPEntry{VTEPIP: addr("10.20.0.30")}},
		imet(100, "10.20.0.11", false), // the local VTEP
		imet(100, "fd00::30", false),   // the other family
		imet(100, "169.254.0.1", false),
		imet(100, "0.0.0.0", false),
	}
	for i, route := range routes {
		if err := h.ctl.HandleEVPNRoute(context.Background(), route); err != nil {
			t.Fatalf("route %d: %v", i, err)
		}
	}
	if got := h.charon.loaded(); !slices.Equal(got, before) {
		t.Fatalf("charon holds %v, want %v", got, before)
	}
}

func TestDetachedRoutesArePushedOnAttach(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.ctl.Detach()
	if err := h.ctl.HandleEVPNRoute(ctx, imet(100, "10.20.0.30", false)); err != nil {
		t.Fatalf("route while detached: %v", err)
	}

	restarted := newFakeCharon()
	if err := h.ctl.Attach(ctx, restarted); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	want := []string{"vtep-10.20.0.1", "vtep-10.20.0.2", "vtep-10.20.0.30"}
	if got := restarted.loaded(); !slices.Equal(got, want) {
		t.Fatalf("restarted charon holds %v, want %v", got, want)
	}
	if got := h.ctl.Peers(); len(got) != 3 {
		t.Fatalf("Peers = %v", got)
	}
}

func TestLoadFailureIsRetriedByTheNextRoute(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.charon.fail["load-conn"] = errInjected
	if err := h.ctl.HandleEVPNRoute(ctx, imet(100, "10.20.0.30", false)); !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want the load failure", err)
	}
	delete(h.charon.fail, "load-conn")
	if err := h.ctl.HandleEVPNRoute(ctx, imet(200, "10.20.0.30", false)); err != nil {
		t.Fatalf("second route: %v", err)
	}
	if _, loaded := h.charon.conns["vtep-10.20.0.30"]; !loaded {
		t.Fatal("the connection was never loaded")
	}
}

func TestEvictCutsThePeerOff(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	peer := addr("10.20.0.2")
	h.charon.sas["vtep-10.20.0.2"] = []string{"7", "9"}

	if err := h.ctl.Evict(ctx, peer); err != nil {
		t.Fatalf("Evict: %v", err)
	}
	if _, dropped := h.dropper.dropped[peer]; !dropped {
		t.Fatal("no kernel drop")
	}
	if _, loaded := h.charon.conns["vtep-10.20.0.2"]; loaded {
		t.Fatal("the connection, and with it the trap, is still loaded")
	}
	if !slices.Equal(h.charon.killed, []string{"7", "9"}) {
		t.Fatalf("terminated %v, want both IKE_SAs", h.charon.killed)
	}

	// A route naming the evicted peer does not bring it back.
	if err := h.ctl.HandleEVPNRoute(ctx, imet(100, "10.20.0.2", false)); err != nil {
		t.Fatalf("route: %v", err)
	}
	if _, loaded := h.charon.conns["vtep-10.20.0.2"]; loaded {
		t.Fatal("a route reloaded an evicted peer")
	}
	if slices.Contains(h.ctl.Peers(), peer) {
		t.Fatal("an evicted peer is still listed")
	}

	if err := h.ctl.Readmit(ctx, peer); err != nil {
		t.Fatalf("Readmit: %v", err)
	}
	if _, dropped := h.dropper.dropped[peer]; dropped {
		t.Fatal("the kernel drop outlived the readmission")
	}
	if _, loaded := h.charon.conns["vtep-10.20.0.2"]; !loaded {
		t.Fatal("a readmitted static peer was not reloaded")
	}
}

func TestEvictHoldsWithoutCharon(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.ctl.Detach()
	if err := h.ctl.Evict(ctx, addr("10.20.0.1")); err != nil {
		t.Fatalf("Evict while detached: %v", err)
	}
	restarted := newFakeCharon()
	if err := h.ctl.Attach(ctx, restarted); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if got := restarted.loaded(); !slices.Equal(got, []string{"vtep-10.20.0.2"}) {
		t.Fatalf("restarted charon holds %v, want only the peer still admitted", got)
	}
}

func TestEvictAndReadmitFailures(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var peerErr *PeerError

	if err := h.ctl.Evict(ctx, addr("10.20.0.11")); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("evicting the local VTEP: err = %v", err)
	}
	if err := h.ctl.Readmit(ctx, addr("10.20.0.1")); !errors.Is(err, ErrNotEvicted) {
		t.Fatalf("readmitting a live peer: err = %v", err)
	}

	h.dropper.fail = errInjected
	if err := h.ctl.Evict(ctx, addr("10.20.0.1")); !errors.As(err, &peerErr) || peerErr.Op != "drop" {
		t.Fatalf("drop failure: err = %v", err)
	}
	// The eviction stands although the kernel half failed: the peer is
	// not reloaded, and Readmit cannot lift a drop it cannot remove.
	if slices.Contains(h.ctl.Peers(), addr("10.20.0.1")) {
		t.Fatal("a failed eviction left the peer admitted")
	}
	if err := h.ctl.Readmit(ctx, addr("10.20.0.1")); !errors.As(err, &peerErr) || peerErr.Op != "undrop" {
		t.Fatalf("undrop failure: err = %v", err)
	}
	h.dropper.fail = nil

	h.charon.fail["list-sas"] = errInjected
	if err := h.ctl.Evict(ctx, addr("10.20.0.2")); !errors.As(err, &peerErr) || peerErr.Op != "list-sas" {
		t.Fatalf("list-sas failure: err = %v", err)
	}
	h.charon.fail["unload-conn"] = errInjected
	if err := h.ctl.Readmit(ctx, addr("10.20.0.2")); err != nil {
		t.Fatalf("Readmit: %v", err)
	}
	if err := h.ctl.Evict(ctx, addr("10.20.0.2")); !errors.As(err, &peerErr) || peerErr.Op != "unload-conn" {
		t.Fatalf("unload failure: err = %v", err)
	}
}

func updown(name string, kv map[string]string) vici.Event {
	sa := vici.NewMessage()
	for k, v := range kv {
		sa.SetValue(k, v)
	}
	msg := vici.NewMessage()
	msg.SetSection(name, sa)
	return vici.Event{Name: "ike-updown", Message: msg}
}

func TestIdentityCheck(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		ev       vici.Event
		mismatch bool
	}{
		{"matching identity", updown("vtep-10.20.0.1", map[string]string{
			"up": "yes", "remote-host": "10.20.0.1", "remote-id": "10.20.0.1", "uniqueid": "4"}), false},
		{"identity of another node", updown("vtep-10.20.0.1", map[string]string{
			"up": "yes", "remote-host": "10.20.0.1", "remote-id": "10.20.0.2", "uniqueid": "4"}), true},
		{"distinguished-name identity", updown("vtep-10.20.0.1", map[string]string{
			"up": "yes", "remote-host": "10.20.0.1", "remote-id": "CN=10.20.0.1", "uniqueid": "4"}), true},
		{"SA from another address", updown("vtep-10.20.0.1", map[string]string{
			"up": "yes", "remote-host": "10.20.0.66", "remote-id": "10.20.0.1", "uniqueid": "4"}), true},
		{"SA going down", updown("vtep-10.20.0.1", map[string]string{
			"remote-host": "10.20.0.1", "remote-id": "10.20.0.2", "uniqueid": "4"}), false},
		{"connection not ours", updown("operator-test", map[string]string{
			"up": "yes", "remote-host": "10.20.0.1", "remote-id": "10.20.0.2", "uniqueid": "4"}), false},
		{"other event", vici.Event{Name: "child-updown", Message: vici.NewMessage()}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			err := h.ctl.HandleEvent(ctx, tt.ev)
			var mismatch *IdentityMismatchError
			if got := errors.As(err, &mismatch); got != tt.mismatch {
				t.Fatalf("err = %v, want mismatch=%v", err, tt.mismatch)
			}
			wantKilled := []string(nil)
			if tt.mismatch {
				wantKilled = []string{"4"}
			}
			if !slices.Equal(h.charon.killed, wantKilled) {
				t.Fatalf("terminated %v, want %v", h.charon.killed, wantKilled)
			}
		})
	}
}

func TestIdentityMismatchStillReportedWhenTerminateFails(t *testing.T) {
	h := newHarness(t)
	h.charon.fail["terminate"] = errInjected
	ev := updown("vtep-10.20.0.1", map[string]string{
		"up": "yes", "remote-host": "10.20.0.1", "remote-id": "10.20.0.2", "uniqueid": "4"})
	err := h.ctl.HandleEvent(context.Background(), ev)
	var mismatch *IdentityMismatchError
	if !errors.As(err, &mismatch) || !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want the mismatch and the terminate failure", err)
	}
	if mismatch.RemoteID != "10.20.0.2" || mismatch.Error() != "ipsec: vtep-10.20.0.1: peer at 10.20.0.1 authenticated as 10.20.0.2" {
		t.Fatalf("mismatch = %q", mismatch.Error())
	}
}
