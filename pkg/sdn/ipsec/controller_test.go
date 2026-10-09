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
	"math/big"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

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
	charon   *fakeSession
	admitter *fakeAdmitter
	dropper  *fakeDropper
	identity *fakeIdentity
	pki      *testPKI
}

// newDetachedHarness builds a controller for validConfig (static peers
// 10.20.0.1 and 10.20.0.2) with the test PKI's identity, not yet attached.
func newDetachedHarness(t *testing.T) *harness {
	t.Helper()
	pki := newTestPKI(t)
	h := &harness{
		charon:   newFakeSession(),
		admitter: &fakeAdmitter{refuse: make(map[netip.Addr]error)},
		dropper:  &fakeDropper{dropped: make(map[netip.Addr]struct{})},
		identity: &fakeIdentity{id: pki.identity(newSecret(t, "1234"))},
		pki:      pki,
	}
	ctl, err := NewController(validConfig(), h.admitter, h.dropper, h.identity)
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	// The test PKI's CRLs are current an hour after issue.
	ctl.now = func() time.Time { return pki.issued.Add(time.Hour) }
	h.ctl = ctl
	return h
}

// newHarness is newDetachedHarness attached to an empty charon.
func newHarness(t *testing.T) *harness {
	t.Helper()
	h := newDetachedHarness(t)
	if err := h.ctl.Attach(context.Background(), h.charon); err != nil {
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
	admitter, dropper, identity := &fakeAdmitter{}, &fakeDropper{}, &fakeIdentity{}
	invalid := validConfig()
	invalid.Token.Handle = ""
	tests := []struct {
		name     string
		cfg      *Config
		admitter Admitter
		dropper  Dropper
		identity IdentityProvider
		want     error
	}{
		{"absent section", nil, admitter, dropper, identity, ErrNotEnabled},
		{"disabled section", &Config{}, admitter, dropper, identity, ErrNotEnabled},
		{"no admitter", validConfig(), nil, dropper, identity, ErrMissingDependency},
		{"no dropper", validConfig(), admitter, nil, identity, ErrMissingDependency},
		{"no identity", validConfig(), admitter, dropper, nil, ErrMissingDependency},
		{"invalid section", invalid, admitter, dropper, identity, ErrRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewController(tt.cfg, tt.admitter, tt.dropper, tt.identity); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAttachLoadsStaticPeersAndPrunesStale(t *testing.T) {
	h := newDetachedHarness(t)
	// charon outlived a platformd that knew 10.20.0.9; someone else's
	// connection sits beside it.
	charon := newFakeSession("vtep-10.20.0.9", "vtep-10.20.0.1", "operator-test")
	if err := h.ctl.Attach(context.Background(), charon); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	want := []string{"operator-test", "vtep-10.20.0.1", "vtep-10.20.0.2"}
	if got := charon.loaded(); !slices.Equal(got, want) {
		t.Fatalf("charon holds %v, want %v", got, want)
	}

	if err := h.ctl.Attach(context.Background(), nil); !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("Attach(nil): err = %v", err)
	}
}

func TestAttachLoadsTheIdentityFirst(t *testing.T) {
	h := newHarness(t)
	want := []Credential{
		{Kind: CredentialEndEntity, DER: h.pki.leaf.Raw},
		{Kind: CredentialAuthority, DER: h.pki.ca.Raw},
	}
	if !slices.EqualFunc(h.charon.certs, want, func(a, b Credential) bool {
		return a.Kind == b.Kind && bytes.Equal(a.DER, b.DER)
	}) {
		t.Fatalf("loaded %d credentials, want the leaf then the CA", len(h.charon.certs))
	}
	if len(h.charon.tokens) != 1 || !bytes.Equal(h.charon.tokens[0].KeyID, []byte("ipsec")) {
		t.Fatalf("tokens = %v, want the identity's key", h.charon.tokens)
	}
	if !bytes.Equal(h.charon.pins[0], []byte("1234")) {
		t.Fatal("load-token did not log in with the identity's PIN")
	}
	if first := slices.Index(h.charon.commands, "load-conn"); first < slices.Index(h.charon.commands, "load-token") {
		t.Fatalf("commands %v: a connection was loaded before the identity", h.charon.commands)
	}
}

func TestAttachWithoutPIN(t *testing.T) {
	h := newDetachedHarness(t)
	h.identity.id = h.pki.identity(nil)
	if err := h.ctl.Attach(context.Background(), h.charon); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if len(h.charon.pins) != 1 || h.charon.pins[0] != nil {
		t.Fatalf("pins = %v, want one load-token without a PIN", h.charon.pins)
	}
}

func TestAttachIdentityFailuresLeaveItDetached(t *testing.T) {
	pki := newTestPKI(t)
	other := pki.identity(nil)
	other.Chain = []*x509.Certificate{pki.ca}
	noKey := pki.identity(nil)
	noKey.Token.KeyID = nil

	tests := []struct {
		name   string
		id     *fakeIdentity
		fail   string
		op     string
		reason error
	}{
		{"provider fails", &fakeIdentity{err: errInjected}, "", "identity", errInjected},
		{"no identity", &fakeIdentity{}, "", "identity", ErrNoCertificate},
		{"certificate for another address", &fakeIdentity{id: other}, "", "identity", ErrCertificateAddress},
		{"no key", &fakeIdentity{id: noKey}, "", "identity", ErrNoKeyID},
		{"load-cert refused", &fakeIdentity{id: pki.identity(nil)}, "load-cert", "load-cert", errInjected},
		{"load-token refused", &fakeIdentity{id: pki.identity(nil)}, "load-token", "load-token", errInjected},
		{"get-conns fails", &fakeIdentity{id: pki.identity(nil)}, "get-conns", "get-conns", errInjected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctl, err := NewController(validConfig(), &fakeAdmitter{}, &fakeDropper{}, tt.id)
			if err != nil {
				t.Fatalf("NewController: %v", err)
			}
			charon := newFakeSession()
			if tt.fail != "" {
				charon.fail[tt.fail] = errInjected
			}
			err = ctl.Attach(context.Background(), charon)
			var opErr *OpError
			if !errors.As(err, &opErr) || opErr.Op != tt.op || !errors.Is(err, tt.reason) {
				t.Fatalf("err = %v, want a %s OpError for %v", err, tt.op, tt.reason)
			}
			if ctl.attached() || len(charon.conns) != 0 {
				t.Fatal("a failed identity load left the controller attached")
			}
		})
	}
}

func TestAttachReportsEveryPeerFailure(t *testing.T) {
	h := newDetachedHarness(t)
	h.charon.fail["load-conn"] = errInjected
	err := h.ctl.Attach(context.Background(), h.charon)
	var peerErr *PeerError
	if !errors.As(err, &peerErr) || peerErr.Op != "load-conn" {
		t.Fatalf("err = %v, want a load-conn PeerError", err)
	}
	if got := len(slices.DeleteFunc(slices.Clone(h.charon.commands), func(c string) bool { return c != "load-conn" })); got != 2 {
		t.Fatalf("load-conn tried %d times, want once per static peer", got)
	}
	if !h.ctl.attached() {
		t.Fatal("peer failures detached the controller")
	}
}

func TestPushCRL(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	day := h.pki.issued
	first := h.pki.crl(t, 1, day)

	if err := h.ctl.PushCRL(ctx, first); err != nil {
		t.Fatalf("PushCRL: %v", err)
	}
	if got := h.charon.crls(); len(got) != 1 || !bytes.Equal(got[0], first) {
		t.Fatal("the CRL was not loaded into the attached charon")
	}

	// An older or equal CRL is ignored; a newer one replaces it.
	if err := h.ctl.PushCRL(ctx, h.pki.crl(t, 1, day.Add(time.Hour))); err != nil {
		t.Fatalf("PushCRL(same number): %v", err)
	}
	if len(h.charon.crls()) != 1 {
		t.Fatal("a CRL with the same number was loaded")
	}
	newer := h.pki.crl(t, 2, day.Add(time.Hour))
	if err := h.ctl.PushCRL(ctx, newer); err != nil {
		t.Fatalf("PushCRL(newer): %v", err)
	}
	if got := h.charon.crls(); len(got) != 2 || !bytes.Equal(got[1], newer) {
		t.Fatal("the newer CRL was not loaded")
	}
	if got := h.ctl.Status().CRLs; got != 1 {
		t.Fatalf("Status().CRLs = %d, want one issuer", got)
	}

	// A restarted charon gets the newest CRL before any connection.
	restarted := newFakeSession()
	if err := h.ctl.Attach(ctx, restarted); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if got := restarted.crls(); len(got) != 1 || !bytes.Equal(got[0], newer) {
		t.Fatal("the held CRL was not pushed on attach")
	}
	if slices.Index(restarted.commands, "load-crl") > slices.Index(restarted.commands, "load-conn") {
		t.Fatalf("commands %v: a connection was loaded before the CRL", restarted.commands)
	}
}

func TestPushCRLFailures(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var opErr *OpError
	if err := h.ctl.PushCRL(ctx, []byte("not a crl")); !errors.As(err, &opErr) || opErr.Op != "parse crl" {
		t.Fatalf("garbage: err = %v, want a parse crl OpError", err)
	}

	h.charon.fail["load-crl"] = errInjected
	crl := h.pki.crl(t, 1, h.pki.issued)
	if err := h.ctl.PushCRL(ctx, crl); !errors.As(err, &opErr) || opErr.Op != "load-cert x509crl" || !errors.Is(err, errInjected) {
		t.Fatalf("refused: err = %v, want a load-cert x509crl OpError", err)
	}
	// The CRL is held although charon refused it, and a charon that cannot
	// take it cannot be attached.
	restarted := newFakeSession()
	restarted.fail["load-crl"] = errInjected
	if err := h.ctl.Attach(ctx, restarted); !errors.As(err, &opErr) || opErr.Op != "load-cert x509crl" {
		t.Fatalf("Attach: err = %v, want the CRL refusal", err)
	}
	if h.ctl.attached() {
		t.Fatal("attached without the CRL")
	}
}

func TestPushCRLWhileDetached(t *testing.T) {
	h := newDetachedHarness(t)
	ctx := context.Background()
	later := h.pki.crl(t, 2, h.pki.issued)
	for _, crl := range [][]byte{h.pki.crl(t, 1, h.pki.issued), later, h.pki.crl(t, 1, h.pki.issued.Add(time.Hour))} {
		if err := h.ctl.PushCRL(ctx, crl); err != nil {
			t.Fatalf("PushCRL: %v", err)
		}
	}
	if err := h.ctl.Attach(ctx, h.charon); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if got := h.charon.crls(); len(got) != 1 || !bytes.Equal(got[0], later) {
		t.Fatal("attach did not load the highest-numbered CRL alone")
	}
}

func TestPushCRLRefusesStaleAndUntrustedCRLs(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	held := h.pki.crl(t, 1, h.pki.issued)
	if err := h.ctl.PushCRL(ctx, held); err != nil {
		t.Fatalf("PushCRL: %v", err)
	}
	tests := []struct {
		name string
		der  []byte
		want error
	}{
		// Higher numbers, so only the check stands between them and charon.
		{"past its next update", h.pki.crl(t, 5, h.pki.issued.Add(-48*time.Hour)), ErrCRLStale},
		{"signed by another CA of the same name", newTestPKI(t).crl(t, 6, h.pki.issued), ErrCRLUntrusted},
	}
	for _, tt := range tests {
		var opErr *OpError
		if err := h.ctl.PushCRL(ctx, tt.der); !errors.As(err, &opErr) || opErr.Op != "verify crl" || !errors.Is(err, tt.want) {
			t.Fatalf("%s: err = %v, want a verify crl OpError for %v", tt.name, err, tt.want)
		}
	}
	if got := h.charon.crls(); len(got) != 1 || !bytes.Equal(got[0], held) || h.ctl.Status().CRLs != 1 {
		t.Fatal("a refused CRL reached charon or replaced the one held")
	}
}

func TestPushCRLBeforeTheFirstAttach(t *testing.T) {
	h := newDetachedHarness(t)
	ctx := context.Background()
	crl := h.pki.crl(t, 1, h.pki.issued)

	// Before any attach the CAs come from the identity provider.
	h.identity.err = errInjected
	var opErr *OpError
	if err := h.ctl.PushCRL(ctx, crl); !errors.As(err, &opErr) || opErr.Op != "identity" || !errors.Is(err, errInjected) {
		t.Fatalf("no identity: err = %v, want an identity OpError", err)
	}
	h.identity.err = nil
	if err := h.ctl.PushCRL(ctx, crl); err != nil {
		t.Fatalf("PushCRL: %v", err)
	}
	if h.ctl.Status().CRLs != 1 {
		t.Fatal("the verified CRL is not held")
	}
}

func TestVerifyCRL(t *testing.T) {
	pki := newTestPKI(t)
	parse := func(der []byte) *x509.RevocationList {
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		return crl
	}
	crl := parse(pki.crl(t, 1, pki.issued))
	cas := []*x509.Certificate{pki.leaf, pki.ca}
	tests := []struct {
		name string
		crl  *x509.RevocationList
		cas  []*x509.Certificate
		now  time.Time
		want error
	}{
		{"current, signed by a CA", crl, cas, pki.issued, nil},
		{"at its next update", crl, cas, crl.NextUpdate, ErrCRLStale},
		{"without a next update", &x509.RevocationList{RawIssuer: crl.RawIssuer}, cas, pki.issued, ErrCRLStale},
		{"no CA", crl, nil, pki.issued, ErrCRLUntrusted},
		{"only a certificate of another name", crl, []*x509.Certificate{pki.leaf}, pki.issued, ErrCRLUntrusted},
		{"another key", parse(newTestPKI(t).crl(t, 1, pki.issued)), cas, pki.issued, ErrCRLUntrusted},
	}
	for _, tt := range tests {
		if err := verifyCRL(tt.crl, tt.cas, tt.now); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestSupersedes(t *testing.T) {
	day := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	crl := func(number int64, at time.Time) *x509.RevocationList {
		l := &x509.RevocationList{ThisUpdate: at}
		if number > 0 {
			l.Number = big.NewInt(number)
		}
		return l
	}
	tests := []struct {
		name       string
		next, prev *x509.RevocationList
		want       bool
	}{
		{"higher number", crl(2, day), crl(1, day.Add(time.Hour)), true},
		{"same number, later", crl(1, day.Add(time.Hour)), crl(1, day), false},
		{"lower number", crl(1, day.Add(time.Hour)), crl(2, day), false},
		{"no numbers, later", crl(0, day.Add(time.Hour)), crl(0, day), true},
		{"no numbers, same time", crl(0, day), crl(0, day), false},
		{"one number missing, earlier", crl(3, day), crl(0, day.Add(time.Hour)), false},
	}
	for _, tt := range tests {
		if got := supersedes(tt.next, tt.prev); got != tt.want {
			t.Errorf("%s: supersedes = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestStatus(t *testing.T) {
	h := newDetachedHarness(t)
	if s := h.ctl.Status(); s.Attached || s.Certificate != nil || len(s.Peers) != 2 {
		t.Fatalf("detached status = %+v", s)
	}
	h.ctl.now = func() time.Time { return h.pki.issued.Add(40 * time.Hour) }
	if err := h.ctl.Attach(context.Background(), h.charon); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := h.ctl.Evict(context.Background(), addr("10.20.0.2")); err != nil {
		t.Fatalf("Evict: %v", err)
	}
	s := h.ctl.Status()
	if !s.Attached || !slices.Equal(s.Peers, []netip.Addr{addr("10.20.0.1")}) || !slices.Equal(s.Evicted, []netip.Addr{addr("10.20.0.2")}) {
		t.Fatalf("status = %+v", s)
	}
	cert := s.Certificate
	if cert == nil || cert.Serial != "2a" || cert.TimeToExpiry != 32*time.Hour || !cert.RenewalDue || cert.Alert {
		t.Fatalf("certificate status = %+v, want renewal due 40h into a 72h lifetime", cert)
	}
}

func TestCertificateStatusThresholds(t *testing.T) {
	pki := newTestPKI(t)
	tests := []struct {
		at         time.Duration // since NotBefore, of a 72h lifetime
		due, alert bool
	}{
		{0, false, false},
		{36*time.Hour - time.Second, false, false},
		{36 * time.Hour, true, false},
		{54*time.Hour - time.Second, true, false},
		{54 * time.Hour, true, true},
		{80 * time.Hour, true, true},
	}
	for _, tt := range tests {
		s := certificateStatus(pki.leaf, pki.issued.Add(tt.at))
		if s.RenewalDue != tt.due || s.Alert != tt.alert {
			t.Errorf("at %v: due=%v alert=%v, want %v %v", tt.at, s.RenewalDue, s.Alert, tt.due, tt.alert)
		}
		if want := 72*time.Hour - tt.at; s.TimeToExpiry != want {
			t.Errorf("at %v: time to expiry %v, want %v", tt.at, s.TimeToExpiry, want)
		}
	}
	s := certificateStatus(pki.leaf, pki.issued)
	if !s.RenewAt.Equal(pki.issued.Add(36*time.Hour)) || !s.AlertAt.Equal(pki.issued.Add(54*time.Hour)) {
		t.Fatalf("renew at %v, alert at %v", s.RenewAt, s.AlertAt)
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

	restarted := newFakeSession()
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
	h.charon.sas["vtep-10.20.0.2"] = []IKESA{{UniqueID: "7"}, {UniqueID: "9"}}

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
	restarted := newFakeSession()
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

	if err := h.ctl.Evict(ctx, addr("10.20.0.1")); err != nil {
		t.Fatalf("Evict: %v", err)
	}
	h.dropper.fail = errInjected
	if err := h.ctl.Readmit(ctx, addr("10.20.0.1")); !errors.As(err, &peerErr) || peerErr.Op != "undrop" {
		t.Fatalf("undrop failure: err = %v", err)
	}
	// The eviction stands while the drop cannot be lifted.
	if slices.Contains(h.ctl.Peers(), addr("10.20.0.1")) {
		t.Fatal("a failed readmission admitted the peer")
	}
	h.dropper.fail = nil

	h.charon.fail["list-sas"] = errInjected
	if err := h.ctl.Evict(ctx, addr("10.20.0.2")); !errors.As(err, &peerErr) || peerErr.Op != "list-sas" {
		t.Fatalf("list-sas failure: err = %v", err)
	}
	delete(h.charon.fail, "list-sas")
	h.charon.fail["unload-conn"] = errInjected
	if err := h.ctl.Readmit(ctx, addr("10.20.0.2")); err != nil {
		t.Fatalf("Readmit: %v", err)
	}
	if err := h.ctl.Evict(ctx, addr("10.20.0.2")); !errors.As(err, &peerErr) || peerErr.Op != "unload-conn" {
		t.Fatalf("unload failure: err = %v", err)
	}
}

func TestEvictRunsEveryStepWhenTheDropFails(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	peer := addr("10.20.0.2")
	h.charon.sas["vtep-10.20.0.2"] = []IKESA{{UniqueID: "7"}}
	h.dropper.fail = errInjected

	var peerErr *PeerError
	if err := h.ctl.Evict(ctx, peer); !errors.As(err, &peerErr) || peerErr.Op != "drop" {
		t.Fatalf("Evict: err = %v, want the drop failure", err)
	}
	if _, loaded := h.charon.conns["vtep-10.20.0.2"]; loaded {
		t.Fatal("a failed drop left the connection loaded")
	}
	if !slices.Equal(h.charon.killed, []string{"7"}) {
		t.Fatalf("terminated %v, want the IKE_SA although the drop failed", h.charon.killed)
	}
	s := h.ctl.Status()
	if !slices.Equal(s.Evicted, []netip.Addr{peer}) || !slices.Equal(s.DropPending, []netip.Addr{peer}) || len(s.Unsynced) != 0 {
		t.Fatalf("status = %+v, want the peer evicted with its drop pending", s)
	}
	select {
	case <-h.ctl.retry:
	default:
		t.Fatal("the failed drop did not signal a retry")
	}

	// Converge retries the drop until it holds.
	if err := h.ctl.Converge(ctx); !errors.Is(err, errInjected) {
		t.Fatalf("Converge with the drop still failing: err = %v", err)
	}
	h.dropper.fail = nil
	if err := h.ctl.Converge(ctx); err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if _, dropped := h.dropper.dropped[peer]; !dropped {
		t.Fatal("Converge did not apply the drop")
	}
	if s := h.ctl.Status(); len(s.DropPending) != 0 {
		t.Fatalf("drop still pending after Converge: %+v", s)
	}
}

func TestEvictUnloadFailureStillTerminates(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	peer := addr("10.20.0.2")
	h.charon.sas["vtep-10.20.0.2"] = []IKESA{{UniqueID: "7"}}
	h.charon.fail["unload-conn"] = errInjected

	var peerErr *PeerError
	if err := h.ctl.Evict(ctx, peer); !errors.As(err, &peerErr) || peerErr.Op != "unload-conn" {
		t.Fatalf("Evict: err = %v, want the unload failure", err)
	}
	if _, dropped := h.dropper.dropped[peer]; !dropped {
		t.Fatal("no kernel drop")
	}
	if !slices.Equal(h.charon.killed, []string{"7"}) {
		t.Fatalf("terminated %v, want the IKE_SA although the unload failed", h.charon.killed)
	}
	if s := h.ctl.Status(); !slices.Equal(s.Unsynced, []netip.Addr{peer}) || len(s.DropPending) != 0 {
		t.Fatalf("status = %+v, want the peer unsynced", s)
	}

	// An SA that came up meanwhile is ended by the retry, with the unload.
	delete(h.charon.fail, "unload-conn")
	h.charon.sas["vtep-10.20.0.2"] = []IKESA{{UniqueID: "8"}}
	if err := h.ctl.Converge(ctx); err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if _, loaded := h.charon.conns["vtep-10.20.0.2"]; loaded {
		t.Fatal("Converge did not unload the connection")
	}
	if !slices.Equal(h.charon.killed, []string{"7", "8"}) {
		t.Fatalf("terminated %v, want the retry to end the new SA", h.charon.killed)
	}
	if s := h.ctl.Status(); len(s.Unsynced) != 0 {
		t.Fatalf("still unsynced after Converge: %+v", s)
	}
}

func TestReadmitWithThePendingDrop(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	peer := addr("10.20.0.2")
	h.dropper.fail = errInjected
	if err := h.ctl.Evict(ctx, peer); !errors.Is(err, errInjected) {
		t.Fatalf("Evict: err = %v", err)
	}
	// The drop never went in, so there is none to lift: the dropper is
	// not asked, and the readmission does not fail on it.
	if err := h.ctl.Readmit(ctx, peer); err != nil {
		t.Fatalf("Readmit: %v", err)
	}
	if s := h.ctl.Status(); len(s.DropPending) != 0 || len(s.Evicted) != 0 {
		t.Fatalf("status = %+v, want nothing pending", s)
	}
	if _, loaded := h.charon.conns["vtep-10.20.0.2"]; !loaded {
		t.Fatal("the readmitted peer was not reloaded")
	}
}

func TestConvergeWhileDetachedRetriesOnlyDrops(t *testing.T) {
	h := newDetachedHarness(t)
	ctx := context.Background()
	peer := addr("10.20.0.2")
	h.dropper.fail = errInjected
	if err := h.ctl.Evict(ctx, peer); !errors.Is(err, errInjected) {
		t.Fatalf("Evict: err = %v", err)
	}
	h.dropper.fail = nil
	if err := h.ctl.Converge(ctx); err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if _, dropped := h.dropper.dropped[peer]; !dropped {
		t.Fatal("Converge did not apply the drop while detached")
	}
	if len(h.charon.commands) != 0 {
		t.Fatalf("Converge reached charon while detached: %v", h.charon.commands)
	}
}

func TestAttachEndsSAsOfPeersEvictedWhileDetached(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.ctl.Detach()
	if err := h.ctl.Evict(ctx, addr("10.20.0.2")); err != nil {
		t.Fatalf("Evict: %v", err)
	}
	// charon kept running: it still holds the connection and its SA.
	same := newFakeSession("vtep-10.20.0.1", "vtep-10.20.0.2")
	same.sas["vtep-10.20.0.2"] = []IKESA{{UniqueID: "7", RemoteHost: "10.20.0.2", RemoteID: "10.20.0.2"}}
	if err := h.ctl.Attach(ctx, same); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if !slices.Equal(same.killed, []string{"7"}) {
		t.Fatalf("terminated %v, want the evicted peer's SA", same.killed)
	}
	if got := same.loaded(); !slices.Equal(got, []string{"vtep-10.20.0.1"}) {
		t.Fatalf("charon holds %v, want the evicted peer's connection gone", got)
	}
}

func updown(up bool, name string, sa IKESA) IKEUpdown {
	return IKEUpdown{Up: up, SAs: map[string]IKESA{name: sa}}
}

func TestIdentityCheck(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		ev       IKEUpdown
		mismatch bool
		killed   []string
	}{
		{"matching identity", updown(true, "vtep-10.20.0.1",
			IKESA{UniqueID: "4", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.1"}), false, nil},
		{"identity of another node", updown(true, "vtep-10.20.0.1",
			IKESA{UniqueID: "4", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.2"}), true, []string{"4"}},
		{"distinguished-name identity", updown(true, "vtep-10.20.0.1",
			IKESA{UniqueID: "4", RemoteHost: "10.20.0.1", RemoteID: "CN=10.20.0.1"}), true, []string{"4"}},
		{"SA from another address", updown(true, "vtep-10.20.0.1",
			IKESA{UniqueID: "4", RemoteHost: "10.20.0.66", RemoteID: "10.20.0.1"}), true, []string{"4"}},
		{"unreadable SA", updown(true, "vtep-10.20.0.1", IKESA{}), true, nil},
		{"SA going down", updown(false, "vtep-10.20.0.1",
			IKESA{UniqueID: "4", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.2"}), false, nil},
		{"connection not ours", updown(true, "operator-test",
			IKESA{UniqueID: "4", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.2"}), false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			err := h.ctl.HandleEvent(ctx, tt.ev)
			var mismatch *IdentityMismatchError
			if got := errors.As(err, &mismatch); got != tt.mismatch {
				t.Fatalf("err = %v, want mismatch=%v", err, tt.mismatch)
			}
			if !slices.Equal(h.charon.killed, tt.killed) {
				t.Fatalf("terminated %v, want %v", h.charon.killed, tt.killed)
			}
		})
	}
}

func TestIdentityMismatchWhileDetached(t *testing.T) {
	h := newHarness(t)
	h.ctl.Detach()
	ev := updown(true, "vtep-10.20.0.1", IKESA{UniqueID: "4", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.2"})
	var mismatch *IdentityMismatchError
	if err := h.ctl.HandleEvent(context.Background(), ev); !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want the mismatch", err)
	}
	if len(h.charon.killed) != 0 {
		t.Fatal("a detached controller drove the old session")
	}
}

func TestIdentityMismatchStillReportedWhenTerminateFails(t *testing.T) {
	h := newHarness(t)
	h.charon.fail["terminate"] = errInjected
	ev := updown(true, "vtep-10.20.0.1", IKESA{UniqueID: "4", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.2"})
	err := h.ctl.HandleEvent(context.Background(), ev)
	var mismatch *IdentityMismatchError
	if !errors.As(err, &mismatch) || !errors.Is(err, errInjected) {
		t.Fatalf("err = %v, want the mismatch and the terminate failure", err)
	}
	if !h.ctl.Status().AuditPending {
		t.Fatal("an SA left up did not leave an audit pending")
	}
	if mismatch.RemoteID != "10.20.0.2" || mismatch.Error() != "ipsec: vtep-10.20.0.1: peer at 10.20.0.1 authenticated as 10.20.0.2" {
		t.Fatalf("mismatch = %q", mismatch.Error())
	}
}

func TestHandleEventEndsSAsOfEvictedPeers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.ctl.Evict(ctx, addr("10.20.0.2")); err != nil {
		t.Fatalf("Evict: %v", err)
	}
	// The peer authenticated correctly, but it is evicted.
	ev := updown(true, "vtep-10.20.0.2", IKESA{UniqueID: "5", RemoteHost: "10.20.0.2", RemoteID: "10.20.0.2"})
	if err := h.ctl.HandleEvent(ctx, ev); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if !slices.Equal(h.charon.killed, []string{"5"}) {
		t.Fatalf("terminated %v, want the evicted peer's SA", h.charon.killed)
	}
}

// heldSAs gives charon one good SA, one of another identity, and one of a
// connection the controller does not own.
func heldSAs(f *fakeSession) {
	f.sas["vtep-10.20.0.1"] = []IKESA{{UniqueID: "1", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.1"}}
	f.sas["vtep-10.20.0.2"] = []IKESA{{UniqueID: "2", RemoteHost: "10.20.0.2", RemoteID: "10.20.0.66"}}
	f.sas["operator-test"] = []IKESA{{UniqueID: "3", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.2"}}
}

func TestAuditChecksEverySA(t *testing.T) {
	h := newHarness(t)
	heldSAs(h.charon)
	err := h.ctl.Audit(context.Background())
	var mismatch *IdentityMismatchError
	if !errors.As(err, &mismatch) || mismatch.Conn != "vtep-10.20.0.2" {
		t.Fatalf("err = %v, want the mismatch on vtep-10.20.0.2", err)
	}
	if !slices.Equal(h.charon.killed, []string{"2"}) {
		t.Fatalf("terminated %v, want only the mismatched SA", h.charon.killed)
	}
}

func TestAttachAuditsHeldSAs(t *testing.T) {
	h := newDetachedHarness(t)
	heldSAs(h.charon)
	var mismatch *IdentityMismatchError
	if err := h.ctl.Attach(context.Background(), h.charon); !errors.As(err, &mismatch) {
		t.Fatalf("Attach: err = %v, want the mismatch the audit found", err)
	}
	if !h.ctl.attached() || !slices.Equal(h.charon.killed, []string{"2"}) {
		t.Fatalf("attached=%v, terminated %v, want attached with the mismatched SA ended", h.ctl.attached(), h.charon.killed)
	}
}

func TestAuditFailureIsRetried(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	heldSAs(h.charon)
	h.charon.fail["list-sas"] = errInjected
	var opErr *OpError
	if err := h.ctl.Audit(ctx); !errors.As(err, &opErr) || opErr.Op != "list-sas" {
		t.Fatalf("Audit: err = %v, want a list-sas OpError", err)
	}
	if !h.ctl.Status().AuditPending {
		t.Fatal("a failed audit is not pending")
	}
	select {
	case <-h.ctl.retry:
	default:
		t.Fatal("a failed audit did not signal a retry")
	}

	delete(h.charon.fail, "list-sas")
	var mismatch *IdentityMismatchError
	if err := h.ctl.Converge(ctx); !errors.As(err, &mismatch) {
		t.Fatalf("Converge: err = %v, want the audit's mismatch", err)
	}
	if h.ctl.Status().AuditPending || !slices.Equal(h.charon.killed, []string{"2"}) {
		t.Fatalf("pending=%v, terminated %v after the retried audit", h.ctl.Status().AuditPending, h.charon.killed)
	}
}

func TestAuditWhileDetached(t *testing.T) {
	h := newDetachedHarness(t)
	if err := h.ctl.Audit(context.Background()); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(h.charon.commands) != 0 {
		t.Fatalf("a detached audit reached charon: %v", h.charon.commands)
	}
}

func TestLostEventAuditsEverySA(t *testing.T) {
	h := newHarness(t)
	heldSAs(h.charon)
	// The event itself carries nothing wrong; the SA that is wrong was missed.
	ev := updown(true, "vtep-10.20.0.1", IKESA{UniqueID: "1", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.1"})
	ev.Lost = true
	var mismatch *IdentityMismatchError
	if err := h.ctl.HandleEvent(context.Background(), ev); !errors.As(err, &mismatch) {
		t.Fatalf("HandleEvent: err = %v, want the mismatch the audit found", err)
	}
	if !slices.Equal(h.charon.killed, []string{"2"}) {
		t.Fatalf("terminated %v, want the missed mismatched SA", h.charon.killed)
	}
	// A Lost event with no SAs audits as well.
	h.charon.sas["vtep-10.20.0.1"] = []IKESA{{UniqueID: "6", RemoteHost: "10.20.0.1", RemoteID: "10.20.0.9"}}
	if err := h.ctl.HandleEvent(context.Background(), IKEUpdown{Lost: true}); !errors.As(err, &mismatch) {
		t.Fatalf("HandleEvent(Lost): err = %v", err)
	}
	if !slices.Equal(h.charon.killed, []string{"2", "6"}) {
		t.Fatalf("terminated %v", h.charon.killed)
	}
}
