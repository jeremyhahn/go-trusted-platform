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
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
	"github.com/vishvananda/netlink"
)

// serviceHarness is a Service over fakes: nf_tables, the XFRM database,
// charon and an identity from a PKI whose CA is an intermediate under a
// root, so CRLs of two issuers apply.
type serviceHarness struct {
	svc      *Service
	nft      *fakeNFT
	xfrm     *fakeXFRM
	identity *fakeIdentity
	root     *testPKI
	pki      *testPKI
}

func newTestService(t *testing.T, cfg *config.Config, attempts ...attempt) *serviceHarness {
	t.Helper()
	return newTestEVPNService(t, cfg, staticPeersOnly{}, attempts...)
}

func newTestEVPNService(t *testing.T, cfg *config.Config, admitter Admitter, attempts ...attempt) *serviceHarness {
	t.Helper()
	root := newTestPKI(t)
	pki := root.intermediate(t, "tunnel intermediate")
	filter, nft := newTestFilter(t, cfg)
	block, x := testBlockPolicy(t, cfg)
	identity := &fakeIdentity{id: pki.identity(nil)}
	svc, err := newService(cfg, admitter, filter, block, identity, &fakeDialer{attempts: attempts}, nil)
	if err != nil {
		t.Fatalf("newService: %v", err)
	}
	svc.ctl.now = func() time.Time { return pki.issued.Add(time.Hour) }
	return &serviceHarness{svc: svc, nft: nft, xfrm: x, identity: identity, root: root, pki: pki}
}

// serviceConfig is validConfig with CRL files in a fresh directory.
func serviceConfig(t *testing.T, names ...string) *config.Config {
	t.Helper()
	cfg := validConfig()
	dir := t.TempDir()
	for _, name := range names {
		cfg.CRLFiles = append(cfg.CRLFiles, filepath.Join(dir, name))
	}
	return cfg
}

// putFile writes data to path, replacing what is there.
func putFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func pemCRL(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

func TestNewServiceRejects(t *testing.T) {
	noCRLs := validConfig()
	noCRLs.CertificateFile = "/etc/platform/ipsec/tunnel.pem"
	noCertificate := validConfig()
	noCertificate.CRLFiles = []string{"/etc/platform/ipsec/tunnel.crl"}
	tests := []struct {
		name  string
		cfg   *config.Config
		want  error
		field string
	}{
		{"absent section", nil, config.ErrNotEnabled, ""},
		{"disabled section", &config.Config{}, config.ErrNotEnabled, ""},
		{"no CRL files", noCRLs, config.ErrRequired, "crl-files"},
		{"no certificate file", noCertificate, config.ErrRequired, "certificate-file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewService(tt.cfg, &fakeAnchor{}, nil)
			if svc != nil || !errors.Is(err, tt.want) {
				t.Fatalf("NewService = %v, %v; want %v", svc, err, tt.want)
			}
			var cfgErr *config.ConfigError
			if tt.field != "" && (!errors.As(err, &cfgErr) || cfgErr.Field != tt.field) {
				t.Fatalf("err = %v, want a ConfigError on %s", err, tt.field)
			}
		})
	}
}

func TestServiceInstallPutsTheFloorIn(t *testing.T) {
	h := newTestService(t, serviceConfig(t, "tunnel.crl"))
	if err := h.svc.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !h.nft.present || len(h.nft.chains) != 3 {
		t.Fatalf("nftables table present %v with %d chains", h.nft.present, len(h.nft.chains))
	}
	if got := action(h.xfrm.lookup(flow{dir: netlink.XFRM_DIR_OUT, src: addr("10.20.0.11"), dst: addr(peer4)})); got != "block" {
		t.Fatalf("outbound XFRM policy %s, want block", got)
	}
}

func TestServiceInstallRefusesWithoutTheFloor(t *testing.T) {
	t.Run("nftables", func(t *testing.T) {
		h := newTestService(t, serviceConfig(t, "tunnel.crl"))
		h.nft.flushErr = errInjected
		err := h.svc.Install(context.Background())
		var floor *FloorError
		var op *OpError
		if !errors.As(err, &floor) || !errors.As(err, &op) || op.Op != "nftables apply" || !errors.Is(err, errInjected) {
			t.Fatalf("err = %v, want a FloorError from nftables apply", err)
		}
		if h.xfrm.updates != 0 {
			t.Fatal("the XFRM block went in after the nftables table failed")
		}
	})
	t.Run("xfrm", func(t *testing.T) {
		h := newTestService(t, serviceConfig(t, "tunnel.crl"))
		h.xfrm.updateErr = errInjected
		err := h.svc.Install(context.Background())
		var floor *FloorError
		var op *OpError
		if !errors.As(err, &floor) || !errors.As(err, &op) || op.Op != "xfrm install" {
			t.Fatalf("err = %v, want a FloorError from xfrm install", err)
		}
		if !h.nft.present {
			t.Fatal("the nftables table was taken out: the floor must stay as far as it went in")
		}
	})
}

func TestServicePushCRLs(t *testing.T) {
	cfg := serviceConfig(t, "tunnel.crl", "root.crl")
	h := newTestService(t, cfg)
	issued := h.pki.issued
	putFile(t, cfg.CRLFiles[0], pemCRL(h.pki.crl(t, 1, issued)))
	putFile(t, cfg.CRLFiles[1], h.root.crl(t, 1, issued)) // DER

	if err := h.svc.pushCRLs(context.Background()); err != nil {
		t.Fatalf("pushCRLs: %v", err)
	}
	if got := h.svc.ctl.Status().CRLs; got != 2 {
		t.Fatalf("held CRLs %d, want 2 (the intermediate's and the root's)", got)
	}
}

func TestServicePushCRLsGoesOnPastABadFile(t *testing.T) {
	cfg := serviceConfig(t, "missing.crl", "garbage.crl", "tunnel.crl")
	h := newTestService(t, cfg)
	putFile(t, cfg.CRLFiles[1], []byte("not a CRL"))
	putFile(t, cfg.CRLFiles[2], pemCRL(h.pki.crl(t, 1, h.pki.issued)))

	err := h.svc.pushCRLs(context.Background())
	var cfgErr *config.ConfigError
	if !errors.As(err, &cfgErr) || cfgErr.Field != "crl-files[0]" || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want the missing file named", err)
	}
	var op *OpError
	if !errors.As(err, &op) || op.Op != "parse crl" {
		t.Fatalf("err = %v, want the garbage refused", err)
	}
	if got := h.svc.ctl.Status().CRLs; got != 1 {
		t.Fatalf("held CRLs %d, want the good file's", got)
	}
}

func TestServiceFeedsAReplacedCRL(t *testing.T) {
	cfg := serviceConfig(t, "tunnel.crl")
	h := newTestService(t, cfg)
	charon := newFakeSession()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.svc.ctl.Attach(ctx, charon); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	first, second := h.pki.crl(t, 1, h.pki.issued), h.pki.crl(t, 2, h.pki.issued)
	putFile(t, cfg.CRLFiles[0], pemCRL(first))

	waits, fire := make(chan time.Duration), make(chan time.Time)
	h.svc.after = func(d time.Duration) <-chan time.Time {
		select {
		case waits <- d:
		case <-ctx.Done():
		}
		return fire
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		h.svc.feedCRLs(ctx)
	}()

	if d, _ := recv(t, waits); d != CRLRefresh {
		t.Fatalf("waited %v, want %v", d, CRLRefresh)
	}
	if got := charon.crls(); len(got) != 1 || !bytes.Equal(got[0], first) {
		t.Fatal("the CRL file was not pushed at start")
	}
	putFile(t, cfg.CRLFiles[0], pemCRL(second))
	fire <- time.Time{}
	recv(t, waits)
	if got := charon.crls(); len(got) != 2 || !bytes.Equal(got[1], second) {
		t.Fatal("the replaced CRL was not pushed")
	}
	fire <- time.Time{}
	recv(t, waits)
	if got := charon.crls(); len(got) != 2 {
		t.Fatalf("an unchanged CRL was loaded again: %d loads", len(got))
	}
	cancel()
	recv(t, stopped)
}

func TestServiceWatchesTheFabricAgain(t *testing.T) {
	h := newTestService(t, serviceConfig(t, "tunnel.crl"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.svc.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	subscriptions := 0
	h.svc.block.subscribe = func(ch chan<- netlink.LinkUpdate, _ <-chan struct{}) error {
		subscriptions++
		close(ch) // the kernel ends the subscription at once
		return nil
	}
	waits, fire := make(chan time.Duration), make(chan time.Time)
	h.svc.after = func(d time.Duration) <-chan time.Time {
		select {
		case waits <- d:
		case <-ctx.Done():
		}
		return fire
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		h.svc.watch(ctx)
	}()

	if d, _ := recv(t, waits); d != MinBackoff {
		t.Fatalf("first wait %v, want %v", d, MinBackoff)
	}
	fire <- time.Time{}
	if d, _ := recv(t, waits); d != 2*MinBackoff {
		t.Fatalf("second wait %v, want %v", d, 2*MinBackoff)
	}
	if subscriptions != 2 {
		t.Fatalf("%d subscriptions, want the watch run again", subscriptions)
	}
	cancel()
	recv(t, stopped)
}

func TestServiceRun(t *testing.T) {
	cfg := serviceConfig(t, "tunnel.crl")
	charon, stream := newFakeSession(), newFakeStream()
	h := newTestService(t, cfg, attempt{sess: charon, stream: stream})
	crl := h.pki.crl(t, 1, h.pki.issued)
	putFile(t, cfg.CRLFiles[0], pemCRL(crl))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.svc.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	h.svc.block.subscribe = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
		go func() {
			<-done
			close(ch)
		}()
		return nil
	}
	refreshing := make(chan struct{}, 1)
	h.svc.after = func(d time.Duration) <-chan time.Time {
		if d == CRLRefresh {
			select {
			case refreshing <- struct{}{}:
			default:
			}
		}
		return nil
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		h.svc.Run(ctx)
	}()

	recv(t, stream.watching) // attached
	recv(t, refreshing)      // the CRL file pushed
	cancel()
	recv(t, stopped)

	if got := charon.loaded(); !slices.Equal(got, []string{"vtep-10.20.0.1", "vtep-10.20.0.2"}) {
		t.Fatalf("charon holds %v, want the static peers", got)
	}
	if got := charon.crls(); len(got) != 1 || !bytes.Equal(got[0], crl) {
		t.Fatal("the CRL file did not reach charon")
	}
	if !charon.closed || !stream.closed {
		t.Fatal("the charon connections were left open")
	}

	h.svc.Close()
	if !h.identity.closed || !h.xfrm.closed {
		t.Fatal("Close did not release the identity and the netlink connection")
	}
	if !h.nft.present || len(h.xfrm.spd) == 0 {
		t.Fatal("the floor came out with the service")
	}
}

func TestStaticPeersOnlyAdmitsNoRoutedVTEP(t *testing.T) {
	h := newTestService(t, serviceConfig(t, "tunnel.crl"))
	err := h.svc.ctl.HandleEVPNRoute(context.Background(), imet(100, "10.20.0.30", false))
	if !errors.Is(err, ErrNoVTEPAdmission) {
		t.Fatalf("err = %v, want %v", err, ErrNoVTEPAdmission)
	}
	if got := h.svc.ctl.Peers(); slices.Contains(got, addr("10.20.0.30")) {
		t.Fatalf("peers %v include a VTEP no admitter vouched for", got)
	}
}

func TestNewEVPNServiceRejectsNoAdmitter(t *testing.T) {
	svc, err := NewEVPNService(serviceConfig(t, "tunnel.crl"), nil, &fakeAnchor{}, nil)
	if svc != nil || !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("NewEVPNService = %v, %v; want %v", svc, err, ErrMissingDependency)
	}
}

// A service without the platform anchor would load any tunnel identity
// the operator supplies: both constructors refuse it before they read the
// certificate or open netlink.
func TestNewServiceRejectsNoAnchor(t *testing.T) {
	cfg := serviceConfig(t, "tunnel.crl")
	if svc, err := NewService(cfg, nil, nil); svc != nil || !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("NewService = %v, %v; want %v", svc, err, ErrMissingDependency)
	}
	if svc, err := NewEVPNService(cfg, staticPeersOnly{}, nil, nil); svc != nil || !errors.Is(err, ErrMissingDependency) {
		t.Fatalf("NewEVPNService = %v, %v; want %v", svc, err, ErrMissingDependency)
	}
}

func TestEVPNServiceFollowsRoutesAndEvictions(t *testing.T) {
	admitter := &fakeAdmitter{refuse: map[netip.Addr]error{addr("10.20.0.31"): errInjected}}
	h := newTestEVPNService(t, serviceConfig(t, "tunnel.crl"), admitter)
	ctx := context.Background()
	vtep := addr("10.20.0.30")
	holds := func() bool { return slices.Contains(h.svc.ctl.Peers(), vtep) }

	if err := h.svc.HandleEVPNRoute(ctx, imet(100, "10.20.0.30", false)); err != nil || !holds() {
		t.Fatalf("an admitted route: err %v, peer held %v", err, holds())
	}
	if err := h.svc.HandleEVPNRoute(ctx, imet(100, "10.20.0.31", false)); !errors.Is(err, errInjected) {
		t.Fatalf("a refused route: err %v, want the admitter's refusal", err)
	}
	if err := h.svc.Evict(ctx, vtep); err != nil || holds() {
		t.Fatalf("Evict: err %v, peer held %v", err, holds())
	}
	if _, dropped := h.svc.filter.evicted[vtep]; !dropped {
		t.Fatal("Evict left the peer's traffic undropped")
	}
	if err := h.svc.Readmit(ctx, vtep); err != nil || !holds() {
		t.Fatalf("Readmit: err %v, peer held %v", err, holds())
	}
	if err := h.svc.Readmit(ctx, vtep); err != nil {
		t.Fatalf("Readmit of a peer never evicted: %v, want nil", err)
	}
	if err := h.svc.HandleEVPNRoute(ctx, imet(100, "10.20.0.30", true)); err != nil || holds() {
		t.Fatalf("a withdrawal: err %v, peer held %v", err, holds())
	}
}

func TestEVPNServiceEvictRejectsANonPeer(t *testing.T) {
	h := newTestEVPNService(t, serviceConfig(t, "tunnel.crl"), &fakeAdmitter{})
	err := h.svc.Evict(context.Background(), netip.Addr{})
	if !errors.Is(err, config.ErrInvalidAddress) {
		t.Fatalf("Evict of no address = %v, want %v", err, config.ErrInvalidAddress)
	}
}
