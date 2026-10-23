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

package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec"
	ipsecconfig "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
)

var errOverlayStart = errors.New("injected overlay start failure")

// fakeOverlayIPsec records its steps in the order the overlay was started.
type fakeOverlayIPsec struct {
	steps      *[]string
	installErr error
	closed     bool
	running    chan struct{} // receives when Run starts
	ended      chan struct{} // receives when Run returns
}

func (f *fakeOverlayIPsec) Install(context.Context) error {
	*f.steps = append(*f.steps, "ipsec floor")
	return f.installErr
}

func (f *fakeOverlayIPsec) Run(ctx context.Context) {
	f.running <- struct{}{}
	<-ctx.Done()
	f.ended <- struct{}{}
}

func (f *fakeOverlayIPsec) Close() { f.closed = true }

// overlayStartHarness drives startOverlay over a fake IPsec service and a
// controller starter that records when it ran.
type overlayStartHarness struct {
	steps   []string
	sec     *fakeOverlayIPsec
	ctrl    *overlay.Controller
	ctlErr  error
	addrs   interfaceAddrsFunc // the node's interfaces: bond0 carries 10.20.0.11
	gotVTEP overlayVTEP        // the VTEP the controller was started with
	logger  *logging.Logger
}

func newOverlayStartHarness(t *testing.T) *overlayStartHarness {
	t.Helper()
	h := &overlayStartHarness{
		addrs:  fabricAddrs("10.20.0.11"),
		logger: logging.NewLoggerWithFormat(slog.LevelError, logging.FormatJSON, io.Discard),
	}
	h.sec = &fakeOverlayIPsec{steps: &h.steps, running: make(chan struct{}), ended: make(chan struct{})}
	ctrl, err := buildOverlayController(context.Background(), overlayTestApp(t), loopbackVTEP, "", h.logger)
	if err != nil {
		t.Fatalf("buildOverlayController: %v", err)
	}
	t.Cleanup(func() { _ = ctrl.Stop(context.Background()) })
	h.ctrl = ctrl
	return h
}

func (h *overlayStartHarness) starters() overlayStarters {
	return overlayStarters{
		ipsec: func(*ipsecconfig.Config) (overlayIPsec, error) { return h.sec, nil },
		vtep: func(cfg *sdn.OverlayConfig) (overlayVTEP, error) {
			return resolveOverlayVTEP(net.ParseIP("203.0.113.7"), cfg, h.addrs)
		},
		controller: func(_ context.Context, vtep overlayVTEP) (*overlay.Controller, error) {
			h.steps = append(h.steps, "overlay controller")
			h.gotVTEP = vtep
			if h.ctlErr != nil {
				return nil, h.ctlErr
			}
			return h.ctrl, nil
		},
	}
}

func (h *overlayStartHarness) start(cfg *sdn.OverlayConfig) (overlayIPsec, *overlay.Controller, error) {
	return startOverlay(context.Background(), cfg, h.starters(), h.logger)
}

// overlayWithIPsec is an enabled overlay with enabled IPsec.
func overlayWithIPsec() *sdn.OverlayConfig {
	return &sdn.OverlayConfig{
		Enabled: true,
		IPsec: &ipsecconfig.Config{
			Enabled:         true,
			FabricInterface: "bond0",
			LocalAddress:    "10.20.0.11",
			Token:           ipsecconfig.TokenConfig{Handle: "6970736563"},
			CertificateFile: "/etc/platform/ipsec/tunnel.pem",
		},
	}
}

func TestStartOverlay_InstallsTheIPsecFloorBeforeTheVTEP(t *testing.T) {
	h := newOverlayStartHarness(t)
	sec, ctrl, err := h.start(overlayWithIPsec())
	if err != nil {
		t.Fatalf("startOverlay: %v", err)
	}
	if want := []string{"ipsec floor", "overlay controller"}; !slices.Equal(h.steps, want) {
		t.Fatalf("steps %v, want %v", h.steps, want)
	}
	if sec != h.sec || ctrl != h.ctrl {
		t.Fatal("startOverlay did not return what it started")
	}
	if want := (overlayVTEP{addr: netip.MustParseAddr("10.20.0.11"), iface: "bond0"}); h.gotVTEP != want {
		t.Fatalf("controller started with VTEP %+v, want the IPsec endpoint %+v", h.gotVTEP, want)
	}
}

// TestStartOverlay_TheVTEPIsTheIPsecEndpoint runs the production controller
// starter on a node whose public IPv4 is not its fabric address.
func TestStartOverlay_TheVTEPIsTheIPsecEndpoint(t *testing.T) {
	h := newOverlayStartHarness(t)
	a := overlayTestApp(t)
	a.PublicIPv4 = net.ParseIP("203.0.113.7")
	starters := newOverlayStarters(&Config{App: a}, h.logger)
	starters.ipsec = h.starters().ipsec
	starters.vtep = func(cfg *sdn.OverlayConfig) (overlayVTEP, error) {
		return resolveOverlayVTEP(a.PublicIPv4, cfg, h.addrs)
	}
	_, ctrl, err := startOverlay(context.Background(), overlayWithIPsec(), starters, h.logger)
	if err != nil || ctrl == nil {
		t.Fatalf("startOverlay = %v, %v; want a controller", ctrl, err)
	}
	t.Cleanup(func() { _ = ctrl.Stop(context.Background()) })
	if cfg := ctrl.GetConfig(); cfg.VTEPIP != netip.MustParseAddr("10.20.0.11") || cfg.UnderlayInterface != "bond0" {
		t.Fatalf("controller VTEP %s on %s, want the IPsec endpoint 10.20.0.11 on bond0", cfg.VTEPIP, cfg.UnderlayInterface)
	}
}

func TestStartOverlay_RefusesAVTEPTheFloorDoesNotProtect(t *testing.T) {
	h := newOverlayStartHarness(t)
	h.addrs = fabricAddrs("10.20.0.12")
	sec, ctrl, err := h.start(overlayWithIPsec())
	var vtepErr *OverlayVTEPError
	if !errors.As(err, &vtepErr) || !errors.Is(err, ErrVTEPNotOnFabric) {
		t.Fatalf("err = %v, want an OverlayVTEPError wrapping ErrVTEPNotOnFabric", err)
	}
	if sec != nil || ctrl != nil || len(h.steps) != 0 {
		t.Fatalf("startOverlay = %v, %v with steps %v; want nothing started", sec, ctrl, h.steps)
	}
	if !h.sec.closed {
		t.Fatal("the refused service was not closed")
	}
}

func TestStartOverlay_RefusesWithoutTheFloor(t *testing.T) {
	h := newOverlayStartHarness(t)
	h.sec.installErr = &ipsec.FloorError{Err: errOverlayStart}
	sec, ctrl, err := h.start(overlayWithIPsec())
	var floor *ipsec.FloorError
	if !errors.As(err, &floor) {
		t.Fatalf("err = %v, want a FloorError", err)
	}
	if sec != nil || ctrl != nil {
		t.Fatal("startOverlay returned a service with no floor")
	}
	if want := []string{"ipsec floor"}; !slices.Equal(h.steps, want) {
		t.Fatalf("steps %v, want the VTEP never registered", h.steps)
	}
	if !h.sec.closed {
		t.Fatal("the refused service was not closed")
	}
}

func TestStartOverlay_RefusesAnIPsecServiceItCannotBuild(t *testing.T) {
	h := newOverlayStartHarness(t)
	starters := h.starters()
	starters.ipsec = newOverlayStarters(&Config{}, h.logger).ipsec // no crl-files: refused before any netlink connection
	_, ctrl, err := startOverlay(context.Background(), overlayWithIPsec(), starters, h.logger)
	var cfgErr *ipsecconfig.ConfigError
	if !errors.As(err, &cfgErr) || cfgErr.Field != "crl-files" {
		t.Fatalf("err = %v, want a ConfigError on crl-files", err)
	}
	if ctrl != nil || len(h.steps) != 0 {
		t.Fatalf("steps %v, want nothing started", h.steps)
	}
}

func TestStartOverlay_WithoutIPsec(t *testing.T) {
	for _, tt := range []struct {
		name  string
		ipsec *ipsecconfig.Config
	}{
		{"absent", nil},
		{"disabled", &ipsecconfig.Config{FabricInterface: "bond0"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newOverlayStartHarness(t)
			sec, ctrl, err := h.start(&sdn.OverlayConfig{Enabled: true, UnderlayInterface: "eth0", IPsec: tt.ipsec})
			if err != nil || sec != nil || ctrl != h.ctrl {
				t.Fatalf("startOverlay = %v, %v, %v; want the controller alone", sec, ctrl, err)
			}
			if want := []string{"overlay controller"}; !slices.Equal(h.steps, want) {
				t.Fatalf("steps %v, want %v", h.steps, want)
			}
			if want := (overlayVTEP{addr: netip.MustParseAddr("203.0.113.7"), iface: "eth0"}); h.gotVTEP != want {
				t.Fatalf("controller started with VTEP %+v, want the public address %+v", h.gotVTEP, want)
			}
		})
	}
}

func TestStartOverlay_IPsecWithoutTheOverlay(t *testing.T) {
	h := newOverlayStartHarness(t)
	cfg := overlayWithIPsec()
	cfg.Enabled = false
	sec, ctrl, err := h.start(cfg)
	if err != nil || sec != h.sec || ctrl != nil {
		t.Fatalf("startOverlay = %v, %v, %v; want IPsec alone", sec, ctrl, err)
	}
	if want := []string{"ipsec floor"}; !slices.Equal(h.steps, want) {
		t.Fatalf("steps %v, want %v", h.steps, want)
	}
}

func TestStartOverlay_ControllerFailureKeepsTheFloor(t *testing.T) {
	h := newOverlayStartHarness(t)
	h.ctlErr = errOverlayStart
	sec, ctrl, err := h.start(overlayWithIPsec())
	if err != nil || sec != h.sec || ctrl != nil {
		t.Fatalf("startOverlay = %v, %v, %v; want IPsec kept and the controller logged as unavailable", sec, ctrl, err)
	}
	if h.sec.closed {
		t.Fatal("the floor's service was closed after the controller failed")
	}
}

func TestStartOverlay_NoSection(t *testing.T) {
	h := newOverlayStartHarness(t)
	sec, ctrl, err := h.start(nil)
	if err != nil || sec != nil || ctrl != nil || len(h.steps) != 0 {
		t.Fatalf("startOverlay = %v, %v, %v with steps %v; want nothing", sec, ctrl, err, h.steps)
	}
}

func recvSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not happen", what)
	}
}

func TestOverlayIPsecRun_StartAndStop(t *testing.T) {
	h := newOverlayStartHarness(t)
	run := &overlayIPsecRun{svc: h.sec}

	run.start()
	recvSignal(t, h.sec.running, "Run")
	run.start() // already running: no second Run
	done := make(chan struct{})
	go func() {
		defer close(done)
		run.stop()
	}()
	recvSignal(t, h.sec.ended, "Run returning")
	recvSignal(t, done, "stop returning")
	run.stop() // already stopped

	// A daemon started again runs the service again.
	run.start()
	recvSignal(t, h.sec.running, "Run after a restart")
	go run.stop()
	recvSignal(t, h.sec.ended, "Run returning after a restart")
	if h.sec.closed {
		t.Fatal("stop closed the service")
	}
}

func TestOverlayIPsecRun_Nil(t *testing.T) {
	var run *overlayIPsecRun
	run.start()
	run.stop()
}

// TestNew_RefusesWithoutTheIPsecFloor checks the wiring: New builds overlay
// IPsec from the SDN section and refuses to start when it cannot.
func TestNew_RefusesWithoutTheIPsecFloor(t *testing.T) {
	config := testConfig("/tmp/test-daemon-overlay-ipsec.sock")
	config.App = &app.App{Hostname: "cp-01", SDNConfig: &sdn.Config{Overlay: overlayWithIPsec()}}
	d, err := New(config)
	var cfgErr *ipsecconfig.ConfigError
	if d != nil || !errors.As(err, &cfgErr) || cfgErr.Field != "crl-files" {
		t.Fatalf("New = %v, %v; want a refusal on overlay.ipsec.crl-files", d, err)
	}
}
