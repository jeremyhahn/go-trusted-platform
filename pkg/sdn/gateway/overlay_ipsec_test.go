package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	ipsecconfig "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
)

var errIPsecDown = errors.New("ipsec down")

// fakeOverlayIPsec records, in order, each call the overlay makes of its
// IPsec, and answers with the error set for that call.
type fakeOverlayIPsec struct {
	mu         sync.Mutex
	calls      []string
	running    chan struct{}
	installErr error
	routeErr   error
	evictErr   error
	readmitErr error
}

func newFakeOverlayIPsec() *fakeOverlayIPsec {
	return &fakeOverlayIPsec{running: make(chan struct{})}
}

func (f *fakeOverlayIPsec) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeOverlayIPsec) Install(context.Context) error {
	f.record("install")
	return f.installErr
}

func (f *fakeOverlayIPsec) Run(ctx context.Context) {
	close(f.running)
	<-ctx.Done()
}

func (f *fakeOverlayIPsec) Close() { f.record("close") }

func (f *fakeOverlayIPsec) HandleEVPNRoute(_ context.Context, route *bgp.EVPNRouteData) error {
	change := "route "
	if route.IsWithdraw {
		change = "withdraw "
	}
	f.record(change + route.IMET.VTEPIP.String())
	return f.routeErr
}

func (f *fakeOverlayIPsec) Evict(_ context.Context, peer netip.Addr) error {
	f.record("evict " + peer.String())
	return f.evictErr
}

func (f *fakeOverlayIPsec) Readmit(_ context.Context, peer netip.Addr) error {
	f.record("readmit " + peer.String())
	return f.readmitErr
}

func (f *fakeOverlayIPsec) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func imetRoute(vtep netip.Addr, withdraw bool) *bgp.EVPNRouteData {
	return &bgp.EVPNRouteData{
		Type:       bgp.EVPNTypeInclusiveMulticast,
		IMET:       &bgp.IMETEntry{VNI: 40100, VTEPIP: vtep},
		NextHop:    vtep,
		IsWithdraw: withdraw,
	}
}

func TestOverlayIPsecPeers(t *testing.T) {
	ctx := context.Background()

	t.Run("an added VTEP is readmitted before its route", func(t *testing.T) {
		ipsec := newFakeOverlayIPsec()
		require.NoError(t, overlayIPsecPeers(ipsec)(ctx, imetRoute(admissionVTEP, false)))
		assert.Equal(t, []string{"readmit " + admissionVTEP.String(), "route " + admissionVTEP.String()}, ipsec.recorded())
	})

	t.Run("a withdrawn VTEP is only withdrawn", func(t *testing.T) {
		ipsec := newFakeOverlayIPsec()
		require.NoError(t, overlayIPsecPeers(ipsec)(ctx, imetRoute(admissionVTEP, true)))
		assert.Equal(t, []string{"withdraw " + admissionVTEP.String()}, ipsec.recorded())
	})

	t.Run("a failed readmission asks for no SA", func(t *testing.T) {
		ipsec := newFakeOverlayIPsec()
		ipsec.readmitErr = errIPsecDown
		assert.ErrorIs(t, overlayIPsecPeers(ipsec)(ctx, imetRoute(admissionVTEP, false)), errIPsecDown)
		assert.Equal(t, []string{"readmit " + admissionVTEP.String()}, ipsec.recorded())
	})

	t.Run("a route failure is returned", func(t *testing.T) {
		ipsec := newFakeOverlayIPsec()
		ipsec.routeErr = errIPsecDown
		assert.ErrorIs(t, overlayIPsecPeers(ipsec)(ctx, imetRoute(admissionVTEP, true)), errIPsecDown)
	})
}

func TestAdmittedVTEPs(t *testing.T) {
	ctx := context.Background()
	f := newAdmissionFixture(t)
	admitted := admittedVTEPs{admitter: f.admitter}
	var notAdmitted ErrOverlayVTEPNotAdmitted

	require.ErrorAs(t, admitted.AdmitVTEP(ctx, 40100, admissionVTEP), &notAdmitted,
		"a VTEP the overlay never admitted gets no SA")
	assert.Equal(t, admissionVTEP, notAdmitted.VTEP)
	assert.Contains(t, notAdmitted.Error(), admissionVTEP.String())

	require.NoError(t, f.admitter.AdmitVTEP(ctx, 40100, admissionVTEP))
	assert.NoError(t, admitted.AdmitVTEP(ctx, 40100, admissionVTEP))

	f.now = f.now.Add(10 * time.Minute)
	assert.ErrorAs(t, admitted.AdmitVTEP(ctx, 40100, admissionVTEP), &notAdmitted,
		"an admission whose verdict went stale gets no SA")
}

func TestOverlayBackend_StartIPsecErrors(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	cfg := validOverlayServiceConfig()
	withOverlayIPsec(cfg)

	t.Run("a factory failure", func(t *testing.T) {
		backend, _ := newTestOverlayBackend(t, cfg, &backendSwitch{})
		backend.newIPsec = func(*ipsecconfig.Config, modes.VTEPAdmitter, *slog.Logger) (OverlayIPsec, error) {
			return nil, errIPsecDown
		}
		_, err := backend.startIPsec(ctx, newAdmissionFixture(t).admitter, logger)
		var failed *ErrOverlayIPsec
		require.ErrorAs(t, err, &failed)
		assert.Equal(t, "build", failed.Operation)
		assert.ErrorIs(t, err, errIPsecDown)
	})

	t.Run("a floor that will not install closes the service", func(t *testing.T) {
		ipsec := newFakeOverlayIPsec()
		ipsec.installErr = errIPsecDown
		backend, _ := newTestOverlayBackend(t, cfg, &backendSwitch{})
		backend.newIPsec = fakeOverlayIPsecFactory(ipsec)
		_, err := backend.startIPsec(ctx, newAdmissionFixture(t).admitter, logger)
		var failed *ErrOverlayIPsec
		require.ErrorAs(t, err, &failed)
		assert.Equal(t, "install floor", failed.Operation)
		assert.Equal(t, []string{"install", "close"}, ipsec.recorded())
	})
}

func fakeOverlayIPsecFactory(ipsec *fakeOverlayIPsec) OverlayIPsecFactory {
	return func(*ipsecconfig.Config, modes.VTEPAdmitter, *slog.Logger) (OverlayIPsec, error) {
		return ipsec, nil
	}
}

func TestOverlayBackend_RunsIPsecWhileStarted(t *testing.T) {
	ctx := context.Background()
	cfg := validOverlayServiceConfig()
	withOverlayIPsec(cfg)
	ipsec := newFakeOverlayIPsec()
	backend, _ := newTestOverlayBackend(t, cfg, &backendSwitch{})
	backend.newIPsec = fakeOverlayIPsecFactory(ipsec)

	require.NoError(t, backend.Start(ctx))
	<-ipsec.running
	assert.Equal(t, []string{"install"}, ipsec.recorded())

	require.NoError(t, backend.Stop(ctx))
	assert.Equal(t, []string{"install", "close"}, ipsec.recorded())
}

func TestOverlayBackend_FailedStartClosesIPsec(t *testing.T) {
	cfg := validOverlayServiceConfig()
	withOverlayIRB(cfg)
	withOverlayIPsec(cfg)
	ipsec := newFakeOverlayIPsec()
	backend, _ := newTestOverlayBackend(t, cfg, &backendSwitch{})
	backend.server = &fakeBGPServer{refusePrefixes: errSwitchRefused}
	backend.newIPsec = fakeOverlayIPsecFactory(ipsec)

	require.ErrorIs(t, backend.Start(context.Background()), errSwitchRefused)
	assert.Equal(t, []string{"install", "close"}, ipsec.recorded())
}

// closableSwitch is a backendSwitch the runtime can own.
type closableSwitch struct{ *backendSwitch }

func (closableSwitch) Close() error { return nil }

func TestBuildOverlay_IPsecNeedsItsFactory(t *testing.T) {
	f := newAdmissionFixture(t)
	runtime := newTestRuntime()
	runtime.OverlayOpenFlow = closableSwitch{&backendSwitch{}}
	runtime.OverlayIPAM = f.ipam
	runtime.OverlayDevices = f.devices
	runtime.OverlayVerdicts = f.verdicts
	runtime.OverlayVerdictStream = idleVerdictStream{}
	cfg := validOverlayServiceConfig()
	withOverlayIPsec(cfg)
	gw := &Gateway{config: &GatewayConfig{Runtime: runtime, Overlay: cfg}}

	_, err := buildOverlay(gw)
	var missing *ErrRuntimeMissing
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, ServiceOverlay, missing.Service)

	runtime.OverlayIPsec = fakeOverlayIPsecFactory(newFakeOverlayIPsec())
	_, err = buildOverlay(gw)
	assert.NoError(t, err)
}

func TestOverlayHandlerProxy_IPsec(t *testing.T) {
	ctx := context.Background()

	t.Run("a revocation evicts after the handler revokes", func(t *testing.T) {
		overlay := &admissionOverlay{}
		ipsec := newFakeOverlayIPsec()
		proxy := &overlayHandlerProxy{}
		proxy.set(overlay, ipsec)

		require.NoError(t, proxy.RevokeVTEP(ctx, admissionVTEP))
		assert.Equal(t, []netip.Addr{admissionVTEP}, overlay.revoked)
		assert.Equal(t, []string{"evict " + admissionVTEP.String()}, ipsec.recorded())
	})

	t.Run("a failed handler revocation still evicts", func(t *testing.T) {
		overlay := &admissionOverlay{fail: map[netip.Addr]error{admissionVTEP: errSwitchRefused}}
		ipsec := newFakeOverlayIPsec()
		ipsec.evictErr = errIPsecDown
		proxy := &overlayHandlerProxy{}
		proxy.set(overlay, ipsec)

		err := proxy.RevokeVTEP(ctx, admissionVTEP)
		assert.ErrorIs(t, err, errSwitchRefused)
		assert.ErrorIs(t, err, errIPsecDown)
		assert.Equal(t, []string{"evict " + admissionVTEP.String()}, ipsec.recorded())
	})

	t.Run("a replay readmits first", func(t *testing.T) {
		overlay := &admissionOverlay{}
		ipsec := newFakeOverlayIPsec()
		proxy := &overlayHandlerProxy{}
		proxy.set(overlay, ipsec)

		require.NoError(t, proxy.ReplayVTEP(ctx, admissionVTEP))
		assert.Equal(t, []string{"readmit " + admissionVTEP.String()}, ipsec.recorded())
		assert.Equal(t, []netip.Addr{admissionVTEP}, overlay.replayed)
	})

	t.Run("a failed readmission replays nothing", func(t *testing.T) {
		overlay := &admissionOverlay{}
		ipsec := newFakeOverlayIPsec()
		ipsec.readmitErr = errIPsecDown
		proxy := &overlayHandlerProxy{}
		proxy.set(overlay, ipsec)

		assert.ErrorIs(t, proxy.ReplayVTEP(ctx, admissionVTEP), errIPsecDown)
		assert.Empty(t, overlay.replayed)
	})
}
