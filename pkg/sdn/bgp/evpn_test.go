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

package bgp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger only reports errors, keeping test output small.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

var errSpeakerFailed = errors.New("speaker failed")

// recordingSpeaker is an in-memory EVPNSpeaker: it records what the
// manager originates and withdraws, and feeds it events.
type recordingSpeaker struct {
	mu        sync.Mutex
	added     []*EVPNRouteData
	deleted   []*EVPNRouteData
	addErr    error
	deleteErr error
	watchErr  error
	events    chan *Event
}

func newRecordingSpeaker() *recordingSpeaker {
	return &recordingSpeaker{events: make(chan *Event)}
}

func (s *recordingSpeaker) AddPath(_ context.Context, path *Path) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.addErr != nil {
		return s.addErr
	}
	s.added = append(s.added, path.EVPN.Clone())
	return nil
}

func (s *recordingSpeaker) DeletePath(_ context.Context, path *Path) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, path.EVPN.Clone())
	return nil
}

func (s *recordingSpeaker) WatchEvent(context.Context, ...WatchOption) (<-chan *Event, error) {
	if s.watchErr != nil {
		return nil, s.watchErr
	}
	return s.events, nil
}

func (s *recordingSpeaker) fail(add, del error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addErr, s.deleteErr = add, del
}

// lastAdded returns the last route originated.
func (s *recordingSpeaker) lastAdded(t *testing.T) *EVPNRouteData {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.added)
	return s.added[len(s.added)-1]
}

func (s *recordingSpeaker) deletedRoutes() []*EVPNRouteData {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*EVPNRouteData(nil), s.deleted...)
}

func (s *recordingSpeaker) addedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.added)
}

// testClock is a clock the test moves.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// notifications records what the manager tells its handlers.
type notifications struct {
	mu     sync.Mutex
	routes []*EVPNRouteData
}

func (n *notifications) handle(_ context.Context, route *EVPNRouteData) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.routes = append(n.routes, route)
	return nil
}

// take returns and clears the notifications.
func (n *notifications) take() []*EVPNRouteData {
	n.mu.Lock()
	defer n.mu.Unlock()
	routes := n.routes
	n.routes = nil
	return routes
}

var testRouterMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x00, 0x01, 0x0b}

// evpnTestConfig is VTEP A (192.0.2.11) in overlay ASN 65000.
func evpnTestConfig(speaker EVPNSpeaker, clock *testClock) *EVPNManagerConfig {
	return &EVPNManagerConfig{
		Speaker:    speaker,
		Logger:     testLogger(),
		LocalVTEP:  vtepA,
		OverlayASN: 65000,
		RouterMAC:  testRouterMAC,
		Mobility:   MobilityConfig{MaxMoves: 2, Window: time.Minute, Hold: time.Minute},
		Clock:      clock.Now,
	}
}

type evpnFixture struct {
	manager  *EVPNManager
	speaker  *recordingSpeaker
	clock    *testClock
	notified *notifications
}

func newEVPNFixture(t *testing.T) *evpnFixture {
	t.Helper()
	f := &evpnFixture{
		speaker:  newRecordingSpeaker(),
		clock:    &testClock{now: time.Unix(1_700_000_000, 0)},
		notified: &notifications{},
	}
	manager, err := NewEVPNManager(evpnTestConfig(f.speaker, f.clock))
	require.NoError(t, err)
	manager.RegisterHandler(f.notified.handle)
	f.manager = manager
	return f
}

// receive hands the manager a received route, as its event loop would.
func (f *evpnFixture) receive(route *EVPNRouteData) {
	f.manager.process(context.Background(), route)
}

// withdrawn is route as withdrawn.
func withdrawn(route *EVPNRouteData) *EVPNRouteData {
	w := route.Clone()
	w.IsWithdraw = true
	return w
}

// remoteIMET is a Type-3 route of vtep on the codec L2VNI.
func remoteIMET(vtep netip.Addr, rdIndex uint16) *EVPNRouteData {
	return &EVPNRouteData{
		Type:         EVPNTypeInclusiveMulticast,
		RD:           RouteDistinguisher{Admin: vtep, Index: rdIndex},
		RouteTargets: []RouteTarget{{AS: 65000, Value: 1<<28 | codecL2VNI}},
		IMET:         &IMETEntry{VNI: codecL2VNI, VTEPIP: vtep},
		NextHop:      vtep,
	}
}

func TestEVPNManagerConfig_Validate(t *testing.T) {
	clock := &testClock{}
	assert.NoError(t, evpnTestConfig(newRecordingSpeaker(), clock).Validate())

	for name, tc := range map[string]struct {
		mutate func(c *EVPNManagerConfig)
		want   any
	}{
		"no speaker":       {func(c *EVPNManagerConfig) { c.Speaker = nil }, &ErrSpeakerNil},
		"no logger":        {func(c *EVPNManagerConfig) { c.Logger = nil }, &ErrLoggerNil},
		"no VTEP":          {func(c *EVPNManagerConfig) { c.LocalVTEP = netip.Addr{} }, &ErrInvalidIP{}},
		"IPv6 VTEP":        {func(c *EVPNManagerConfig) { c.LocalVTEP = netip.MustParseAddr("2001:db8::1") }, &ErrInvalidIP{}},
		"unspecified VTEP": {func(c *EVPNManagerConfig) { c.LocalVTEP = netip.IPv4Unspecified() }, &ErrInvalidIP{}},
		"public ASN":       {func(c *EVPNManagerConfig) { c.OverlayASN = 64001 }, &ErrRouteTargetInvalid{}},
		"domain ID > 15":   {func(c *EVPNManagerConfig) { c.DomainID = 16 }, nil},
		"group router MAC": {func(c *EVPNManagerConfig) { c.RouterMAC = net.HardwareAddr{0x01, 0, 0, 0, 0, 1} }, &ErrInvalidMAC{}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := evpnTestConfig(newRecordingSpeaker(), clock)
			tc.mutate(cfg)
			err := cfg.Validate()
			require.Error(t, err)
			if tc.want != nil {
				assert.ErrorAs(t, err, tc.want)
			}
		})
	}

	t.Run("no router MAC is valid without IRB", func(t *testing.T) {
		cfg := evpnTestConfig(newRecordingSpeaker(), clock)
		cfg.RouterMAC = nil
		assert.NoError(t, cfg.Validate())
	})
}

func TestNewEVPNManager(t *testing.T) {
	_, err := NewEVPNManager(nil)
	var nilEntry ErrEntryNil
	require.ErrorAs(t, err, &nilEntry)

	cfg := evpnTestConfig(newRecordingSpeaker(), &testClock{})
	cfg.Logger = nil
	_, err = NewEVPNManager(cfg)
	require.ErrorIs(t, err, ErrLoggerNil)

	cfg = evpnTestConfig(newRecordingSpeaker(), &testClock{})
	cfg.RouterMAC = cloneMAC(testRouterMAC)
	cfg.Mobility = MobilityConfig{}
	cfg.Clock = nil
	manager, err := NewEVPNManager(cfg)
	require.NoError(t, err)
	assert.Equal(t, DefaultMobilityMaxMoves, manager.config.Mobility.MaxMoves)
	assert.NotNil(t, manager.clock)
	cfg.RouterMAC[0] = 0x06
	assert.Equal(t, testRouterMAC[0], manager.config.RouterMAC[0], "the manager keeps its own router MAC")
}

func TestEVPNManager_StartStop(t *testing.T) {
	ctx := context.Background()

	t.Run("events reach the handlers until Stop", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		seen := make(chan *EVPNRouteData, 1)
		f.manager.RegisterHandler(func(_ context.Context, route *EVPNRouteData) error {
			seen <- route
			return nil
		})
		f.manager.RegisterHandler(nil)

		require.NoError(t, f.manager.Start(ctx))
		assert.ErrorIs(t, f.manager.Start(ctx), ErrManagerAlreadyStarted)

		f.speaker.events <- nil
		f.speaker.events <- &Event{Type: EventPathReceived}
		f.speaker.events <- &Event{Type: EventPathReceived, Path: &Path{Family: AFamilyEVPN, EVPN: remoteIMET(vtepB, 1)}}
		select {
		case route := <-seen:
			assert.Equal(t, vtepB, route.IMET.VTEPIP)
		case <-time.After(5 * time.Second):
			t.Fatal("the event was not processed")
		}

		require.NoError(t, f.manager.Stop(ctx))
		assert.ErrorIs(t, f.manager.Stop(ctx), ErrManagerNotStarted)
	})

	t.Run("the watch ending ends the loop", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.Start(ctx))
		close(f.speaker.events)
		<-f.manager.done
		require.NoError(t, f.manager.Stop(ctx))
	})

	t.Run("a failed watch leaves the manager stopped", func(t *testing.T) {
		f := newEVPNFixture(t)
		f.speaker.watchErr = errSpeakerFailed
		require.ErrorIs(t, f.manager.Start(ctx), errSpeakerFailed)
		assert.ErrorIs(t, f.manager.Stop(ctx), ErrManagerNotStarted)
	})
}

func TestEVPNManager_JoinVNI(t *testing.T) {
	ctx := context.Background()

	t.Run("advertises the EVI's Type-3 route", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		imet := f.speaker.lastAdded(t)
		assert.Equal(t, EVPNTypeInclusiveMulticast, imet.Type)
		assert.Equal(t, "192.0.2.11:1", imet.RD.String())
		assert.Equal(t, []RouteTarget{mustRT(t, codecL2VNI)}, imet.RouteTargets)
		assert.Equal(t, IMETEntry{VNI: codecL2VNI, VTEPIP: vtepA}, *imet.IMET)
		assert.Equal(t, vtepA, imet.NextHop)

		rd, ok := f.manager.RouteDistinguisher(codecL2VNI)
		assert.True(t, ok)
		assert.Equal(t, imet.RD, rd)
	})

	t.Run("rejoining is idempotent; another L3VNI conflicts", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		assert.Equal(t, 1, f.speaker.addedCount())
		var invalid ErrInvalidVNI
		assert.ErrorAs(t, f.manager.JoinVNI(ctx, codecL2VNI, 0), &invalid)
	})

	t.Run("invalid input", func(t *testing.T) {
		f := newEVPNFixture(t)
		var invalid ErrInvalidVNI
		assert.ErrorAs(t, f.manager.JoinVNI(ctx, 0, 0), &invalid)
		assert.ErrorAs(t, f.manager.JoinVNI(ctx, codecL2VNI, MaxVNI+1), &invalid)
		assert.ErrorAs(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL2VNI), &invalid)

		cfg := evpnTestConfig(newRecordingSpeaker(), f.clock)
		cfg.RouterMAC = nil
		noIRB, err := NewEVPNManager(cfg)
		require.NoError(t, err)
		var invalidMAC ErrInvalidMAC
		assert.ErrorAs(t, noIRB.JoinVNI(ctx, codecL2VNI, codecL3VNI), &invalidMAC, "IRB needs a router MAC")
		assert.NoError(t, noIRB.JoinVNI(ctx, codecL2VNI, 0))
	})

	t.Run("a failed advertisement rolls the join back", func(t *testing.T) {
		f := newEVPNFixture(t)
		f.speaker.fail(errSpeakerFailed, nil)
		var failed ErrRouteAdvertisementFailed
		require.ErrorAs(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI), &failed)
		assert.ErrorIs(t, failed, errSpeakerFailed)
		_, ok := f.manager.RouteDistinguisher(codecL2VNI)
		assert.False(t, ok)

		f.speaker.fail(nil, nil)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		rd, _ := f.manager.RouteDistinguisher(codecL2VNI)
		assert.Equal(t, uint16(1), rd.Index, "the released RD is reused")
	})

	t.Run("a second join is not told it joined while the first waits on BGP", func(t *testing.T) {
		f, speaker, _ := newGatedFixture(t)
		speaker.holdNext(true, false)
		first := make(chan error, 1)
		go func() { first <- f.manager.JoinVNI(ctx, codecL2VNI, 0) }()
		<-speaker.entered

		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		assert.ErrorIs(t, f.manager.JoinVNI(cancelled, codecL2VNI, 0), context.Canceled,
			"the second join waits for the first's outcome until its context ends")

		close(speaker.release)
		require.NoError(t, <-first)
		assert.NoError(t, f.manager.JoinVNI(cancelled, codecL2VNI, 0), "a joined VNI answers at once")
	})

	t.Run("a second join waiting on a failed first one tries for itself", func(t *testing.T) {
		f, speaker, _ := newGatedFixture(t)
		speaker.holdNext(true, false)
		first := make(chan error, 1)
		go func() { first <- f.manager.JoinVNI(ctx, codecL2VNI, 0) }()
		<-speaker.entered
		second := make(chan error, 1)
		go func() { second <- f.manager.JoinVNI(ctx, codecL2VNI, 0) }()

		f.speaker.fail(errSpeakerFailed, nil)
		close(speaker.release)

		var failed ErrRouteAdvertisementFailed
		require.ErrorAs(t, <-first, &failed)
		require.ErrorAs(t, <-second, &failed, "the second join is not told it joined")
		_, ok := f.manager.RouteDistinguisher(codecL2VNI)
		assert.False(t, ok)
	})
}

func TestEVPNManager_LeaveVNI(t *testing.T) {
	ctx := context.Background()

	t.Run("withdraws the EVI's routes and the unused IP-VRF's", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, IP: netip.MustParseAddr("10.1.0.10"), VNI: codecL2VNI}))
		require.NoError(t, f.manager.AdvertisePrefix(ctx, codecL3VNI, netip.MustParsePrefix("10.1.0.0/24")))
		f.receive(remoteIMET(vtepB, 1))

		require.NoError(t, f.manager.LeaveVNI(ctx, codecL2VNI))
		types := map[EVPNRouteType]int{}
		for _, route := range f.speaker.deletedRoutes() {
			types[route.Type]++
		}
		assert.Equal(t, map[EVPNRouteType]int{EVPNTypeInclusiveMulticast: 1, EVPNTypeMACIPAdvertisement: 1, EVPNTypeIPPrefix: 1}, types)
		assert.Empty(t, f.manager.RemoteVTEPs(codecL2VNI))
		_, ok := f.manager.LookupMACForIP(codecL2VNI, netip.MustParseAddr("10.1.0.10"))
		assert.False(t, ok)
		var notJoined ErrVNINotJoined
		assert.ErrorAs(t, f.manager.AdvertisePrefix(ctx, codecL3VNI, netip.MustParsePrefix("10.1.0.0/24")), &notJoined)
	})

	t.Run("a shared IP-VRF keeps its prefixes", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI+1, codecL3VNI))
		require.NoError(t, f.manager.AdvertisePrefix(ctx, codecL3VNI, netip.MustParsePrefix("10.1.0.0/24")))
		require.NoError(t, f.manager.LeaveVNI(ctx, codecL2VNI))
		assert.Len(t, f.speaker.deletedRoutes(), 1, "only the Type-3 route")
		require.NoError(t, f.manager.WithdrawPrefix(ctx, codecL3VNI, netip.MustParsePrefix("10.1.0.0/24")))
	})

	t.Run("errors", func(t *testing.T) {
		f := newEVPNFixture(t)
		var notJoined ErrVNINotJoined
		require.ErrorAs(t, f.manager.LeaveVNI(ctx, codecL2VNI), &notJoined)
		assert.Equal(t, codecL2VNI, notJoined.VNI)

		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		f.speaker.fail(nil, errSpeakerFailed)
		var failed ErrRouteWithdrawalFailed
		require.ErrorAs(t, f.manager.LeaveVNI(ctx, codecL2VNI), &failed)
		assert.Equal(t, EVPNTypeInclusiveMulticast, failed.RouteType)
		require.ErrorAs(t, f.manager.LeaveVNI(ctx, codecL2VNI), &notJoined, "the VNI is left all the same")
	})
}

func TestEVPNManager_AdvertiseMACIP(t *testing.T) {
	ctx := context.Background()
	hostIP := netip.MustParseAddr("10.1.0.10")

	t.Run("symmetric IRB route", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, IP: hostIP, VNI: codecL2VNI, Sequence: 99}))

		route := f.speaker.lastAdded(t)
		assert.Equal(t, EVPNTypeMACIPAdvertisement, route.Type)
		assert.Equal(t, "192.0.2.11:1", route.RD.String())
		assert.Equal(t, []RouteTarget{mustRT(t, codecL2VNI), mustRT(t, codecL3VNI)}, route.RouteTargets)
		assert.Equal(t, codecL3VNI, route.MACIP.L3VNI)
		assert.Equal(t, testRouterMAC, route.RouterMAC)
		assert.Equal(t, vtepA, route.MACIP.VTEPIP)
		assert.Zero(t, route.MACIP.Sequence, "the sequence is the manager's")

		mac, ok := f.manager.LookupMACForIP(codecL2VNI, hostIP)
		assert.True(t, ok)
		assert.Equal(t, codecHostMAC, mac)
		_, err := encodeEVPNPath(route)
		assert.NoError(t, err, "the route is one the codec sends")
	})

	t.Run("an L2-only EVI carries no IRB", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}))
		route := f.speaker.lastAdded(t)
		assert.Zero(t, route.MACIP.L3VNI)
		assert.Nil(t, route.RouterMAC)
		assert.Len(t, route.RouteTargets, 1)
	})

	t.Run("errors", func(t *testing.T) {
		f := newEVPNFixture(t)
		var nilEntry ErrEntryNil
		assert.ErrorAs(t, f.manager.AdvertiseMACIP(ctx, nil), &nilEntry)
		var invalidMAC ErrInvalidMAC
		assert.ErrorAs(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, VNI: codecL2VNI}), &invalidMAC)
		var notJoined ErrVNINotJoined
		assert.ErrorAs(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}), &notJoined)
	})

	t.Run("a failed advertisement is rolled back", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		f.speaker.fail(errSpeakerFailed, nil)
		var failed ErrRouteAdvertisementFailed
		require.ErrorAs(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, IP: hostIP, VNI: codecL2VNI}), &failed)
		_, ok := f.manager.LookupMACForIP(codecL2VNI, hostIP)
		assert.False(t, ok)
		var notFound ErrMACIPNotFound
		assert.ErrorAs(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, hostIP), &notFound)
	})
}

func TestEVPNManager_WithdrawMACIP(t *testing.T) {
	ctx := context.Background()
	hostIP := netip.MustParseAddr("10.1.0.10")

	t.Run("withdraws each route of the MAC", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, IP: hostIP, VNI: codecL2VNI}))

		require.NoError(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, hostIP))
		_, ok := f.manager.LookupMACForIP(codecL2VNI, hostIP)
		assert.False(t, ok)
		require.NoError(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, netip.Addr{}))

		deleted := f.speaker.deletedRoutes()
		require.Len(t, deleted, 2)
		assert.Equal(t, hostIP, deleted[0].MACIP.IP)
		assert.False(t, deleted[1].MACIP.IP.IsValid())
	})

	t.Run("errors", func(t *testing.T) {
		f := newEVPNFixture(t)
		var notFound ErrMACIPNotFound
		assert.ErrorAs(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, hostIP), &notFound)

		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}))
		assert.ErrorAs(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, hostIP), &notFound, "another IP of the MAC")

		f.speaker.fail(nil, errSpeakerFailed)
		var failed ErrRouteWithdrawalFailed
		assert.ErrorAs(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, netip.Addr{}), &failed)
	})

	t.Run("a failed withdrawal still hands the MAC to the remote VTEP", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}))
		f.receive(remoteMACRoute(vtepB, "", 0))
		assert.Empty(t, f.notified.take(), "our route wins the tie")

		f.speaker.fail(nil, errSpeakerFailed)
		var failed ErrRouteWithdrawalFailed
		require.ErrorAs(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, netip.Addr{}), &failed)
		assert.ErrorIs(t, failed, errSpeakerFailed)

		moved := f.notified.take()
		require.Len(t, moved, 1, "the handlers are told where the MAC is now")
		assert.False(t, moved[0].IsWithdraw)
		assert.Equal(t, vtepB, moved[0].MACIP.VTEPIP)
		vtep, ok := f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		assert.True(t, ok)
		assert.Equal(t, vtepB, vtep)
	})

	t.Run("a retry completes a failed withdrawal", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, IP: hostIP, VNI: codecL2VNI}))
		f.speaker.fail(nil, errSpeakerFailed)
		var failed ErrRouteWithdrawalFailed
		require.ErrorAs(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, hostIP), &failed)
		f.speaker.fail(nil, nil)

		require.NoError(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, hostIP))

		deleted := f.speaker.deletedRoutes()
		require.Len(t, deleted, 1)
		assert.Equal(t, hostIP, deleted[0].MACIP.IP)
		var notFound ErrMACIPNotFound
		assert.ErrorAs(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, hostIP), &notFound,
			"a completed withdrawal is not repeated")
	})

	t.Run("leaving the VNI completes a failed withdrawal", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, IP: hostIP, VNI: codecL2VNI}))
		f.speaker.fail(nil, errSpeakerFailed)
		require.Error(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, hostIP))
		f.speaker.fail(nil, nil)

		require.NoError(t, f.manager.LeaveVNI(ctx, codecL2VNI))

		var macips []*EVPNRouteData
		for _, route := range f.speaker.deletedRoutes() {
			if route.MACIP != nil {
				macips = append(macips, route)
			}
		}
		require.Len(t, macips, 1)
		assert.Equal(t, hostIP, macips[0].MACIP.IP)
	})

	t.Run("advertising the binding again drops its failed withdrawal", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, IP: hostIP, VNI: codecL2VNI}))
		f.speaker.fail(nil, errSpeakerFailed)
		require.Error(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, hostIP))
		f.speaker.fail(nil, nil)

		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, IP: hostIP, VNI: codecL2VNI}))
		require.NoError(t, f.manager.LeaveVNI(ctx, codecL2VNI))

		var macips int
		for _, route := range f.speaker.deletedRoutes() {
			if route.MACIP != nil {
				macips++
			}
		}
		assert.Equal(t, 1, macips, "the route is withdrawn once, as the advertised binding")
	})
}

func TestEVPNManager_Prefixes(t *testing.T) {
	ctx := context.Background()
	prefix := netip.MustParsePrefix("10.1.0.0/24")

	t.Run("interface-less Type-5 route in the IP-VRF", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		require.NoError(t, f.manager.AdvertisePrefix(ctx, codecL3VNI, netip.MustParsePrefix("10.1.0.77/24")))

		route := f.speaker.lastAdded(t)
		assert.Equal(t, EVPNTypeIPPrefix, route.Type)
		assert.Equal(t, "192.0.2.11:2", route.RD.String(), "the IP-VRF has its own RD")
		assert.Equal(t, []RouteTarget{mustRT(t, codecL3VNI)}, route.RouteTargets)
		assert.Equal(t, prefix, route.PrefixData.Prefix, "the prefix is masked")
		assert.Equal(t, codecL3VNI, route.PrefixData.VNI)
		assert.Equal(t, testRouterMAC, route.RouterMAC)

		require.NoError(t, f.manager.WithdrawPrefix(ctx, codecL3VNI, prefix))
		var notFound ErrPrefixNotFound
		assert.ErrorAs(t, f.manager.WithdrawPrefix(ctx, codecL3VNI, prefix), &notFound)
	})

	t.Run("errors", func(t *testing.T) {
		f := newEVPNFixture(t)
		var invalid ErrPrefixInvalid
		assert.ErrorAs(t, f.manager.AdvertisePrefix(ctx, codecL3VNI, netip.Prefix{}), &invalid)
		var notJoined ErrVNINotJoined
		assert.ErrorAs(t, f.manager.AdvertisePrefix(ctx, codecL3VNI, prefix), &notJoined)
		assert.ErrorAs(t, f.manager.WithdrawPrefix(ctx, codecL3VNI, prefix), &notJoined)

		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		f.speaker.fail(errSpeakerFailed, nil)
		var advertise ErrRouteAdvertisementFailed
		assert.ErrorAs(t, f.manager.AdvertisePrefix(ctx, codecL3VNI, prefix), &advertise)
		f.speaker.fail(nil, nil)
		assert.ErrorAs(t, f.manager.WithdrawPrefix(ctx, codecL3VNI, prefix), new(ErrPrefixNotFound), "the failed prefix was not kept")

		require.NoError(t, f.manager.AdvertisePrefix(ctx, codecL3VNI, prefix))
		f.speaker.fail(nil, errSpeakerFailed)
		var withdraw ErrRouteWithdrawalFailed
		assert.ErrorAs(t, f.manager.WithdrawPrefix(ctx, codecL3VNI, prefix), &withdraw)
	})
}

func TestEVPNManager_Import(t *testing.T) {
	ctx := context.Background()

	t.Run("only joined VNIs with their route target", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))

		foreign := remoteMACRoute(vtepB, "10.1.0.20", 0)
		foreign.RouteTargets = []RouteTarget{{AS: 65000, Value: 1<<28 | 999}}
		f.receive(foreign)
		other := remoteMACRoute(vtepB, "", 0)
		other.MACIP.VNI = codecL2VNI + 1
		f.receive(other)
		assert.Empty(t, f.notified.take())

		irb := remoteMACRoute(vtepB, "10.1.0.20", 0)
		irb.MACIP.L3VNI = codecL3VNI
		irb.RouteTargets = append(irb.RouteTargets, mustRT(t, codecL3VNI))
		irb.RouterMAC = codecRouterMAC
		f.receive(irb)
		got := f.notified.take()
		require.Len(t, got, 1)
		assert.Equal(t, codecRouterMAC, got[0].RouterMAC)
		assert.Equal(t, codecL3VNI, got[0].MACIP.L3VNI)

		mac, ok := f.manager.LookupMACForIP(codecL2VNI, netip.MustParseAddr("10.1.0.20"))
		assert.True(t, ok, "ARP suppression learns the remote binding")
		assert.Equal(t, codecHostMAC, mac)
		vtep, ok := f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		assert.True(t, ok)
		assert.Equal(t, vtepB, vtep)
	})

	t.Run("an L3VNI label without the IP-VRF's route target is not taken", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		// RFC 9135 §5.1: the label names an IP-VRF only with its route target.
		bridged := remoteMACRoute(vtepB, "10.1.0.20", 0)
		bridged.MACIP.L3VNI = codecL3VNI
		bridged.RouterMAC = codecRouterMAC
		f.receive(bridged)
		got := f.notified.take()
		require.Len(t, got, 1)
		assert.Zero(t, got[0].MACIP.L3VNI)
		assert.Nil(t, got[0].RouterMAC)

		f.receive(withdrawn(bridged))
		gone := f.notified.take()
		require.Len(t, gone, 1)
		assert.True(t, gone[0].IsWithdraw)
		assert.Zero(t, gone[0].MACIP.L3VNI, "the withdrawal matches what was reported")
	})

	t.Run("own routes are skipped", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		f.receive(remoteMACRoute(vtepA, "", 0))
		reflected := remoteIMET(vtepB, 1)
		reflected.NextHop = vtepA
		f.receive(reflected)
		assert.Empty(t, f.notified.take())
		assert.Empty(t, f.manager.RemoteVTEPs(codecL2VNI))
	})

	t.Run("routes received before the join are taken in by it", func(t *testing.T) {
		f := newEVPNFixture(t)
		f.receive(remoteIMET(vtepB, 1))
		f.receive(remoteMACRoute(vtepB, "", 0))
		f.receive(&EVPNRouteData{
			Type:         EVPNTypeIPPrefix,
			RD:           RouteDistinguisher{Admin: vtepB, Index: 2},
			RouteTargets: []RouteTarget{mustRT(t, codecL3VNI)},
			PrefixData:   &PrefixRoute{Prefix: netip.MustParsePrefix("10.9.0.0/16"), VNI: codecL3VNI, VTEPIP: vtepB},
			NextHop:      vtepB,
			RouterMAC:    codecRouterMAC,
		})
		assert.Empty(t, f.notified.take())

		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		assert.Len(t, f.notified.take(), 3)
		assert.Equal(t, []netip.Addr{vtepB}, f.manager.RemoteVTEPs(codecL2VNI))

		require.NoError(t, f.manager.LeaveVNI(ctx, codecL2VNI))
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		assert.Len(t, f.notified.take(), 3, "leaving keeps the routes received")
	})

	t.Run("Type-3 membership is counted per VTEP", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		f.receive(remoteIMET(vtepB, 1))
		f.receive(remoteIMET(vtepB, 1))
		f.receive(remoteIMET(vtepB, 7))
		f.receive(remoteIMET(vtepC, 1))
		assert.Len(t, f.notified.take(), 2, "one join per VTEP")
		assert.Equal(t, []netip.Addr{vtepB, vtepC}, f.manager.RemoteVTEPs(codecL2VNI))

		f.receive(withdrawn(remoteIMET(vtepB, 1)))
		assert.Empty(t, f.notified.take(), "B still has a Type-3 route")
		f.receive(withdrawn(remoteIMET(vtepB, 7)))
		left := f.notified.take()
		require.Len(t, left, 1)
		assert.True(t, left[0].IsWithdraw)
		assert.Equal(t, []netip.Addr{vtepC}, f.manager.RemoteVTEPs(codecL2VNI))

		f.receive(withdrawn(remoteIMET(vtepB, 7)))
		assert.Empty(t, f.notified.take(), "an unknown withdrawal is ignored")
	})

	t.Run("a route that changes its route target leaves the import", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		f.receive(remoteIMET(vtepB, 1))
		retargeted := remoteIMET(vtepB, 1)
		retargeted.RouteTargets = []RouteTarget{{AS: 65000, Value: 1}}
		f.receive(retargeted)
		left := f.notified.take()
		require.Len(t, left, 2)
		assert.True(t, left[1].IsWithdraw)
		assert.Empty(t, f.manager.RemoteVTEPs(codecL2VNI))
	})

	t.Run("a failing handler does not stop the others", func(t *testing.T) {
		f := newEVPNFixture(t)
		f.manager.RegisterHandler(func(context.Context, *EVPNRouteData) error { return errSpeakerFailed })
		second := &notifications{}
		f.manager.RegisterHandler(second.handle)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		f.receive(remoteIMET(vtepB, 1))
		assert.Len(t, second.take(), 1)
	})
}

func TestEVPNManager_NextHopChange(t *testing.T) {
	ctx := context.Background()

	t.Run("a Type-5 route moved to another VTEP leaves the old one", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, codecL3VNI))
		route := &EVPNRouteData{
			Type:         EVPNTypeIPPrefix,
			RD:           RouteDistinguisher{Admin: vtepB, Index: 2},
			RouteTargets: []RouteTarget{mustRT(t, codecL3VNI)},
			PrefixData:   &PrefixRoute{Prefix: netip.MustParsePrefix("10.9.0.0/16"), VNI: codecL3VNI, VTEPIP: vtepB},
			NextHop:      vtepB,
			RouterMAC:    codecRouterMAC,
		}
		f.receive(route)
		f.notified.take()

		moved := route.Clone()
		moved.NextHop = vtepC
		moved.PrefixData.VTEPIP = vtepC
		f.receive(moved)
		got := f.notified.take()
		require.Len(t, got, 2)
		assert.True(t, got[0].IsWithdraw)
		assert.Equal(t, vtepB, got[0].PrefixData.VTEPIP, "the route at the old VTEP is withdrawn")
		assert.False(t, got[1].IsWithdraw)
		assert.Equal(t, vtepC, got[1].PrefixData.VTEPIP)
	})

	t.Run("a Type-2 binding moved to another VTEP leaves the old one", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		f.receive(remoteMACRoute(vtepB, "", 0))
		binding := remoteMACRoute(vtepB, "10.1.0.20", 0)
		f.receive(binding)
		f.notified.take()

		moved := binding.Clone()
		moved.NextHop = vtepC
		moved.MACIP.VTEPIP = vtepC
		f.receive(moved)
		got := f.notified.take()
		require.Len(t, got, 1, "the MAC stays at B, its lower VTEP; the binding at B is gone")
		assert.True(t, got[0].IsWithdraw)
		assert.Equal(t, vtepB, got[0].MACIP.VTEPIP)
		_, bound := f.manager.LookupMACForIP(codecL2VNI, netip.MustParseAddr("10.1.0.20"))
		assert.False(t, bound, "ARP suppression forgets the binding at B")
	})

	t.Run("a Type-3 route with a new tunnel endpoint leaves the old one", func(t *testing.T) {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		route := remoteIMET(vtepB, 1)
		route.IMET.OriginatorIP = vtepB
		f.receive(route)
		f.notified.take()

		moved := route.Clone()
		moved.IMET.VTEPIP = vtepC
		f.receive(moved)
		got := f.notified.take()
		require.Len(t, got, 2)
		assert.True(t, got[0].IsWithdraw)
		assert.Equal(t, vtepB, got[0].IMET.VTEPIP)
		assert.Equal(t, vtepC, got[1].IMET.VTEPIP)
		assert.Equal(t, []netip.Addr{vtepC}, f.manager.RemoteVTEPs(codecL2VNI))

		// A withdrawal carries only the NLRI, whose originator is B.
		f.receive(&EVPNRouteData{
			Type:       EVPNTypeInclusiveMulticast,
			RD:         route.RD,
			IMET:       &IMETEntry{VTEPIP: vtepB, OriginatorIP: vtepB},
			IsWithdraw: true,
		})
		assert.Empty(t, f.manager.RemoteVTEPs(codecL2VNI), "the withdrawal removes the route at C")
	})
}

func TestEVPNManager_MACMobility(t *testing.T) {
	ctx := context.Background()
	hostIP := netip.MustParseAddr("10.1.0.10")

	join := func(t *testing.T) *evpnFixture {
		f := newEVPNFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		return f
	}

	t.Run("a remote route with a higher sequence takes the MAC from us", func(t *testing.T) {
		f := join(t)
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, IP: hostIP, VNI: codecL2VNI}))

		f.receive(remoteMACRoute(vtepB, "10.1.0.10", 1))
		deleted := f.speaker.deletedRoutes()
		require.Len(t, deleted, 1, "our route is withdrawn")
		assert.Equal(t, vtepA, deleted[0].MACIP.VTEPIP)
		vtep, ok := f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		assert.True(t, ok)
		assert.Equal(t, vtepB, vtep)
		assert.Len(t, f.notified.take(), 1)
		var notFound ErrMACIPNotFound
		assert.ErrorAs(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, hostIP), &notFound)
	})

	t.Run("a stale remote route loses to ours", func(t *testing.T) {
		f := join(t)
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}))
		f.receive(remoteMACRoute(vtepB, "", 0))
		assert.Empty(t, f.speaker.deletedRoutes(), "a tie goes to the lower address: ours")
		_, ok := f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		assert.False(t, ok)
		assert.Empty(t, f.notified.take())
	})

	t.Run("taking a MAC over uses the remote sequence plus one", func(t *testing.T) {
		f := join(t)
		f.receive(remoteMACRoute(vtepB, "", 2))
		require.Len(t, f.notified.take(), 1)
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}))
		assert.Equal(t, uint32(3), f.speaker.lastAdded(t).MACIP.Sequence)
		_, ok := f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		assert.False(t, ok, "the MAC is local now")

		f.receive(withdrawn(remoteMACRoute(vtepB, "", 2)))
		assert.Empty(t, f.notified.take(), "B's withdrawal after the move changes nothing")
	})

	t.Run("a remote move, then fallback on withdrawal", func(t *testing.T) {
		f := join(t)
		f.receive(remoteMACRoute(vtepB, "", 0))
		f.receive(remoteMACRoute(vtepC, "", 1))
		vtep, ok := f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		require.True(t, ok)
		assert.Equal(t, vtepC, vtep)
		require.Len(t, f.notified.take(), 2)

		f.receive(withdrawn(remoteMACRoute(vtepC, "", 1)))
		vtep, ok = f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		require.True(t, ok)
		assert.Equal(t, vtepB, vtep, "B still advertises the MAC")
		back := f.notified.take()
		require.Len(t, back, 1)
		assert.Equal(t, vtepB, back[0].MACIP.VTEPIP)

		f.receive(withdrawn(remoteMACRoute(vtepB, "", 0)))
		gone := f.notified.take()
		require.Len(t, gone, 1)
		assert.True(t, gone[0].IsWithdraw)
		_, ok = f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		assert.False(t, ok)
	})

	t.Run("withdrawing one of the active VTEP's routes reports that binding gone", func(t *testing.T) {
		f := join(t)
		f.receive(remoteMACRoute(vtepB, "", 0))
		f.receive(remoteMACRoute(vtepB, "10.1.0.10", 0))
		require.Len(t, f.notified.take(), 2)

		f.receive(withdrawn(remoteMACRoute(vtepB, "10.1.0.10", 0)))
		gone := f.notified.take()
		require.Len(t, gone, 1)
		assert.True(t, gone[0].IsWithdraw)
		assert.Equal(t, hostIP, gone[0].MACIP.IP)
		vtep, ok := f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		assert.True(t, ok, "the MAC-only route keeps the MAC at B")
		assert.Equal(t, vtepB, vtep)
		_, bound := f.manager.LookupMACForIP(codecL2VNI, hostIP)
		assert.False(t, bound)
	})

	t.Run("withdrawing our route hands the MAC to a remote VTEP", func(t *testing.T) {
		f := join(t)
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}))
		f.receive(remoteMACRoute(vtepB, "", 0))
		require.NoError(t, f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, netip.Addr{}))
		vtep, ok := f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		assert.True(t, ok)
		assert.Equal(t, vtepB, vtep)
	})

	t.Run("a MAC that keeps moving is frozen for the hold", func(t *testing.T) {
		f := join(t)
		f.receive(remoteMACRoute(vtepB, "", 0))
		f.receive(remoteMACRoute(vtepC, "", 1))
		f.receive(remoteMACRoute(vtepB, "", 2))
		vtep, ok := f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		require.True(t, ok)
		assert.Equal(t, vtepB, vtep)
		f.notified.take()

		f.receive(remoteMACRoute(vtepC, "", 3))
		vtep, ok = f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		require.True(t, ok)
		assert.Equal(t, vtepB, vtep, "a frozen MAC ignores routes")
		assert.Empty(t, f.notified.take())
		assert.ErrorIs(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}), ErrDampeningActive)

		f.clock.advance(time.Minute)
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}))
		assert.Equal(t, uint32(3), f.speaker.lastAdded(t).MACIP.Sequence, "after B's 2")
	})
}

// gatedSpeaker holds the next gated speaker call until the test releases
// it, so the test can act while the manager waits on BGP.
type gatedSpeaker struct {
	*recordingSpeaker
	gateMu     sync.Mutex
	holdAdd    bool
	holdDelete bool
	entered    chan struct{}
	release    chan struct{}
}

func newGatedSpeaker() *gatedSpeaker {
	return &gatedSpeaker{
		recordingSpeaker: newRecordingSpeaker(),
		entered:          make(chan struct{}),
		release:          make(chan struct{}),
	}
}

// holdNext gates the next AddPath, DeletePath, or both.
func (s *gatedSpeaker) holdNext(add, del bool) {
	s.gateMu.Lock()
	defer s.gateMu.Unlock()
	s.holdAdd, s.holdDelete = add, del
}

func (s *gatedSpeaker) AddPath(ctx context.Context, path *Path) error {
	s.hold(&s.holdAdd)
	return s.recordingSpeaker.AddPath(ctx, path)
}

func (s *gatedSpeaker) DeletePath(ctx context.Context, path *Path) error {
	s.hold(&s.holdDelete)
	return s.recordingSpeaker.DeletePath(ctx, path)
}

// hold signals entered and waits for release when the call is gated.
func (s *gatedSpeaker) hold(gate *bool) {
	s.gateMu.Lock()
	gated := *gate
	*gate = false
	s.gateMu.Unlock()
	if gated {
		s.entered <- struct{}{}
		<-s.release
	}
}

// fabricView is the fabric as a handler that applies the notifications in
// the order it is told them sees it: the remote VTEPs of the VNI and where
// each remote MAC is. The routes it is used with are MAC-only, so a Type-2
// withdrawal is the MAC gone.
type fabricView struct {
	mu    sync.Mutex
	vteps map[netip.Addr]bool
	macs  map[string]netip.Addr
}

func (v *fabricView) handle(_ context.Context, route *EVPNRouteData) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case route.IMET != nil && route.IsWithdraw:
		delete(v.vteps, route.IMET.VTEPIP)
	case route.IMET != nil:
		v.vteps[route.IMET.VTEPIP] = true
	case route.MACIP != nil && route.IsWithdraw:
		if v.macs[route.MACIP.MAC.String()] == route.MACIP.VTEPIP {
			delete(v.macs, route.MACIP.MAC.String())
		}
	case route.MACIP != nil:
		v.macs[route.MACIP.MAC.String()] = route.MACIP.VTEPIP
	}
	return nil
}

func (v *fabricView) remoteVTEPs() []netip.Addr {
	v.mu.Lock()
	defer v.mu.Unlock()
	vteps := make([]netip.Addr, 0, len(v.vteps))
	for vtep := range v.vteps {
		vteps = append(vteps, vtep)
	}
	slices.SortFunc(vteps, netip.Addr.Compare)
	return vteps
}

func (v *fabricView) remoteMAC(mac net.HardwareAddr) (netip.Addr, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	vtep, ok := v.macs[mac.String()]
	return vtep, ok
}

// newGatedFixture is an EVPN fixture whose speaker can be gated, with a
// fabric view registered as a handler.
func newGatedFixture(t *testing.T) (*evpnFixture, *gatedSpeaker, *fabricView) {
	t.Helper()
	speaker := newGatedSpeaker()
	f := &evpnFixture{
		speaker:  speaker.recordingSpeaker,
		clock:    &testClock{now: time.Unix(1_700_000_000, 0)},
		notified: &notifications{},
	}
	manager, err := NewEVPNManager(evpnTestConfig(speaker, f.clock))
	require.NoError(t, err)
	manager.RegisterHandler(f.notified.handle)
	view := &fabricView{vteps: make(map[netip.Addr]bool), macs: make(map[string]netip.Addr)}
	manager.RegisterHandler(view.handle)
	f.manager = manager
	return f, speaker, view
}

// TestEVPNManager_HandlerOrder interleaves a received route with a join or
// a local withdrawal waiting on BGP: the handlers must be told the changes
// in the order they were made, so what they program matches the manager.
func TestEVPNManager_HandlerOrder(t *testing.T) {
	ctx := context.Background()

	t.Run("a Type-3 withdrawal during a join is not undone by the join", func(t *testing.T) {
		f, speaker, view := newGatedFixture(t)
		f.receive(remoteIMET(vtepB, 1))

		speaker.holdNext(true, false)
		joined := make(chan error, 1)
		go func() { joined <- f.manager.JoinVNI(ctx, codecL2VNI, 0) }()
		<-speaker.entered
		f.receive(withdrawn(remoteIMET(vtepB, 1)))
		close(speaker.release)
		require.NoError(t, <-joined)

		assert.Empty(t, f.manager.RemoteVTEPs(codecL2VNI))
		assert.Empty(t, view.remoteVTEPs(), "the handlers were told B joined after it left")
	})

	t.Run("a Type-3 route received during a join is taken in once", func(t *testing.T) {
		f, speaker, view := newGatedFixture(t)

		speaker.holdNext(true, false)
		joined := make(chan error, 1)
		go func() { joined <- f.manager.JoinVNI(ctx, codecL2VNI, 0) }()
		<-speaker.entered
		f.receive(remoteIMET(vtepB, 1))
		assert.ErrorAs(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}), new(ErrVNINotJoined), "the join is not done")
		assert.ErrorAs(t, f.manager.LeaveVNI(ctx, codecL2VNI), new(ErrVNINotJoined), "the join is not done")
		close(speaker.release)
		require.NoError(t, <-joined)

		assert.Len(t, f.notified.take(), 1)
		assert.Equal(t, []netip.Addr{vtepB}, f.manager.RemoteVTEPs(codecL2VNI))
		assert.Equal(t, []netip.Addr{vtepB}, view.remoteVTEPs())
		require.NoError(t, f.manager.LeaveVNI(ctx, codecL2VNI))
	})

	t.Run("a remote withdrawal during WithdrawMACIP is not undone by it", func(t *testing.T) {
		f, speaker, view := newGatedFixture(t)
		require.NoError(t, f.manager.JoinVNI(ctx, codecL2VNI, 0))
		require.NoError(t, f.manager.AdvertiseMACIP(ctx, &MACIPEntry{MAC: codecHostMAC, VNI: codecL2VNI}))
		f.receive(remoteMACRoute(vtepB, "", 0))

		speaker.holdNext(false, true)
		released := make(chan error, 1)
		go func() { released <- f.manager.WithdrawMACIP(ctx, codecL2VNI, codecHostMAC, netip.Addr{}) }()
		<-speaker.entered
		f.receive(withdrawn(remoteMACRoute(vtepB, "", 0)))
		close(speaker.release)
		require.NoError(t, <-released)

		_, ok := f.manager.RemoteMAC(codecL2VNI, codecHostMAC)
		assert.False(t, ok)
		_, seen := view.remoteMAC(codecHostMAC)
		assert.False(t, seen, "the handlers were told the MAC moved to B after B withdrew it")
	})
}
