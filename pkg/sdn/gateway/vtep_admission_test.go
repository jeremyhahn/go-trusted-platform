package gateway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/deviceverdict"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	admissionNow    = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	admissionVTEP   = netip.MustParseAddr("10.4.100.20")
	admissionVTEP2  = netip.MustParseAddr("10.4.100.21")
	errPlatformDown = errors.New("platformd unreachable")
)

type admissionIPAM struct {
	ipam.Allocator
	err       error
	refreshes int
}

func (s *admissionIPAM) GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.Allocator.GetAllocation(ctx, ip)
}

func (s *admissionIPAM) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.Allocator.GetAllocationsByDevice(ctx, deviceID)
}

func (s *admissionIPAM) Refresh(context.Context) error {
	s.refreshes++
	return s.err
}

type admissionDeviceStore struct {
	devices map[uint64]*deviceentities.Device
	err     error
}

func (s *admissionDeviceStore) Get(_ context.Context, id uint64) (*deviceentities.Device, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.devices[id], nil
}

type admissionVerdicts struct {
	records map[uint64]*deviceverdict.RecordedDeviceVerdict
	err     error
}

func (s *admissionVerdicts) LatestDeviceVerdict(_ context.Context, deviceID uint64) (*deviceverdict.RecordedDeviceVerdict, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.records[deviceID], nil
}

// admissionOverlay stands in for the overlay handler. It records the VTEPs
// revoked and replayed and, as the handler does, leaves a revoked VTEP
// refused until it is replayed.
type admissionOverlay struct {
	revoked    []netip.Addr
	replayed   []netip.Addr
	refused    []netip.Addr
	fail       map[netip.Addr]error
	failReplay error
}

func (r *admissionOverlay) RevokeVTEP(_ context.Context, vtep netip.Addr) error {
	if err := r.fail[vtep]; err != nil {
		return err
	}
	r.revoked = append(r.revoked, vtep)
	r.refuse(vtep)
	return nil
}

func (r *admissionOverlay) ReplayVTEP(_ context.Context, vtep netip.Addr) error {
	if r.failReplay != nil {
		return r.failReplay
	}
	r.replayed = append(r.replayed, vtep)
	r.refused = slices.DeleteFunc(r.refused, func(refused netip.Addr) bool { return refused == vtep })
	return nil
}

func (r *admissionOverlay) RefusedVTEPs() []netip.Addr { return slices.Clone(r.refused) }

func (r *admissionOverlay) refuse(vtep netip.Addr) {
	if !slices.Contains(r.refused, vtep) {
		r.refused = append(r.refused, vtep)
	}
}

// admissionFixture is device 7, holding the fabric VTEPs it is given, with a
// fresh signed passing verdict and a clock the test moves.
type admissionFixture struct {
	admitter *VTEPAdmitter
	ipam     *admissionIPAM
	devices  *admissionDeviceStore
	verdicts *admissionVerdicts
	overlay  *admissionOverlay
	now      time.Time
}

func newAdmissionFixture(t *testing.T, vteps ...netip.Addr) *admissionFixture {
	t.Helper()
	if len(vteps) == 0 {
		vteps = []netip.Addr{admissionVTEP}
	}
	f := &admissionFixture{
		ipam:    &admissionIPAM{Allocator: newAdmissionAllocator(t, "7", vteps...)},
		devices: &admissionDeviceStore{devices: map[uint64]*deviceentities.Device{7: {ID: 7, Hostname: "node-7", Serial: "SN7"}}},
		verdicts: &admissionVerdicts{records: map[uint64]*deviceverdict.RecordedDeviceVerdict{
			7: signedVerdict(admissionNow.Add(-time.Minute)),
		}},
		overlay: &admissionOverlay{},
		now:     admissionNow,
	}
	admitter, err := NewVTEPAdmitter(VTEPAdmissionConfig{
		IPAM:             f.ipam,
		Devices:          f.devices,
		Verdicts:         f.verdicts,
		Revoker:          f.overlay,
		Replayer:         f.overlay,
		MaxVerdictAge:    5 * time.Minute,
		VerdictClockSkew: 30 * time.Second,
		Now:              func() time.Time { return f.now },
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	f.admitter = admitter
	return f
}

func (f *admissionFixture) verdict() *deviceverdict.RecordedDeviceVerdict {
	return f.verdicts.records[7]
}

func newAdmissionAllocator(t *testing.T, deviceID string, vteps ...netip.Addr) ipam.Allocator {
	t.Helper()
	allocator := backends.NewMemoryBackend()
	pool := &ipam.Pool{
		ID:   "fabric-pool",
		Name: "fabric",
		CIDR: netip.MustParsePrefix("10.4.100.0/24"),
		Zone: string(zone.ZoneFabric),
	}
	require.NoError(t, allocator.CreatePool(context.Background(), pool))
	for _, vtep := range vteps {
		_, err := allocator.AllocateSpecific(context.Background(), &ipam.AllocationRequest{
			PoolID:      pool.ID,
			Zone:        string(zone.ZoneFabric),
			DeviceID:    deviceID,
			Hostname:    "node-" + deviceID,
			RequestedIP: vtep,
		})
		require.NoError(t, err)
	}
	return allocator
}

func signedVerdict(recordedAt time.Time) *deviceverdict.RecordedDeviceVerdict {
	return &deviceverdict.RecordedDeviceVerdict{
		EventID:    "verdict-7",
		RecordedAt: recordedAt,
		Verdict: deviceverdict.DeviceVerdict{
			DeviceID:       7,
			HostID:         "node-7",
			Serial:         "SN7",
			Passed:         true,
			BaselineSource: "signed",
			ProfileID:      3,
		},
	}
}

func installed(vteps ...netip.Addr) []modes.InstalledVTEP {
	out := make([]modes.InstalledVTEP, 0, len(vteps))
	for _, vtep := range vteps {
		out = append(out, modes.InstalledVTEP{VTEP: vtep, VNIs: []uint32{10100}})
	}
	return out
}

func requireVerdictDenied(t *testing.T, err error, reason string) {
	t.Helper()
	var verdictErr ErrOverlayVTEPVerdict
	require.True(t, errors.As(err, &verdictErr), "got %v", err)
	assert.Contains(t, verdictErr.Reason, reason)
}

func TestNewVTEPAdmitter_RejectsBadConfig(t *testing.T) {
	base := func() VTEPAdmissionConfig {
		return VTEPAdmissionConfig{
			IPAM:     &admissionIPAM{},
			Devices:  &admissionDeviceStore{},
			Verdicts: &admissionVerdicts{},
			Revoker:  &admissionOverlay{},
			Replayer: &admissionOverlay{},
		}
	}
	cases := map[string]func(*VTEPAdmissionConfig){
		"ipam":               func(c *VTEPAdmissionConfig) { c.IPAM = nil },
		"devices":            func(c *VTEPAdmissionConfig) { c.Devices = nil },
		"verdicts":           func(c *VTEPAdmissionConfig) { c.Verdicts = nil },
		"revoker":            func(c *VTEPAdmissionConfig) { c.Revoker = nil },
		"replayer":           func(c *VTEPAdmissionConfig) { c.Replayer = nil },
		"max_verdict_age":    func(c *VTEPAdmissionConfig) { c.MaxVerdictAge = -time.Second },
		"verdict_clock_skew": func(c *VTEPAdmissionConfig) { c.VerdictClockSkew = -time.Second },
		"read_timeout":       func(c *VTEPAdmissionConfig) { c.ReadTimeout = -time.Second },
	}
	for field, breakIt := range cases {
		t.Run(field, func(t *testing.T) {
			cfg := base()
			breakIt(&cfg)

			_, err := NewVTEPAdmitter(cfg)

			var configErr ErrOverlayAdmissionConfig
			require.True(t, errors.As(err, &configErr), "got %v", err)
			assert.Equal(t, field, configErr.Field)
		})
	}

	t.Run("defaults", func(t *testing.T) {
		admitter, err := NewVTEPAdmitter(base())

		require.NoError(t, err)
		assert.Equal(t, DefaultOverlayVerdictMaxAge, admitter.maxVerdictAge)
		assert.Equal(t, DefaultOverlayVerdictClockSkew, admitter.clockSkew)
		assert.Equal(t, DefaultOverlayAdmissionReadTimeout, admitter.readTimeout)
	})
}

func TestVTEPAdmitter_AdmitsSignedFreshFabricVerdict(t *testing.T) {
	f := newAdmissionFixture(t)

	require.NoError(t, f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP))

	got := f.admitter.Admitted(installed(admissionVTEP))
	require.Len(t, got, 1)
	assert.Equal(t, uint64(7), got[0].DeviceID)
	assert.Equal(t, "signed", got[0].BaselineSource)
	assert.Equal(t, "node-7", got[0].Hostname)
	assert.Equal(t, admissionNow.Add(-time.Minute), got[0].VerdictAt)
}

func TestVTEPAdmitter_RejectsBadVerdicts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*deviceverdict.RecordedDeviceVerdict)
		reason string
	}{
		{"failed verdict", func(r *deviceverdict.RecordedDeviceVerdict) { r.Verdict.Passed = false }, "failed"},
		{"unsigned baseline", func(r *deviceverdict.RecordedDeviceVerdict) { r.Verdict.BaselineSource = "tofu" }, "signed baseline"},
		{"stale verdict", func(r *deviceverdict.RecordedDeviceVerdict) { r.RecordedAt = admissionNow.Add(-10 * time.Minute) }, "stale"},
		{"no attestation time", func(r *deviceverdict.RecordedDeviceVerdict) { r.RecordedAt = time.Time{} }, "no attestation time"},
		{"recorded beyond the clock skew", func(r *deviceverdict.RecordedDeviceVerdict) { r.RecordedAt = admissionNow.Add(time.Minute) }, "future"},
		{"serial mismatch", func(r *deviceverdict.RecordedDeviceVerdict) { r.Verdict.Serial = "SN8" }, "serial"},
		{"no serial while the device has one", func(r *deviceverdict.RecordedDeviceVerdict) { r.Verdict.Serial = "" }, "serial"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdmissionFixture(t)
			tc.mutate(f.verdict())

			err := f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP)

			requireVerdictDenied(t, err, tc.reason)
		})
	}

	t.Run("no verdict recorded", func(t *testing.T) {
		f := newAdmissionFixture(t)
		delete(f.verdicts.records, 7)

		requireVerdictDenied(t, f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP), "no verdict")
	})

	t.Run("a verdict recorded within the clock skew is admitted", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.verdict().RecordedAt = admissionNow.Add(20 * time.Second)

		require.NoError(t, f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP))
	})
}

func TestVTEPAdmitter_RejectsMissingRegistryFacts(t *testing.T) {
	t.Run("unknown VTEP", func(t *testing.T) {
		f := newAdmissionFixture(t)

		err := f.admitter.AdmitVTEP(context.Background(), 10100, netip.MustParseAddr("10.4.100.99"))

		var registryErr ErrOverlayVTEPRegistry
		require.True(t, errors.As(err, &registryErr), "got %v", err)
		assert.Contains(t, registryErr.Reason, "no fabric allocation")
	})

	t.Run("non-numeric device id", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.ipam.Allocator = newAdmissionAllocator(t, "node-7", admissionVTEP)

		err := f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP)

		var registryErr ErrOverlayVTEPRegistry
		require.True(t, errors.As(err, &registryErr), "got %v", err)
		assert.Contains(t, registryErr.Reason, "numeric")
	})

	t.Run("unregistered device", func(t *testing.T) {
		for name, err := range map[string]error{"missing": nil, "not found": ErrOverlayRecordNotFound} {
			t.Run(name, func(t *testing.T) {
				f := newAdmissionFixture(t)
				delete(f.devices.devices, 7)
				f.devices.err = err

				var deviceErr ErrOverlayVTEPDevice
				admitErr := f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP)
				require.True(t, errors.As(admitErr, &deviceErr), "got %v", admitErr)
				assert.Equal(t, uint64(7), deviceErr.DeviceID)
			})
		}
	})
}

// TestVTEPAdmitter_OutageIsNotADenial pins that a platformd read failure
// refuses the route without being mistaken for the device being denied.
func TestVTEPAdmitter_OutageIsNotADenial(t *testing.T) {
	outages := map[string]func(*admissionFixture){
		"ipam":    func(f *admissionFixture) { f.ipam.err = errPlatformDown },
		"device":  func(f *admissionFixture) { f.devices.err = errPlatformDown },
		"verdict": func(f *admissionFixture) { f.verdicts.err = errPlatformDown },
	}
	for source, fail := range outages {
		t.Run(source, func(t *testing.T) {
			f := newAdmissionFixture(t)
			require.NoError(t, f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP))
			fail(f)

			err := f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP)

			var unavailable ErrOverlayAdmissionUnavailable
			require.True(t, errors.As(err, &unavailable), "got %v", err)
			assert.Equal(t, source, unavailable.Source)
			assert.ErrorIs(t, err, errPlatformDown)
			assert.Equal(t, uint64(7), f.admitter.Admitted(installed(admissionVTEP))[0].DeviceID,
				"an outage leaves the earlier admission in place")
		})
	}
}

// cachedIPAM answers from the allocations of its last refresh, as the
// gatewayd allocation index does, while platformd already holds current.
type cachedIPAM struct {
	cached, current ipam.Allocator
	refreshErr      error
	refreshes       int
}

func (c *cachedIPAM) GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error) {
	return c.cached.GetAllocation(ctx, ip)
}

func (c *cachedIPAM) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	return c.cached.GetAllocationsByDevice(ctx, deviceID)
}

func (c *cachedIPAM) Refresh(context.Context) error {
	c.refreshes++
	if c.refreshErr != nil {
		return c.refreshErr
	}
	c.cached = c.current
	return nil
}

// reassignedFixture is the admission fixture whose cached allocations still
// give admissionVTEP to device 7 after IPAM handed it to device 8, which has
// no verdict.
func reassignedFixture(t *testing.T) (*admissionFixture, *cachedIPAM) {
	t.Helper()
	f := newAdmissionFixture(t)
	cache := &cachedIPAM{
		cached:  newAdmissionAllocator(t, "7", admissionVTEP),
		current: newAdmissionAllocator(t, "8", admissionVTEP),
	}
	f.admitter.ipam = cache
	f.devices.devices[8] = &deviceentities.Device{ID: 8, Hostname: "node-8", Serial: "SN8"}
	return f, cache
}

// An address IPAM gave to another device stayed in the cached allocations
// until the next sweep, so the new holder's routes were judged, and admitted,
// on the previous holder's verdict.
func TestVTEPAdmitter_JudgesAReassignedAddressByItsNewDevice(t *testing.T) {
	f, cache := reassignedFixture(t)

	err := f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP)

	var verdictErr ErrOverlayVTEPVerdict
	require.True(t, errors.As(err, &verdictErr), "got %v", err)
	assert.Equal(t, uint64(8), verdictErr.DeviceID)
	assert.Equal(t, 1, cache.refreshes)
	assert.Equal(t, []AdmittedVTEP{{VTEP: admissionVTEP}}, f.admitter.Admitted(installed(admissionVTEP)))

	t.Run("a denial from the cache costs no listing", func(t *testing.T) {
		require.Error(t, f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP))
		assert.Equal(t, 1, cache.refreshes)
	})
}

func TestVTEPAdmitter_ConfirmsANewAdmissionOnce(t *testing.T) {
	f, cache := reassignedFixture(t)
	cache.current = cache.cached

	for range 3 {
		require.NoError(t, f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP))
	}

	assert.Equal(t, 1, cache.refreshes, "routes of an admitted VTEP are answered from the cache")
	assert.Equal(t, uint64(7), f.admitter.Admitted(installed(admissionVTEP))[0].DeviceID)
}

func TestVTEPAdmitter_RefusesANewAdmissionItCannotConfirm(t *testing.T) {
	f, cache := reassignedFixture(t)
	cache.refreshErr = errPlatformDown

	err := f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP)

	var unavailable ErrOverlayAdmissionUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, "ipam", unavailable.Source)
	assert.ErrorIs(t, err, errPlatformDown)
	assert.Equal(t, []AdmittedVTEP{{VTEP: admissionVTEP}}, f.admitter.Admitted(installed(admissionVTEP)))
}

// A replay installs new decap flows, so it must rest on a fresh listing. With
// the refresh failed, the sweep judged a VTEP that was both installed and
// refused from the cached allocation, remembered it, and the replayed routes
// were then admitted without being confirmed: new flows from an address IPAM
// had already given to another device.
func TestVTEPAdmitter_ReplaysNothingWithoutAFreshListing(t *testing.T) {
	ctx := context.Background()
	stale := func(t *testing.T) (*admissionFixture, *cachedIPAM) {
		f, cache := reassignedFixture(t)
		cache.refreshErr = errPlatformDown
		f.overlay.refuse(admissionVTEP)
		return f, cache
	}

	t.Run("an installed and refused VTEP", func(t *testing.T) {
		f, _ := stale(t)

		err := f.admitter.Sweep(ctx, installed(admissionVTEP))

		var unavailable ErrOverlayAdmissionUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		assert.Equal(t, "ipam", unavailable.Source)
		assert.Empty(t, f.overlay.replayed, "no route is replayed from a stale allocation")
		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.refused)
	})

	t.Run("a refused VTEP that is not installed", func(t *testing.T) {
		f, _ := stale(t)

		require.Error(t, f.admitter.Sweep(ctx, nil))

		assert.Empty(t, f.overlay.replayed)
	})

	t.Run("a device that passed attestation", func(t *testing.T) {
		f, _ := stale(t)

		deliverVerdict(ctx, f.admitter, *signedVerdict(admissionNow))

		assert.Empty(t, f.overlay.replayed)
	})

	t.Run("the next sweep with a fresh listing judges the new holder", func(t *testing.T) {
		f, cache := stale(t)
		require.Error(t, f.admitter.Sweep(ctx, nil))
		cache.refreshErr = nil

		require.NoError(t, f.admitter.Sweep(ctx, nil))

		assert.Empty(t, f.overlay.replayed, "device 8 has no verdict")
	})
}

// outageFixture admits admissionVTEP for device 7 on a fresh listing, with
// a verdict attested at outageValidated, and then fails every IPAM refresh.
func outageFixture(t *testing.T) (*admissionFixture, *cachedIPAM) {
	t.Helper()
	f := newAdmissionFixture(t)
	owned := newAdmissionAllocator(t, "7", admissionVTEP)
	cache := &cachedIPAM{cached: owned, current: owned}
	f.admitter.ipam = cache
	require.NoError(t, f.admitter.Sweep(context.Background(), installed(admissionVTEP)))
	cache.refreshErr = errPlatformDown
	return f, cache
}

// outageValidated is when the verdict behind outageFixture's last fully
// validated admission was attested; that admission lapses five minutes later.
var outageValidated = admissionNow.Add(-time.Minute)

// attestAt moves the clock to at and records a passing verdict attested then.
func (f *admissionFixture) attestAt(at time.Time) {
	f.now = at
	f.verdicts.records[7] = signedVerdict(at)
}

func (f *admissionFixture) admittedVerdictAt(t *testing.T) time.Time {
	t.Helper()
	admitted := f.admitter.Admitted(installed(admissionVTEP))
	require.Len(t, admitted, 1)
	return admitted[0].VerdictAt
}

func TestVTEPAdmitter_AnIPAMOutageCannotRenewAdmission(t *testing.T) {
	ctx := context.Background()
	f, _ := outageFixture(t)

	f.attestAt(admissionNow.Add(3 * time.Minute))
	err := f.admitter.Sweep(ctx, installed(admissionVTEP))

	var unavailable ErrOverlayAdmissionUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, "ipam", unavailable.Source)
	assert.Empty(t, f.overlay.revoked, "the last validated admission is still within verdict-max-age")
	assert.Equal(t, outageValidated, f.admittedVerdictAt(t), "a pass on a stale allocation renews nothing")

	f.attestAt(outageValidated.Add(5*time.Minute + time.Second))
	require.Error(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))

	assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked,
		"the VTEP is withdrawn at the last validated bound, however fresh its verdict")
}

func TestVTEPAdmitter_ReportsAFailedRevocationOfALapsedAdmission(t *testing.T) {
	f, _ := outageFixture(t)
	f.overlay.fail = map[netip.Addr]error{admissionVTEP: errPlatformDown}
	f.attestAt(outageValidated.Add(5*time.Minute + time.Second))

	err := f.admitter.Sweep(context.Background(), installed(admissionVTEP))

	var revokeErr ErrOverlayVTEPRevoke
	require.True(t, errors.As(err, &revokeErr), "got %v", err)
	assert.Equal(t, admissionVTEP, revokeErr.VTEP)
	assert.Equal(t, []AdmittedVTEP{{VTEP: admissionVTEP}}, f.admitter.Admitted(installed(admissionVTEP)))
}

func TestVTEPAdmitter_AnIPAMOutageCannotRenewAdmissionThroughARoute(t *testing.T) {
	f, cache := outageFixture(t)
	require.Error(t, f.admitter.Sweep(context.Background(), installed(admissionVTEP)))
	f.attestAt(admissionNow.Add(3 * time.Minute))

	err := f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP)

	var unavailable ErrOverlayAdmissionUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.ErrorIs(t, err, errPlatformDown)
	assert.Equal(t, 3, cache.refreshes, "a route on a stale index is confirmed first")
	assert.Equal(t, outageValidated, f.admittedVerdictAt(t))
}

func TestVTEPAdmitter_RenewsAdmissionWhenIPAMRecovers(t *testing.T) {
	ctx := context.Background()
	f, cache := outageFixture(t)
	f.attestAt(admissionNow.Add(3 * time.Minute))
	require.Error(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))

	cache.refreshErr = nil
	require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))
	assert.Equal(t, f.now, f.admittedVerdictAt(t), "a fresh listing that still names device 7 renews")

	f.now = outageValidated.Add(5*time.Minute + time.Second)
	require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))
	assert.Empty(t, f.overlay.revoked)

	t.Run("a route after recovery needs no listing", func(t *testing.T) {
		refreshes := cache.refreshes
		require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))
		assert.Equal(t, refreshes, cache.refreshes)
	})
}

func TestVTEPAdmitter_WithdrawsAnAddressReassignedDuringAnIPAMOutage(t *testing.T) {
	ctx := context.Background()
	f, cache := outageFixture(t)
	f.attestAt(admissionNow.Add(time.Minute))
	require.Error(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))
	require.Empty(t, f.overlay.revoked)

	cache.current = newAdmissionAllocator(t, "8", admissionVTEP)
	f.devices.devices[8] = &deviceentities.Device{ID: 8, Hostname: "node-8", Serial: "SN8"}
	cache.refreshErr = nil

	require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))
	assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked, "device 8 has no verdict")
	assert.Equal(t, []AdmittedVTEP{{VTEP: admissionVTEP}}, f.admitter.Admitted(installed(admissionVTEP)))
}

func TestVTEPAdmitter_Admitted(t *testing.T) {
	f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
	require.NoError(t, f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP))
	require.NoError(t, f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP2))

	t.Run("reports only what is installed", func(t *testing.T) {
		got := f.admitter.Admitted(installed(admissionVTEP2))

		require.Len(t, got, 1)
		assert.Equal(t, admissionVTEP2, got[0].VTEP)
	})

	t.Run("an installed VTEP without an admission is reported by address", func(t *testing.T) {
		other := netip.MustParseAddr("10.4.100.30")

		got := f.admitter.Admitted(installed(other))

		assert.Equal(t, []AdmittedVTEP{{VTEP: other}}, got)
	})

	t.Run("a denial forgets the admission", func(t *testing.T) {
		f.verdict().Verdict.Passed = false
		require.Error(t, f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP))

		assert.Equal(t, []AdmittedVTEP{{VTEP: admissionVTEP}}, f.admitter.Admitted(installed(admissionVTEP)))
	})
}

func TestVTEPAdmitter_Sweep(t *testing.T) {
	ctx := context.Background()

	t.Run("keeps a VTEP the policy still admits", func(t *testing.T) {
		f := newAdmissionFixture(t)
		require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))
		refreshes := f.ipam.refreshes

		require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))

		assert.Empty(t, f.overlay.revoked)
		assert.Equal(t, refreshes+1, f.ipam.refreshes, "the sweep refreshes a caching IPAM reader")
	})

	denials := map[string]func(*admissionFixture){
		"verdict aged past the maximum": func(f *admissionFixture) { f.now = f.now.Add(10 * time.Minute) },
		"non-cryptographic failure":     func(f *admissionFixture) { f.verdict().Verdict.Passed = false },
		"allocation released": func(f *admissionFixture) {
			f.ipam.Allocator = newAdmissionAllocator(t, "7")
		},
	}
	for name, deny := range denials {
		t.Run("revokes on "+name, func(t *testing.T) {
			f := newAdmissionFixture(t)
			require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))
			deny(f)

			require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))

			assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked)
			assert.Equal(t, []AdmittedVTEP{{VTEP: admissionVTEP}}, f.admitter.Admitted(installed(admissionVTEP)))
		})
	}

	t.Run("an outage keeps a VTEP only while its verdict is fresh", func(t *testing.T) {
		f := newAdmissionFixture(t)
		require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))
		f.verdicts.err = errPlatformDown

		err := f.admitter.Sweep(ctx, installed(admissionVTEP))

		var unavailable ErrOverlayAdmissionUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		assert.Empty(t, f.overlay.revoked)

		f.now = f.now.Add(4 * time.Minute)
		require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))

		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked, "trust never outlives the verdict's maximum age")
	})

	t.Run("an outage revokes a VTEP installed without an admission", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.verdicts.err = errPlatformDown

		require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))

		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked)
	})

	t.Run("continues past a failed revocation", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		f.verdict().Verdict.Passed = false
		f.overlay.fail = map[netip.Addr]error{admissionVTEP: errPlatformDown}

		err := f.admitter.Sweep(ctx, installed(admissionVTEP, admissionVTEP2))

		var revokeErr ErrOverlayVTEPRevoke
		require.True(t, errors.As(err, &revokeErr), "got %v", err)
		assert.Equal(t, admissionVTEP, revokeErr.VTEP)
		assert.Equal(t, []netip.Addr{admissionVTEP2}, f.overlay.revoked)
	})

	t.Run("forgets admissions for VTEPs no longer installed", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))
		require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP2))

		require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP2)))

		assert.Equal(t, []AdmittedVTEP{{VTEP: admissionVTEP}}, f.admitter.Admitted(installed(admissionVTEP)))
	})

	t.Run("replays a revoked VTEP once its device passes again", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.verdict().Verdict.Passed = false
		require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))
		require.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.refused)

		require.NoError(t, f.admitter.Sweep(ctx, nil))
		require.Empty(t, f.overlay.replayed, "the device still fails")

		f.verdicts.records[7] = signedVerdict(f.now)
		require.NoError(t, f.admitter.Sweep(ctx, nil))

		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.replayed)
		assert.Empty(t, f.overlay.refused)
	})

	t.Run("replays the refused routes of an installed VTEP it admits", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.overlay.refused = []netip.Addr{admissionVTEP}

		require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))

		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.replayed)
	})

	t.Run("does not judge again a VTEP it revoked", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.verdicts.err = errPlatformDown

		require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))

		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked)
		assert.Empty(t, f.overlay.replayed)
	})

	t.Run("reports a refused VTEP it cannot judge", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.overlay.refused = []netip.Addr{admissionVTEP}
		f.verdicts.err = errPlatformDown

		err := f.admitter.Sweep(ctx, nil)

		var unavailable ErrOverlayAdmissionUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		assert.Empty(t, f.overlay.replayed)
	})

	t.Run("reports a replay that fails and continues", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		f.overlay.refused = []netip.Addr{admissionVTEP, admissionVTEP2}
		f.overlay.failReplay = errPlatformDown

		err := f.admitter.Sweep(ctx, nil)

		require.Error(t, err)
		var replayErrs []ErrOverlayVTEPReplay
		for _, joined := range err.(interface{ Unwrap() []error }).Unwrap() {
			var replayErr ErrOverlayVTEPReplay
			require.True(t, errors.As(joined, &replayErr), "got %v", joined)
			replayErrs = append(replayErrs, replayErr)
		}
		require.Len(t, replayErrs, 2, "the second VTEP is tried after the first fails")
		assert.ErrorIs(t, err, errPlatformDown)
	})
}

func TestVTEPAdmitter_RevokeDevice(t *testing.T) {
	ctx := context.Background()

	t.Run("withdraws every fabric allocation", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)

		require.NoError(t, f.admitter.RevokeDevice(ctx, 7))

		assert.ElementsMatch(t, []netip.Addr{admissionVTEP, admissionVTEP2}, f.overlay.revoked)
	})

	t.Run("continues past a failed withdrawal", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		f.overlay.fail = map[netip.Addr]error{admissionVTEP: errPlatformDown}

		err := f.admitter.RevokeDevice(ctx, 7)

		var revokeErr ErrOverlayVTEPRevoke
		require.True(t, errors.As(err, &revokeErr), "got %v", err)
		assert.Equal(t, admissionVTEP, revokeErr.VTEP)
		assert.ErrorIs(t, err, errPlatformDown)
		assert.Equal(t, []netip.Addr{admissionVTEP2}, f.overlay.revoked)
	})

	t.Run("withdraws admitted VTEPs while IPAM is down", func(t *testing.T) {
		f := newAdmissionFixture(t)
		require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))
		f.ipam.err = errPlatformDown

		err := f.admitter.RevokeDevice(ctx, 7)

		var unavailable ErrOverlayAdmissionUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked)
	})
}

// staticDatapath reports a fixed installed set.
type staticDatapath []modes.InstalledVTEP

func (d staticDatapath) InstalledVTEPs() []modes.InstalledVTEP { return d }

func TestRunAdmissionSweep(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("sweeps the installed set on every tick", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.verdicts.records[7].Verdict.Passed = false
		ticks := make(chan time.Time)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			runAdmissionSweep(ctx, ticks, staticDatapath(installed(admissionVTEP)), f.admitter, logger)
		}()
		// The channel is unbuffered, so the second send is taken only once
		// the first sweep has finished.
		ticks <- f.now
		ticks <- f.now
		cancel()
		<-done
		assert.Equal(t, []netip.Addr{admissionVTEP, admissionVTEP}, f.overlay.revoked,
			"each tick re-evaluates the installed VTEP and revokes it again")
	})

	t.Run("a sweep whose platform reads hang ends before the next tick", func(t *testing.T) {
		f := newAdmissionFixture(t)
		require.NoError(t, f.admitter.Sweep(context.Background(), installed(admissionVTEP)))
		hung := &hungPlatform{}
		f.admitter.devices = hung
		f.admitter.readTimeout = time.Nanosecond
		f.now = admissionNow.Add(5 * time.Minute)
		ticks := make(chan time.Time)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			runAdmissionSweep(ctx, ticks, staticDatapath(installed(admissionVTEP)), f.admitter, logger)
		}()
		// The second send is taken only once the hung first sweep has ended.
		ticks <- f.now
		ticks <- f.now
		cancel()
		<-done
		assert.Zero(t, hung.unbounded, "every platform read ran under a deadline")
		assert.Equal(t, []netip.Addr{admissionVTEP, admissionVTEP}, f.overlay.revoked,
			"both sweeps ran and withdrew the expired admission")
	})

	t.Run("returns on cancel without sweeping", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.verdicts.records[7].Verdict.Passed = false
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		runAdmissionSweep(ctx, make(chan time.Time), staticDatapath(installed(admissionVTEP)), f.admitter, logger)
		assert.Empty(t, f.overlay.revoked)
	})
}

// errUnboundedRead fails a platform read made without a deadline: against a
// hung platformd that read would never return.
var errUnboundedRead = errors.New("platform read has no deadline")

// hungPlatform is a platformd that accepted each read and stopped answering:
// a read ends only when its ctx does. A read with no deadline is counted and
// failed at once, so a missing bound fails the test instead of hanging it.
type hungPlatform struct {
	unbounded int
}

func (h *hungPlatform) wait(ctx context.Context) error {
	if _, bounded := ctx.Deadline(); !bounded {
		h.unbounded++
		return errUnboundedRead
	}
	<-ctx.Done()
	return ctx.Err()
}

func (h *hungPlatform) Get(ctx context.Context, _ uint64) (*deviceentities.Device, error) {
	return nil, h.wait(ctx)
}

func (h *hungPlatform) GetAllocation(ctx context.Context, _ netip.Addr) (*ipam.Allocation, error) {
	return nil, h.wait(ctx)
}

func (h *hungPlatform) GetAllocationsByDevice(ctx context.Context, _ string) ([]*ipam.Allocation, error) {
	return nil, h.wait(ctx)
}

func (h *hungPlatform) Refresh(ctx context.Context) error {
	return h.wait(ctx)
}

// liveRevoker records the state of the ctx each revocation ran under.
type liveRevoker struct {
	*admissionOverlay
	ctxErrs []error
}

func (r *liveRevoker) RevokeVTEP(ctx context.Context, vtep netip.Addr) error {
	r.ctxErrs = append(r.ctxErrs, ctx.Err())
	return r.admissionOverlay.RevokeVTEP(ctx, vtep)
}

func TestVTEPAdmitter_HungPlatformReads(t *testing.T) {
	ctx := context.Background()
	// hang admits the fixture's VTEP, then routes the reads named by attach
	// to a platformd that never answers, behind a deadline that has already
	// passed by the time a read waits on it.
	hang := func(t *testing.T, attach func(*VTEPAdmitter, *hungPlatform)) (*admissionFixture, *hungPlatform, *liveRevoker) {
		t.Helper()
		f := newAdmissionFixture(t)
		require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))
		hung := &hungPlatform{}
		revoker := &liveRevoker{admissionOverlay: f.overlay}
		attach(f.admitter, hung)
		f.admitter.revoker = revoker
		f.admitter.readTimeout = time.Nanosecond
		return f, hung, revoker
	}
	hangDevices := func(a *VTEPAdmitter, hung *hungPlatform) { a.devices = hung }
	hangIPAM := func(a *VTEPAdmitter, hung *hungPlatform) { a.ipam = hung }

	t.Run("a sweep withdraws an expired admission while platformd hangs", func(t *testing.T) {
		f, hung, revoker := hang(t, hangDevices)
		f.now = admissionNow.Add(5 * time.Minute)

		require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))

		assert.Zero(t, hung.unbounded, "every platform read ran under a deadline")
		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked)
		assert.Equal(t, []error{nil}, revoker.ctxErrs, "the revocation did not wait on the read deadline")
	})

	t.Run("a sweep holds a fresh admission through the hang as an outage", func(t *testing.T) {
		f, hung, _ := hang(t, hangDevices)

		err := f.admitter.Sweep(ctx, installed(admissionVTEP))

		var unavailable ErrOverlayAdmissionUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		assert.Equal(t, "device", unavailable.Source)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Zero(t, hung.unbounded)
		assert.Empty(t, f.overlay.revoked)
		assert.Equal(t, uint64(7), f.admitter.Admitted(installed(admissionVTEP))[0].DeviceID)
	})

	t.Run("route admission reports a hung read as an outage", func(t *testing.T) {
		f, hung, _ := hang(t, hangDevices)

		err := f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP)

		var unavailable ErrOverlayAdmissionUnavailable
		require.True(t, errors.As(err, &unavailable), "got %v", err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Zero(t, hung.unbounded)
	})

	t.Run("a failed verdict withdraws the device while the IPAM listing hangs", func(t *testing.T) {
		f, hung, revoker := hang(t, hangIPAM)

		deliverVerdict(ctx, f.admitter, streamed(deviceverdict.DeviceVerdict{DeviceID: 7}, admissionNow))

		assert.Zero(t, hung.unbounded)
		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked)
		assert.Equal(t, []error{nil}, revoker.ctxErrs, "the revocation did not wait on the listing")
	})

	t.Run("a passed verdict replays nothing while the IPAM refresh hangs", func(t *testing.T) {
		f, hung, _ := hang(t, hangIPAM)
		f.overlay.refuse(admissionVTEP)

		deliverVerdict(ctx, f.admitter, streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Passed: true}, admissionNow))

		assert.Zero(t, hung.unbounded)
		assert.Empty(t, f.overlay.replayed)
		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.refused)
	})
}

func TestVTEPAdmitter_PlatformReads(t *testing.T) {
	t.Run("bounds the reads by the read timeout", func(t *testing.T) {
		f := newAdmissionFixture(t)

		reads, cancel := f.admitter.platformReads(context.Background())
		defer cancel()

		deadline, bounded := reads.Deadline()
		require.True(t, bounded)
		assert.False(t, deadline.After(time.Now().Add(DefaultOverlayAdmissionReadTimeout)))
	})

	t.Run("a cancelled caller ends the reads", func(t *testing.T) {
		f := newAdmissionFixture(t)
		ctx, cancelCaller := context.WithCancel(context.Background())
		cancelCaller()

		reads, cancel := f.admitter.platformReads(ctx)
		defer cancel()

		assert.ErrorIs(t, reads.Err(), context.Canceled)
	})
}

func TestOverlayHandlerProxy(t *testing.T) {
	ctx := context.Background()

	t.Run("refuses revocations and replays before the handler is built", func(t *testing.T) {
		proxy := &overlayHandlerProxy{}
		var unavailable *ErrServiceUnavailable

		assert.ErrorAs(t, proxy.RevokeVTEP(ctx, admissionVTEP), &unavailable)
		assert.ErrorAs(t, proxy.ReplayVTEP(ctx, admissionVTEP), &unavailable)
		assert.Empty(t, proxy.RefusedVTEPs())
	})

	t.Run("hands everything to the handler once built", func(t *testing.T) {
		overlay := &admissionOverlay{}
		proxy := &overlayHandlerProxy{}
		proxy.set(overlay, nil)

		require.NoError(t, proxy.RevokeVTEP(ctx, admissionVTEP))
		assert.Equal(t, []netip.Addr{admissionVTEP}, proxy.RefusedVTEPs())
		require.NoError(t, proxy.ReplayVTEP(ctx, admissionVTEP))

		assert.Equal(t, []netip.Addr{admissionVTEP}, overlay.revoked)
		assert.Equal(t, []netip.Addr{admissionVTEP}, overlay.replayed)
		assert.Empty(t, proxy.RefusedVTEPs())
	})
}

// streamed is v as the verdict stream delivers it, recorded at at.
func streamed(v deviceverdict.DeviceVerdict, at time.Time) deviceverdict.RecordedDeviceVerdict {
	return deviceverdict.RecordedDeviceVerdict{Verdict: v, EventID: "streamed-verdict", RecordedAt: at}
}

// deliverVerdict hands the admitter a streamed verdict and waits for the IPAM
// listing a failed verdict leaves running, as the follower does before it returns.
func deliverVerdict(ctx context.Context, a *VTEPAdmitter, recorded deviceverdict.RecordedDeviceVerdict) {
	a.OnDeviceVerdict(ctx, recorded)
	a.waitListings()
}

// gatedIPAM announces each device listing on listing and holds it until
// release is closed or the listing's ctx ends.
type gatedIPAM struct {
	*admissionIPAM
	listing chan string
	release chan struct{}
}

func (g *gatedIPAM) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	g.listing <- deviceID
	select {
	case <-g.release:
		return g.admissionIPAM.GetAllocationsByDevice(ctx, deviceID)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// signalRevoker reports each revoked VTEP on revoked.
type signalRevoker struct {
	revoked chan netip.Addr
}

func (r signalRevoker) RevokeVTEP(_ context.Context, vtep netip.Addr) error {
	r.revoked <- vtep
	return nil
}

// drain closes revoked and returns what is left on it. Call it only once no
// revocation can still be running.
func (r signalRevoker) drain() []netip.Addr {
	close(r.revoked)
	var left []netip.Addr
	for vtep := range r.revoked {
		left = append(left, vtep)
	}
	return left
}

func TestVTEPAdmitter_FailedVerdictDoesNotWaitOnIPAM(t *testing.T) {
	device8VTEP := netip.MustParseAddr("10.4.100.30")
	// gate admits admissionVTEP for device 7 and device8VTEP for device 8,
	// leaves admissionVTEP2 allocated to device 7 but never admitted, and
	// puts the admitter behind an IPAM that holds every listing.
	gate := func(t *testing.T) (*admissionFixture, *gatedIPAM, signalRevoker) {
		t.Helper()
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		gated := &gatedIPAM{admissionIPAM: f.ipam, listing: make(chan string, 2), release: make(chan struct{})}
		revoker := signalRevoker{revoked: make(chan netip.Addr, 8)}
		f.admitter.ipam = gated
		f.admitter.revoker = revoker
		// Only release or the caller's ctx ends a held listing; a read
		// deadline would let an admitter that waits on IPAM through.
		f.admitter.readTimeout = time.Hour
		require.NoError(t, f.admitter.remember(0, evaluation{admitted: AdmittedVTEP{VTEP: admissionVTEP, DeviceID: 7}}))
		require.NoError(t, f.admitter.remember(0, evaluation{admitted: AdmittedVTEP{VTEP: device8VTEP, DeviceID: 8}}))
		return f, gated, revoker
	}
	failed := func(deviceID uint64) deviceverdict.RecordedDeviceVerdict {
		return streamed(deviceverdict.DeviceVerdict{DeviceID: deviceID, Reason: "quote rejected"}, admissionNow)
	}

	t.Run("withdraws admitted VTEPs while the listing is held", func(t *testing.T) {
		ctx := context.Background()
		f, gated, revoker := gate(t)

		f.admitter.OnDeviceVerdict(ctx, failed(7))
		assert.Equal(t, admissionVTEP, <-revoker.revoked, "the admitted VTEP goes before IPAM answers")
		assert.Equal(t, "7", <-gated.listing)

		f.admitter.OnDeviceVerdict(ctx, failed(8))
		assert.Equal(t, device8VTEP, <-revoker.revoked, "the next failure is withdrawn while the first listing is pending")
		assert.Equal(t, "8", <-gated.listing)

		close(gated.release)
		f.admitter.waitListings()
		assert.Equal(t, []netip.Addr{admissionVTEP2}, revoker.drain(),
			"the listing withdraws only the allocation never admitted")
		assert.False(t, f.admitter.admittedFor(admissionVTEP, 7))
		assert.False(t, f.admitter.admittedFor(device8VTEP, 8))
	})

	t.Run("listing ends with the stream", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		f, gated, revoker := gate(t)

		f.admitter.OnDeviceVerdict(ctx, failed(7))
		assert.Equal(t, admissionVTEP, <-revoker.revoked)
		assert.Equal(t, "7", <-gated.listing)

		cancel()
		f.admitter.waitListings()
		assert.Empty(t, revoker.drain(),
			"a listing cut off by the stream withdraws nothing more; the held failure leaves the rest to the sweep")
		held, epoch := f.admitter.failureHeld(7, admissionNow)
		assert.True(t, held)
		assert.NotZero(t, epoch)
	})

	t.Run("skips an allocation admitted again on a newer verdict during the listing", func(t *testing.T) {
		ctx := context.Background()
		f, gated, revoker := gate(t)

		f.admitter.OnDeviceVerdict(ctx, failed(7))
		assert.Equal(t, admissionVTEP, <-revoker.revoked)
		assert.Equal(t, "7", <-gated.listing)

		newer := AdmittedVTEP{VTEP: admissionVTEP2, DeviceID: 7, VerdictAt: admissionNow.Add(time.Second)}
		require.NoError(t, f.admitter.remember(0, evaluation{admitted: newer}))
		close(gated.release)
		f.admitter.waitListings()
		assert.Empty(t, revoker.drain())
		assert.True(t, f.admitter.admittedFor(admissionVTEP2, 7))
	})
}

// gatedClock is the admitter's clock. Once armed, the next reading signals
// entered and waits for release. evaluate reads the clock after its hold
// check, so an armed clock stops an admission between that check and
// remember.
type gatedClock struct {
	now     time.Time
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func newGatedClock(now time.Time) *gatedClock {
	clock := &gatedClock{now: now, entered: make(chan struct{}), release: make(chan struct{})}
	clock.armed.Store(true)
	return clock
}

func (c *gatedClock) Now() time.Time {
	if c.armed.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.release
	}
	return c.now
}

// overlayReaderOnly hides a caching reader's Refresh, so a first admission
// is published straight from its one evaluation.
type overlayReaderOnly struct {
	OverlayIPAMReader
}

func TestVTEPAdmitter_FailureDuringAdmissionWithdrawsIt(t *testing.T) {
	failed := streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Reason: "quote rejected"}, admissionNow)
	// admitInFlight starts a first admission of admissionVTEP and returns once
	// it has passed the hold check and not yet been published.
	admitInFlight := func(f *admissionFixture, clock *gatedClock) <-chan error {
		result := make(chan error, 1)
		f.admitter.now = clock.Now
		go func() { result <- f.admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP) }()
		<-clock.entered
		return result
	}

	t.Run("failure listed before the admission is published", func(t *testing.T) {
		ctx := context.Background()
		f := newAdmissionFixture(t)
		f.admitter.ipam = overlayReaderOnly{f.ipam}
		clock := newGatedClock(admissionNow)
		result := admitInFlight(f, clock)

		deliverVerdict(ctx, f.admitter, failed)
		close(clock.release)

		requireVerdictDenied(t, <-result, "while the admission was judged")
		assert.False(t, f.admitter.admittedFor(admissionVTEP, 7))
		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked)
	})

	t.Run("failure listed after the admission would have been published", func(t *testing.T) {
		ctx := context.Background()
		f := newAdmissionFixture(t)
		gated := &gatedIPAM{admissionIPAM: f.ipam, listing: make(chan string, 1), release: make(chan struct{})}
		revoker := signalRevoker{revoked: make(chan netip.Addr, 4)}
		f.admitter.ipam = overlayReaderOnly{gated}
		f.admitter.revoker = revoker
		f.admitter.readTimeout = time.Hour
		clock := newGatedClock(admissionNow)
		result := admitInFlight(f, clock)

		f.admitter.OnDeviceVerdict(ctx, failed)
		assert.Equal(t, "7", <-gated.listing)
		close(clock.release)
		requireVerdictDenied(t, <-result, "while the admission was judged")

		close(gated.release)
		f.admitter.waitListings()
		assert.Equal(t, []netip.Addr{admissionVTEP}, revoker.drain(),
			"the listing withdraws the allocation the refused admission would have kept")
		assert.False(t, f.admitter.admittedFor(admissionVTEP, 7))
	})
}

func TestVTEPAdmitter_AdmissionOnANewerPassOutlivesTheFailure(t *testing.T) {
	ctx := context.Background()
	f := newAdmissionFixture(t)
	gated := &gatedIPAM{admissionIPAM: f.ipam, listing: make(chan string, 1), release: make(chan struct{})}
	revoker := signalRevoker{revoked: make(chan netip.Addr, 4)}
	f.admitter.ipam = gated
	f.admitter.revoker = revoker
	f.admitter.readTimeout = time.Hour

	f.admitter.OnDeviceVerdict(ctx, streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Reason: "quote rejected"}, admissionNow))
	assert.Equal(t, "7", <-gated.listing)

	f.verdicts.records[7] = signedVerdict(admissionNow.Add(time.Second))
	require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))

	close(gated.release)
	f.admitter.waitListings()
	assert.Empty(t, revoker.drain(), "an admission on a report attested after the failure is not withdrawn")
	assert.True(t, f.admitter.admittedFor(admissionVTEP, 7))
}

func TestVTEPAdmitter_Remember(t *testing.T) {
	older := AdmittedVTEP{VTEP: admissionVTEP, DeviceID: 7, VerdictAt: admissionNow.Add(-time.Minute)}

	t.Run("publishes an admission judged against the failure still held", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.admitter.holdFailure(7, admissionNow)
		_, epoch := f.admitter.failureHeld(7, admissionNow)

		require.NoError(t, f.admitter.remember(10100, evaluation{admitted: older, failureEpoch: epoch}))
		assert.True(t, f.admitter.admittedFor(admissionVTEP, 7))
	})

	t.Run("publishes an admission newer than the failure that overtook it", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.admitter.holdFailure(7, admissionNow)
		newer := older
		newer.VerdictAt = admissionNow.Add(time.Second)

		require.NoError(t, f.admitter.remember(10100, evaluation{admitted: newer}))
		assert.True(t, f.admitter.admittedFor(admissionVTEP, 7))
	})

	t.Run("refuses an admission a failure overtook", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.admitter.holdFailure(7, admissionNow)

		err := f.admitter.remember(10100, evaluation{admitted: older})
		requireVerdictDenied(t, err, "while the admission was judged")
		var verdictErr ErrOverlayVTEPVerdict
		require.True(t, errors.As(err, &verdictErr))
		assert.Equal(t, uint32(10100), verdictErr.VNI)
		assert.False(t, f.admitter.admittedFor(admissionVTEP, 7))
	})
}

func TestVTEPAdmitter_AdmittedSince(t *testing.T) {
	f := newAdmissionFixture(t)
	admitted := AdmittedVTEP{VTEP: admissionVTEP, DeviceID: 7, VerdictAt: admissionNow}
	require.NoError(t, f.admitter.remember(0, evaluation{admitted: admitted}))

	assert.True(t, f.admitter.admittedSince(admissionVTEP, 7, admissionNow.Add(-time.Second)))
	assert.False(t, f.admitter.admittedSince(admissionVTEP, 7, admissionNow), "a verdict recorded at since is not newer")
	assert.False(t, f.admitter.admittedSince(admissionVTEP, 8, admissionNow.Add(-time.Second)), "admitted for another device")
	assert.False(t, f.admitter.admittedSince(admissionVTEP2, 7, admissionNow.Add(-time.Second)), "never admitted")
}

func TestVTEPAdmitter_OnDeviceVerdict(t *testing.T) {
	ctx := context.Background()
	failures := map[string]deviceverdict.RecordedDeviceVerdict{
		"cryptographic failure": streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Cryptographic: true, Reason: "signature invalid"}, admissionNow),
		"absence of evidence":   streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Reason: "no attestation certificate enrolled"}, admissionNow),
	}
	for name, failed := range failures {
		t.Run("withdraws the device on a "+name, func(t *testing.T) {
			f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
			require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))

			deliverVerdict(ctx, f.admitter, failed)

			assert.ElementsMatch(t, []netip.Addr{admissionVTEP, admissionVTEP2}, f.overlay.revoked)
			assert.Equal(t, []AdmittedVTEP{{VTEP: admissionVTEP}}, f.admitter.Admitted(installed(admissionVTEP)))
		})
	}

	passed := streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Passed: true}, admissionNow.Add(time.Second))

	t.Run("a passed verdict withdraws nothing", func(t *testing.T) {
		f := newAdmissionFixture(t)
		require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))

		deliverVerdict(ctx, f.admitter, passed)

		assert.Empty(t, f.overlay.revoked)
		assert.Empty(t, f.overlay.replayed, "nothing was refused")
	})

	t.Run("a device withdrawn and then passing again is replayed", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		f.verdict().Verdict.Passed = false
		deliverVerdict(ctx, f.admitter, failures["cryptographic failure"])
		require.ElementsMatch(t, []netip.Addr{admissionVTEP, admissionVTEP2}, f.overlay.refused)

		f.verdicts.records[7] = signedVerdict(passed.RecordedAt)
		deliverVerdict(ctx, f.admitter, passed)

		assert.ElementsMatch(t, []netip.Addr{admissionVTEP, admissionVTEP2}, f.overlay.replayed)
		assert.Empty(t, f.overlay.refused)
	})

	t.Run("a passed verdict replays only the device's refused VTEPs", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		other := netip.MustParseAddr("10.4.100.30")
		f.overlay.refused = []netip.Addr{admissionVTEP, other}

		deliverVerdict(ctx, f.admitter, passed)

		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.replayed)
		assert.Equal(t, []netip.Addr{other}, f.overlay.refused)
	})

	t.Run("a passed verdict the platform does not yet hold replays nothing", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.verdict().Verdict.Passed = false
		f.overlay.refused = []netip.Addr{admissionVTEP}

		deliverVerdict(ctx, f.admitter, passed)

		assert.Empty(t, f.overlay.replayed)
		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.refused, "the sweep tries it again")
	})

	t.Run("a passed verdict replays nothing while IPAM is down", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.overlay.refused = []netip.Addr{admissionVTEP}
		f.ipam.err = errPlatformDown

		deliverVerdict(ctx, f.admitter, passed)

		assert.Empty(t, f.overlay.replayed)
	})

	t.Run("a failed withdrawal leaves the other VTEPs withdrawn", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		f.overlay.fail = map[netip.Addr]error{admissionVTEP: errPlatformDown}

		deliverVerdict(ctx, f.admitter, failures["cryptographic failure"])

		assert.Equal(t, []netip.Addr{admissionVTEP2}, f.overlay.revoked)
	})
}

// platformd streams a failed verdict before its report cache holds the failing
// report, so for a moment the report still shows the device's previous pass.
// Admission read that pass back and let the revoked device in again.
func TestVTEPAdmitter_HoldsAStreamedFailureUntilANewerPass(t *testing.T) {
	ctx := context.Background()
	failedAt := admissionNow
	failed := streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Reason: "PCR mismatch", Cryptographic: true}, failedAt)

	f := newAdmissionFixture(t)
	require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))
	deliverVerdict(ctx, f.admitter, failed)
	require.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked)

	err := f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP)
	requireVerdictDenied(t, err, "failed verdict")

	require.NoError(t, f.admitter.Sweep(ctx, installed()))
	assert.Empty(t, f.overlay.replayed, "the sweep must not replay a device the stream failed")
	assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.refused)

	f.verdicts.records[7] = signedVerdict(failedAt)
	requireVerdictDenied(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP), "failed verdict")

	f.verdicts.records[7] = signedVerdict(failedAt.Add(time.Second))
	deliverVerdict(ctx, f.admitter, streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Passed: true}, failedAt.Add(2*time.Second)))
	assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.replayed)
	require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))
}

// A streamed failure refuses the VTEP for its verdict even when platformd
// cannot serve the device's report: the failure is a judgement, not an
// outage. A device the stream never failed stays an outage.
func TestVTEPAdmitter_StreamedFailureRefusesWhileTheReportCannotBeRead(t *testing.T) {
	ctx := context.Background()
	f := newAdmissionFixture(t)
	require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))
	f.verdicts.err = errPlatformDown

	var unavailable ErrOverlayAdmissionUnavailable
	require.True(t, errors.As(f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP), &unavailable),
		"a report read outage without a streamed failure is an outage")

	deliverVerdict(ctx, f.admitter, streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Reason: "PCR mismatch"}, admissionNow))

	err := f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP)
	requireVerdictDenied(t, err, "failed verdict was streamed")
	assert.ErrorIs(t, err, errPlatformDown)
	var verdictErr ErrOverlayVTEPVerdict
	require.True(t, errors.As(err, &verdictErr))
	assert.Equal(t, uint64(7), verdictErr.DeviceID)
}

func TestVTEPAdmitter_HeldFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("an event without a recording time is held from the gateway's clock", func(t *testing.T) {
		f := newAdmissionFixture(t)
		deliverVerdict(ctx, f.admitter, streamed(deviceverdict.DeviceVerdict{DeviceID: 7}, time.Time{}))

		requireVerdictDenied(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP), "failed verdict")
	})

	t.Run("a later failure moves the hold forward", func(t *testing.T) {
		f := newAdmissionFixture(t)
		deliverVerdict(ctx, f.admitter, streamed(deviceverdict.DeviceVerdict{DeviceID: 7}, admissionNow.Add(-time.Hour)))
		deliverVerdict(ctx, f.admitter, streamed(deviceverdict.DeviceVerdict{DeviceID: 7}, admissionNow))
		deliverVerdict(ctx, f.admitter, streamed(deviceverdict.DeviceVerdict{DeviceID: 7}, admissionNow.Add(-2*time.Hour)))

		requireVerdictDenied(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP), "failed verdict")
	})

	t.Run("every failure takes a new epoch and an older one keeps the hold time", func(t *testing.T) {
		f := newAdmissionFixture(t)
		require.Equal(t, admissionNow, f.admitter.holdFailure(7, admissionNow))
		first := f.admitter.heldFailures[7]

		require.Equal(t, admissionNow.Add(-time.Hour), f.admitter.holdFailure(7, admissionNow.Add(-time.Hour)))
		second := f.admitter.heldFailures[7]

		assert.Equal(t, admissionNow, second.at, "an older failure does not move the hold back")
		assert.Greater(t, second.epoch, first.epoch)
	})

	t.Run("holds only the failed device", func(t *testing.T) {
		f := newAdmissionFixture(t)
		deliverVerdict(ctx, f.admitter, streamed(deviceverdict.DeviceVerdict{DeviceID: 8}, admissionNow))

		require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))
	})

	t.Run("the sweep drops a hold no report could outlast", func(t *testing.T) {
		f := newAdmissionFixture(t)
		deliverVerdict(ctx, f.admitter, streamed(deviceverdict.DeviceVerdict{DeviceID: 7}, admissionNow))
		require.NoError(t, f.admitter.Sweep(ctx, installed()))
		require.Len(t, f.admitter.heldFailures, 1)

		f.now = f.now.Add(f.admitter.maxVerdictAge + f.admitter.clockSkew + time.Second)
		require.NoError(t, f.admitter.Sweep(ctx, installed()))

		assert.Empty(t, f.admitter.heldFailures)
	})
}

type (
	verdictDeliver = func(context.Context, deviceverdict.RecordedDeviceVerdict)
	followScript   = func(context.Context, verdictDeliver) error
)

// scriptedVerdictStream plays one scripted follow per call, then follows
// until the context ends.
type scriptedVerdictStream struct {
	calls  int
	script []followScript
}

func (s *scriptedVerdictStream) Follow(ctx context.Context, deliver verdictDeliver) error {
	call := s.calls
	s.calls++
	if call < len(s.script) {
		return s.script[call](ctx, deliver)
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestRunVerdictFollower(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	failed := streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Reason: "no attestation certificate enrolled"}, admissionNow)

	// follow runs the follower until the scripted follows are played and
	// the next one is waiting, then stops it.
	follow := func(t *testing.T, f *admissionFixture, stream *scriptedVerdictStream) {
		t.Helper()
		played := make(chan struct{})
		stream.script = append(stream.script, func(ctx context.Context, _ verdictDeliver) error {
			close(played)
			<-ctx.Done()
			return ctx.Err()
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			runVerdictFollower(ctx, stream, f.admitter, 0, logger)
		}()
		<-played
		cancel()
		<-done
	}

	t.Run("withdraws the device of every failed verdict", func(t *testing.T) {
		f := newAdmissionFixture(t)
		stream := &scriptedVerdictStream{script: []followScript{
			func(ctx context.Context, deliver verdictDeliver) error {
				deliver(ctx, streamed(deviceverdict.DeviceVerdict{DeviceID: 7, Passed: true}, admissionNow))
				deliver(ctx, failed)
				return errPlatformDown
			},
		}}

		follow(t, f, stream)

		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked)
	})

	t.Run("follows again after the stream breaks", func(t *testing.T) {
		f := newAdmissionFixture(t)
		stream := &scriptedVerdictStream{script: []followScript{
			func(context.Context, verdictDeliver) error { return errPlatformDown },
			func(context.Context, verdictDeliver) error { return nil },
			func(ctx context.Context, deliver verdictDeliver) error {
				deliver(ctx, failed)
				return errPlatformDown
			},
		}}

		follow(t, f, stream)

		assert.Equal(t, 4, stream.calls)
		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.revoked)
	})

	t.Run("returns on cancel without following again", func(t *testing.T) {
		f := newAdmissionFixture(t)
		stream := &scriptedVerdictStream{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		runVerdictFollower(ctx, stream, f.admitter, time.Hour, logger)

		assert.Equal(t, 1, stream.calls)
		assert.Empty(t, f.overlay.revoked)
	})
}
