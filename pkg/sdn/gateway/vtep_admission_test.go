package gateway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
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

		require.NoError(t, f.admitter.Sweep(ctx, installed(admissionVTEP)))

		assert.Empty(t, f.overlay.revoked)
		assert.Equal(t, 1, f.ipam.refreshes, "the sweep refreshes a caching IPAM reader")
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

	t.Run("returns on cancel without sweeping", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.verdicts.records[7].Verdict.Passed = false
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		runAdmissionSweep(ctx, make(chan time.Time), staticDatapath(installed(admissionVTEP)), f.admitter, logger)
		assert.Empty(t, f.overlay.revoked)
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
		proxy.set(overlay)

		require.NoError(t, proxy.RevokeVTEP(ctx, admissionVTEP))
		assert.Equal(t, []netip.Addr{admissionVTEP}, proxy.RefusedVTEPs())
		require.NoError(t, proxy.ReplayVTEP(ctx, admissionVTEP))

		assert.Equal(t, []netip.Addr{admissionVTEP}, overlay.revoked)
		assert.Equal(t, []netip.Addr{admissionVTEP}, overlay.replayed)
		assert.Empty(t, proxy.RefusedVTEPs())
	})
}

func TestVTEPAdmitter_OnDeviceVerdict(t *testing.T) {
	ctx := context.Background()
	failures := map[string]deviceverdict.DeviceVerdict{
		"cryptographic failure": {DeviceID: 7, Cryptographic: true, Reason: "signature invalid"},
		"absence of evidence":   {DeviceID: 7, Reason: "no attestation certificate enrolled"},
	}
	for name, failed := range failures {
		t.Run("withdraws the device on a "+name, func(t *testing.T) {
			f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
			require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))

			f.admitter.OnDeviceVerdict(ctx, failed)

			assert.ElementsMatch(t, []netip.Addr{admissionVTEP, admissionVTEP2}, f.overlay.revoked)
			assert.Equal(t, []AdmittedVTEP{{VTEP: admissionVTEP}}, f.admitter.Admitted(installed(admissionVTEP)))
		})
	}

	passed := deviceverdict.DeviceVerdict{DeviceID: 7, Passed: true}

	t.Run("a passed verdict withdraws nothing", func(t *testing.T) {
		f := newAdmissionFixture(t)
		require.NoError(t, f.admitter.AdmitVTEP(ctx, 10100, admissionVTEP))

		f.admitter.OnDeviceVerdict(ctx, passed)

		assert.Empty(t, f.overlay.revoked)
		assert.Empty(t, f.overlay.replayed, "nothing was refused")
	})

	t.Run("a device withdrawn and then passing again is replayed", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		f.verdict().Verdict.Passed = false
		f.admitter.OnDeviceVerdict(ctx, failures["cryptographic failure"])
		require.ElementsMatch(t, []netip.Addr{admissionVTEP, admissionVTEP2}, f.overlay.refused)

		f.verdicts.records[7] = signedVerdict(f.now)
		f.admitter.OnDeviceVerdict(ctx, passed)

		assert.ElementsMatch(t, []netip.Addr{admissionVTEP, admissionVTEP2}, f.overlay.replayed)
		assert.Empty(t, f.overlay.refused)
	})

	t.Run("a passed verdict replays only the device's refused VTEPs", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		other := netip.MustParseAddr("10.4.100.30")
		f.overlay.refused = []netip.Addr{admissionVTEP, other}

		f.admitter.OnDeviceVerdict(ctx, passed)

		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.replayed)
		assert.Equal(t, []netip.Addr{other}, f.overlay.refused)
	})

	t.Run("a passed verdict the platform does not yet hold replays nothing", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.verdict().Verdict.Passed = false
		f.overlay.refused = []netip.Addr{admissionVTEP}

		f.admitter.OnDeviceVerdict(ctx, passed)

		assert.Empty(t, f.overlay.replayed)
		assert.Equal(t, []netip.Addr{admissionVTEP}, f.overlay.refused, "the sweep tries it again")
	})

	t.Run("a passed verdict replays nothing while IPAM is down", func(t *testing.T) {
		f := newAdmissionFixture(t)
		f.overlay.refused = []netip.Addr{admissionVTEP}
		f.ipam.err = errPlatformDown

		f.admitter.OnDeviceVerdict(ctx, passed)

		assert.Empty(t, f.overlay.replayed)
	})

	t.Run("a failed withdrawal leaves the other VTEPs withdrawn", func(t *testing.T) {
		f := newAdmissionFixture(t, admissionVTEP, admissionVTEP2)
		f.overlay.fail = map[netip.Addr]error{admissionVTEP: errPlatformDown}

		f.admitter.OnDeviceVerdict(ctx, failures["cryptographic failure"])

		assert.Equal(t, []netip.Addr{admissionVTEP2}, f.overlay.revoked)
	})
}

type (
	verdictDeliver = func(context.Context, deviceverdict.DeviceVerdict)
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
	failed := deviceverdict.DeviceVerdict{DeviceID: 7, Reason: "no attestation certificate enrolled"}

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
				deliver(ctx, deviceverdict.DeviceVerdict{DeviceID: 7, Passed: true})
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
