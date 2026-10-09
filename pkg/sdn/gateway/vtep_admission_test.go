package gateway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/deviceverdict"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	admissionNow  = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	admissionVTEP = netip.MustParseAddr("10.4.100.20")
)

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

type admissionRevoker struct {
	vteps []netip.Addr
	err   error
}

func (r *admissionRevoker) RevokeVTEP(_ context.Context, vtep netip.Addr) error {
	if r.err != nil {
		return r.err
	}
	r.vteps = append(r.vteps, vtep)
	return nil
}

func newAdmissionAllocator(t *testing.T, deviceID string, vtep netip.Addr) ipam.Allocator {
	t.Helper()
	allocator := backends.NewMemoryBackend()
	pool := &ipam.Pool{
		ID:   "fabric-pool",
		Name: "fabric",
		CIDR: netip.MustParsePrefix("10.4.100.0/24"),
		Zone: string(zone.ZoneFabric),
	}
	require.NoError(t, allocator.CreatePool(context.Background(), pool))
	_, err := allocator.AllocateSpecific(context.Background(), &ipam.AllocationRequest{
		PoolID:      pool.ID,
		Zone:        string(zone.ZoneFabric),
		DeviceID:    deviceID,
		Hostname:    "node-" + deviceID,
		RequestedIP: vtep,
	})
	require.NoError(t, err)
	return allocator
}

func newAdmissionAdmitter(t *testing.T, record *deviceverdict.RecordedDeviceVerdict, revoker *admissionRevoker) *VTEPAdmitter {
	t.Helper()
	if revoker == nil {
		revoker = &admissionRevoker{}
	}
	admitter, err := NewVTEPAdmitter(VTEPAdmissionConfig{
		IPAM:    newAdmissionAllocator(t, "7", admissionVTEP),
		Devices: &admissionDeviceStore{devices: map[uint64]*deviceentities.Device{7: {ID: 7, Hostname: "node-7", Serial: "SN7"}}},
		Verdicts: &admissionVerdicts{records: map[uint64]*deviceverdict.RecordedDeviceVerdict{
			7: record,
		}},
		Revoker:       revoker,
		MaxVerdictAge: 5 * time.Minute,
		Now:           func() time.Time { return admissionNow },
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	return admitter
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

func TestVTEPAdmitter_AdmitsSignedFreshFabricVerdict(t *testing.T) {
	admitter := newAdmissionAdmitter(t, signedVerdict(admissionNow.Add(-time.Minute)), nil)

	require.NoError(t, admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP))

	got, err := admitter.GetAdmittedVTEP(context.Background(), admissionVTEP)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), got.DeviceID)
	assert.Equal(t, "signed", got.BaselineSource)
	assert.Equal(t, "node-7", got.Hostname)
}

func TestVTEPAdmitter_RejectsBadVerdicts(t *testing.T) {
	t.Run("unsigned baseline", func(t *testing.T) {
		record := signedVerdict(admissionNow.Add(-time.Minute))
		record.Verdict.BaselineSource = "tofu"
		admitter := newAdmissionAdmitter(t, record, nil)

		err := admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP)

		var verdictErr ErrOverlayVTEPVerdict
		require.True(t, errors.As(err, &verdictErr), "got %v", err)
		assert.Contains(t, verdictErr.Reason, "signed baseline")
	})

	t.Run("stale verdict", func(t *testing.T) {
		admitter := newAdmissionAdmitter(t, signedVerdict(admissionNow.Add(-10*time.Minute)), nil)

		err := admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP)

		var verdictErr ErrOverlayVTEPVerdict
		require.True(t, errors.As(err, &verdictErr), "got %v", err)
		assert.Contains(t, verdictErr.Reason, "stale")
	})
}

func TestVTEPAdmitter_RejectsMissingRegistryFacts(t *testing.T) {
	t.Run("unknown VTEP", func(t *testing.T) {
		admitter := newAdmissionAdmitter(t, signedVerdict(admissionNow.Add(-time.Minute)), nil)

		err := admitter.AdmitVTEP(context.Background(), 10100, netip.MustParseAddr("10.4.100.99"))

		var registryErr ErrOverlayVTEPRegistry
		require.True(t, errors.As(err, &registryErr), "got %v", err)
		assert.Contains(t, registryErr.Reason, "no fabric allocation")
	})

	t.Run("non-numeric device id", func(t *testing.T) {
		allocator := newAdmissionAllocator(t, "node-7", admissionVTEP)
		admitter, err := NewVTEPAdmitter(VTEPAdmissionConfig{
			IPAM:          allocator,
			Devices:       &admissionDeviceStore{devices: map[uint64]*deviceentities.Device{}},
			Verdicts:      &admissionVerdicts{},
			Revoker:       &admissionRevoker{},
			MaxVerdictAge: time.Minute,
			Now:           func() time.Time { return admissionNow },
			Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		require.NoError(t, err)

		err = admitter.AdmitVTEP(context.Background(), 10100, admissionVTEP)

		var registryErr ErrOverlayVTEPRegistry
		require.True(t, errors.As(err, &registryErr), "got %v", err)
		assert.Contains(t, registryErr.Reason, "numeric")
	})
}

func TestVTEPAdmitter_RevokeDeviceWithdrawsFabricAllocations(t *testing.T) {
	revoker := &admissionRevoker{}
	admitter := newAdmissionAdmitter(t, signedVerdict(admissionNow.Add(-time.Minute)), revoker)

	require.NoError(t, admitter.RevokeDevice(context.Background(), 7))

	assert.Equal(t, []netip.Addr{admissionVTEP}, revoker.vteps)
}

func TestVTEPAdmitter_ListAdmittedVTEPsFiltersRejectedDevices(t *testing.T) {
	record := signedVerdict(admissionNow.Add(-time.Minute))
	admitter := newAdmissionAdmitter(t, record, nil)
	record.Verdict.Passed = false

	got, err := admitter.ListAdmittedVTEPs(context.Background())

	require.NoError(t, err)
	assert.Empty(t, got)
}
