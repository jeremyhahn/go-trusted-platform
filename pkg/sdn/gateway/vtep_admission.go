package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/deviceverdict"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

const (
	// DefaultOverlayVerdictMaxAge is the default maximum age of the latest
	// recorded device verdict accepted by the gateway overlay admission policy.
	DefaultOverlayVerdictMaxAge = 15 * time.Minute

	overlaySignedBaselineSource = "signed"
)

// OverlayDeviceGetter loads platform device records by their numeric device ID.
type OverlayDeviceGetter interface {
	Get(ctx context.Context, id uint64) (*deviceentities.Device, error)
}

// OverlayVerdictReader reads the platform-side attestation verdict log.
type OverlayVerdictReader interface {
	LatestDeviceVerdict(ctx context.Context, deviceID uint64) (*deviceverdict.RecordedDeviceVerdict, error)
}

// OverlayVTEPRevoker withdraws all overlay reachability from a VTEP.
type OverlayVTEPRevoker interface {
	RevokeVTEP(ctx context.Context, vtep netip.Addr) error
}

// VTEPAdmissionConfig wires the production overlay VTEP admission policy.
type VTEPAdmissionConfig struct {
	IPAM          ipam.Allocator
	Devices       OverlayDeviceGetter
	Verdicts      OverlayVerdictReader
	Revoker       OverlayVTEPRevoker
	MaxVerdictAge time.Duration
	Now           func() time.Time
	Logger        *slog.Logger
}

// AdmittedVTEP is a VTEP whose registry and attestation state currently allow
// it to carry overlay traffic.
type AdmittedVTEP struct {
	VTEP           netip.Addr
	DeviceID       uint64
	HostID         string
	Serial         string
	Hostname       string
	AllocationID   string
	BaselineSource string
	ProfileID      uint64
	VerdictAt      time.Time
}

// VTEPAdmitter is the production implementation of modes.VTEPAdmitter. The
// registry is the platform IPAM fabric allocation for the VTEP address; the
// relying-party decision comes from the platform attestation event log.
type VTEPAdmitter struct {
	ipam          ipam.Allocator
	devices       OverlayDeviceGetter
	verdicts      OverlayVerdictReader
	revoker       OverlayVTEPRevoker
	maxVerdictAge time.Duration
	now           func() time.Time
	logger        *slog.Logger
}

func NewVTEPAdmitter(cfg VTEPAdmissionConfig) (*VTEPAdmitter, error) {
	if cfg.IPAM == nil {
		return nil, ErrOverlayAdmissionConfig{Field: "ipam", Reason: "nil"}
	}
	if cfg.Devices == nil {
		return nil, ErrOverlayAdmissionConfig{Field: "devices", Reason: "nil"}
	}
	if cfg.Verdicts == nil {
		return nil, ErrOverlayAdmissionConfig{Field: "verdicts", Reason: "nil"}
	}
	if cfg.Revoker == nil {
		return nil, ErrOverlayAdmissionConfig{Field: "revoker", Reason: "nil"}
	}
	if cfg.MaxVerdictAge < 0 {
		return nil, ErrOverlayAdmissionConfig{Field: "max_verdict_age", Reason: "negative"}
	}
	if cfg.MaxVerdictAge == 0 {
		cfg.MaxVerdictAge = DefaultOverlayVerdictMaxAge
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &VTEPAdmitter{
		ipam:          cfg.IPAM,
		devices:       cfg.Devices,
		verdicts:      cfg.Verdicts,
		revoker:       cfg.Revoker,
		maxVerdictAge: cfg.MaxVerdictAge,
		now:           cfg.Now,
		logger:        cfg.Logger,
	}, nil
}

func (a *VTEPAdmitter) AdmitVTEP(ctx context.Context, vni uint32, vtep netip.Addr) error {
	_, err := a.admittedVTEP(ctx, vni, vtep)
	return err
}

func (a *VTEPAdmitter) GetAdmittedVTEP(ctx context.Context, vtep netip.Addr) (*AdmittedVTEP, error) {
	return a.admittedVTEP(ctx, 0, vtep)
}

func (a *VTEPAdmitter) ListAdmittedVTEPs(ctx context.Context) ([]AdmittedVTEP, error) {
	pools, err := a.ipam.ListPoolsByZone(ctx, string(zone.ZoneFabric))
	if err != nil {
		return nil, err
	}
	out := make([]AdmittedVTEP, 0)
	for _, pool := range pools {
		if pool == nil {
			continue
		}
		allocations, err := a.ipam.GetAllocationsByPool(ctx, pool.ID)
		if err != nil {
			return nil, err
		}
		for _, allocation := range allocations {
			if allocation == nil || !allocation.IsActive() {
				continue
			}
			admitted, err := a.admittedAllocation(ctx, 0, allocation)
			if err == nil {
				out = append(out, *admitted)
				continue
			}
			if !isOverlayAdmissionDeny(err) {
				return nil, err
			}
		}
	}
	return out, nil
}

// OnAttestationFailed implements the attestation quarantine observer. The
// attestation service calls it for cryptographic failures; the admitter resolves
// the device's fabric VTEP allocations and withdraws them through the overlay
// route-handler path.
func (a *VTEPAdmitter) OnAttestationFailed(ctx context.Context, deviceID uint64, hostID, detail string) {
	if err := a.RevokeDevice(ctx, deviceID); err != nil {
		a.logger.Warn("overlay VTEP revocation failed",
			slog.Uint64("device_id", deviceID),
			slog.String("host_id", hostID),
			slog.String("detail", detail),
			slog.Any("error", err))
	}
}

// OnAttestationPassed implements the attestation observer interface. A fresh
// pass makes future route admission possible; it does not re-add withdrawn
// routes on its own.
func (a *VTEPAdmitter) OnAttestationPassed(context.Context, uint64, string) {}

func (a *VTEPAdmitter) RevokeDevice(ctx context.Context, deviceID uint64) error {
	allocations, err := a.ipam.GetAllocationsByDevice(ctx, strconv.FormatUint(deviceID, 10))
	if err != nil {
		return err
	}
	for _, allocation := range allocations {
		if allocation == nil || !allocation.IP.IsValid() || allocation.Zone != string(zone.ZoneFabric) {
			continue
		}
		if err := a.revoker.RevokeVTEP(ctx, allocation.IP); err != nil {
			return &ErrOverlayVTEPRevoke{VTEP: allocation.IP, Cause: err}
		}
	}
	return nil
}

func (a *VTEPAdmitter) admittedVTEP(ctx context.Context, vni uint32, vtep netip.Addr) (*AdmittedVTEP, error) {
	if !vtep.Is4() || vtep.IsUnspecified() {
		return nil, ErrOverlayVTEPRegistry{VTEP: vtep, Reason: "invalid VTEP address"}
	}
	allocation, err := a.ipam.GetAllocation(ctx, vtep)
	if err != nil {
		return nil, ErrOverlayVTEPRegistry{VTEP: vtep, Reason: "no fabric allocation", Cause: err}
	}
	return a.admittedAllocation(ctx, vni, allocation)
}

func (a *VTEPAdmitter) admittedAllocation(ctx context.Context, vni uint32, allocation *ipam.Allocation) (*AdmittedVTEP, error) {
	if allocation == nil {
		return nil, ErrOverlayVTEPRegistry{Reason: "nil allocation"}
	}
	if !allocation.IsActive() {
		return nil, ErrOverlayVTEPRegistry{VTEP: allocation.IP, Reason: "allocation is not active"}
	}
	if allocation.Zone != string(zone.ZoneFabric) {
		return nil, ErrOverlayVTEPRegistry{VTEP: allocation.IP, Reason: "allocation is not in the fabric zone"}
	}
	deviceID, err := strconv.ParseUint(allocation.DeviceID, 10, 64)
	if err != nil || deviceID == 0 {
		return nil, ErrOverlayVTEPRegistry{VTEP: allocation.IP, Reason: "allocation device id is not numeric"}
	}
	device, err := a.devices.Get(ctx, deviceID)
	if err != nil {
		return nil, ErrOverlayVTEPDevice{VTEP: allocation.IP, DeviceID: deviceID, Cause: err}
	}
	if device == nil || device.ID != deviceID {
		return nil, ErrOverlayVTEPRegistry{VTEP: allocation.IP, Reason: "device record does not match allocation"}
	}
	recorded, err := a.verdicts.LatestDeviceVerdict(ctx, deviceID)
	if err != nil {
		return nil, ErrOverlayVTEPVerdict{VTEP: allocation.IP, DeviceID: deviceID, VNI: vni, Reason: "latest verdict unavailable", Cause: err}
	}
	if recorded == nil {
		return nil, ErrOverlayVTEPVerdict{VTEP: allocation.IP, DeviceID: deviceID, VNI: vni, Reason: "latest verdict unavailable"}
	}
	if !recorded.Verdict.Passed {
		return nil, ErrOverlayVTEPVerdict{VTEP: allocation.IP, DeviceID: deviceID, VNI: vni, Reason: "latest verdict failed"}
	}
	if recorded.Verdict.BaselineSource != overlaySignedBaselineSource {
		return nil, ErrOverlayVTEPVerdict{
			VTEP: allocation.IP, DeviceID: deviceID, VNI: vni,
			Reason: "latest verdict did not use a signed baseline",
		}
	}
	if recorded.RecordedAt.IsZero() || recorded.RecordedAt.Add(a.maxVerdictAge).Before(a.now()) {
		return nil, ErrOverlayVTEPVerdict{
			VTEP: allocation.IP, DeviceID: deviceID, VNI: vni,
			Reason: "latest verdict is stale",
		}
	}
	if recorded.Verdict.Serial != "" && device.Serial != "" && recorded.Verdict.Serial != device.Serial {
		return nil, ErrOverlayVTEPVerdict{VTEP: allocation.IP, DeviceID: deviceID, VNI: vni, Reason: "verdict serial does not match device"}
	}
	return &AdmittedVTEP{
		VTEP:           allocation.IP,
		DeviceID:       deviceID,
		HostID:         recorded.Verdict.HostID,
		Serial:         recorded.Verdict.Serial,
		Hostname:       device.Hostname,
		AllocationID:   allocation.ID,
		BaselineSource: recorded.Verdict.BaselineSource,
		ProfileID:      recorded.Verdict.ProfileID,
		VerdictAt:      recorded.RecordedAt,
	}, nil
}

func isOverlayAdmissionDeny(err error) bool {
	switch err.(type) {
	case ErrOverlayVTEPRegistry, ErrOverlayVTEPDevice, ErrOverlayVTEPVerdict:
		return true
	default:
		return false
	}
}

type ErrOverlayAdmissionConfig struct {
	Field  string
	Reason string
}

func (e ErrOverlayAdmissionConfig) Error() string {
	return "gateway overlay admission: invalid " + e.Field + ": " + e.Reason
}

type ErrOverlayVTEPRegistry struct {
	VTEP   netip.Addr
	Reason string
	Cause  error
}

func (e ErrOverlayVTEPRegistry) Error() string {
	if e.VTEP.IsValid() {
		return "gateway overlay admission: VTEP " + e.VTEP.String() + " is not registered: " + e.Reason
	}
	return "gateway overlay admission: VTEP is not registered: " + e.Reason
}

func (e ErrOverlayVTEPRegistry) Unwrap() error { return e.Cause }

type ErrOverlayVTEPDevice struct {
	VTEP     netip.Addr
	DeviceID uint64
	Cause    error
}

func (e ErrOverlayVTEPDevice) Error() string {
	return fmt.Sprintf("gateway overlay admission: VTEP %s device %d unavailable", e.VTEP, e.DeviceID)
}

func (e ErrOverlayVTEPDevice) Unwrap() error { return e.Cause }

type ErrOverlayVTEPVerdict struct {
	VTEP     netip.Addr
	DeviceID uint64
	VNI      uint32
	Reason   string
	Cause    error
}

func (e ErrOverlayVTEPVerdict) Error() string {
	if e.VNI != 0 {
		return fmt.Sprintf("gateway overlay admission: VTEP %s device %d refused for VNI %d: %s", e.VTEP, e.DeviceID, e.VNI, e.Reason)
	}
	return fmt.Sprintf("gateway overlay admission: VTEP %s device %d refused: %s", e.VTEP, e.DeviceID, e.Reason)
}

func (e ErrOverlayVTEPVerdict) Unwrap() error { return e.Cause }

type ErrOverlayVTEPRevoke struct {
	VTEP  netip.Addr
	Cause error
}

func (e ErrOverlayVTEPRevoke) Error() string {
	return "gateway overlay admission: revoke VTEP " + e.VTEP.String() + ": " + e.Cause.Error()
}

func (e ErrOverlayVTEPRevoke) Unwrap() error { return e.Cause }
