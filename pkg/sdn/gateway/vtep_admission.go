package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/deviceverdict"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

const (
	// DefaultOverlayVerdictMaxAge is the default maximum age of the latest
	// recorded device verdict accepted by the gateway overlay admission policy.
	DefaultOverlayVerdictMaxAge = 15 * time.Minute

	// DefaultOverlayVerdictClockSkew is the default bound on how far past the
	// gateway's clock a verdict's attestation time may lie. A verdict stamped
	// further ahead would stay "fresh" beyond MaxVerdictAge, so it is refused.
	DefaultOverlayVerdictClockSkew = 30 * time.Second

	// DefaultOverlayAdmissionSweepInterval is the default period of the sweep
	// that re-admits every installed remote VTEP. It bounds how long a VTEP
	// whose verdict aged out or turned non-cryptographically failed keeps
	// decap state.
	DefaultOverlayAdmissionSweepInterval = 30 * time.Second

	overlaySignedBaselineSource = "signed"
)

// OverlayDeviceGetter loads platform device records by their numeric device
// ID. A device the platform does not hold is reported as a nil device or as
// ErrOverlayRecordNotFound; any other error is an outage.
type OverlayDeviceGetter interface {
	Get(ctx context.Context, id uint64) (*deviceentities.Device, error)
}

// OverlayVerdictReader reads the platform-side attestation verdict log. A
// device with no verdict is reported as a nil record or as
// ErrOverlayRecordNotFound; any other error is an outage.
type OverlayVerdictReader interface {
	LatestDeviceVerdict(ctx context.Context, deviceID uint64) (*deviceverdict.RecordedDeviceVerdict, error)
}

// OverlayVerdictStream delivers the platform's device verdicts as they are
// recorded. Follow hands each verdict to deliver until ctx ends or the stream
// breaks, and returns why it stopped. Verdicts recorded while no one follows
// are not replayed.
type OverlayVerdictStream interface {
	Follow(ctx context.Context, deliver func(context.Context, deviceverdict.DeviceVerdict)) error
}

// OverlayVTEPRevoker withdraws all overlay reachability from a VTEP.
type OverlayVTEPRevoker interface {
	RevokeVTEP(ctx context.Context, vtep netip.Addr) error
}

// OverlayIPAMReader reads the fabric allocations that authorize remote VTEPs.
// An address with no allocation is reported as ipam.ErrAllocationNotFound or
// ErrOverlayRecordNotFound; any other error is an outage.
type OverlayIPAMReader interface {
	GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error)
	GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error)
}

// OverlayIPAMRefresher is implemented by an OverlayIPAMReader that caches the
// fabric allocations. The admission sweep refreshes it before each pass, so
// route admission never has to list the allocations itself.
type OverlayIPAMRefresher interface {
	Refresh(ctx context.Context) error
}

// VTEPAdmissionConfig wires the production overlay VTEP admission policy.
type VTEPAdmissionConfig struct {
	IPAM     OverlayIPAMReader
	Devices  OverlayDeviceGetter
	Verdicts OverlayVerdictReader
	Revoker  OverlayVTEPRevoker
	// MaxVerdictAge bounds the age of an admitting verdict. Zero defaults to
	// DefaultOverlayVerdictMaxAge.
	MaxVerdictAge time.Duration
	// VerdictClockSkew bounds how far in the future an admitting verdict's
	// attestation time may lie. Zero defaults to
	// DefaultOverlayVerdictClockSkew.
	VerdictClockSkew time.Duration
	Now              func() time.Time
	Logger           *slog.Logger
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

// admissionRecord is the last admission of a VTEP and the sweep generation it
// was made in.
type admissionRecord struct {
	vtep       AdmittedVTEP
	generation uint64
}

// VTEPAdmitter is the production implementation of modes.VTEPAdmitter. The
// registry is the platform IPAM fabric allocation for the VTEP address; the
// relying-party decision comes from the platform attestation event log. It
// remembers each admission so the sweep can re-judge it and the admitted-VTEP
// listing can say why an installed VTEP was let in.
type VTEPAdmitter struct {
	ipam          OverlayIPAMReader
	devices       OverlayDeviceGetter
	verdicts      OverlayVerdictReader
	revoker       OverlayVTEPRevoker
	maxVerdictAge time.Duration
	clockSkew     time.Duration
	now           func() time.Time
	logger        *slog.Logger

	mu         sync.Mutex
	admitted   map[netip.Addr]admissionRecord
	generation uint64
}

// NewVTEPAdmitter validates cfg, applies its defaults and returns the
// admitter.
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
	if cfg.VerdictClockSkew < 0 {
		return nil, ErrOverlayAdmissionConfig{Field: "verdict_clock_skew", Reason: "negative"}
	}
	if cfg.MaxVerdictAge == 0 {
		cfg.MaxVerdictAge = DefaultOverlayVerdictMaxAge
	}
	if cfg.VerdictClockSkew == 0 {
		cfg.VerdictClockSkew = DefaultOverlayVerdictClockSkew
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
		clockSkew:     cfg.VerdictClockSkew,
		now:           cfg.Now,
		logger:        cfg.Logger,
		admitted:      make(map[netip.Addr]admissionRecord),
	}, nil
}

// AdmitVTEP implements modes.VTEPAdmitter: vtep may carry vni when its fabric
// allocation, its device record and its device's latest verdict all pass the
// policy. An admission is remembered and a denial forgets any earlier one. An
// outage refuses the route but leaves the earlier admission for the sweep to
// judge.
func (a *VTEPAdmitter) AdmitVTEP(ctx context.Context, vni uint32, vtep netip.Addr) error {
	admitted, err := a.evaluate(ctx, vni, vtep)
	switch {
	case err == nil:
		a.remember(*admitted)
	case isOverlayAdmissionDeny(err):
		a.forget(vtep)
	}
	return err
}

// Admitted reports the installed VTEPs with the admission that let each in.
// A VTEP installed without a remembered admission is reported by address
// alone, so the listing never hides what the datapath holds.
func (a *VTEPAdmitter) Admitted(installed []modes.InstalledVTEP) []AdmittedVTEP {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AdmittedVTEP, 0, len(installed))
	for _, vtep := range installed {
		record, ok := a.admitted[vtep.VTEP]
		if !ok {
			record.vtep = AdmittedVTEP{VTEP: vtep.VTEP}
		}
		out = append(out, record.vtep)
	}
	return out
}

// Sweep re-judges every installed VTEP, so a verdict that ages past
// MaxVerdictAge or turns to a failure withdraws the VTEP even when no route
// arrives for it. The policy does not depend on the VNI, so a VTEP is judged
// once for all the VNIs it is installed in. A denied VTEP is revoked. While
// the platform cannot be read, a VTEP keeps its admission only until its
// verdict would have gone stale, so an outage never extends trust past
// MaxVerdictAge. Admissions of VTEPs no longer installed are forgotten. Sweep
// continues past failures and returns them joined.
func (a *VTEPAdmitter) Sweep(ctx context.Context, installed []modes.InstalledVTEP) error {
	a.mu.Lock()
	a.generation++
	generation := a.generation
	a.mu.Unlock()

	var errs []error
	if refresher, ok := a.ipam.(OverlayIPAMRefresher); ok {
		if err := refresher.Refresh(ctx); err != nil {
			errs = append(errs, ErrOverlayAdmissionUnavailable{Source: "ipam", Cause: err})
		}
	}
	current := make(map[netip.Addr]struct{}, len(installed))
	for _, vtep := range installed {
		current[vtep.VTEP] = struct{}{}
		if err := a.sweepVTEP(ctx, vtep.VTEP); err != nil {
			errs = append(errs, err)
		}
	}

	// An admission made since the sweep began belongs to a route that
	// installed after the snapshot of installed VTEPs was taken.
	a.mu.Lock()
	for vtep, record := range a.admitted {
		if _, ok := current[vtep]; !ok && record.generation < generation {
			delete(a.admitted, vtep)
		}
	}
	a.mu.Unlock()
	return errors.Join(errs...)
}

func (a *VTEPAdmitter) sweepVTEP(ctx context.Context, vtep netip.Addr) error {
	admitted, err := a.evaluate(ctx, 0, vtep)
	if err == nil {
		a.remember(*admitted)
		return nil
	}
	if !isOverlayAdmissionDeny(err) && a.verdictStillFresh(vtep) {
		return err
	}
	a.logger.Warn("overlay: revoking a VTEP the admission policy no longer admits",
		slog.String("vtep", vtep.String()), slog.Any("error", err))
	return a.revoke(ctx, vtep)
}

// OnDeviceVerdict withdraws every VTEP of a device whose verdict failed,
// whether cryptographically or for an absence of evidence: either way the
// policy no longer admits it, and waiting for the sweep would leave its decap
// state in place for up to a sweep interval. A passed verdict changes nothing;
// the device's routes are admitted when they are next advertised.
func (a *VTEPAdmitter) OnDeviceVerdict(ctx context.Context, v deviceverdict.DeviceVerdict) {
	if v.Passed {
		return
	}
	a.logger.Warn("overlay: withdrawing a device whose attestation failed",
		slog.Uint64("device_id", v.DeviceID),
		slog.Bool("cryptographic", v.Cryptographic),
		slog.String("reason", v.Reason))
	if err := a.RevokeDevice(ctx, v.DeviceID); err != nil {
		a.logger.Warn("overlay: withdrawing the device did not complete; the sweep retries it",
			slog.Uint64("device_id", v.DeviceID),
			slog.Any("error", err))
	}
}

// RevokeDevice withdraws every VTEP of the device: those admitted for it and
// its fabric allocations. It continues past a VTEP whose withdrawal fails, and
// past an IPAM outage, and returns the failures joined.
func (a *VTEPAdmitter) RevokeDevice(ctx context.Context, deviceID uint64) error {
	vteps := make(map[netip.Addr]struct{})
	a.mu.Lock()
	for vtep, record := range a.admitted {
		if record.vtep.DeviceID == deviceID {
			vteps[vtep] = struct{}{}
		}
	}
	a.mu.Unlock()

	var errs []error
	allocations, err := a.ipam.GetAllocationsByDevice(ctx, strconv.FormatUint(deviceID, 10))
	if err != nil {
		errs = append(errs, ErrOverlayAdmissionUnavailable{DeviceID: deviceID, Source: "ipam", Cause: err})
	}
	for _, allocation := range allocations {
		if allocation != nil && allocation.IP.IsValid() && allocation.Zone == string(zone.ZoneFabric) {
			vteps[allocation.IP] = struct{}{}
		}
	}
	for vtep := range vteps {
		if err := a.revoke(ctx, vtep); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (a *VTEPAdmitter) revoke(ctx context.Context, vtep netip.Addr) error {
	a.forget(vtep)
	if err := a.revoker.RevokeVTEP(ctx, vtep); err != nil {
		return ErrOverlayVTEPRevoke{VTEP: vtep, Cause: err}
	}
	return nil
}

func (a *VTEPAdmitter) remember(admitted AdmittedVTEP) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.admitted[admitted.VTEP] = admissionRecord{vtep: admitted, generation: a.generation}
}

func (a *VTEPAdmitter) forget(vtep netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.admitted, vtep)
}

// verdictStillFresh reports whether vtep's remembered admission rests on a
// verdict younger than MaxVerdictAge.
func (a *VTEPAdmitter) verdictStillFresh(vtep netip.Addr) bool {
	a.mu.Lock()
	record, ok := a.admitted[vtep]
	a.mu.Unlock()
	return ok && a.now().Before(record.vtep.VerdictAt.Add(a.maxVerdictAge))
}

// evaluate applies the admission policy to vtep. A denial is one of the
// ErrOverlayVTEP* types; a platform read failure is
// ErrOverlayAdmissionUnavailable.
func (a *VTEPAdmitter) evaluate(ctx context.Context, vni uint32, vtep netip.Addr) (*AdmittedVTEP, error) {
	if !vtep.Is4() || vtep.IsUnspecified() {
		return nil, ErrOverlayVTEPRegistry{VTEP: vtep, Reason: "invalid VTEP address"}
	}
	allocation, err := a.ipam.GetAllocation(ctx, vtep)
	if isOverlayRecordNotFound(err) || (err == nil && allocation == nil) {
		return nil, ErrOverlayVTEPRegistry{VTEP: vtep, Reason: "no fabric allocation", Cause: err}
	}
	if err != nil {
		return nil, ErrOverlayAdmissionUnavailable{VTEP: vtep, Source: "ipam", Cause: err}
	}
	if allocation.IP != vtep || !allocation.IsActive() {
		return nil, ErrOverlayVTEPRegistry{VTEP: vtep, Reason: "allocation is not active"}
	}
	if allocation.Zone != string(zone.ZoneFabric) {
		return nil, ErrOverlayVTEPRegistry{VTEP: vtep, Reason: "allocation is not in the fabric zone"}
	}
	deviceID, err := strconv.ParseUint(allocation.DeviceID, 10, 64)
	if err != nil || deviceID == 0 {
		return nil, ErrOverlayVTEPRegistry{VTEP: vtep, Reason: "allocation device id is not numeric"}
	}
	device, err := a.devices.Get(ctx, deviceID)
	if isOverlayRecordNotFound(err) || (err == nil && device == nil) {
		return nil, ErrOverlayVTEPDevice{VTEP: vtep, DeviceID: deviceID, Cause: err}
	}
	if err != nil {
		return nil, ErrOverlayAdmissionUnavailable{VTEP: vtep, DeviceID: deviceID, Source: "device", Cause: err}
	}
	if device.ID != deviceID {
		return nil, ErrOverlayVTEPRegistry{VTEP: vtep, Reason: "device record does not match allocation"}
	}
	recorded, err := a.verdicts.LatestDeviceVerdict(ctx, deviceID)
	if isOverlayRecordNotFound(err) || (err == nil && recorded == nil) {
		return nil, ErrOverlayVTEPVerdict{VTEP: vtep, DeviceID: deviceID, VNI: vni, Reason: "no verdict recorded", Cause: err}
	}
	if err != nil {
		return nil, ErrOverlayAdmissionUnavailable{VTEP: vtep, DeviceID: deviceID, Source: "verdict", Cause: err}
	}
	if reason := a.verdictRefusal(recorded, device); reason != "" {
		return nil, ErrOverlayVTEPVerdict{VTEP: vtep, DeviceID: deviceID, VNI: vni, Reason: reason}
	}
	return &AdmittedVTEP{
		VTEP:           vtep,
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

// verdictRefusal returns why the verdict does not admit the device, or "" when
// it does.
func (a *VTEPAdmitter) verdictRefusal(recorded *deviceverdict.RecordedDeviceVerdict, device *deviceentities.Device) string {
	now := a.now()
	switch {
	case !recorded.Verdict.Passed:
		return "latest verdict failed"
	case recorded.Verdict.BaselineSource != overlaySignedBaselineSource:
		return "latest verdict did not use a signed baseline"
	case recorded.RecordedAt.IsZero():
		return "latest verdict has no attestation time"
	case recorded.RecordedAt.After(now.Add(a.clockSkew)):
		return "latest verdict is recorded in the future"
	case recorded.RecordedAt.Add(a.maxVerdictAge).Before(now):
		return "latest verdict is stale"
	case device.Serial != "" && recorded.Verdict.Serial != device.Serial:
		return "verdict serial does not match device"
	}
	return ""
}

func isOverlayAdmissionDeny(err error) bool {
	switch err.(type) {
	case ErrOverlayVTEPRegistry, ErrOverlayVTEPDevice, ErrOverlayVTEPVerdict:
		return true
	default:
		return false
	}
}

func isOverlayRecordNotFound(err error) bool {
	return errors.Is(err, ErrOverlayRecordNotFound) || errors.Is(err, ipam.ErrAllocationNotFound)
}

// ErrOverlayRecordNotFound is returned, bare or wrapped, by an overlay
// platform reader that holds no record for the request, so the admitter can
// tell a denial from an outage.
var ErrOverlayRecordNotFound error = errOverlayRecordNotFound{}

type errOverlayRecordNotFound struct{}

func (errOverlayRecordNotFound) Error() string {
	return "gateway overlay admission: platform record not found"
}

// ErrOverlayAdmissionConfig reports an invalid VTEPAdmissionConfig field.
type ErrOverlayAdmissionConfig struct {
	Field  string
	Reason string
}

func (e ErrOverlayAdmissionConfig) Error() string {
	return "gateway overlay admission: invalid " + e.Field + ": " + e.Reason
}

// ErrOverlayAdmissionUnavailable reports that a platform record an admission
// decision needs could not be read. Route admission refuses on it; the sweep
// keeps an earlier admission only until its verdict would go stale.
type ErrOverlayAdmissionUnavailable struct {
	VTEP     netip.Addr
	DeviceID uint64
	// Source names the record that could not be read: ipam, device or
	// verdict.
	Source string
	Cause  error
}

func (e ErrOverlayAdmissionUnavailable) Error() string {
	msg := "gateway overlay admission: platform " + e.Source + " unavailable"
	if e.VTEP.IsValid() {
		msg += " for VTEP " + e.VTEP.String()
	}
	if e.DeviceID != 0 {
		msg += " device " + strconv.FormatUint(e.DeviceID, 10)
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e ErrOverlayAdmissionUnavailable) Unwrap() error { return e.Cause }

// ErrOverlayVTEPRegistry denies a VTEP without a usable fabric allocation.
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

// ErrOverlayVTEPDevice denies a VTEP whose allocation names a device the
// platform does not hold.
type ErrOverlayVTEPDevice struct {
	VTEP     netip.Addr
	DeviceID uint64
	Cause    error
}

func (e ErrOverlayVTEPDevice) Error() string {
	return fmt.Sprintf("gateway overlay admission: VTEP %s device %d is not registered", e.VTEP, e.DeviceID)
}

func (e ErrOverlayVTEPDevice) Unwrap() error { return e.Cause }

// ErrOverlayVTEPVerdict denies a VTEP whose device's latest verdict does not
// admit it.
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

// ErrOverlayVTEPRevoke reports a VTEP whose withdrawal from the overlay
// failed.
type ErrOverlayVTEPRevoke struct {
	VTEP  netip.Addr
	Cause error
}

func (e ErrOverlayVTEPRevoke) Error() string {
	return "gateway overlay admission: revoke VTEP " + e.VTEP.String() + ": " + e.Cause.Error()
}

func (e ErrOverlayVTEPRevoke) Unwrap() error { return e.Cause }
