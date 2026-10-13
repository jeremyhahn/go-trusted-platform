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

package container

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// FleetDeviceRegistry reads and saves device records in the platform
// registry. Save is how the attestor quarantines a drifted host itself.
// device.DeviceService satisfies it.
type FleetDeviceRegistry interface {
	Get(ctx context.Context, id uint64) (*entities.Device, error)
	Save(ctx context.Context, device *entities.Device) error
}

// FleetBaselineResolver resolves the profile, and so the golden PCR
// baseline, that governs a device. device.DeviceProfileService satisfies it.
type FleetBaselineResolver interface {
	FindProfileForDevice(ctx context.Context, dev *entities.Device) (*entities.DeviceProfile, error)
}

// FleetVerdictRecorder records a device attestation verdict. A
// cryptographic failure reaches the attestation observers, which isolate
// the device's port when SDN is wired. The attestation service satisfies it.
type FleetVerdictRecorder interface {
	RecordDeviceVerdict(ctx context.Context, v verdict.DeviceVerdict) error
}

// FleetReattestationRequester asks the reporting collector to re-attest a
// device now rather than at its next scheduled pass. The id is decimal.
// device.ReattestationRequester has the same shape.
type FleetReattestationRequester interface {
	Refresh(deviceID string) error
}

// FleetAttestorConfig is what NewFleetContainerAttestor composes. Reattest
// is optional: without it a drifted host is still quarantined, and the
// collector's next scheduled pass re-attests it.
type FleetAttestorConfig struct {
	// Attestor quotes the host TPM and checks the expected PCRs; the
	// runtime attestor from NewSDKContainerAttestor.
	Attestor service.ContainerAttestor
	// Devices is the device registry; it also records the quarantine.
	Devices FleetDeviceRegistry
	// Baselines resolves the golden PCR baseline from the device profile.
	Baselines FleetBaselineResolver
	// Verdicts records the drift verdict.
	Verdicts FleetVerdictRecorder
	// Reattest requests an immediate re-attestation after drift.
	Reattest FleetReattestationRequester
	// LocalDeviceID is this host's record in the registry. The host TPM
	// can only speak for this host, so it is the only device attested.
	LocalDeviceID uint64
	// Logger receives drift and re-attestation reports.
	Logger *slog.Logger
}

// FleetContainerAttestor is the platform's container attestor, registered
// into quicbaas WithContainerAttestor. It puts fleet policy around the
// upstream runtime attestor:
//
//   - the device must be this host's registry record and in a state that
//     may attest (activated or attested; never quarantined, suspended or
//     revoked);
//   - the request must ask for a host-TPM tier (attested or measured);
//   - the golden PCR values come from the device profile's baseline, and a
//     request may add PCRs but never override a baseline value;
//   - the baseline is quoted and checked on its own before any PCR the
//     request added, so a failing request PCR cannot hide drift;
//   - a quote that differs from the baseline is drift: a cryptographic
//     verdict is recorded, the device is moved to quarantine in the
//     registry, and re-attestation is requested.
//
// Every refusal is a typed error and every path that cannot prove the host
// matches its baseline fails closed. A pass is not recorded as a device
// verdict: a host's quote of itself must not readmit it from quarantine.
type FleetContainerAttestor struct {
	attestor  service.ContainerAttestor
	devices   FleetDeviceRegistry
	baselines FleetBaselineResolver
	verdicts  FleetVerdictRecorder
	reattest  FleetReattestationRequester
	localID   uint64
	logger    *slog.Logger
	now       func() time.Time
}

var _ service.ContainerAttestor = (*FleetContainerAttestor)(nil)

// NewFleetContainerAttestor validates cfg and returns the attestor.
func NewFleetContainerAttestor(cfg FleetAttestorConfig) (*FleetContainerAttestor, error) {
	switch {
	case cfg.Attestor == nil:
		return nil, ErrFleetAttestorDependency{Name: "container attestor"}
	case cfg.Devices == nil:
		return nil, ErrFleetAttestorDependency{Name: "device registry"}
	case cfg.Baselines == nil:
		return nil, ErrFleetAttestorDependency{Name: "baseline resolver"}
	case cfg.Verdicts == nil:
		return nil, ErrFleetAttestorDependency{Name: "verdict recorder"}
	case cfg.LocalDeviceID == 0:
		return nil, ErrFleetAttestorDependency{Name: "local device id"}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &FleetContainerAttestor{
		attestor:  cfg.Attestor,
		devices:   cfg.Devices,
		baselines: cfg.Baselines,
		verdicts:  cfg.Verdicts,
		reattest:  cfg.Reattest,
		localID:   cfg.LocalDeviceID,
		logger:    logger,
		now:       time.Now,
	}, nil
}

// AttestContainer attests a container on this host against the device
// profile's golden PCR baseline.
func (a *FleetContainerAttestor) AttestContainer(ctx context.Context, req *service.AttestContainerRequest) (*service.AttestContainerResponse, error) {
	if req == nil {
		return nil, ErrFleetAttestRequestRequired{}
	}
	if err := a.checkTrustLevel(req.TrustLevel); err != nil {
		return nil, err
	}
	dev, err := a.attestableDevice(ctx, req.DeviceID)
	if err != nil {
		return nil, err
	}
	profile, baseline, err := a.baseline(ctx, dev)
	if err != nil {
		return nil, err
	}
	expected, err := mergeExpectedPCRs(dev.ID, baseline, req.ExpectedPCRs)
	if err != nil {
		return nil, err
	}

	// The upstream check reports only the lowest-numbered mismatch, so a
	// failing request PCR would hide drift in a higher baseline PCR. The
	// baseline is therefore quoted on its own first; the request's own
	// PCRs are quoted only once the baseline holds.
	scoped := *req
	scoped.DeviceID = strconv.FormatUint(dev.ID, 10)
	scoped.ExpectedPCRs = baseline
	resp, err := a.quote(ctx, dev, profile, baseline, &scoped)
	if err != nil {
		return nil, err
	}
	if len(expected) > len(baseline) {
		scoped.ExpectedPCRs = expected
		if resp, err = a.quote(ctx, dev, profile, baseline, &scoped); err != nil {
			return nil, err
		}
	}
	resp.DeviceID = scoped.DeviceID
	return resp, nil
}

// quote runs one upstream attestation and classifies its failure.
func (a *FleetContainerAttestor) quote(ctx context.Context, dev *entities.Device, profile *entities.DeviceProfile, baseline map[uint32][]byte, req *service.AttestContainerRequest) (*service.AttestContainerResponse, error) {
	resp, err := a.attestor.AttestContainer(ctx, req)
	if err != nil {
		return nil, a.classify(ctx, dev, profile, baseline, err)
	}
	if resp == nil || !resp.Attested {
		return nil, ErrFleetAttestationFailed{DeviceID: dev.ID, Reason: "the attestor returned no attested result"}
	}
	return resp, nil
}

// checkTrustLevel refuses a tier that does not quote the host TPM: without
// a quote there is nothing to hold against the baseline. The default tier
// is attested.
func (a *FleetContainerAttestor) checkTrustLevel(raw string) error {
	level, err := orchestration.ParseTrustLevel(raw)
	if err != nil {
		return ErrFleetTrustLevelRefused{TrustLevel: raw, Cause: err}
	}
	if level == orchestration.TrustLevelDefault || level.RequiresHostTPM() {
		return nil
	}
	return ErrFleetTrustLevelRefused{TrustLevel: raw}
}

// attestableDevice resolves the request's device: empty means this host,
// anything else must name this host's record.
func (a *FleetContainerAttestor) attestableDevice(ctx context.Context, raw string) (*entities.Device, error) {
	id := a.localID
	if raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return nil, ErrFleetDeviceIDInvalid{DeviceID: raw, Cause: err}
		}
		id = parsed
	}
	if id != a.localID {
		return nil, ErrFleetDeviceNotLocal{DeviceID: id, LocalDeviceID: a.localID}
	}
	dev, err := a.devices.Get(ctx, id)
	if err != nil {
		return nil, ErrFleetDeviceLookup{DeviceID: id, Cause: err}
	}
	if dev == nil {
		return nil, ErrFleetDeviceLookup{DeviceID: id}
	}
	if !dev.CanAttest() {
		return nil, ErrFleetDeviceCannotAttest{DeviceID: id, State: dev.State}
	}
	return dev, nil
}

// baseline resolves the device profile's golden PCR values. A device with
// no profile, or a profile with no baseline, cannot be attested here: the
// fleet path never captures a baseline on first use.
func (a *FleetContainerAttestor) baseline(ctx context.Context, dev *entities.Device) (*entities.DeviceProfile, map[uint32][]byte, error) {
	profile, err := a.baselines.FindProfileForDevice(ctx, dev)
	if err != nil {
		return nil, nil, ErrFleetBaselineUnavailable{DeviceID: dev.ID, Reason: "no profile resolves for the device", Cause: err}
	}
	if profile == nil || profile.PCRBaseline == nil || len(profile.PCRBaseline.Values) == 0 {
		return nil, nil, ErrFleetBaselineUnavailable{DeviceID: dev.ID, Reason: "the device profile records no PCR baseline"}
	}
	golden := make(map[uint32][]byte, len(profile.PCRBaseline.Values))
	for index, value := range profile.PCRBaseline.Values {
		if index < 0 || index > orchestration.MaxPCRIndex || len(value) == 0 {
			return nil, nil, ErrFleetBaselineUnavailable{
				DeviceID: dev.ID,
				Reason:   fmt.Sprintf("profile %d records an unusable value for PCR %d", profile.ID, index),
			}
		}
		golden[uint32(index)] = value
	}
	return profile, golden, nil
}

// mergeExpectedPCRs adds the request's PCRs to the baseline. A request may
// pin further registers but never relax a baseline value.
func mergeExpectedPCRs(deviceID uint64, baseline, requested map[uint32][]byte) (map[uint32][]byte, error) {
	merged := make(map[uint32][]byte, len(baseline)+len(requested))
	for index, value := range baseline {
		merged[index] = value
	}
	for index, value := range requested {
		if golden, ok := baseline[index]; ok {
			if !bytes.Equal(golden, value) {
				return nil, ErrFleetBaselineConflict{DeviceID: deviceID, Index: index}
			}
			continue
		}
		merged[index] = value
	}
	return merged, nil
}

// classify turns an attestor failure into the fleet's answer. Only a
// baseline register that quotes a different value is drift; every other
// failure is a refusal that leaves the device's standing alone, because
// absence of evidence is not failed attestation.
func (a *FleetContainerAttestor) classify(ctx context.Context, dev *entities.Device, profile *entities.DeviceProfile, baseline map[uint32][]byte, err error) error {
	var mismatch *orchestration.PCRMismatchError
	if !errors.As(err, &mismatch) {
		return ErrFleetAttestationFailed{DeviceID: dev.ID, Reason: "the host could not be attested", Cause: err}
	}
	if _, golden := baseline[mismatch.Index]; !golden {
		return ErrFleetPCRPolicyMismatch{DeviceID: dev.ID, Index: mismatch.Index, Cause: err}
	}
	return a.quarantine(ctx, dev, profile, mismatch.Index, err)
}

// quarantine records the drift as a cryptographic failure verdict, moves
// the device to quarantine, and asks the collector to re-attest it. A step
// that fails does not stop the next: each is reported on the drift error.
func (a *FleetContainerAttestor) quarantine(ctx context.Context, dev *entities.Device, profile *entities.DeviceProfile, index uint32, mismatch error) error {
	reason := fmt.Sprintf("container attestation: PCR %d differs from the profile's golden baseline", index)
	drift := ErrFleetHostDrift{DeviceID: dev.ID, Index: index, Mismatch: mismatch}
	drift.VerdictErr = a.verdicts.RecordDeviceVerdict(ctx, verdict.DeviceVerdict{
		DeviceID:       dev.ID,
		TenantID:       dev.TenantID,
		HostID:         dev.Hostname,
		Serial:         dev.Serial,
		Passed:         false,
		Cryptographic:  true,
		Reason:         reason,
		BaselineSource: string(profile.PCRBaseline.Source),
		ProfileID:      profile.ID,
		AttestedAt:     a.now().UTC(),
	})
	drift.QuarantineErr = a.enterQuarantine(ctx, dev.ID, reason)
	if a.reattest != nil {
		drift.ReattestErr = a.reattest.Refresh(strconv.FormatUint(dev.ID, 10))
	}
	a.logger.Error("container attestation found host drift",
		"device_id", dev.ID, "pcr", index, "verdict_error", drift.VerdictErr,
		"quarantine_error", drift.QuarantineErr, "reattest_error", drift.ReattestErr)
	return drift
}

// enterQuarantine moves the device to quarantine in the registry. It runs
// after the verdict, so when SDN is wired its observer has already isolated
// the port and quarantined the device, and this finds it contained. Without
// SDN, or for a device with no SDN port, this transition is the quarantine.
// A suspended or revoked device is already held more strictly and is left
// alone.
func (a *FleetContainerAttestor) enterQuarantine(ctx context.Context, id uint64, reason string) error {
	dev, err := a.devices.Get(ctx, id)
	if err != nil {
		return ErrFleetQuarantineFailed{DeviceID: id, Cause: err}
	}
	if dev == nil {
		return ErrFleetQuarantineFailed{DeviceID: id, Cause: ErrFleetDeviceLookup{DeviceID: id}}
	}
	switch dev.State {
	case entities.DeviceStateQuarantined, entities.DeviceStateSuspended, entities.DeviceStateRevoked:
		return nil
	}
	prior := dev.State
	if err := dev.Transition(entities.DeviceStateQuarantined); err != nil {
		return ErrFleetQuarantineFailed{DeviceID: id, Cause: err}
	}
	dev.PriorState = prior
	dev.StateReason = reason
	if err := a.devices.Save(ctx, dev); err != nil {
		return ErrFleetQuarantineFailed{DeviceID: id, Cause: err}
	}
	return nil
}

// ErrFleetAttestorDependency is returned when the fleet attestor is built
// without a required dependency.
type ErrFleetAttestorDependency struct {
	Name string
}

// Error implements the error interface.
func (e ErrFleetAttestorDependency) Error() string {
	return "container fleet attestor: a " + e.Name + " is required"
}

// ErrFleetAttestRequestRequired is returned for a nil request.
type ErrFleetAttestRequestRequired struct{}

// Error implements the error interface.
func (ErrFleetAttestRequestRequired) Error() string {
	return "container fleet attestor: the attestation request is required"
}

// ErrFleetTrustLevelRefused is returned when the requested trust level does
// not parse or does not quote the host TPM.
type ErrFleetTrustLevelRefused struct {
	TrustLevel string
	Cause      error
}

// Error implements the error interface.
func (e ErrFleetTrustLevelRefused) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("container fleet attestor: trust level %q is invalid: %v", e.TrustLevel, e.Cause)
	}
	return fmt.Sprintf("container fleet attestor: trust level %q does not quote the host TPM; request attested or measured", e.TrustLevel)
}

// Unwrap returns the parse error.
func (e ErrFleetTrustLevelRefused) Unwrap() error {
	return e.Cause
}

// ErrFleetDeviceIDInvalid is returned when the request's device id is not a
// decimal registry id.
type ErrFleetDeviceIDInvalid struct {
	DeviceID string
	Cause    error
}

// Error implements the error interface.
func (e ErrFleetDeviceIDInvalid) Error() string {
	return fmt.Sprintf("container fleet attestor: device id %q is not a registry id: %v", e.DeviceID, e.Cause)
}

// Unwrap returns the parse error.
func (e ErrFleetDeviceIDInvalid) Unwrap() error {
	return e.Cause
}

// ErrFleetDeviceNotLocal is returned when the request names a device other
// than this host. The host TPM can only quote this host.
type ErrFleetDeviceNotLocal struct {
	DeviceID      uint64
	LocalDeviceID uint64
}

// Error implements the error interface.
func (e ErrFleetDeviceNotLocal) Error() string {
	return fmt.Sprintf("container fleet attestor: device %d is not this host (device %d); only this host's TPM can be quoted", e.DeviceID, e.LocalDeviceID)
}

// ErrFleetDeviceLookup is returned when the device record cannot be read.
type ErrFleetDeviceLookup struct {
	DeviceID uint64
	Cause    error
}

// Error implements the error interface.
func (e ErrFleetDeviceLookup) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("container fleet attestor: device %d is not in the registry", e.DeviceID)
	}
	return fmt.Sprintf("container fleet attestor: device %d could not be read: %v", e.DeviceID, e.Cause)
}

// Unwrap returns the registry error.
func (e ErrFleetDeviceLookup) Unwrap() error {
	return e.Cause
}

// ErrFleetDeviceCannotAttest is returned when the device's lifecycle state
// does not allow attestation, for example a quarantined or revoked host.
type ErrFleetDeviceCannotAttest struct {
	DeviceID uint64
	State    entities.DeviceState
}

// Error implements the error interface.
func (e ErrFleetDeviceCannotAttest) Error() string {
	return fmt.Sprintf("container fleet attestor: device %d is %s and may not attest containers", e.DeviceID, e.State)
}

// ErrFleetBaselineUnavailable is returned when no golden PCR baseline
// governs the device.
type ErrFleetBaselineUnavailable struct {
	DeviceID uint64
	Reason   string
	Cause    error
}

// Error implements the error interface.
func (e ErrFleetBaselineUnavailable) Error() string {
	msg := fmt.Sprintf("container fleet attestor: no golden PCR baseline for device %d: %s", e.DeviceID, e.Reason)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the profile lookup error.
func (e ErrFleetBaselineUnavailable) Unwrap() error {
	return e.Cause
}

// ErrFleetBaselineConflict is returned when the request expects a value for
// a baseline PCR that differs from the baseline's.
type ErrFleetBaselineConflict struct {
	DeviceID uint64
	Index    uint32
}

// Error implements the error interface.
func (e ErrFleetBaselineConflict) Error() string {
	return fmt.Sprintf("container fleet attestor: the request expects a value for PCR %d that differs from device %d's golden baseline", e.Index, e.DeviceID)
}

// ErrFleetHostDrift is returned when the host quotes a baseline PCR with a
// value other than the golden one. The drift verdict was recorded unless
// VerdictErr says otherwise, the device was moved to quarantine unless
// QuarantineErr says otherwise, and re-attestation was requested unless
// ReattestErr says otherwise.
type ErrFleetHostDrift struct {
	DeviceID      uint64
	Index         uint32
	Mismatch      error
	VerdictErr    error
	QuarantineErr error
	ReattestErr   error
}

// Error implements the error interface.
func (e ErrFleetHostDrift) Error() string {
	msg := fmt.Sprintf("container fleet attestor: device %d drifted from its golden baseline at PCR %d", e.DeviceID, e.Index)
	if e.VerdictErr != nil {
		msg += "; the drift verdict was not recorded: " + e.VerdictErr.Error()
	}
	if e.QuarantineErr != nil {
		msg += "; the device was not quarantined: " + e.QuarantineErr.Error()
	}
	if e.ReattestErr != nil {
		msg += "; re-attestation was not requested: " + e.ReattestErr.Error()
	}
	return msg
}

// Unwrap returns the PCR mismatch and any verdict, quarantine or
// re-attestation failure.
func (e ErrFleetHostDrift) Unwrap() []error {
	errs := make([]error, 0, 4)
	for _, err := range []error{e.Mismatch, e.VerdictErr, e.QuarantineErr, e.ReattestErr} {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// ErrFleetQuarantineFailed is returned, inside ErrFleetHostDrift, when a
// drifted device could not be moved to quarantine in the registry.
type ErrFleetQuarantineFailed struct {
	DeviceID uint64
	Cause    error
}

// Error implements the error interface.
func (e ErrFleetQuarantineFailed) Error() string {
	return fmt.Sprintf("container fleet attestor: device %d could not be moved to quarantine: %v", e.DeviceID, e.Cause)
}

// Unwrap returns the registry or state-transition failure.
func (e ErrFleetQuarantineFailed) Unwrap() error {
	return e.Cause
}

// ErrFleetPCRPolicyMismatch is returned when a PCR the request added, not
// one from the baseline, quotes a different value. The caller's policy
// failed; the device's standing is unchanged.
type ErrFleetPCRPolicyMismatch struct {
	DeviceID uint64
	Index    uint32
	Cause    error
}

// Error implements the error interface.
func (e ErrFleetPCRPolicyMismatch) Error() string {
	return fmt.Sprintf("container fleet attestor: device %d PCR %d does not match the value the request expects: %v", e.DeviceID, e.Index, e.Cause)
}

// Unwrap returns the PCR mismatch.
func (e ErrFleetPCRPolicyMismatch) Unwrap() error {
	return e.Cause
}

// ErrFleetAttestationFailed is returned when the host produced no usable
// evidence. It is a refusal, not a verdict: the device is not quarantined.
type ErrFleetAttestationFailed struct {
	DeviceID uint64
	Reason   string
	Cause    error
}

// Error implements the error interface.
func (e ErrFleetAttestationFailed) Error() string {
	msg := fmt.Sprintf("container fleet attestor: device %d: %s", e.DeviceID, e.Reason)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the attestor error.
func (e ErrFleetAttestationFailed) Unwrap() error {
	return e.Cause
}
