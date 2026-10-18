package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
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

	// DefaultOverlayAdmissionReadTimeout is the default bound on the platform
	// reads behind one admission decision, and on all the reads of one sweep.
	// Half the sweep interval lets a sweep whose reads hang end before the
	// next tick, so an unresponsive platformd cannot hold trust open.
	DefaultOverlayAdmissionReadTimeout = DefaultOverlayAdmissionSweepInterval / 2

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
// recorded. Follow hands each verdict, with the platform time it was recorded
// at, to deliver until ctx ends or the stream breaks, and returns why it
// stopped. Verdicts recorded while no one follows are not replayed.
type OverlayVerdictStream interface {
	Follow(ctx context.Context, deliver func(context.Context, deviceverdict.RecordedDeviceVerdict)) error
}

// OverlayVTEPRevoker withdraws all overlay reachability from a VTEP.
type OverlayVTEPRevoker interface {
	RevokeVTEP(ctx context.Context, vtep netip.Addr) error
}

// OverlayVTEPReplayer brings back the routes of remote VTEPs the overlay
// refused or revoked. BGP does not send an unchanged route again, so a VTEP
// refused before its device passed attestation is installed only by a replay.
type OverlayVTEPReplayer interface {
	// RefusedVTEPs reports the refused VTEPs that still have routes.
	RefusedVTEPs() []netip.Addr
	// ReplayVTEP hands the VTEP's routes through admission again.
	ReplayVTEP(ctx context.Context, vtep netip.Addr) error
}

// OverlayIPAMReader reads the fabric allocations that authorize remote VTEPs.
// An address with no allocation is reported as ipam.ErrAllocationNotFound or
// ErrOverlayRecordNotFound; any other error is an outage.
type OverlayIPAMReader interface {
	GetAllocation(ctx context.Context, ip netip.Addr) (*ipam.Allocation, error)
	GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error)
}

// OverlayIPAMRefresher is implemented by an OverlayIPAMReader that caches the
// fabric allocations. The admission sweep refreshes it before each pass, and
// route admission refreshes it only to confirm a VTEP it would newly admit.
type OverlayIPAMRefresher interface {
	Refresh(ctx context.Context) error
}

// VTEPAdmissionConfig wires the production overlay VTEP admission policy.
type VTEPAdmissionConfig struct {
	IPAM     OverlayIPAMReader
	Devices  OverlayDeviceGetter
	Verdicts OverlayVerdictReader
	Revoker  OverlayVTEPRevoker
	Replayer OverlayVTEPReplayer
	// MaxVerdictAge bounds the age of an admitting verdict. Zero defaults to
	// DefaultOverlayVerdictMaxAge.
	MaxVerdictAge time.Duration
	// VerdictClockSkew bounds how far in the future an admitting verdict's
	// attestation time may lie. Zero defaults to
	// DefaultOverlayVerdictClockSkew.
	VerdictClockSkew time.Duration
	// ReadTimeout bounds the platform reads behind one admission decision,
	// and all the reads of one sweep together. A read still waiting when it
	// passes is an outage. Zero defaults to DefaultOverlayAdmissionReadTimeout.
	ReadTimeout time.Duration
	Now         func() time.Time
	Logger      *slog.Logger
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
	replayer      OverlayVTEPReplayer
	maxVerdictAge time.Duration
	clockSkew     time.Duration
	readTimeout   time.Duration
	now           func() time.Time
	logger        *slog.Logger

	mu         sync.Mutex
	admitted   map[netip.Addr]admissionRecord
	generation uint64
	// heldFailures holds, per device, the stream's latest failed verdict.
	// platformd streams a verdict before its report shows it, so admission
	// denies the device until it reads a report attested after that time.
	heldFailures map[uint64]heldFailure
	// failureEpoch numbers the failed verdicts streamed for any device, so
	// an epoch never repeats, even after a failure is dropped.
	failureEpoch uint64
	// ownershipStale is set while the latest IPAM refresh failed: the index
	// may name a device that no longer holds the address, so no admission
	// read from it renews an admitted VTEP.
	ownershipStale atomic.Bool
	// listings tracks the IPAM listings OnDeviceVerdict leaves running for
	// failed devices.
	listings sync.WaitGroup
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
	if cfg.Replayer == nil {
		return nil, ErrOverlayAdmissionConfig{Field: "replayer", Reason: "nil"}
	}
	if cfg.MaxVerdictAge < 0 {
		return nil, ErrOverlayAdmissionConfig{Field: "max_verdict_age", Reason: "negative"}
	}
	if cfg.VerdictClockSkew < 0 {
		return nil, ErrOverlayAdmissionConfig{Field: "verdict_clock_skew", Reason: "negative"}
	}
	if cfg.ReadTimeout < 0 {
		return nil, ErrOverlayAdmissionConfig{Field: "read_timeout", Reason: "negative"}
	}
	if cfg.MaxVerdictAge == 0 {
		cfg.MaxVerdictAge = DefaultOverlayVerdictMaxAge
	}
	if cfg.VerdictClockSkew == 0 {
		cfg.VerdictClockSkew = DefaultOverlayVerdictClockSkew
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = DefaultOverlayAdmissionReadTimeout
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
		replayer:      cfg.Replayer,
		maxVerdictAge: cfg.MaxVerdictAge,
		clockSkew:     cfg.VerdictClockSkew,
		readTimeout:   cfg.ReadTimeout,
		now:           cfg.Now,
		logger:        cfg.Logger,
		admitted:      make(map[netip.Addr]admissionRecord),
		heldFailures:  make(map[uint64]heldFailure),
	}, nil
}

// AdmitVTEP implements modes.VTEPAdmitter: vtep may carry vni when its fabric
// allocation, its device record and its device's latest verdict all pass the
// policy. An admission is remembered and a denial forgets any earlier one. An
// outage refuses the route but leaves the earlier admission for the sweep to
// judge.
//
// A caching IPAM reader can still hold an address IPAM has since given to
// another device, so a decision that would newly admit the VTEP, or admit it
// for another device, is made again against a fresh listing. So is any
// admission while the latest IPAM refresh has failed, so a route cannot renew
// an admission from an allocation nobody could re-validate. A denial needs no
// listing: refusing on a stale allocation fails closed, and the sweep judges
// every refused VTEP again.
//
// A failed verdict streamed while the decision was in flight refuses it when
// it is published, unless the decision rests on a report attested after
// that failure.
func (a *VTEPAdmitter) AdmitVTEP(ctx context.Context, vni uint32, vtep netip.Addr) error {
	reads, cancel := a.platformReads(ctx)
	defer cancel()

	evaluated, err := a.evaluate(reads, vni, vtep)
	if err == nil && (a.ownershipStale.Load() || !a.admittedFor(vtep, evaluated.admitted.DeviceID)) {
		evaluated, err = a.confirm(reads, vni, vtep, evaluated)
	}
	if err == nil {
		return a.remember(vni, *evaluated)
	}
	if isOverlayAdmissionDeny(err) {
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
// MaxVerdictAge. The same bound holds when only the IPAM refresh fails: a
// newer passing verdict read against the stale index renews nothing. Every
// VTEP the overlay refused is judged again too, and its
// routes replayed once the policy admits it, so a device whose passing
// verdict was missed is still brought up; a sweep whose IPAM refresh failed
// replays nothing. Admissions of VTEPs no longer
// installed are forgotten. Sweep continues past failures and returns them
// joined.
func (a *VTEPAdmitter) Sweep(ctx context.Context, installed []modes.InstalledVTEP) error {
	a.mu.Lock()
	a.generation++
	generation := a.generation
	a.mu.Unlock()

	// The platform reads share one deadline, so a platformd that accepts a
	// read and never answers ends the sweep as an outage before the next
	// tick. Revocation is local and keeps the live ctx: it must not wait on
	// the platform it is protecting against.
	reads, cancel := a.platformReads(ctx)
	defer cancel()

	var errs []error
	refreshErr := a.refreshIPAM(reads)
	if refreshErr != nil {
		errs = append(errs, refreshErr)
	}
	// judged holds whether each installed VTEP was admitted, so a VTEP both
	// installed and refused is not judged twice.
	judged := make(map[netip.Addr]bool, len(installed))
	for _, vtep := range installed {
		admitted, err := a.sweepVTEP(ctx, reads, vtep.VTEP, refreshErr)
		judged[vtep.VTEP] = admitted
		if err != nil {
			errs = append(errs, err)
		}
	}
	// A replay installs decap flows, so it rests on a fresh listing: without
	// one the refused VTEPs stay refused until a sweep that has one.
	for _, vtep := range a.refusedToJudge(refreshErr) {
		var err error
		admitted, ok := judged[vtep]
		switch {
		case !ok:
			err = a.readmit(reads, vtep)
		case admitted:
			err = a.replay(reads, vtep)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}

	// An admission made since the sweep began belongs to a route that
	// installed after the snapshot of installed VTEPs was taken.
	a.mu.Lock()
	for vtep, record := range a.admitted {
		if _, ok := judged[vtep]; !ok && record.generation < generation {
			delete(a.admitted, vtep)
		}
	}
	a.mu.Unlock()
	a.dropOutlastedFailures()
	return errors.Join(errs...)
}

// sweepVTEP re-judges an installed VTEP and reports whether the policy
// admitted it.
func (a *VTEPAdmitter) sweepVTEP(ctx, reads context.Context, vtep netip.Addr, refreshErr error) (bool, error) {
	evaluated, err := a.evaluate(reads, 0, vtep)
	if err == nil && refreshErr != nil {
		return false, a.holdUnvalidated(ctx, vtep, evaluated.admitted.DeviceID, refreshErr)
	}
	if err == nil {
		if err = a.remember(0, *evaluated); err == nil {
			return true, nil
		}
	}
	if !isOverlayAdmissionDeny(err) && a.verdictStillFresh(vtep) {
		return false, err
	}
	a.logger.Warn("overlay: revoking a VTEP the admission policy no longer admits",
		slog.String("vtep", vtep.String()), slog.Any("error", err))
	return false, a.revoke(ctx, vtep)
}

// holdUnvalidated judges an installed VTEP that passed admission on an
// allocation the sweep's failed IPAM refresh could not re-validate. The pass
// renews nothing: the VTEP keeps its last fully validated admission for the
// same device until that verdict is older than verdict-max-age, and is
// revoked after that. refreshErr is already in the sweep's error.
func (a *VTEPAdmitter) holdUnvalidated(ctx context.Context, vtep netip.Addr, deviceID uint64, refreshErr error) error {
	if a.admittedFor(vtep, deviceID) && a.verdictStillFresh(vtep) {
		return nil
	}
	a.logger.Warn("overlay: revoking a VTEP whose last validated admission lapsed while IPAM is unavailable",
		slog.String("vtep", vtep.String()), slog.Any("error", refreshErr))
	return a.revoke(ctx, vtep)
}

// OnDeviceVerdict withdraws every VTEP of a device whose verdict failed,
// whether cryptographically or for an absence of evidence: either way the
// policy no longer admits it, and waiting for the sweep would leave its decap
// state in place for up to a sweep interval. A passed verdict replays the
// routes of the device's refused VTEPs, which BGP will not send again, so a
// device attested after its routes arrived is admitted without waiting for
// the sweep.
//
// A failed verdict is also held against the device: admission denies it
// until the platform's report of the device was attested after the failure
// was recorded. Without the hold, a report that does not show the failure
// yet would let the device straight back in.
//
// The VTEPs this gatewayd admitted for a failed device are withdrawn before
// OnDeviceVerdict returns; they need no platform read. The device's other
// fabric allocations come from an IPAM listing that runs beside the caller,
// so the verdict follower never waits on IPAM and the next failure is
// withdrawn while the listing is still pending. The listing ends with ctx;
// the held failure leaves anything it did not reach to the sweep.
func (a *VTEPAdmitter) OnDeviceVerdict(ctx context.Context, recorded deviceverdict.RecordedDeviceVerdict) {
	v := recorded.Verdict
	if v.Passed {
		if err := a.readmitDevice(ctx, v.DeviceID); err != nil {
			a.logger.Warn("overlay: admitting a device that passed attestation did not complete; the sweep retries it",
				slog.Uint64("device_id", v.DeviceID),
				slog.Any("error", err))
		}
		return
	}
	failedAt := a.holdFailure(v.DeviceID, recorded.RecordedAt)
	a.logger.Warn("overlay: withdrawing a device whose attestation failed",
		slog.Uint64("device_id", v.DeviceID),
		slog.Bool("cryptographic", v.Cryptographic),
		slog.String("reason", v.Reason))
	withdrawn, err := a.revokeAdmitted(ctx, v.DeviceID)
	a.warnIncompleteWithdrawal(v.DeviceID, err)
	a.listings.Add(1)
	go func() {
		defer a.listings.Done()
		a.warnIncompleteWithdrawal(v.DeviceID, a.revokeAllocated(ctx, v.DeviceID, withdrawn, failedAt))
	}()
}

// warnIncompleteWithdrawal logs a withdrawal that left VTEPs of a failed
// device in place, if err says one did.
func (a *VTEPAdmitter) warnIncompleteWithdrawal(deviceID uint64, err error) {
	if err == nil {
		return
	}
	a.logger.Warn("overlay: withdrawing the device did not complete; the sweep retries it",
		slog.Uint64("device_id", deviceID),
		slog.Any("error", err))
}

// waitListings returns once every IPAM listing OnDeviceVerdict started has
// ended. The verdict follower waits on it before returning, so stopping the
// follower stops the listings too.
func (a *VTEPAdmitter) waitListings() {
	a.listings.Wait()
}

// RevokeDevice withdraws every VTEP of the device: first those admitted for
// it, which needs no platform read, then its fabric allocations. It continues
// past a VTEP whose withdrawal fails, and past an IPAM outage, and returns the
// failures joined. Only an allocation admitted again on a verdict recorded
// after the call began is left in place.
func (a *VTEPAdmitter) RevokeDevice(ctx context.Context, deviceID uint64) error {
	since := a.now()
	withdrawn, err := a.revokeAdmitted(ctx, deviceID)
	return errors.Join(err, a.revokeAllocated(ctx, deviceID, withdrawn, since))
}

// revokeAdmitted withdraws the VTEPs this gatewayd admitted for the device
// and returns them. It reads nothing from platformd, so a hung platform
// cannot delay it.
func (a *VTEPAdmitter) revokeAdmitted(ctx context.Context, deviceID uint64) (map[netip.Addr]struct{}, error) {
	withdrawn := make(map[netip.Addr]struct{})
	a.mu.Lock()
	for vtep, record := range a.admitted {
		if record.vtep.DeviceID == deviceID {
			withdrawn[vtep] = struct{}{}
		}
	}
	a.mu.Unlock()

	var errs []error
	for vtep := range withdrawn {
		if err := a.revoke(ctx, vtep); err != nil {
			errs = append(errs, err)
		}
	}
	return withdrawn, errors.Join(errs...)
}

// revokeAllocated withdraws the device's fabric allocations that
// revokeAdmitted did not: VTEPs installed without this gatewayd's admission,
// such as those admitted before it restarted. Only the listing waits on
// platformd; the revocations keep the live ctx. An allocation admitted again
// while the listing ran is skipped only when its verdict was recorded after
// since, the failure that started the withdrawal: an admission judged on an
// older verdict is no evidence the device has recovered.
func (a *VTEPAdmitter) revokeAllocated(ctx context.Context, deviceID uint64, withdrawn map[netip.Addr]struct{}, since time.Time) error {
	reads, cancel := a.platformReads(ctx)
	allocations, err := a.ipam.GetAllocationsByDevice(reads, strconv.FormatUint(deviceID, 10))
	cancel()
	if err != nil {
		return ErrOverlayAdmissionUnavailable{DeviceID: deviceID, Source: "ipam", Cause: err}
	}
	var errs []error
	for _, allocation := range allocations {
		if allocation == nil || !allocation.IP.IsValid() || allocation.Zone != string(zone.ZoneFabric) {
			continue
		}
		if _, done := withdrawn[allocation.IP]; done || a.admittedSince(allocation.IP, deviceID, since) {
			continue
		}
		if err := a.revoke(ctx, allocation.IP); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// readmitDevice replays the refused VTEPs among the device's fabric
// allocations. It continues past a VTEP that fails and returns the failures
// joined.
func (a *VTEPAdmitter) readmitDevice(ctx context.Context, deviceID uint64) error {
	refused := a.replayer.RefusedVTEPs()
	if len(refused) == 0 {
		return nil
	}
	reads, cancel := a.platformReads(ctx)
	defer cancel()

	if err := a.refreshIPAM(reads); err != nil {
		return err
	}
	allocations, err := a.ipam.GetAllocationsByDevice(reads, strconv.FormatUint(deviceID, 10))
	if err != nil {
		return ErrOverlayAdmissionUnavailable{DeviceID: deviceID, Source: "ipam", Cause: err}
	}
	var errs []error
	for _, allocation := range allocations {
		if allocation == nil || !slices.Contains(refused, allocation.IP) {
			continue
		}
		if err := a.readmit(reads, allocation.IP); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// readmit replays the routes of a refused VTEP once the policy admits it; the
// replayed routes are admitted, and remembered, as any route is. A VTEP the
// policy still denies stays refused, which is not a failure.
func (a *VTEPAdmitter) readmit(ctx context.Context, vtep netip.Addr) error {
	_, err := a.evaluate(ctx, 0, vtep)
	if isOverlayAdmissionDeny(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return a.replay(ctx, vtep)
}

func (a *VTEPAdmitter) replay(ctx context.Context, vtep netip.Addr) error {
	if err := a.replayer.ReplayVTEP(ctx, vtep); err != nil {
		return ErrOverlayVTEPReplay{VTEP: vtep, Cause: err}
	}
	return nil
}

func (a *VTEPAdmitter) revoke(ctx context.Context, vtep netip.Addr) error {
	a.forget(vtep)
	if err := a.revoker.RevokeVTEP(ctx, vtep); err != nil {
		return ErrOverlayVTEPRevoke{VTEP: vtep, Cause: err}
	}
	return nil
}

// confirm judges vtep again after refreshing a caching IPAM reader, so the
// admission rests on the address's current holder. A reader that does not
// cache reads platformd every time, and the evaluation already stands.
func (a *VTEPAdmitter) confirm(ctx context.Context, vni uint32, vtep netip.Addr, evaluated *evaluation) (*evaluation, error) {
	refresher, ok := a.ipam.(OverlayIPAMRefresher)
	if !ok {
		return evaluated, nil
	}
	if err := a.relist(ctx, refresher); err != nil {
		return nil, ErrOverlayAdmissionUnavailable{VTEP: vtep, Source: "ipam", Cause: err}
	}
	return a.evaluate(ctx, vni, vtep)
}

// refreshIPAM refreshes a caching IPAM reader. A reader that does not cache
// reads platformd every time and is always fresh.
// platformReads bounds the platformd reads behind one admission decision, or
// behind one whole sweep. A platformd that accepts a read and never answers
// then fails it with the deadline, which evaluate reports as an outage, so
// the outage rules decide the VTEP instead of a read that never returns.
func (a *VTEPAdmitter) platformReads(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, a.readTimeout)
}

func (a *VTEPAdmitter) refreshIPAM(ctx context.Context) error {
	refresher, ok := a.ipam.(OverlayIPAMRefresher)
	if !ok {
		return nil
	}
	if err := a.relist(ctx, refresher); err != nil {
		return ErrOverlayAdmissionUnavailable{Source: "ipam", Cause: err}
	}
	return nil
}

// relist refreshes the IPAM index and records whether the ownership it
// holds is now validated or stale.
func (a *VTEPAdmitter) relist(ctx context.Context, refresher OverlayIPAMRefresher) error {
	err := refresher.Refresh(ctx)
	a.ownershipStale.Store(err != nil)
	return err
}

// refusedToJudge lists the refused VTEPs a sweep may replay: none when its
// IPAM refresh failed, since a cached allocation may name a device that no
// longer holds the address.
func (a *VTEPAdmitter) refusedToJudge(refreshErr error) []netip.Addr {
	if refreshErr != nil {
		return nil
	}
	return a.replayer.RefusedVTEPs()
}

// heldFailure is the latest failed verdict held against a device: when it
// was recorded, and the epoch of the last failure streamed for the device.
type heldFailure struct {
	at    time.Time
	epoch uint64
}

// holdFailure holds a failed verdict recorded at failedAt against the device,
// keeping the latest failure, and returns the time it was held from. An event
// with no recording time is held from the gateway's own clock. Every failure
// takes a new epoch, even one older than the failure already held, so an
// admission judged before it cannot be published after it.
func (a *VTEPAdmitter) holdFailure(deviceID uint64, failedAt time.Time) time.Time {
	if failedAt.IsZero() {
		failedAt = a.now()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failureEpoch++
	held, ok := a.heldFailures[deviceID]
	if !ok || failedAt.After(held.at) {
		held.at = failedAt
	}
	held.epoch = a.failureEpoch
	a.heldFailures[deviceID] = held
	return failedAt
}

// failureHeld reports whether a failed verdict held against the device is
// newer than a report attested at attestedAt, and the epoch of the failure
// it found, 0 for none. A newer report has caught up with the failure and
// releases the hold, whatever it says.
func (a *VTEPAdmitter) failureHeld(deviceID uint64, attestedAt time.Time) (bool, uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	held, ok := a.heldFailures[deviceID]
	if !ok {
		return false, 0
	}
	if attestedAt.After(held.at) {
		delete(a.heldFailures, deviceID)
		return false, held.epoch
	}
	return true, held.epoch
}

// dropOutlastedFailures forgets the failures every report they could still
// shadow is too old to admit by now.
func (a *VTEPAdmitter) dropOutlastedFailures() {
	cutoff := a.now().Add(-a.maxVerdictAge - a.clockSkew)
	a.mu.Lock()
	defer a.mu.Unlock()
	for deviceID, held := range a.heldFailures {
		if held.at.Before(cutoff) {
			delete(a.heldFailures, deviceID)
		}
	}
}

// admittedFor reports whether vtep is remembered as admitted for deviceID.
func (a *VTEPAdmitter) admittedFor(vtep netip.Addr, deviceID uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	record, ok := a.admitted[vtep]
	return ok && record.vtep.DeviceID == deviceID
}

// admittedSince reports whether vtep is remembered as admitted for deviceID
// on a verdict recorded after since.
func (a *VTEPAdmitter) admittedSince(vtep netip.Addr, deviceID uint64, since time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	record, ok := a.admitted[vtep]
	return ok && record.vtep.DeviceID == deviceID && record.vtep.VerdictAt.After(since)
}

// remember publishes an admission, unless a failed verdict was held against
// the device after the admission was judged and the admission's verdict is
// not newer than that failure. The check and the publication share a.mu
// with holdFailure, so a failure either sees the admission and withdraws it,
// or the admission sees the failure and is refused. A refusal leaves the
// device's other admissions to the failure's withdrawal.
func (a *VTEPAdmitter) remember(vni uint32, evaluated evaluation) error {
	admitted := evaluated.admitted
	a.mu.Lock()
	defer a.mu.Unlock()
	held, ok := a.heldFailures[admitted.DeviceID]
	if ok && held.epoch != evaluated.failureEpoch && !admitted.VerdictAt.After(held.at) {
		return ErrOverlayVTEPVerdict{VTEP: admitted.VTEP, DeviceID: admitted.DeviceID, VNI: vni,
			Reason: "a failed verdict was streamed while the admission was judged"}
	}
	a.admitted[admitted.VTEP] = admissionRecord{vtep: admitted, generation: a.generation}
	return nil
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

// evaluation is an admission the policy granted, with the epoch of the
// failure held against the device when it was judged, 0 for none. remember
// compares that epoch to tell a failure streamed while the admission was in
// flight.
type evaluation struct {
	admitted     AdmittedVTEP
	failureEpoch uint64
}

// evaluate applies the admission policy to vtep. A denial is one of the
// ErrOverlayVTEP* types; a platform read failure is
// ErrOverlayAdmissionUnavailable.
func (a *VTEPAdmitter) evaluate(ctx context.Context, vni uint32, vtep netip.Addr) (*evaluation, error) {
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
		// A failed verdict platformd streamed is a judgement no report read
		// can overturn until a newer pass arrives, so it refuses the VTEP
		// even while the report cannot be read.
		if held, _ := a.failureHeld(deviceID, time.Time{}); held {
			return nil, ErrOverlayVTEPVerdict{VTEP: vtep, DeviceID: deviceID, VNI: vni,
				Reason: "a failed verdict was streamed and no newer report can be read", Cause: err}
		}
		return nil, ErrOverlayAdmissionUnavailable{VTEP: vtep, DeviceID: deviceID, Source: "verdict", Cause: err}
	}
	held, failureEpoch := a.failureHeld(deviceID, recorded.RecordedAt)
	if held {
		return nil, ErrOverlayVTEPVerdict{VTEP: vtep, DeviceID: deviceID, VNI: vni,
			Reason: "a failed verdict was streamed after the latest report was attested"}
	}
	if reason := a.verdictRefusal(recorded, device); reason != "" {
		return nil, ErrOverlayVTEPVerdict{VTEP: vtep, DeviceID: deviceID, VNI: vni, Reason: reason}
	}
	return &evaluation{
		admitted: AdmittedVTEP{
			VTEP:           vtep,
			DeviceID:       deviceID,
			HostID:         recorded.Verdict.HostID,
			Serial:         recorded.Verdict.Serial,
			Hostname:       device.Hostname,
			AllocationID:   allocation.ID,
			BaselineSource: recorded.Verdict.BaselineSource,
			ProfileID:      recorded.Verdict.ProfileID,
			VerdictAt:      recorded.RecordedAt,
		},
		failureEpoch: failureEpoch,
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

// ErrOverlayVTEPReplay reports an admitted VTEP whose refused routes could
// not be replayed into the overlay.
type ErrOverlayVTEPReplay struct {
	VTEP  netip.Addr
	Cause error
}

func (e ErrOverlayVTEPReplay) Error() string {
	return "gateway overlay admission: replay VTEP " + e.VTEP.String() + ": " + e.Cause.Error()
}

func (e ErrOverlayVTEPReplay) Unwrap() error { return e.Cause }
