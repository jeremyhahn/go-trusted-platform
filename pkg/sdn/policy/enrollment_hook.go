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

package policy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strings"
	"sync"
	"time"

	devicedao "github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// EnrollmentEvent mirrors go-trusted-ca's OrderFinalizeHookContext
// This is a local type to avoid direct import dependency
type EnrollmentEvent struct {
	// Context is the request context
	Context context.Context

	// Certificate is the issued IDevID/certificate
	Certificate *x509.Certificate

	// CertificatePEM is the PEM-encoded certificate
	CertificatePEM []byte

	// ClientIP is the IP address of the enrolling device
	ClientIP string

	// IsTCGCSR indicates if this was a TCG-CSR-IDEVID enrollment
	IsTCGCSR bool

	// ProductModel is the device product model (only set if IsTCGCSR)
	ProductModel string

	// ProductSerial is the device serial number (only set if IsTCGCSR)
	ProductSerial string

	// PermanentIdentifier is the device permanent identifier
	PermanentIdentifier string
}

// EnrollmentHook is the function signature for enrollment callbacks
type EnrollmentHook func(event *EnrollmentEvent) error

// MACExtractor is a function type for extracting MAC addresses from IPs
// This allows for dependency injection during testing
type MACExtractor func(ipAddr string) string

// PortBinder is called after a device is successfully activated so that the
// OVS port name can be persisted on the device record. serial is the device
// serial number; portID is the real OVS tap/interface name resolved from the
// enrollment hook's MAC-to-port registry.
type PortBinder func(ctx context.Context, serial, portID string) error

// ActivationStatus is the outcome class of a completed activation.
type ActivationStatus string

const (
	// ActivationStatusActivated means the production policy was applied and
	// the port is authorized on the trusted network.
	ActivationStatusActivated ActivationStatus = "activated"
	// ActivationStatusQuarantined means a zone mismatch was detected and the
	// quarantine policy was applied and enforced; the port is isolated.
	ActivationStatusQuarantined ActivationStatus = "quarantined"
)

// ActivationResult reports what ActivateDevice actually did: the outcome
// status and the VLAN and zone applied to the port, read from the policy
// the engine applied — so a quarantined result carries the quarantine VLAN,
// never the trusted one. ZoneMismatch is set when the outcome is quarantine,
// for audit correlation.
type ActivationResult struct {
	Status       ActivationStatus
	PortID       string
	VLAN         uint16
	Zone         zone.Zone
	ZoneMismatch *ErrZoneMismatch
}

// PendingActivation stores pending activation data. PortID is empty when the
// device enrolled before attaching to the OVS fabric (no MAC-to-port mapping
// existed yet); in that case MAC is used to resolve the port at activation
// time, once a connect event has registered the mapping.
type PendingActivation struct {
	PortID      string
	MAC         string
	Profile     *entities.DeviceProfile
	Certificate *x509.Certificate
	EnrolledAt  time.Time
}

// serialLockStripes is the fixed number of per-serial lock stripes.
// Striping bounds the memory by construction regardless of how many
// distinct serials enroll or activate.
const serialLockStripes = 64

// SDNEnrollmentHook handles SDN network transitions on device enrollment
type SDNEnrollmentHook struct {
	mu                 sync.RWMutex
	logger             *slog.Logger
	policyEngine       PolicyEngine
	profileDAO         devicedao.DeviceProfileDAO
	portBinder         PortBinder        // Optional: called after successful activation to persist portID
	macToPort          map[string]string // MAC address to port ID mapping
	macExtractor       MACExtractor      // Pluggable MAC extraction function
	pendingActivations sync.Map          // serial -> *PendingActivation
	extractor          PolicyExtractor   // Optional: extracts zone from certificate extensions
	zones              []zone.ZoneConfig // Resolved zone set for quarantine resolution
	// serialLocks serializes enrollment completion and activation per
	// device serial via a fixed array of stripes indexed by an FNV-1a
	// hash of the serial. OnEnrollmentComplete acquires the stripe before
	// storing a pending activation, and activation callers hold it across
	// their whole precheck -> external side effects -> ActivateDevice
	// sequence (see LockSerial), so a re-enrollment can never replace the
	// pending record in the middle of an activation.
	serialLocks [serialLockStripes]sync.Mutex
}

// SDNEnrollmentHookConfig configures the enrollment hook
type SDNEnrollmentHookConfig struct {
	Logger       *slog.Logger
	PolicyEngine PolicyEngine
	ProfileDAO   devicedao.DeviceProfileDAO
	MACExtractor MACExtractor // Optional: defaults to ARP-based extraction
	// PortBinder is an optional callback invoked after a device is successfully
	// activated. It receives the device serial number and the real OVS port ID
	// so that the port can be stamped onto the device record for restart
	// survivability. When nil, the stamp step is skipped (useful in tests that
	// do not need persistence).
	PortBinder PortBinder
	// Extractor is an optional PolicyExtractor used to read the
	// OIDTPNetworkZone extension from issued certificates during zone
	// cross-check in buildPortPolicy. When nil, zone cross-check is skipped
	// and the profile zone is used unconditionally.
	Extractor PolicyExtractor
	// Zones is the resolved zone set used to determine the quarantine zone
	// when a zone mismatch is detected. When nil the default quarantine zone
	// name is used.
	Zones []zone.ZoneConfig
}

// NewSDNEnrollmentHook creates a new SDN enrollment hook
func NewSDNEnrollmentHook(config SDNEnrollmentHookConfig) (*SDNEnrollmentHook, error) {
	if config.PolicyEngine == nil {
		return nil, ErrInvalidPolicy
	}

	if config.ProfileDAO == nil {
		return nil, &MessageError{Msg: "profile DAO is required"}
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	hook := &SDNEnrollmentHook{
		logger:       logger,
		policyEngine: config.PolicyEngine,
		profileDAO:   config.ProfileDAO,
		portBinder:   config.PortBinder,
		macToPort:    make(map[string]string),
		extractor:    config.Extractor,
		zones:        config.Zones,
	}

	// Use provided MAC extractor or default to ARP-based extraction
	if config.MACExtractor != nil {
		hook.macExtractor = config.MACExtractor
	} else {
		hook.macExtractor = hook.extractMACFromARPTable
	}

	return hook, nil
}

// PolicyEngine returns the underlying policy engine
func (h *SDNEnrollmentHook) PolicyEngine() PolicyEngine {
	return h.policyEngine
}

// serialLock returns the lock stripe for the given device serial.
func (h *SDNEnrollmentHook) serialLock(serial string) *sync.Mutex {
	hasher := fnv.New32a()
	// fnv's Write never fails; the error return exists only to satisfy
	// hash.Hash's io.Writer embedding.
	if _, err := hasher.Write([]byte(serial)); err != nil {
		return &h.serialLocks[0]
	}
	return &h.serialLocks[hasher.Sum32()%serialLockStripes]
}

// LockSerial acquires the per-serial ordering lock and returns its unlock
// function. Enrollment completion takes it internally; an activation caller
// holds it across its whole precheck -> external side effects ->
// ActivateDevice sequence so that a concurrent re-enrollment for the same
// serial waits instead of replacing the pending activation mid-flight.
func (h *SDNEnrollmentHook) LockSerial(serial string) (unlock func()) {
	lock := h.serialLock(serial)
	lock.Lock()
	return lock.Unlock
}

// OnEnrollmentComplete implements the enrollment callback
// This can be registered with go-trusted-ca's OrderFinalizeHookRegistry
func (h *SDNEnrollmentHook) OnEnrollmentComplete(event *EnrollmentEvent) error {
	if event == nil {
		return &MessageError{Msg: "enrollment event is nil"}
	}

	if event.Certificate == nil {
		return ErrInvalidCertificate
	}

	// Serialize against activation for this serial: an activation caller
	// holds the same lock across precheck -> switch move -> ActivateDevice,
	// so this store can never land in the middle of that sequence.
	unlock := h.LockSerial(event.ProductSerial)
	defer unlock()

	h.logger.Info("processing enrollment completion",
		slog.String("client_ip", event.ClientIP),
		slog.String("serial", event.ProductSerial),
		slog.String("model", event.ProductModel),
		slog.Bool("is_tcg_csr", event.IsTCGCSR))

	// Try to find the device profile
	var profile *entities.DeviceProfile
	var err error

	// First try by serial number if available
	if event.ProductSerial != "" {
		profile, err = h.findProfileBySerial(event.ProductSerial)
		if err != nil {
			h.logger.Debug("profile not found by serial, trying MAC lookup",
				slog.String("serial", event.ProductSerial),
				slog.String("error", err.Error()))
		}
	}

	// If not found by serial, try by MAC address
	if profile == nil && event.ClientIP != "" {
		macAddr := h.macExtractor(event.ClientIP)
		if macAddr != "" {
			profile, err = h.findProfileByMAC(macAddr)
			if err != nil {
				h.logger.Warn("profile not found by MAC or serial",
					slog.String("mac", macAddr),
					slog.String("serial", event.ProductSerial),
					slog.String("error", err.Error()))
				return &WrappedError{Msg: "device profile not found", Err: err}
			}
		} else {
			h.logger.Warn("unable to extract MAC address from client IP",
				slog.String("client_ip", event.ClientIP))
			return &MessageError{Msg: "unable to identify device: no MAC or serial match"}
		}
	}

	if profile == nil {
		return &MessageError{Msg: fmt.Sprintf("device profile not found for serial=%s", event.ProductSerial)}
	}

	h.logger.Info("found device profile",
		slog.String("profile_name", profile.Name),
		slog.String("profile_id", fmt.Sprintf("%d", profile.ID)),
		slog.String("role", string(profile.Role)))

	// Extract MAC from IP for port lookup
	macAddr := h.macExtractor(event.ClientIP)
	if macAddr == "" {
		return &MessageError{Msg: fmt.Sprintf("unable to extract MAC address from IP %s", event.ClientIP)}
	}

	// Look up the port ID by MAC address. MAC-to-port mappings are created
	// only when a device attaches through the OVS fabric (connect-time
	// registration), so a device enrolling over the management LAN has no
	// port here. That is not an error: the certificate is issued on the
	// strength of the validated attestation, and the port transition is
	// deferred — the pending activation is recorded with the device MAC so
	// profile retrieval works and a later activation can resolve the port
	// once a connect event has registered it.
	portID, ok := h.GetPortByMAC(macAddr)
	if !ok {
		h.logger.Warn("port not registered for MAC address, deferring SDN port transition to connect-time assessment",
			slog.String("mac", macAddr),
			slog.String("serial", event.ProductSerial))
		h.pendingActivations.Store(event.ProductSerial, &PendingActivation{
			MAC:         macAddr,
			Profile:     profile,
			Certificate: event.Certificate,
			EnrolledAt:  time.Now(),
		})
		return nil
	}

	h.logger.Info("found port for device",
		slog.String("port_id", portID),
		slog.String("mac", macAddr))

	// Check current port state
	currentState, err := h.policyEngine.GetPortState(portID)
	if err != nil {
		h.logger.Debug("port state not found, will transition from provisioning",
			slog.String("port_id", portID))
	}

	// Transition from Provisioning to Enrolled
	// The device will remain in the enrollment VLAN until activated
	if err := h.policyEngine.SetPortState(portID, PortStateEnrolled); err != nil {
		h.logger.Error("failed to transition port to enrolled state",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
		return &WrappedError{Msg: "failed to transition port to enrolled state", Err: err}
	}

	// Store pending activation data for later retrieval
	pending := &PendingActivation{
		PortID:      portID,
		MAC:         macAddr,
		Profile:     profile,
		Certificate: event.Certificate,
		EnrolledAt:  time.Now(),
	}
	h.pendingActivations.Store(event.ProductSerial, pending)

	h.logger.Info("device enrolled successfully, awaiting activation",
		slog.String("port_id", portID),
		slog.String("previous_state", currentState.String()),
		slog.String("new_state", PortStateEnrolled.String()),
		slog.String("serial", event.ProductSerial))

	return nil
}

// GetPendingActivation retrieves and removes a pending activation by serial.
// A slot holding another activation's in-flight reservation is reported as
// absent and left untouched.
func (h *SDNEnrollmentHook) GetPendingActivation(serial string) (*PendingActivation, bool) {
	value, ok := h.pendingActivations.Load(serial)
	if !ok {
		return nil, false
	}
	pending, ok := value.(*PendingActivation)
	if !ok {
		return nil, false
	}
	if !h.pendingActivations.CompareAndDelete(serial, value) {
		// The record moved on between the load and the delete.
		return nil, false
	}
	return pending, true
}

// PeekPendingActivation retrieves a pending activation by serial without removing it.
// This is used by the device profile handler to return profile information.
// A slot holding an in-flight activation reservation is reported as absent.
func (h *SDNEnrollmentHook) PeekPendingActivation(serial string) (*PendingActivation, bool) {
	value, ok := h.pendingActivations.Load(serial)
	if !ok {
		return nil, false
	}
	pending, ok := value.(*PendingActivation)
	return pending, ok
}

// ActivationVLANs is the physical-switch move input snapshotted into an
// ActivationPlan at precheck time. The fields are value copies taken from
// the profile when the plan was issued, so a later in-place mutation of the
// profile (or of the pending record it hangs off) cannot desynchronize the
// physical switch move from the policy the plan carries.
type ActivationVLANs struct {
	// Trusted is the post-enrollment (trusted) network VLAN — the target
	// of the physical switch move on a clean activation.
	Trusted uint16
	// Provisioning is the enrollment-phase VLAN — the one fail-closed
	// revert target. Meaningful only when HasProvisioning is true.
	Provisioning uint16
	// HasProvisioning reports whether the profile declares an
	// enrollment-phase network at all; without one there is no fail-closed
	// revert target and the physical move must be refused.
	HasProvisioning bool
}

// ActivationPlan is an immutable reservation of one pending-activation
// version, produced by PrecheckActivation. It carries the exact pending
// record that was validated, the port policy built from it, and a
// value-copy snapshot of the physical-switch VLANs, so ActivateDevice and
// the caller's external side effects apply precisely what the precheck
// approved: a concurrent re-enrollment that replaces the pending record
// makes ActivateDevice fail with ErrPendingActivationSuperseded instead of
// activating a profile the caller never validated. The only implementation
// is the hook's own; ActivateDevice refuses a plan it did not produce.
type ActivationPlan interface {
	// Serial returns the device serial the plan reserves.
	Serial() string
	// VLANs returns the physical-switch move inputs snapshotted at
	// precheck time — value copies, immune to later mutation of the
	// profile they came from.
	VLANs() ActivationVLANs
	// ExpectQuarantine reports whether the plan's policy is the quarantine
	// policy: a zone mismatch was detected at precheck, so activating this
	// plan isolates the port instead of opening it.
	ExpectQuarantine() bool
	// ZoneMismatch returns the zone mismatch detected at precheck, or nil
	// when the zones matched and the plan's policy is the production policy.
	ZoneMismatch() *ErrZoneMismatch
}

// activationPlan is the hook's ActivationPlan implementation. inFlight is
// set by ActivateDevice when the plan's reservation is swapped for the
// in-flight marker; FinalizeActivation and ReinstateActivation act on that
// same marker.
type activationPlan struct {
	serial       string
	pending      *PendingActivation
	policy       *PortPolicy
	vlans        ActivationVLANs
	zoneMismatch *ErrZoneMismatch
	inFlight     *activationInFlight
}

func (p *activationPlan) Serial() string                 { return p.serial }
func (p *activationPlan) VLANs() ActivationVLANs         { return p.vlans }
func (p *activationPlan) ExpectQuarantine() bool         { return p.zoneMismatch != nil }
func (p *activationPlan) ZoneMismatch() *ErrZoneMismatch { return p.zoneMismatch }

// activationInFlight is the marker ActivateDevice swaps into
// pendingActivations while a consumed plan is being applied. It reserves
// the slot: a failed activation restores the reserved record only over its
// own marker, so a record stored by a concurrent re-enrollment (which
// overwrites the marker) is kept, and a slot that moved on in any other
// way is never overwritten with a stale record.
type activationInFlight struct {
	reserved *PendingActivation
}

// ActivateDevice consumes an ActivationPlan produced by PrecheckActivation
// and transitions the device from Enrolled to Authorized — or, on a plan
// carrying a zone mismatch, applies and enforces the quarantine policy —
// and stamps the OVS port ID onto the device record via the PortBinder
// callback (when set). The plan's pending-activation version is consumed
// atomically: if a concurrent re-enrollment replaced it since the precheck,
// nothing is applied and the error is ErrPendingActivationSuperseded. It
// returns an ActivationResult describing the outcome actually applied
// (status, VLAN, zone) — fixed by the plan's policy, so the outcome can
// never diverge from what the precheck reported. A quarantined outcome is a
// completed activation with a nil error; every failure is a typed error
// with nothing reported as done that did not happen, and the reservation is
// returned so the client can retry. On success the reservation stays held:
// the caller MUST complete the activation with FinalizeActivation once its
// own external commits succeed, or call ReinstateActivation when an
// external commit fails, so a transient failure after the SDN side was
// applied remains retryable without re-enrollment. This is called when the
// client explicitly requests activation via /device/activate.
func (h *SDNEnrollmentHook) ActivateDevice(plan ActivationPlan) (*ActivationResult, error) {
	if plan == nil {
		return nil, &MessageError{Msg: "nil activation plan"}
	}
	reserved, ok := plan.(*activationPlan)
	if !ok {
		return nil, &MessageError{Msg: "activation plan was not produced by this hook's PrecheckActivation"}
	}
	serial := reserved.serial

	// Atomically reserve exactly the pending-activation version the plan
	// carries by swapping in this activation's own in-flight marker. A
	// different stored record means a concurrent re-enrollment replaced it
	// after the precheck (or another activation holds the slot); an absent
	// one means it was already consumed. Either way nothing is applied.
	inFlight := &activationInFlight{reserved: reserved.pending}
	if !h.pendingActivations.CompareAndSwap(serial, reserved.pending, inFlight) {
		if _, exists := h.pendingActivations.Load(serial); exists {
			return nil, ErrPendingActivationSuperseded{Serial: serial}
		}
		return nil, ErrNoPendingActivation{Serial: serial}
	}
	pending := reserved.pending

	// Resolve a deferred port. A device that enrolled before attaching to
	// the OVS fabric carries no port ID; a connect event since enrollment may
	// have registered its MAC-to-port mapping. Without a known port there is
	// nothing to open — the activation fails closed and the pending
	// activation is retained for a later attempt. The pending record itself
	// is never mutated: PeekPendingActivation callers may hold a reference
	// to it concurrently.
	portID := pending.PortID
	if portID == "" {
		resolved, found := h.GetPortByMAC(pending.MAC)
		if !found {
			h.restoreReservation(serial, inFlight)
			return nil, ErrPortNotRegisteredForDevice{MAC: pending.MAC}
		}
		portID = resolved
	}

	h.logger.Info("activating device",
		slog.String("serial", serial),
		slog.String("port_id", portID),
		slog.String("profile", pending.Profile.Name))

	// The policy was built by PrecheckActivation from this same pending
	// record; a plan carrying a zone mismatch carries the quarantine policy.
	policy := reserved.policy
	zoneMismatch := reserved.zoneMismatch

	// Apply the policy — production on a clean zone check, quarantine on a
	// mismatch — and transition to Authorized
	if err := h.policyEngine.ApplyPolicy(portID, policy); err != nil {
		// Restore the pending activation since we failed
		h.restoreReservation(serial, inFlight)
		h.logger.Error("failed to apply policy during activation",
			slog.String("port_id", portID),
			slog.String("serial", serial),
			slog.String("error", err.Error()))
		return nil, &WrappedError{Msg: "failed to apply production policy", Err: err}
	}

	// A quarantine policy isolates the port on the quarantine VLAN; the
	// engine leaves the port authorized after ApplyPolicy, so record the
	// state honestly. If the state cannot be marked, the datapath isolation
	// stays (the safe direction) but the recorded state disagrees with
	// reality: that is an indeterminate outcome, never a reported
	// quarantine. The pending activation is retained.
	if zoneMismatch != nil {
		if stateErr := h.policyEngine.SetPortState(portID, PortStateQuarantined); stateErr != nil {
			h.restoreReservation(serial, inFlight)
			err := ErrQuarantineStateIndeterminate{PortID: portID, Serial: serial, Cause: stateErr}
			h.logger.Error(err.Error(),
				slog.String("port_id", portID),
				slog.String("serial", serial))
			return nil, err
		}
	}

	// Port zone application: SC-7 (boundary), AC-4 (flow enforcement).
	h.logger.Info("successfully activated device",
		slog.String("port_id", portID),
		slog.String("serial", serial),
		slog.Uint64("vlan", uint64(policy.VLAN)),
		slog.String("zone", string(policy.Zone)),
		slog.String("tenant_id", policy.TenantID),
		complianceAttr(complianceSC7, complianceAC4))

	// Stamp the real OVS port ID onto the device record so it survives
	// daemon restarts. The binder is optional; when nil (e.g. in unit tests)
	// the stamp step is skipped.
	if h.portBinder != nil {
		ctx := context.Background()
		if err := h.portBinder(ctx, serial, portID); err != nil {
			// Log the failure but do not roll back the policy application —
			// the device is on the correct VLAN. The missing stamp means the
			// quarantine observer will warn and skip on next restart, which is
			// safer than leaving the device in an ambiguous policy state.
			h.logger.Warn("failed to stamp network port ID on device record",
				slog.String("serial", serial),
				slog.String("port_id", portID),
				slog.String("error", err.Error()))
		}
	}

	// The in-flight reservation is deliberately NOT released here: the
	// caller completes the activation with FinalizeActivation once its own
	// external commits (the physical switch move) succeed, or returns the
	// plan to a retryable state with ReinstateActivation when an external
	// commit fails after the SDN side was applied. The marker is stamped on
	// the plan only on this success path — after a failed activation (whose
	// reservation was already restored above) both calls are no-ops.
	reserved.inFlight = inFlight

	// Report exactly what was applied: policy.VLAN is populated by the
	// engine from the resolved zone on the zone path, so a quarantined
	// result carries the quarantine VLAN.
	result := &ActivationResult{
		Status:       ActivationStatusActivated,
		PortID:       portID,
		VLAN:         policy.VLAN,
		Zone:         policy.Zone,
		ZoneMismatch: zoneMismatch,
	}
	if zoneMismatch != nil {
		result.Status = ActivationStatusQuarantined
	}
	return result, nil
}

// restoreReservation returns the reserved pending activation to the map
// after a failed activation — but only over this activation's own in-flight
// marker. A record stored by a concurrent re-enrollment overwrites the
// marker and is kept in preference to the stale one, and a slot that moved
// on in any other way (consumed, cleared) is never overwritten — a stale
// record can never be resurrected into an empty slot.
func (h *SDNEnrollmentHook) restoreReservation(serial string, inFlight *activationInFlight) {
	h.pendingActivations.CompareAndSwap(serial, inFlight, inFlight.reserved)
}

// FinalizeActivation completes a successful ActivateDevice by releasing the
// plan's in-flight reservation. Callers invoke it after every external
// commit tied to the activation (the physical switch move) has succeeded —
// or immediately for an activation with no external commits. A reservation
// that is no longer in place means a concurrent re-enrollment overwrote it
// while the activation was in flight — the newer record is kept for the
// next activation, and the overlap is alarmed because it can only happen to
// a caller that did not hold LockSerial. A plan that never reached a
// successful ActivateDevice is a no-op.
func (h *SDNEnrollmentHook) FinalizeActivation(plan ActivationPlan) {
	reserved, ok := plan.(*activationPlan)
	if !ok || reserved == nil || reserved.inFlight == nil {
		return
	}
	if !h.pendingActivations.CompareAndDelete(reserved.serial, reserved.inFlight) {
		h.logger.Warn("pending activation replaced while an activation was in flight — keeping the newer record; the caller did not hold the serial lock",
			slog.String("serial", reserved.serial))
	}
}

// ReinstateActivation returns a successfully activated plan's pending
// record to the map after a FAILED external commit (e.g. the physical
// switch move), so the client can retry activation without re-enrolling:
// the next precheck sees the same pending record and issues a fresh plan.
// The restore lands only over this activation's own in-flight marker — a
// record stored by a concurrent re-enrollment is kept in preference, and a
// slot that moved on in any other way is never overwritten. A plan that
// never reached a successful ActivateDevice is a no-op. Callers hold
// LockSerial across the whole sequence, exactly as for the activation
// itself.
func (h *SDNEnrollmentHook) ReinstateActivation(plan ActivationPlan) {
	reserved, ok := plan.(*activationPlan)
	if !ok || reserved == nil || reserved.inFlight == nil {
		return
	}
	h.restoreReservation(reserved.serial, reserved.inFlight)
}

// PrecheckActivation validates that ActivateDevice can proceed for the
// given serial without performing any state change: the pending activation
// must exist, its port must be resolvable, and a policy must be buildable
// from the profile. On success it returns an ActivationPlan reserving the
// exact pending-activation version and policy that were validated — a zone
// mismatch is not an error but an expected outcome recorded on the plan
// (ExpectQuarantine), because activating such a plan applies the
// enforceable quarantine policy. Errors are ErrNoPendingActivation,
// ErrPortNotRegisteredForDevice, a typed policy-build failure (e.g. no
// quarantine VLAN for a mismatched zone), or a MessageError when no policy
// can be built from the profile. Callers use the plan to order external
// side effects — such as a physical switch VLAN move — after validation,
// deriving every VLAN from the plan's snapshot (VLANs), and then pass the
// same plan to ActivateDevice, holding LockSerial across the whole sequence
// so a concurrent re-enrollment cannot replace the record mid-flight. No
// port state, policy, or pending-activation mutation occurs here.
func (h *SDNEnrollmentHook) PrecheckActivation(serial string) (ActivationPlan, error) {
	pending, ok := h.PeekPendingActivation(serial)
	if !ok || pending == nil {
		return nil, ErrNoPendingActivation{Serial: serial}
	}

	if pending.PortID == "" {
		if _, found := h.GetPortByMAC(pending.MAC); !found {
			return nil, ErrPortNotRegisteredForDevice{MAC: pending.MAC}
		}
	}

	policy, policyErr := h.buildPortPolicy(pending.Profile, pending.Certificate)
	if policy == nil {
		// A typed cause (e.g. no quarantine VLAN for a zone mismatch) is
		// surfaced as-is.
		if policyErr != nil {
			return nil, policyErr
		}
		return nil, &MessageError{Msg: "unable to build port policy from profile"}
	}

	// Snapshot the physical-switch move inputs as value copies: a later
	// in-place mutation of the profile cannot change what the caller
	// commits to the switch.
	vlans := ActivationVLANs{}
	if prodNet := pending.Profile.GetPostEnrollmentNetworkConfig(); prodNet != nil {
		vlans.Trusted = prodNet.VLAN
	}
	if provNet := pending.Profile.GetEnrollmentNetworkConfig(); provNet != nil {
		vlans.Provisioning = provNet.VLAN
		vlans.HasProvisioning = true
	}

	plan := &activationPlan{serial: serial, pending: pending, policy: policy, vlans: vlans}
	if policyErr != nil {
		// With a non-nil policy the only possible policyErr is a zone
		// mismatch: the policy is a quarantine policy. Anything else is
		// a contract violation and fails closed.
		var mismatch ErrZoneMismatch
		if !errors.As(policyErr, &mismatch) {
			return nil, policyErr
		}
		plan.zoneMismatch = &mismatch
	}
	return plan, nil
}

// RegisterPort maps a MAC address to a port ID for later lookup
func (h *SDNEnrollmentHook) RegisterPort(mac string, portID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Normalize MAC address to lowercase with colons
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")

	h.macToPort[mac] = portID

	h.logger.Debug("registered port mapping",
		slog.String("mac", mac),
		slog.String("port_id", portID))
}

// GetPortByMAC returns the port ID for a given MAC address
func (h *SDNEnrollmentHook) GetPortByMAC(mac string) (string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Normalize MAC address
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")

	portID, ok := h.macToPort[mac]
	return portID, ok
}

// extractMACFromARPTable attempts to look up the MAC address from the ARP table
// Uses pure Go implementation by reading /proc/net/arp directly
// Returns empty string if not found. This is the default MAC extractor.
func (h *SDNEnrollmentHook) extractMACFromARPTable(ipAddr string) string {
	if ipAddr == "" {
		return ""
	}

	// Use the pure Go ARP table implementation
	table := arp.NewTable()
	mac, err := table.LookupMAC(ipAddr)
	if err != nil {
		h.logger.Debug("MAC address not found in ARP table",
			slog.String("ip", ipAddr),
			slog.String("error", err.Error()))
		return ""
	}

	h.logger.Debug("extracted MAC from ARP table",
		slog.String("ip", ipAddr),
		slog.String("mac", mac.String()))
	return mac.String()
}

// findProfileBySerial looks up a device profile by serial number
func (h *SDNEnrollmentHook) findProfileBySerial(serial string) (*entities.DeviceProfile, error) {
	if serial == "" {
		return nil, &MessageError{Msg: "serial number is empty"}
	}

	// Search all profiles using ForEachPage
	var foundProfile *entities.DeviceProfile
	ctx := context.Background()

	err := h.profileDAO.ForEachPage(
		ctx,
		datastore.PageQuery{
			Page:     1,
			PageSize: 100,
		},
		func(result datastore.PageResult[*entities.DeviceProfile]) error {
			for _, profile := range result.Entities {
				if profile.MatchRules != nil && !profile.MatchRules.IsEmpty() {
					if profile.MatchRules.Matches("", serial, "") {
						h.logger.Debug("found profile by serial",
							slog.String("serial", serial),
							slog.String("profile", profile.Name))
						foundProfile = profile
						// Return stop iteration to stop
						return datastore.ErrStopIteration
					}
				}
			}
			return nil
		},
	)

	if foundProfile != nil {
		return foundProfile, nil
	}

	if err != nil {
		return nil, &WrappedError{Msg: "failed to search profiles", Err: err}
	}

	return nil, &MessageError{Msg: fmt.Sprintf("no profile found for serial: %s", serial)}
}

// findProfileByMAC looks up a device profile by MAC prefix
func (h *SDNEnrollmentHook) findProfileByMAC(mac string) (*entities.DeviceProfile, error) {
	if mac == "" {
		return nil, &MessageError{Msg: "MAC address is empty"}
	}

	// Normalize MAC address
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, "-", ":")

	// Search all profiles using ForEachPage
	var foundProfile *entities.DeviceProfile
	ctx := context.Background()

	err := h.profileDAO.ForEachPage(
		ctx,
		datastore.PageQuery{
			Page:     1,
			PageSize: 100,
		},
		func(result datastore.PageResult[*entities.DeviceProfile]) error {
			for _, profile := range result.Entities {
				if profile.MatchRules != nil && !profile.MatchRules.IsEmpty() {
					if profile.MatchRules.Matches(mac, "", "") {
						h.logger.Debug("found profile by MAC",
							slog.String("mac", mac),
							slog.String("profile", profile.Name))
						foundProfile = profile
						// Return stop iteration to stop
						return datastore.ErrStopIteration
					}
				}
			}
			return nil
		},
	)

	if foundProfile != nil {
		return foundProfile, nil
	}

	if err != nil {
		return nil, &WrappedError{Msg: "failed to search profiles", Err: err}
	}

	return nil, &MessageError{Msg: fmt.Sprintf("no profile found for MAC: %s", mac)}
}

// quarantineVLANFor returns the VLAN a quarantine policy for the profile must
// carry: the failure-network (quarantine) VLAN, or the provisioning VLAN when
// no failure network is declared. ok is false when the profile declares
// neither.
func quarantineVLANFor(profile *entities.DeviceProfile) (uint16, bool) {
	if failureNet := profile.GetFailureNetworkConfig(); failureNet != nil && failureNet.VLAN != 0 {
		return failureNet.VLAN, true
	}
	if provNet := profile.GetEnrollmentNetworkConfig(); provNet != nil && provNet.VLAN != 0 {
		return provNet.VLAN, true
	}
	return 0, false
}

// buildPortPolicy creates a PortPolicy from a DeviceProfile's production network
// config and the issued certificate. When an extractor is configured, the zone
// embedded in the certificate is compared against the profile zone:
//   - When both match, the cert zone is used (authoritative).
//   - When they differ, the device is placed in the quarantine zone and
//     ErrZoneMismatch is returned so the caller can emit an audit event.
//   - When the cert carries no zone extension, the profile zone is used
//     (backward compatible with pre-Z3 certs).
//   - When the cert carries an unreadable zone extension, no policy is
//     built and ErrZoneExtensionInvalid is returned: invalid policy input
//     never falls open to the trusted policy.
func (h *SDNEnrollmentHook) buildPortPolicy(profile *entities.DeviceProfile, cert *x509.Certificate) (*PortPolicy, error) {
	prodNet := profile.GetPostEnrollmentNetworkConfig()
	if prodNet == nil {
		h.logger.Warn("profile has no production network configuration",
			slog.String("profile", profile.Name))
		return nil, nil
	}

	// Extract tenant ID from certificate (e.g., from Organization field)
	tenantID := "default"
	if len(cert.Subject.Organization) > 0 {
		tenantID = cert.Subject.Organization[0]
	}

	// Resolve zone: cert zone is authoritative; fall back to profile zone.
	resolvedZone := zone.Zone(prodNet.Zone)
	var zoneErr error
	if h.extractor != nil {
		certZoneName, extractErr := h.extractor.ExtractZone(cert)
		// Only a genuinely ABSENT extension falls back to the profile zone
		// (backward compatible with pre-Z3 certs). A present-but-unreadable
		// extension is invalid policy input and fails closed by building no
		// policy — it must never fall through to the trusted policy.
		if extractErr != nil && !errors.Is(extractErr, ErrMissingZoneExtension) {
			err := ErrZoneExtensionInvalid{Serial: cert.Subject.CommonName, Cause: extractErr}
			h.logger.Error(err.Error(),
				slog.String("serial", cert.Subject.CommonName),
				slog.String("profile", profile.Name),
				complianceAttr(complianceSC7, complianceSC4, complianceAC4))
			return nil, err
		}
		if extractErr == nil {
			// Cert carries a zone — cross-check against profile zone.
			certZone := zone.Zone(certZoneName)
			profileZone := zone.Zone(prodNet.Zone)
			if profileZone != "" && certZone != profileZone {
				// Zone mismatch: resolve quarantine and fail closed.
				quarantine := zone.ZoneQuarantine
				if qz, qErr := zone.ZoneForRole(h.zones, zone.LifecycleRoleQuarantine); qErr == nil {
					quarantine = qz
				}
				// Zone mismatch quarantine: SC-7 (boundary), SC-4 (tenant isolation), AC-4 (flow).
				h.logger.Warn("zone mismatch between certificate and profile, applying quarantine",
					slog.String("cert_zone", string(certZone)),
					slog.String("profile_zone", string(profileZone)),
					slog.String("zone", string(quarantine)),
					slog.String("serial", cert.Subject.CommonName),
					slog.String("profile", profile.Name),
					complianceAttr(complianceSC7, complianceSC4, complianceAC4))
				resolvedZone = quarantine
				zoneErr = ErrZoneMismatch{
					CertZone:    certZone,
					ProfileZone: profileZone,
					Serial:      cert.Subject.CommonName,
				}
			} else {
				resolvedZone = certZone
			}
		}
	}

	// A quarantine policy must carry the quarantine VLAN, never the trusted
	// one: the profile's failure-network VLAN, or its provisioning VLAN when
	// no failure network is declared. It carries none of the production
	// ACLs. A quarantine that would share the trusted VLAN is a
	// contradiction, and a profile with neither VLAN cannot be quarantined
	// at all — both fail closed by building no policy.
	vlan := prodNet.VLAN
	acls := prodNet.ACLs
	if zoneErr != nil {
		quarantineVLAN, ok := quarantineVLANFor(profile)
		if !ok {
			h.logger.Error("zone mismatch requires quarantine but profile declares no quarantine or provisioning VLAN; refusing to build a policy",
				slog.String("serial", cert.Subject.CommonName),
				slog.String("profile", profile.Name),
				complianceAttr(complianceSC7, complianceSC4, complianceAC4))
			return nil, ErrQuarantineVLANUnavailable{Serial: cert.Subject.CommonName, Profile: profile.Name}
		}
		if quarantineVLAN == prodNet.VLAN {
			h.logger.Error("quarantine policy would carry the trusted VLAN; refusing to build a policy",
				slog.String("serial", cert.Subject.CommonName),
				slog.String("profile", profile.Name),
				slog.Uint64("vlan", uint64(quarantineVLAN)),
				complianceAttr(complianceSC7, complianceSC4, complianceAC4))
			return nil, ErrQuarantinePolicyContradiction{Serial: cert.Subject.CommonName, Profile: profile.Name, VLAN: quarantineVLAN}
		}
		vlan = quarantineVLAN
		acls = nil
	}

	// Build the port policy
	policy := &PortPolicy{
		TenantID:    tenantID,
		Zone:        resolvedZone,
		VLAN:        vlan,
		Certificate: cert,
		ExpiresAt:   cert.NotAfter,
		IssuedAt:    time.Now(),
		Metadata: map[string]string{
			"profile_id":   fmt.Sprintf("%d", profile.ID),
			"profile_name": profile.Name,
			"device_role":  string(profile.Role),
		},
	}

	// Convert profile ACLs to policy ACLs
	if len(acls) > 0 {
		policy.ACLs = make([]ACLRule, 0, len(acls))
		for i, aclConfig := range acls {
			if !aclConfig.IsValid() {
				h.logger.Warn("skipping invalid ACL rule",
					slog.Int("index", i),
					slog.String("profile", profile.Name))
				continue
			}

			// Build the flow match based on ACL config
			match := FlowMatch{
				VLANVid: vlan,
			}

			// Set source/destination IPs
			if aclConfig.SrcIP != "" && aclConfig.SrcIP != "any" {
				match.IPv4Src = aclConfig.SrcIP
			}
			if aclConfig.DstIP != "" && aclConfig.DstIP != "any" {
				match.IPv4Dst = aclConfig.DstIP
			}

			// Set protocol and ports
			switch aclConfig.Protocol {
			case "tcp":
				match.IPProto = 6 // TCP protocol number
				if aclConfig.SrcPort > 0 {
					match.TCPSrc = aclConfig.SrcPort
				}
				if aclConfig.DstPort > 0 {
					match.TCPDst = aclConfig.DstPort
				}
			case "udp":
				match.IPProto = 17 // UDP protocol number
				if aclConfig.SrcPort > 0 {
					match.UDPSrc = aclConfig.SrcPort
				}
				if aclConfig.DstPort > 0 {
					match.UDPDst = aclConfig.DstPort
				}
			case "icmp":
				match.IPProto = 1 // ICMP protocol number
			}

			// Build the flow action
			action := FlowAction{
				Type: FlowActionNormal, // Default to normal L2/L3 switching
			}

			switch aclConfig.Action {
			case "allow":
				action.Type = FlowActionAllow
			case "deny":
				action.Type = FlowActionDeny
			}

			policy.ACLs = append(policy.ACLs, ACLRule{
				Priority:    aclConfig.Priority,
				Match:       match,
				Action:      action,
				Description: fmt.Sprintf("Profile %s ACL rule %d", profile.Name, i),
			})
		}
	}

	h.logger.Debug("built port policy from profile",
		slog.String("profile", profile.Name),
		slog.String("zone", string(resolvedZone)),
		slog.Uint64("vlan", uint64(policy.VLAN)),
		slog.Int("acl_count", len(policy.ACLs)),
		slog.String("tenant_id", tenantID))

	return policy, zoneErr
}
