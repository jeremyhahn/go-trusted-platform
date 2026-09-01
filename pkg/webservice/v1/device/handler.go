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

package device

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// RestHandler defines the device REST endpoint interface
type RestHandler interface {
	GetProfile(w http.ResponseWriter, r *http.Request)
	Activate(w http.ResponseWriter, r *http.Request)
	Heartbeat(w http.ResponseWriter, r *http.Request)
}

// ProfileResponse is the response for GET /device/profile.
// ProvisioningNetwork carries the enrollment-phase network when the profile
// defines one; the activation handler uses its VLAN as the one fail-closed
// revert target for the physical switch move.
type ProfileResponse struct {
	SerialNumber        string           `json:"serialNumber"`
	TrustedNetwork      NetworkConfig    `json:"trustedNetwork"`
	ProvisioningNetwork *NetworkConfig   `json:"provisioningNetwork,omitempty"`
	ACLs                []ACLConfig      `json:"acls,omitempty"`
	RateLimit           *RateLimitConfig `json:"rateLimit,omitempty"`
}

type NetworkConfig struct {
	VLAN     uint16   `json:"vlan"`
	UseDHCP  bool     `json:"useDHCP"`
	StaticIP string   `json:"staticIP,omitempty"`
	Gateway  string   `json:"gateway,omitempty"`
	DNS      []string `json:"dns,omitempty"`
}

type ACLConfig struct {
	Name     string            `json:"name"`
	Priority int               `json:"priority"`
	Match    map[string]string `json:"match"`
	Action   string            `json:"action"`
}

type RateLimitConfig struct {
	IngressMbps int `json:"ingressMbps"`
	EgressMbps  int `json:"egressMbps"`
}

// ActivateResponse is the response for POST /device/activate. Status is the
// outcome actually applied ("activated" or "quarantined") and VLAN is the
// VLAN the port was actually placed on — the quarantine VLAN when the
// status is "quarantined", never the trusted VLAN.
type ActivateResponse struct {
	Status         string    `json:"status"`
	VLAN           uint16    `json:"vlan"`
	TransitionedAt time.Time `json:"transitionedAt"`
}

// DeviceActivator applies the SDN activation for an enrolled device: it
// resolves the device's port (deferred to the device MAC when enrollment
// happened before any fabric attach), applies the policy the plan carries,
// and transitions the port to authorized. PrecheckActivation validates with
// no side effects and returns an ActivationPlan reserving the exact
// pending-activation version it validated, so external commitments — such
// as a physical switch VLAN move — can be ordered after validation and
// derived from the plan's value-copy VLAN snapshot, taken from the same
// profile the SDN policy was built from at the same instant;
// ActivateDevice atomically consumes that same version or fails with
// ErrPendingActivationSuperseded. LockSerial serializes the whole
// precheck -> commit sequence against concurrent re-enrollments for the
// same serial. It is the single implementation of that logic; the HTTP
// handler only binds it to the route.
// FinalizeActivation releases a successful activation's reservation once
// every external commit succeeded; ReinstateActivation instead returns the
// pending record so the client can retry activation after a failed external
// commit without re-enrolling.
type DeviceActivator interface {
	LockSerial(serial string) (unlock func())
	PrecheckActivation(serial string) (policy.ActivationPlan, error)
	ActivateDevice(plan policy.ActivationPlan) (*policy.ActivationResult, error)
	FinalizeActivation(plan policy.ActivationPlan)
	ReinstateActivation(plan policy.ActivationPlan)
}

// Compile-time check that the SDN enrollment hook satisfies DeviceActivator.
var _ DeviceActivator = (*policy.SDNEnrollmentHook)(nil)

// Compile-time check that the device service satisfies HeartbeatRecorder.
var _ HeartbeatRecorder = (*device.Service)(nil)

// SwitchServiceProvider abstracts the switch management service for
// dependency injection. It allows the handler to resolve a Manager
// by switch name without depending on the concrete Service type.
type SwitchServiceProvider interface {
	// Manager returns the Manager for the named switch.
	Manager(name string) (switchmgmt.Manager, error)
}

// HeartbeatRecorder is the narrow liveness-write seam the heartbeat
// endpoint needs. It is deliberately not the full device.DeviceService:
// the mTLS device-facing routes carry one verb each, and widening the
// shared service interface would ripple through every transport mock
// for a write that only this route performs.
type HeartbeatRecorder interface {
	RecordHeartbeat(ctx context.Context, identity string) (*entities.Device, error)
}

// Handler implements RestHandler
type Handler struct {
	logger            *logging.Logger
	responseWriter    response.HttpWriter
	activator         DeviceActivator
	profileService    ProfileService
	switchService     SwitchServiceProvider
	heartbeatRecorder HeartbeatRecorder
}

// ProfileService provides device profile lookup
type ProfileService interface {
	GetBySerial(ctx context.Context, serial string) (*ProfileResponse, error)
}

func NewHandler(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	activator DeviceActivator,
	profileService ProfileService,
	opts ...HandlerOption,
) RestHandler {
	h := &Handler{
		logger:         logger,
		responseWriter: responseWriter,
		activator:      activator,
		profileService: profileService,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// HandlerOption configures optional Handler dependencies.
type HandlerOption func(*Handler)

// WithSwitchService injects a physical switch service into the handler.
// When set, Activate validates the physical move up front (no side
// effects) and moves the device's physical port to the trusted VLAN only
// AFTER the SDN policy is applied and enforced; on a failed move the port
// is moved to the plan's provisioning VLAN and verified by read-back — an
// unverifiable port is reported as ErrSwitchPortIndeterminate. See
// Activate for the validate-then-commit contract.
func WithSwitchService(svc SwitchServiceProvider) HandlerOption {
	return func(h *Handler) {
		h.switchService = svc
	}
}

// WithHeartbeatRecorder injects the liveness-write seam backing
// POST /device/heartbeat. Without it the route responds 503 so a
// misconfigured deployment is visible rather than silently dropping
// liveness reports.
func WithHeartbeatRecorder(recorder HeartbeatRecorder) HandlerOption {
	return func(h *Handler) {
		h.heartbeatRecorder = recorder
	}
}

// Heartbeat records the calling device's liveness. Like Activate, the
// device identity comes exclusively from the verified mTLS client
// certificate (never a body), so a device can only ever report itself.
// The body is ignored entirely — liveness is the timestamp of an
// authenticated arrival, not client-supplied data.
func (h *Handler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	serial, ok := r.Context().Value(ContextKeyDeviceSerial).(string)
	if !ok || serial == "" {
		h.responseWriter.Error400(w, r, ErrMissingSerial)
		return
	}
	if h.heartbeatRecorder == nil {
		h.responseWriter.Error500(w, r, ErrHeartbeatNotConfigured{})
		return
	}
	dev, err := h.heartbeatRecorder.RecordHeartbeat(r.Context(), serial)
	if err != nil {
		// An unknown identity is the caller's problem; anything after
		// resolution (re-read, save) is a storage fault and must not
		// masquerade as an enrollment failure.
		var notFound *device.HeartbeatDeviceNotFoundError
		if errors.As(err, &notFound) {
			h.responseWriter.Error404(w, r, ErrDeviceNotFound{Serial: serial})
			return
		}
		h.logger.Error(err, "failed to record device heartbeat")
		h.responseWriter.Error500(w, r, err)
		return
	}
	// Raw JSON, matching the other device-facing mTLS routes (profile,
	// activate): the provisioning client decodes the response shape
	// directly, not the operator API envelope.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(HeartbeatResponse{
		DeviceID:   dev.ID,
		Serial:     dev.Serial,
		ReceivedAt: dev.LastHeartbeatAt,
	}); err != nil {
		h.logger.Error(err, "failed to encode heartbeat response")
	}
}

// GetProfile returns the device profile for the authenticated device
func (h *Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	// Extract serial from client certificate (set by mTLS middleware)
	serial, ok := r.Context().Value(ContextKeyDeviceSerial).(string)
	if !ok || serial == "" {
		h.responseWriter.Error400(w, r, ErrMissingSerial)
		return
	}
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrActivationNotConfigured{})
		return
	}

	profile, err := h.profileService.GetBySerial(r.Context(), serial)
	if err != nil {
		h.responseWriter.Error404(w, r, ErrProfileNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

// Activate transitions the device to the trusted network zone. The SDN port
// transition is owned by the activator (the SDN enrollment hook): it resolves
// the device's port — deferred to the device MAC when enrollment happened
// before any fabric attach — applies the plan's policy, and moves the port
// to authorized. The handler holds only the HTTP binding and the physical
// switch VLAN move, which is validated before and committed strictly after
// the SDN enforcement so the trusted VLAN never opens onto an unenforced
// datapath.
func (h *Handler) Activate(w http.ResponseWriter, r *http.Request) {
	// Extract serial from client certificate
	serial, ok := r.Context().Value(ContextKeyDeviceSerial).(string)
	if !ok || serial == "" {
		h.responseWriter.Error400(w, r, ErrMissingSerial)
		return
	}
	// A deployment without SDN enrollment still registers this handler
	// for the heartbeat route; activation honestly reports that it is
	// not configured instead of panicking on a nil activator.
	if h.activator == nil {
		h.responseWriter.Error500(w, r, ErrActivationNotConfigured{})
		return
	}

	// Serialize the whole validate-then-commit sequence for this serial
	// against concurrent activations AND concurrent re-enrollments: the
	// activator's OnEnrollmentComplete takes the same per-serial lock, so
	// the pending activation cannot be replaced between the precheck below
	// and its consumption by ActivateDevice.
	unlock := h.activator.LockSerial(serial)
	defer unlock()

	// Validate-then-commit. The hook precheck confirms the activation can
	// proceed — pending activation present, port resolvable, and either the
	// zones match or an enforceable quarantine is expected — with NO side
	// effects, before the physical port is opened. The returned plan
	// reserves the exact pending-activation version that was validated;
	// everything below derives from it.
	plan, err := h.activator.PrecheckActivation(serial)
	if err != nil {
		var noPending policy.ErrNoPendingActivation
		var noPort policy.ErrPortNotRegisteredForDevice
		switch {
		case errors.As(err, &noPending), errors.As(err, &noPort):
			// Retryable preconditions — nothing has been changed anywhere.
			h.responseWriter.Error404(w, r, err)
		default:
			h.logger.Errorf("SDN activation precheck failed for device %s: %v", serial, err)
			h.responseWriter.Error500(w, r, err)
		}
		return
	}

	// A plan carrying a zone mismatch activates into quarantine: the
	// physical port is never opened and the hook applies the quarantine
	// policy below.
	expectQuarantine := plan.ExpectQuarantine()
	if expectQuarantine {
		h.logger.Errorf("Zone mismatch during activation of device %s: %v", serial, plan.ZoneMismatch())
	}

	// Validate the physical switch move up front with NO side effects —
	// provisioning VLAN present and distinct, switch manager resolvable —
	// so an unmovable port is refused before anything is committed
	// anywhere. The VLANs are the plan's value-copy snapshot: the same
	// immutable plan the SDN policy comes from, never a separate,
	// concurrently mutable lookup. A nil move means no switch mapping —
	// the physical move is a no-op for this device.
	var move *switchTransition
	if !expectQuarantine {
		prepared, switchErr := h.prepareSwitchTransition(r.Context(), serial, plan.VLANs())
		if switchErr != nil {
			h.logger.Errorf("Switch VLAN transition refused for device %s: %v", serial, switchErr)
			h.responseWriter.Error500(w, r, switchErr)
			return
		}
		move = prepared
	}

	// Apply the SDN activation through the enrollment hook — the single
	// implementation of port resolution, policy application and the
	// authorized transition. The plan fixes the policy, so the outcome
	// cannot diverge from what the precheck reported. The physical port
	// has NOT been opened yet: enforcement is installed before any
	// trusted-network exposure exists, so a slow or failed policy
	// application admits no traffic.
	result, err := h.activator.ActivateDevice(plan)
	if err != nil {
		// Nothing physical was committed — the switch was never touched.
		var noPending policy.ErrNoPendingActivation
		var noPort policy.ErrPortNotRegisteredForDevice
		switch {
		case errors.As(err, &noPending), errors.As(err, &noPort):
			h.responseWriter.Error404(w, r, err)
		default:
			h.logger.Errorf("SDN activation failed for device %s: %v", serial, err)
			h.responseWriter.Error500(w, r, err)
		}
		return
	}

	if result.ZoneMismatch != nil {
		// The quarantine policy was applied and enforced; the physical
		// port was never opened. Logged for audit correlation.
		h.logger.Errorf("Zone mismatch during activation of device %s: %v", serial, result.ZoneMismatch)
	}

	// Commit the physical port only AFTER the SDN policy is applied and
	// the port is authorized: the trusted VLAN opens onto an enforced
	// datapath, never an unenforced one. A failed physical commit leaves
	// the SDN side authorized and the physical port fail-closed on the
	// provisioning VLAN (verified by read-back inside the commit) — an
	// isolated device, never an unenforced one — and reinstates the
	// pending activation so the client can retry the whole activation
	// without re-enrolling.
	if err := h.commitSwitchTransition(r.Context(), serial, move); err != nil {
		h.activator.ReinstateActivation(plan)
		h.logger.Errorf("Switch VLAN transition failed for device %s after SDN activation — the SDN side is authorized, the physical port stays closed, the activation is retryable: %v", serial, err)
		h.responseWriter.Error500(w, r, err)
		return
	}

	// Every commit succeeded: release the activation's reservation.
	h.activator.FinalizeActivation(plan)

	h.logger.Infof("Device %s activation complete: status=%s vlan=%d zone=%s port=%s",
		serial, result.Status, result.VLAN, result.Zone, result.PortID)

	resp := ActivateResponse{
		Status:         string(result.Status),
		VLAN:           result.VLAN,
		TransitionedAt: time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// switchTransition is a validated, not-yet-committed physical switch move:
// the manager, port, and VLANs were checked by prepareSwitchTransition
// with no side effects, and commitSwitchTransition performs the move only
// after the SDN policy is enforced.
type switchTransition struct {
	mgr              switchmgmt.Manager
	switchName       string
	switchPort       string
	trustedVLAN      uint16
	provisioningVLAN uint16
}

// prepareSwitchTransition validates the physical switch move with NO side
// effects: the device's switch mapping, a provisioning VLAN distinct from
// the trusted VLAN (the one fail-closed revert target), and a resolvable
// switch manager. Both return values are nil when no switch service is
// configured or the device has no switch/port mapping — the physical move
// is a no-op for this device. The switch itself is never touched here.
func (h *Handler) prepareSwitchTransition(ctx context.Context, serial string, vlans policy.ActivationVLANs) (*switchTransition, error) {
	if h.switchService == nil {
		return nil, nil
	}

	// Look up device switch info from the profile service context.
	// The switch name and port are stored per-device; the profile service
	// provides them via the serial lookup. For now, we extract them from
	// the context set by the mTLS middleware or registration data.
	switchName, _ := ctx.Value(contextKeySwitchName).(string)
	switchPort, _ := ctx.Value(contextKeySwitchPort).(string)

	if switchName == "" || switchPort == "" {
		// No physical switch mapping for this device - skip VLAN move.
		return nil, nil
	}

	// Without a provisioning VLAN there is no fail-closed revert target,
	// so the physical port is never opened.
	if !vlans.HasProvisioning {
		return nil, &MessageError{Msg: "device profile has no provisioning network VLAN; refusing physical VLAN move for " + serial}
	}

	// Equal VLANs would make the fail-closed target the trusted VLAN
	// itself, so "closed" would mean "open". Profile validation rejects
	// this at create/update; the runtime guard refuses the move before
	// anything is committed in case a stored profile predates the rule.
	if vlans.Provisioning == vlans.Trusted {
		return nil, device.ErrProfileVLANsNotDistinct{VLAN: vlans.Trusted}
	}

	mgr, err := h.switchService.Manager(switchName)
	if err != nil {
		return nil, ErrSwitchNotConfigured{SwitchName: switchName}
	}

	return &switchTransition{
		mgr:              mgr,
		switchName:       switchName,
		switchPort:       switchPort,
		trustedVLAN:      vlans.Trusted,
		provisioningVLAN: vlans.Provisioning,
	}, nil
}

// commitSwitchTransition moves the prepared physical switch port to the
// trusted VLAN. Callers invoke it only AFTER the SDN policy is applied and
// enforced, so the trusted VLAN never opens onto an unenforced datapath. A
// nil transition (no switch mapping) is a no-op. On any failure the port
// is actively moved to the provisioning VLAN and verified by read-back —
// only a verified fail-closed port lets the plain transition error stand;
// anything else is ErrSwitchPortIndeterminate.
func (h *Handler) commitSwitchTransition(ctx context.Context, serial string, t *switchTransition) error {
	if t == nil {
		return nil
	}

	// Read the port's VLAN before the move. The value is informational —
	// the fail-closed revert target is always the provisioning VLAN — but
	// a port already sitting on the trusted VLAN means the port state
	// machine and switch reality diverged, which is worth an alarm. A
	// failed read leaves the port's state unknown while the SDN side is
	// already authorized, so it goes through the same fail-closed path as
	// a failed move: force the provisioning VLAN and verify by read-back;
	// only a verified closed port lets the plain transition error stand.
	previousVLAN, err := t.mgr.GetPortVLAN(ctx, t.switchPort)
	if err != nil {
		if vErr := h.revertAndVerify(ctx, t.mgr, t.switchName, t.switchPort, t.provisioningVLAN); vErr != nil {
			return vErr
		}
		return ErrSwitchVLANTransitionFailed{
			SwitchName: t.switchName,
			Port:       t.switchPort,
			VLAN:       t.trustedVLAN,
			Cause:      err,
		}
	}
	if previousVLAN == t.trustedVLAN {
		h.logger.Warnf("Switch port %s/%s is ALREADY on trusted VLAN %d before activation of device %s — port state machine and switch reality diverged",
			t.switchName, t.switchPort, t.trustedVLAN, serial)
	}

	if err := t.mgr.SetPortVLAN(ctx, t.switchPort, t.trustedVLAN); err != nil {
		// The manager's SSH command sequence is not atomic: the VLAN
		// change may have taken effect even though the sequence failed.
		// Actively fail closed — move the port to the provisioning VLAN
		// and verify by read-back. Only a verified revert lets the plain
		// transition error stand.
		if vErr := h.revertAndVerify(ctx, t.mgr, t.switchName, t.switchPort, t.provisioningVLAN); vErr != nil {
			return vErr
		}
		return ErrSwitchVLANTransitionFailed{
			SwitchName: t.switchName,
			Port:       t.switchPort,
			VLAN:       t.trustedVLAN,
			Cause:      err,
		}
	}

	h.logger.Infof("Switch port %s/%s moved from VLAN %d to trusted VLAN %d for device %s",
		t.switchName, t.switchPort, previousVLAN, t.trustedVLAN, serial)
	return nil
}

// revertAndVerify moves the port to the profile's provisioning VLAN — the
// one fail-closed target — and confirms the result by reading the port's
// VLAN back. The switch manager's SSH command sequences are not atomic, so
// a failed command may still have changed the VLAN; only a read-back
// showing the provisioning VLAN proves the port is closed. Any other
// outcome is ErrSwitchPortIndeterminate: the port may remain on the
// trusted VLAN and requires operator action.
func (h *Handler) revertAndVerify(ctx context.Context, mgr switchmgmt.Manager, switchName, switchPort string, provisioningVLAN uint16) error {
	revertErr := mgr.SetPortVLAN(ctx, switchPort, provisioningVLAN)

	currentVLAN, readErr := mgr.GetPortVLAN(ctx, switchPort)
	if readErr != nil {
		err := ErrSwitchPortIndeterminate{SwitchName: switchName, Port: switchPort, Cause: readErr}
		h.logger.Errorf("%s", err.Error())
		return err
	}
	if currentVLAN != provisioningVLAN {
		err := ErrSwitchPortIndeterminate{SwitchName: switchName, Port: switchPort, Cause: revertErr}
		h.logger.Errorf("%s", err.Error())
		return err
	}
	return nil
}

// Context keys for switch information passed through request context.
const (
	contextKeySwitchName ContextKey = "switch_name"
	contextKeySwitchPort ContextKey = "switch_port"
)

var (
	ErrMissingSerial   = &MessageError{Msg: "missing device serial number"}
	ErrProfileNotFound = &MessageError{Msg: "device profile not found"}
)
