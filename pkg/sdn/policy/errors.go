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
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

var (
	// ErrPortNotFound is returned when a port does not exist.
	ErrPortNotFound = errors.New("port not found")

	// ErrPortExists is returned when attempting to create a port that already exists.
	ErrPortExists = errors.New("port already exists")

	// ErrInvalidPortID is returned when a port ID is invalid.
	ErrInvalidPortID = errors.New("invalid port ID")

	// ErrInvalidState is returned when a state transition is invalid.
	ErrInvalidState = errors.New("invalid state transition")

	// ErrPolicyNotFound is returned when a policy does not exist.
	ErrPolicyNotFound = errors.New("policy not found")

	// ErrPolicyExists is returned when attempting to apply a policy that already exists.
	ErrPolicyExists = errors.New("policy already exists")

	// ErrInvalidPolicy is returned when a policy specification is invalid.
	ErrInvalidPolicy = errors.New("invalid policy specification")

	// ErrInvalidConfiguration is returned when a configuration is invalid.
	ErrInvalidConfiguration = errors.New("invalid configuration")

	// ErrInvalidCertificate is returned when a certificate is invalid or cannot be parsed.
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrCertificateExpired is returned when a certificate has expired.
	ErrCertificateExpired = errors.New("certificate expired")

	// ErrCertificateRevoked is returned when a certificate has been revoked.
	ErrCertificateRevoked = errors.New("certificate revoked")

	// ErrMissingTenantID is returned when a tenant ID is required but not provided.
	ErrMissingTenantID = errors.New("missing tenant ID in certificate")

	// ErrMissingVLAN is returned when a VLAN is required but not provided.
	// Retained for backward compatibility; zone-based enforcement replaces direct
	// VLAN extraction from certificates.
	ErrMissingVLAN = errors.New("missing VLAN in certificate")

	// ErrInvalidVLAN is returned when a VLAN ID is invalid.
	ErrInvalidVLAN = errors.New("invalid VLAN ID")

	// ErrInvalidACL is returned when an ACL rule is invalid.
	ErrInvalidACL = errors.New("invalid ACL rule")

	// ErrFlowInstallFailed is returned when installing an OpenFlow rule fails.
	ErrFlowInstallFailed = errors.New("failed to install flow rule")

	// ErrFlowDeleteFailed is returned when deleting an OpenFlow rule fails.
	ErrFlowDeleteFailed = errors.New("failed to delete flow rule")

	// ErrEngineNotRunning is returned when attempting operations on a stopped engine.
	ErrEngineNotRunning = errors.New("policy engine not running")

	// ErrEngineAlreadyRunning is returned when attempting to start an already running engine.
	ErrEngineAlreadyRunning = errors.New("policy engine already running")

	// ErrInvalidClient is returned when a client is nil or invalid.
	ErrInvalidClient = errors.New("invalid client")

	// ErrInvalidBridgeName is returned when a bridge name is empty or invalid.
	ErrInvalidBridgeName = errors.New("invalid bridge name")

	// ErrMissingZoneExtension is returned by ExtractZone when a certificate
	// does not carry the OIDTPNetworkZone extension.
	ErrMissingZoneExtension = errors.New("sdn/policy: certificate has no network zone extension")
)

// ErrZoneNotDeclared is returned when a certificate carries a zone value that
// is not present in the configured resolved zone set. The policy engine
// applies fail-closed behaviour: the port is placed in the quarantine zone
// and this error is returned so callers can emit audit events.
type ErrZoneNotDeclared struct {
	// Zone is the undeclared zone value found in the certificate.
	Zone zone.Zone
	// Subject is the certificate subject for log correlation.
	Subject string
}

// Error implements the error interface.
func (e ErrZoneNotDeclared) Error() string {
	return fmt.Sprintf("sdn/policy: certificate zone %q is not declared in the resolved zone set (subject %q)", e.Zone, e.Subject)
}

// ErrEmptyZoneForEncoding is returned when encode_zone_in_cert is enabled
// but no zone can be resolved from the device profile.
type ErrEmptyZoneForEncoding struct {
	// Serial is the device serial number, when known.
	Serial string
}

// Error implements the error interface.
func (e ErrEmptyZoneForEncoding) Error() string {
	return fmt.Sprintf("sdn/policy: encode_zone_in_cert is enabled but no zone is configured for device serial %q", e.Serial)
}

// ErrZoneMismatch is returned by buildPortPolicy when the zone embedded in
// the issued certificate does not match the device profile's expected zone.
// Callers apply quarantine flows and emit an audit event.
type ErrZoneMismatch struct {
	// CertZone is the zone read from the certificate extension.
	CertZone zone.Zone
	// ProfileZone is the zone expected from the device profile.
	ProfileZone zone.Zone
	// Serial is the device serial number for audit correlation.
	Serial string
}

// Error implements the error interface.
func (e ErrZoneMismatch) Error() string {
	return fmt.Sprintf("sdn/policy: zone mismatch for serial %q: cert=%q profile=%q", e.Serial, e.CertZone, e.ProfileZone)
}

// ErrQuarantineVLANUnavailable is returned when a zone mismatch requires
// quarantine but the device profile declares neither a failure-network
// (quarantine) VLAN nor a provisioning VLAN to isolate the port on. Without
// one, no quarantine policy can be built, so activation fails closed
// instead of authorizing the device on its post-enrollment VLAN.
type ErrQuarantineVLANUnavailable struct {
	// Serial is the device serial number for audit correlation.
	Serial string
	// Profile is the device profile name.
	Profile string
}

// Error implements the error interface.
func (e ErrQuarantineVLANUnavailable) Error() string {
	return fmt.Sprintf("sdn/policy: zone mismatch for serial %q requires quarantine but profile %q declares no quarantine or provisioning VLAN; refusing activation", e.Serial, e.Profile)
}

// ErrQuarantinePolicyContradiction is returned when a quarantine policy
// would carry the profile's post-enrollment VLAN: a policy whose zone is
// quarantine and whose VLAN is the post-enrollment VLAN would isolate nothing.
type ErrQuarantinePolicyContradiction struct {
	// Serial is the device serial number for audit correlation.
	Serial string
	// Profile is the device profile name.
	Profile string
	// VLAN is the VLAN shared by the quarantine and post-enrollment networks.
	VLAN uint16
}

// Error implements the error interface.
func (e ErrQuarantinePolicyContradiction) Error() string {
	return fmt.Sprintf("sdn/policy: quarantine policy for serial %q would carry post-enrollment VLAN %d (profile %q): a quarantine that shares the post-enrollment VLAN isolates nothing; refusing activation", e.Serial, e.VLAN, e.Profile)
}

// ErrQuarantineStateIndeterminate is returned when the quarantine policy was
// applied to the datapath but the port could not be marked quarantined in
// the state machine. The datapath isolation is not rolled back — that is the
// safe direction — but the recorded state disagrees with reality and needs
// operator attention. The pending activation is retained.
type ErrQuarantineStateIndeterminate struct {
	// PortID is the port whose state could not be updated.
	PortID string
	// Serial is the device serial number for audit correlation.
	Serial string
	// Cause is the state-machine error.
	Cause error
}

// Error implements the error interface.
func (e ErrQuarantineStateIndeterminate) Error() string {
	return fmt.Sprintf("sdn/policy: quarantine policy applied to port %q for serial %q but the port state could not be marked quarantined — state INDETERMINATE, operator action required: %v", e.PortID, e.Serial, e.Cause)
}

// Unwrap returns the state-machine cause.
func (e ErrQuarantineStateIndeterminate) Unwrap() error { return e.Cause }

// ErrZoneEnforcementUnavailable is returned by the engine when a policy
// declares the quarantine zone but no ZoneFlowManager is configured. The
// VLAN-direct fallback cannot enforce zone isolation, so the policy is
// refused rather than silently degraded to an authorized port.
type ErrZoneEnforcementUnavailable struct {
	// PortID is the port the policy targeted.
	PortID string
	// Zone is the zone that required enforcement.
	Zone zone.Zone
}

// Error implements the error interface.
func (e ErrZoneEnforcementUnavailable) Error() string {
	return fmt.Sprintf("sdn/policy: zone %q on port %q requires zone flow enforcement but no zone flow manager is configured; refusing to authorize", e.Zone, e.PortID)
}

// ErrPortAuthNotEnforced refuses port authentication and its revocation on
// every transport (#304). Answering "authenticated" or "revoked" would claim
// the switch admits or blocks a port when nothing enforces it. Two pieces
// are missing before the engine can enforce it:
//
//   - The Engine is not reachable from the API's SDN service: the daemon
//     builds it for quarantine and enrollment only (initSDNPolicy in
//     pkg/daemon/commands/quarantine_init.go).
//   - That engine has no CertificateValidator, so Engine.AuthenticatePort
//     would admit any certificate. DefaultCertificateValidator checks a chain
//     to the roots it is given and the client-auth usage, but nothing hands
//     it the platform anchor (pkg/trust), and it does not check that the
//     certificate is an IDevID.
//
// It is FailedPrecondition on every transport.
type ErrPortAuthNotEnforced struct {
	// Operation names the refused call or tool.
	Operation string
}

// Error implements the error interface.
func (e ErrPortAuthNotEnforced) Error() string {
	return "sdn/policy: " + e.Operation + " is refused: port authentication is not enforced on the switch"
}

// GRPCStatus classes the error FailedPrecondition.
func (e ErrPortAuthNotEnforced) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// ErrNoPendingActivation is returned by ActivateDevice when no pending
// activation exists for the given device serial.
type ErrNoPendingActivation struct {
	// Serial is the device serial number the activation was requested for.
	Serial string
}

// Error implements the error interface.
func (e ErrNoPendingActivation) Error() string {
	return fmt.Sprintf("no pending activation found for serial: %s", e.Serial)
}

// ErrZoneExtensionInvalid reports a certificate whose OIDTPNetworkZone
// extension is present but unreadable. Invalid policy input never falls
// back to the profile zone — the activation is refused outright.
type ErrZoneExtensionInvalid struct {
	// Serial is the certificate subject the extension belongs to.
	Serial string
	// Cause is the parse failure.
	Cause error
}

// Error implements the error interface.
func (e ErrZoneExtensionInvalid) Error() string {
	return fmt.Sprintf("sdn/policy: certificate for %s carries an unreadable network zone extension; refusing activation: %v", e.Serial, e.Cause)
}

// Unwrap returns the underlying parse failure.
func (e ErrZoneExtensionInvalid) Unwrap() error { return e.Cause }

// ErrPendingActivationSuperseded is returned by ActivateDevice when the
// pending-activation version reserved by the caller's ActivationPlan was
// replaced by a concurrent re-enrollment before it could be consumed.
// Nothing was applied; the caller must precheck again to obtain a plan for
// the current record.
type ErrPendingActivationSuperseded struct {
	// Serial is the device serial number the activation was requested for.
	Serial string
}

// Error implements the error interface.
func (e ErrPendingActivationSuperseded) Error() string {
	return fmt.Sprintf("pending activation for serial %s was superseded by a concurrent re-enrollment: nothing was applied, precheck again for the current record", e.Serial)
}

// ErrPortNotRegisteredForDevice is returned by ActivateDevice when the
// device's MAC still has no registered port — the device has not attached
// to the fabric, so the port transition remains deferred.
type ErrPortNotRegisteredForDevice struct {
	// MAC is the device MAC address recorded at enrollment.
	MAC string
}

// Error implements the error interface.
func (e ErrPortNotRegisteredForDevice) Error() string {
	return fmt.Sprintf("no port registered for device MAC %s: device has not attached to the fabric, port transition deferred to connect-time assessment", e.MAC)
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

// ErrNetworkPlanRequired is returned when a zone operation needs the network
// plan (sdn.Config.Plan()) and none was supplied. There is no fallback
// numbering: every VLAN comes from the plan.
type ErrNetworkPlanRequired struct {
	// Operation names what needed the plan.
	Operation string
}

// Error implements the error interface.
func (e ErrNetworkPlanRequired) Error() string {
	return fmt.Sprintf("sdn/policy: %s needs the network plan (sdn.environment); none is configured", e.Operation)
}

// ErrPortClassUnresolved is returned when the port class a device is
// admitted to cannot be resolved against the network plan.
type ErrPortClassUnresolved struct {
	// Class is the port class.
	Class string
	// Cause is the underlying plan error.
	Cause error
}

// Error implements the error interface.
func (e ErrPortClassUnresolved) Error() string {
	return fmt.Sprintf("sdn/policy: port class %q cannot be resolved: %v", e.Class, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrPortClassUnresolved) Unwrap() error { return e.Cause }
