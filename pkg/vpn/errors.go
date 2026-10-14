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

package vpn

// ErrMissingDependency reports a service built without a collaborator it
// cannot work without.
type ErrMissingDependency struct {
	Name string
}

// Error implements the error interface.
func (e *ErrMissingDependency) Error() string {
	return "vpn: the control-plane service needs " + e.Name
}

// ErrInvalidArgument reports a request field that is missing or malformed.
type ErrInvalidArgument struct {
	Field  string
	Reason string
}

// Error implements the error interface.
func (e *ErrInvalidArgument) Error() string {
	return "vpn: " + e.Field + ": " + e.Reason
}

// ErrPeerNotFound reports a device that is not an enrolled peer of the tenant.
type ErrPeerNotFound struct {
	TenantID string
	DeviceID string
}

// Error implements the error interface.
func (e *ErrPeerNotFound) Error() string {
	return "vpn: device " + e.DeviceID + " is not an enrolled peer of tenant " + e.TenantID
}

// ErrPosturePolicyNotFound reports a tenant posture policy that does not
// exist.
type ErrPosturePolicyNotFound struct {
	TenantID string
	Name     string
}

// Error implements the error interface.
func (e *ErrPosturePolicyNotFound) Error() string {
	return "vpn: tenant " + e.TenantID + " has no posture policy " + e.Name
}

// ErrInvalidPosturePolicy reports a posture policy module that does not
// compile as a vpn.posture policy. Nothing is stored.
type ErrInvalidPosturePolicy struct {
	TenantID string
	Name     string
	Reason   string
}

// Error implements the error interface.
func (e *ErrInvalidPosturePolicy) Error() string {
	return "vpn: posture policy " + e.Name + " of tenant " + e.TenantID + " is invalid: " + e.Reason
}

// ErrPolicyEngineUnavailable reports that the policy engine could not be
// started to validate a posture policy. Nothing is stored.
type ErrPolicyEngineUnavailable struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrPolicyEngineUnavailable) Error() string {
	return "vpn: the policy engine is unavailable: " + e.Cause.Error()
}

// Unwrap returns the engine failure.
func (e *ErrPolicyEngineUnavailable) Unwrap() error { return e.Cause }

// ErrStoreUnavailable reports a control-plane store operation that failed.
type ErrStoreUnavailable struct {
	Op    string
	Cause error
}

// Error implements the error interface.
func (e *ErrStoreUnavailable) Error() string {
	return "vpn: store " + e.Op + " failed: " + e.Cause.Error()
}

// Unwrap returns the store failure.
func (e *ErrStoreUnavailable) Unwrap() error { return e.Cause }

// ErrKeyCollision reports two distinct keys that hash to the same record ID.
// The write is refused rather than overwriting the other key's record.
type ErrKeyCollision struct {
	Kind   string
	Key    string
	Stored string
}

// Error implements the error interface.
func (e *ErrKeyCollision) Error() string {
	return "vpn: " + e.Kind + " " + e.Key + " collides with the stored " + e.Stored
}

// ErrStatusUnavailable reports that no gateway telemetry store is wired, so
// the control plane has no session state to report.
type ErrStatusUnavailable struct {
	Reason string
}

// Error implements the error interface.
func (e *ErrStatusUnavailable) Error() string {
	return "vpn: session status is unavailable: " + e.Reason
}

// ErrGatewayNotFound reports a gateway that has never reported telemetry.
type ErrGatewayNotFound struct {
	GatewayID string
}

// Error implements the error interface.
func (e *ErrGatewayNotFound) Error() string {
	return "vpn: gateway " + e.GatewayID + " has not reported"
}

// ErrLeaseOwnedByOtherGateway reports a lease write or delete from a gateway
// that did not issue the lease. Only the gateway that admitted a lease writes
// it through, so the write is refused rather than moving the lease.
type ErrLeaseOwnedByOtherGateway struct {
	TenantID  string
	LeaseID   string
	GatewayID string
}

// Error implements the error interface.
func (e *ErrLeaseOwnedByOtherGateway) Error() string {
	return "vpn: lease " + e.LeaseID + " of tenant " + e.TenantID + " was not issued by gateway " + e.GatewayID
}
