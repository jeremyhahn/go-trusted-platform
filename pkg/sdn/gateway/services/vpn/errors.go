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

import (
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
)

// ErrPeerRefused is the device-identity refusal: the mTLS peer was not
// admitted by the caller-admission policy. Reason is the policy's reason
// class; the policy's identity list is never carried.
type ErrPeerRefused struct {
	Reason calleradmission.Reason
}

func (e *ErrPeerRefused) Error() string {
	return "vpn: peer refused: " + string(e.Reason)
}

// Unauthenticated reports whether the refusal is an identity failure (401)
// rather than an authorization failure (403).
func (e *ErrPeerRefused) Unauthenticated() bool {
	return e.Reason == calleradmission.ReasonUntrustedIssuer || e.Reason == calleradmission.ReasonNoIdentity
}

// ErrAttestationFailed is returned when the verdict did not pass, was not
// cryptographic, or the verifier could not produce one.
type ErrAttestationFailed struct {
	DeviceID string
	Reason   string
	Cause    error
}

func (e *ErrAttestationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vpn: attestation failed for device %s: %s: %v", e.DeviceID, e.Reason, e.Cause)
	}
	return fmt.Sprintf("vpn: attestation failed for device %s: %s", e.DeviceID, e.Reason)
}

func (e *ErrAttestationFailed) Unwrap() error { return e.Cause }

// ErrPostureViolation is returned when the posture policy reports violations.
// Violations carries rule names only, never the policy text.
type ErrPostureViolation struct {
	Violations []string
}

func (e *ErrPostureViolation) Error() string {
	return "vpn: posture violation: " + strings.Join(e.Violations, ", ")
}

// ErrPostureUnavailable is returned when the posture policy cannot be
// evaluated at all. It is a refusal, never a bypass.
type ErrPostureUnavailable struct {
	Cause error
}

func (e *ErrPostureUnavailable) Error() string {
	return fmt.Sprintf("vpn: posture policy unavailable: %v", e.Cause)
}

func (e *ErrPostureUnavailable) Unwrap() error { return e.Cause }

// ErrPersonFactorRequired is returned when the policy requires a person
// factor and none was presented.
type ErrPersonFactorRequired struct{}

func (e *ErrPersonFactorRequired) Error() string {
	return "vpn: a person factor is required and none was presented"
}

// ErrPersonFactorInvalid is returned when the presented factor did not
// verify against the session nonce.
type ErrPersonFactorInvalid struct {
	FactorName string
	Cause      error
}

func (e *ErrPersonFactorInvalid) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vpn: person factor %q invalid: %v", e.FactorName, e.Cause)
	}
	return fmt.Sprintf("vpn: person factor %q invalid", e.FactorName)
}

func (e *ErrPersonFactorInvalid) Unwrap() error { return e.Cause }

// ErrPoolExhausted is returned when the remote-access pool has no address.
type ErrPoolExhausted struct {
	Pool  string
	Cause error
}

func (e *ErrPoolExhausted) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vpn: pool %q exhausted: %v", e.Pool, e.Cause)
	}
	return fmt.Sprintf("vpn: pool %q exhausted", e.Pool)
}

func (e *ErrPoolExhausted) Unwrap() error { return e.Cause }

// ErrDataPlaneUnavailable is returned when the requested data plane is not
// offered by this build or configuration, or the datapath refused the peer.
type ErrDataPlaneUnavailable struct {
	Kind  DataPlaneKind
	Cause error
}

func (e *ErrDataPlaneUnavailable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vpn: data plane %q unavailable: %v", e.Kind, e.Cause)
	}
	return fmt.Sprintf("vpn: data plane %q unavailable", e.Kind)
}

func (e *ErrDataPlaneUnavailable) Unwrap() error { return e.Cause }

// ErrLeaseStoreUnavailable is returned when the lease store itself failed:
// the record could not be read or written. It is distinct from a data-plane
// failure so a caller retries the right subsystem.
type ErrLeaseStoreUnavailable struct {
	Cause error
}

func (e *ErrLeaseStoreUnavailable) Error() string {
	return fmt.Sprintf("vpn: lease store unavailable: %v", e.Cause)
}

func (e *ErrLeaseStoreUnavailable) Unwrap() error { return e.Cause }

// ErrLeaseExpired is returned when a renewal arrives after the lease expired.
type ErrLeaseExpired struct {
	LeaseID LeaseID
}

func (e *ErrLeaseExpired) Error() string {
	return fmt.Sprintf("vpn: lease %s expired", e.LeaseID)
}

// ErrLeaseNotFound is returned for an unknown or already revoked lease.
type ErrLeaseNotFound struct {
	LeaseID LeaseID
}

func (e *ErrLeaseNotFound) Error() string {
	return fmt.Sprintf("vpn: lease %s not found", e.LeaseID)
}

// ErrInvalidConfig is the startup refusal for a configuration the service
// cannot run: lease bounds, a data plane this build does not offer, an
// empty pool, an unknown zone.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e *ErrInvalidConfig) Error() string {
	return fmt.Sprintf("vpn: invalid config %s: %s", e.Field, e.Reason)
}

// ErrInvalidRequest is returned when an admission or renewal request is
// malformed before any step runs.
// ErrRenewalNotOpen is returned when a renewal arrives before the lease's
// renew window has opened; OpensAt is when it will.
type ErrRenewalNotOpen struct {
	LeaseID LeaseID
	OpensAt time.Time
}

func (e *ErrRenewalNotOpen) Error() string {
	return "vpn: lease " + string(e.LeaseID) + " cannot be renewed before " + e.OpensAt.UTC().Format(time.RFC3339)
}

type ErrInvalidRequest struct {
	Field  string
	Reason string
}

func (e *ErrInvalidRequest) Error() string {
	return fmt.Sprintf("vpn: invalid request %s: %s", e.Field, e.Reason)
}

// ErrNonceUnknown is returned when a request echoes a nonce the service did
// not issue or has already consumed.
type ErrNonceUnknown struct{}

func (e *ErrNonceUnknown) Error() string {
	return "vpn: unknown or consumed nonce"
}

// ErrZoneNotAllowed is returned when a request names a zone outside the
// service's allow-to set.
type ErrZoneNotAllowed struct {
	Zone string
}

func (e *ErrZoneNotAllowed) Error() string {
	return fmt.Sprintf("vpn: zone %q is not reachable through this service", e.Zone)
}

// ErrDepsMissing is returned by New when a required dependency is nil.
type ErrDepsMissing struct {
	Dep string
}

func (e *ErrDepsMissing) Error() string {
	return "vpn: dependency missing: " + e.Dep
}

// ErrAlreadyStarted is returned by Start on a running service.
type ErrAlreadyStarted struct{}

func (e *ErrAlreadyStarted) Error() string { return "vpn: service already started" }

// ErrNotStarted is returned by Stop and the admission verbs on a stopped
// service.
type ErrNotStarted struct{}

func (e *ErrNotStarted) Error() string { return "vpn: service not started" }
