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

package agent

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// RefusedError is a refusal from the gateway: the class it named, the
// posture rules that failed (posture violations only) and the HTTP status.
type RefusedError struct {
	Status int
	Class  gwvpn.RefusalClass
	Rules  []string
}

// refusalPhrases overrides the printed phrase where the class name would read
// badly; every other class prints with its dashes as spaces.
var refusalPhrases = map[gwvpn.RefusalClass]string{
	gwvpn.RefusalPostureUnavailable: "posture policy",
}

func (e *RefusedError) Error() string {
	phrase, ok := refusalPhrases[e.Class]
	if !ok {
		phrase = strings.ReplaceAll(strings.TrimSuffix(string(e.Class), "-unavailable"), "-", " ")
	}
	verb := "refused"
	if e.Status == http.StatusServiceUnavailable {
		verb = "unavailable"
	}
	if len(e.Rules) > 0 {
		return verb + ": " + phrase + ": " + strings.Join(e.Rules, ", ")
	}
	return verb + ": " + phrase
}

// ErrNotConnected is returned when the agent holds no lease.
type ErrNotConnected struct{}

func (e *ErrNotConnected) Error() string { return "not connected" }

// ErrNoDevice is returned when the host has no TPM identity to present to a
// gateway: Connect and Disconnect on an agent built without a Device, and
// OpenHostDevice on a host with no TPM, no tpm configuration or no IDevID.
type ErrNoDevice struct {
	Reason string
	Cause  error
}

func (e *ErrNoDevice) Error() string {
	msg := "this host has no TPM device identity for the VPN client"
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *ErrNoDevice) Unwrap() error { return e.Cause }

// ErrNoIDevIDConfig is returned when the TPM configuration names no IDevID.
type ErrNoIDevIDConfig struct{}

func (e *ErrNoIDevIDConfig) Error() string { return "the tpm configuration has no idevid section" }

// ErrPlatformConfig is returned when a platform configuration file exists
// but cannot be read or decoded.
type ErrPlatformConfig struct {
	Path  string
	Cause error
}

func (e *ErrPlatformConfig) Error() string {
	return fmt.Sprintf("platform configuration %s: %v", e.Path, e.Cause)
}

func (e *ErrPlatformConfig) Unwrap() error { return e.Cause }

// ErrIDevIDCertificate is returned when the IDevID certificate chain could
// not be read: from Path when one was given, otherwise from the TPM.
type ErrIDevIDCertificate struct {
	Path  string
	Cause error
}

func (e *ErrIDevIDCertificate) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("IDevID certificate unavailable from the TPM (pass --idevid-cert): %v", e.Cause)
	}
	return fmt.Sprintf("IDevID certificate %s: %v", e.Path, e.Cause)
}

func (e *ErrIDevIDCertificate) Unwrap() error { return e.Cause }

// ErrNoCertificate is returned when a PEM file holds no certificate.
type ErrNoCertificate struct{}

func (e *ErrNoCertificate) Error() string { return "no CERTIFICATE block" }

// ErrDeviceClose is returned when the TPM could not be closed.
type ErrDeviceClose struct {
	Cause error
}

func (e *ErrDeviceClose) Error() string { return fmt.Sprintf("close TPM: %v", e.Cause) }

func (e *ErrDeviceClose) Unwrap() error { return e.Cause }

// ErrAlreadyConnected is returned by Connect while a lease is held.
type ErrAlreadyConnected struct {
	Gateway string
	LeaseID gwvpn.LeaseID
}

func (e *ErrAlreadyConnected) Error() string {
	return fmt.Sprintf("already connected to %s (lease %s); disconnect first", e.Gateway, e.LeaseID)
}

// ErrInvalidOptions is returned for an agent built or called with a missing
// or invalid setting.
type ErrInvalidOptions struct {
	Field  string
	Reason string
}

func (e *ErrInvalidOptions) Error() string {
	return fmt.Sprintf("vpn agent: invalid %s: %s", e.Field, e.Reason)
}

// ErrGatewayUnreachable is returned when the request never got an answer.
type ErrGatewayUnreachable struct {
	Gateway string
	Cause   error
}

func (e *ErrGatewayUnreachable) Error() string {
	return fmt.Sprintf("gateway %s unreachable: %v", e.Gateway, e.Cause)
}

func (e *ErrGatewayUnreachable) Unwrap() error { return e.Cause }

// ErrInvalidResponse is returned when the gateway answered with something
// that is not the admission contract.
type ErrInvalidResponse struct {
	Gateway string
	Reason  string
}

func (e *ErrInvalidResponse) Error() string {
	return fmt.Sprintf("gateway %s: invalid response: %s", e.Gateway, e.Reason)
}

// ErrEvidence is returned when the agent could not produce one piece of its
// evidence: the device certificate, the quote, the posture report or the
// person factor.
type ErrEvidence struct {
	Step  string
	Cause error
}

func (e *ErrEvidence) Error() string {
	return fmt.Sprintf("collect %s: %v", e.Step, e.Cause)
}

func (e *ErrEvidence) Unwrap() error { return e.Cause }

// ErrPostureFact is returned when one posture fact could not be read. A
// fact the host does not have (no efivarfs, no securityfs) is reported as
// unavailable rather than as this error.
type ErrPostureFact struct {
	Fact  string
	Cause error
}

func (e *ErrPostureFact) Error() string {
	return fmt.Sprintf("posture fact %s: %v", e.Fact, e.Cause)
}

func (e *ErrPostureFact) Unwrap() error { return e.Cause }

// ErrNoRootMount is returned when the mount table has no root mount.
type ErrNoRootMount struct {
	MountInfo string
}

func (e *ErrNoRootMount) Error() string {
	return "no root mount in " + e.MountInfo
}

// ErrDataPlaneUnsupported is returned when this build has no client for the
// data plane: WireGuard in a FIPS build.
type ErrDataPlaneUnsupported struct {
	Kind gwvpn.DataPlaneKind
}

func (e *ErrDataPlaneUnsupported) Error() string {
	return fmt.Sprintf("data plane %s not available", e.Kind)
}

// ErrDataPlane is returned when the client data plane failed to come up or
// go down.
type ErrDataPlane struct {
	Op    string
	Kind  gwvpn.DataPlaneKind
	Cause error
}

func (e *ErrDataPlane) Error() string {
	return fmt.Sprintf("data plane %s %s: %v", e.Kind, e.Op, e.Cause)
}

func (e *ErrDataPlane) Unwrap() error { return e.Cause }

// ErrLeaseUnusable is returned when the lease the gateway answered cannot set
// up the data plane it names: no endpoint, or a key, endpoint, address or
// route the client cannot use. The agent revokes such a lease.
type ErrLeaseUnusable struct {
	Kind   gwvpn.DataPlaneKind
	Reason string
	Cause  error
}

func (e *ErrLeaseUnusable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("data plane %s: unusable lease: %s: %v", e.Kind, e.Reason, e.Cause)
	}
	return fmt.Sprintf("data plane %s: unusable lease: %s", e.Kind, e.Reason)
}

func (e *ErrLeaseUnusable) Unwrap() error { return e.Cause }

// ErrNotPrepared is returned when a data plane is brought up without the key
// Prepare made for the admission, or a second time with the same key.
type ErrNotPrepared struct {
	Kind gwvpn.DataPlaneKind
}

func (e *ErrNotPrepared) Error() string {
	return fmt.Sprintf("data plane %s: no client key was prepared for this lease", e.Kind)
}

// ErrSessionRefused is returned when the gateway answered the CONNECT-IP
// request with a status other than success: it holds no lease for the
// certificate presented, or the request was not one it serves.
type ErrSessionRefused struct {
	Gateway string
	Status  int
}

func (e *ErrSessionRefused) Error() string {
	return fmt.Sprintf("gateway %s refused the MASQUE session: HTTP %d", e.Gateway, e.Status)
}

// ErrAddressNotAssigned is returned when the session's assigned addresses do
// not include the address the lease names.
type ErrAddressNotAssigned struct {
	Kind     gwvpn.DataPlaneKind
	Lease    netip.Prefix
	Assigned []netip.Prefix
}

func (e *ErrAddressNotAssigned) Error() string {
	return fmt.Sprintf("data plane %s: the gateway assigned %v, not the lease address %s", e.Kind, e.Assigned, e.Lease)
}

// ErrStateStore is returned when the lease state file could not be read,
// written or removed.
type ErrStateStore struct {
	Op    string
	Path  string
	Cause error
}

func (e *ErrStateStore) Error() string {
	return fmt.Sprintf("vpn state %s %s: %v", e.Op, e.Path, e.Cause)
}

func (e *ErrStateStore) Unwrap() error { return e.Cause }

// ErrLeaseLapsed is returned by KeepAlive when the lease expired before any
// renewal succeeded; Cause is the last renewal's failure.
type ErrLeaseLapsed struct {
	LeaseID gwvpn.LeaseID
	Cause   error
}

func (e *ErrLeaseLapsed) Error() string {
	return fmt.Sprintf("lease %s expired before it could be renewed: %v", e.LeaseID, e.Cause)
}

func (e *ErrLeaseLapsed) Unwrap() error { return e.Cause }

// ErrRollback is returned when Connect failed after admission, or a renewal
// ended the lease, and undoing the admission or tearing the lease down failed
// too. It unwraps to the failure only, so the exit code reflects what went
// wrong rather than the cleanup.
type ErrRollback struct {
	Cause    error
	Rollback error
}

func (e *ErrRollback) Error() string {
	return fmt.Sprintf("%v (rollback: %v)", e.Cause, e.Rollback)
}

func (e *ErrRollback) Unwrap() error { return e.Cause }
