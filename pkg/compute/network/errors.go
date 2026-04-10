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

package network

import "fmt"

// ErrAuthFailed indicates that authentication failed.
type ErrAuthFailed struct {
	PortID string
	Reason string
	Cause  error
}

func (e ErrAuthFailed) Error() string {
	msg := "network: authentication failed"
	if e.PortID != "" {
		msg = fmt.Sprintf("%s for port %q", msg, e.PortID)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrAuthFailed) Unwrap() error {
	return e.Cause
}

// ErrCertInvalid indicates that the certificate is invalid.
type ErrCertInvalid struct {
	Subject string
	Reason  string
	Cause   error
}

func (e ErrCertInvalid) Error() string {
	msg := "network: certificate invalid"
	if e.Subject != "" {
		msg = fmt.Sprintf("%s for subject %q", msg, e.Subject)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrCertInvalid) Unwrap() error {
	return e.Cause
}

// ErrPolicyViolation indicates a policy violation.
type ErrPolicyViolation struct {
	PortID   string
	PolicyID string
	Reason   string
	Details  []string
}

func (e ErrPolicyViolation) Error() string {
	msg := "network: policy violation"
	if e.PortID != "" {
		msg = fmt.Sprintf("%s for port %q", msg, e.PortID)
	}
	if e.PolicyID != "" {
		msg = fmt.Sprintf("%s (policy=%q)", msg, e.PolicyID)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrAttestFailed indicates that attestation failed.
type ErrAttestFailed struct {
	DeviceID string
	Reason   string
	Cause    error
}

func (e ErrAttestFailed) Error() string {
	msg := "network: attestation failed"
	if e.DeviceID != "" {
		msg = fmt.Sprintf("%s for device %q", msg, e.DeviceID)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrAttestFailed) Unwrap() error {
	return e.Cause
}

// ErrVLANFailed indicates that a VLAN operation failed.
type ErrVLANFailed struct {
	PortID   string
	FromVLAN uint16
	ToVLAN   uint16
	Reason   string
	Cause    error
}

func (e ErrVLANFailed) Error() string {
	msg := "network: VLAN operation failed"
	if e.PortID != "" {
		msg = fmt.Sprintf("%s for port %q", msg, e.PortID)
	}
	if e.FromVLAN != 0 || e.ToVLAN != 0 {
		msg = fmt.Sprintf("%s (from=%d, to=%d)", msg, e.FromVLAN, e.ToVLAN)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrVLANFailed) Unwrap() error {
	return e.Cause
}

// ErrOPAEvaluation indicates an OPA policy evaluation error.
type ErrOPAEvaluation struct {
	Endpoint   string
	PolicyPath string
	Reason     string
	Cause      error
}

func (e ErrOPAEvaluation) Error() string {
	msg := "network: OPA evaluation failed"
	if e.PolicyPath != "" {
		msg = fmt.Sprintf("%s (policy=%q)", msg, e.PolicyPath)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrOPAEvaluation) Unwrap() error {
	return e.Cause
}

// ErrFlowRule indicates an OpenFlow rule error.
type ErrFlowRule struct {
	PortID    string
	RuleID    string
	Operation string
	Reason    string
	Cause     error
}

func (e ErrFlowRule) Error() string {
	msg := "network: OpenFlow rule error"
	if e.Operation != "" {
		msg = fmt.Sprintf("%s during %s", msg, e.Operation)
	}
	if e.PortID != "" {
		msg = fmt.Sprintf("%s for port %q", msg, e.PortID)
	}
	if e.RuleID != "" {
		msg = fmt.Sprintf("%s (rule=%q)", msg, e.RuleID)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrFlowRule) Unwrap() error {
	return e.Cause
}

// ErrInvalidConfig indicates invalid configuration.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("network: invalid config for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("network: invalid config: %s", e.Reason)
}

// ErrContextCanceled indicates the operation was canceled via context.
type ErrContextCanceled struct {
	Operation string
}

func (e ErrContextCanceled) Error() string {
	if e.Operation != "" {
		return fmt.Sprintf("network: %s canceled", e.Operation)
	}
	return "network: operation canceled"
}

// ErrServiceNotInitialized indicates the service is not initialized.
type ErrServiceNotInitialized struct{}

func (e ErrServiceNotInitialized) Error() string {
	return "network: service not initialized"
}

// ErrPortNotFound indicates that a port was not found.
type ErrPortNotFound struct {
	PortID string
}

func (e ErrPortNotFound) Error() string {
	if e.PortID != "" {
		return fmt.Sprintf("network: port %q not found", e.PortID)
	}
	return "network: port not found"
}

// ErrSessionExpired indicates that an authentication session has expired.
type ErrSessionExpired struct {
	SessionID string
	PortID    string
}

func (e ErrSessionExpired) Error() string {
	msg := "network: session expired"
	if e.SessionID != "" {
		msg = fmt.Sprintf("%s (session=%q)", msg, e.SessionID)
	}
	if e.PortID != "" {
		msg = fmt.Sprintf("%s for port %q", msg, e.PortID)
	}
	return msg
}

// ErrStateTransition indicates an invalid state transition.
type ErrStateTransition struct {
	PortID    string
	FromState AuthState
	ToState   AuthState
	Reason    string
}

func (e ErrStateTransition) Error() string {
	msg := fmt.Sprintf("network: invalid state transition from %q to %q", e.FromState, e.ToState)
	if e.PortID != "" {
		msg = fmt.Sprintf("%s for port %q", msg, e.PortID)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrOIDMissing indicates that a required OID is missing from the certificate.
type ErrOIDMissing struct {
	OID     string
	Subject string
}

func (e ErrOIDMissing) Error() string {
	msg := fmt.Sprintf("network: required OID %q missing", e.OID)
	if e.Subject != "" {
		msg = fmt.Sprintf("%s from certificate %q", msg, e.Subject)
	}
	return msg
}

// ErrReattestRequired indicates that re-attestation is required.
type ErrReattestRequired struct {
	PortID   string
	LastTime string
}

func (e ErrReattestRequired) Error() string {
	msg := "network: re-attestation required"
	if e.PortID != "" {
		msg = fmt.Sprintf("%s for port %q", msg, e.PortID)
	}
	if e.LastTime != "" {
		msg = fmt.Sprintf("%s (last=%s)", msg, e.LastTime)
	}
	return msg
}
