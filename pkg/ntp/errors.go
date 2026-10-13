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

package ntp

import (
	"strconv"
	"strings"
)

// causeText renders a wrapped cause, tolerating a nil Cause so an error value
// constructed without one (or decoded from the wire) never panics on Error().
func causeText(cause error) string {
	if cause == nil {
		return "unknown cause"
	}
	return cause.Error()
}

// ErrNilConfig is returned when a Service is constructed without a Config.
type ErrNilConfig struct{}

// Error implements the error interface.
func (ErrNilConfig) Error() string { return "ntp: configuration is nil" }

// ErrInvalidMode is returned when the mode is not serve, consume, or both.
type ErrInvalidMode struct{ Mode string }

// Error implements the error interface.
func (e ErrInvalidMode) Error() string {
	return "ntp: invalid mode " + strconv.Quote(e.Mode) + " (want serve, consume, or both)"
}

// ErrInvalidTimeoutAction is returned when startup-gate.on-timeout is not a
// recognized action.
type ErrInvalidTimeoutAction struct{ Action string }

// Error implements the error interface.
func (e ErrInvalidTimeoutAction) Error() string {
	return "ntp: invalid startup-gate.on-timeout " + strconv.Quote(e.Action) +
		" (want warn-and-continue or fail-startup)"
}

// ErrMissingConsumeSection is returned when the mode consumes time but no
// consume section is present.
type ErrMissingConsumeSection struct{ Mode string }

// Error implements the error interface.
func (e ErrMissingConsumeSection) Error() string {
	return "ntp: mode " + strconv.Quote(e.Mode) + " requires a consume section"
}

// ErrMissingServeSection is returned when the mode serves time but no serve
// section is present.
type ErrMissingServeSection struct{ Mode string }

// Error implements the error interface.
func (e ErrMissingServeSection) Error() string {
	return "ntp: mode " + strconv.Quote(e.Mode) + " requires a serve section"
}

// ErrNoUpstream is returned when a consuming node has neither an upstream
// source nor orphan fallback enabled.
type ErrNoUpstream struct{}

// Error implements the error interface.
func (ErrNoUpstream) Error() string {
	return "ntp: consume.upstream is empty and consume.orphan-fallback is false; " +
		"the node would have no time source"
}

// ErrEmptyUpstreamAddress is returned when an upstream entry has no address.
type ErrEmptyUpstreamAddress struct{ Index int }

// Error implements the error interface.
func (e ErrEmptyUpstreamAddress) Error() string {
	return "ntp: consume.upstream[" + strconv.Itoa(e.Index) + "].address is empty"
}

// ErrInvalidUpstreamAddress is returned when an upstream address contains
// characters that cannot appear in a chrony.conf directive.
type ErrInvalidUpstreamAddress struct{ Address string }

// Error implements the error interface.
func (e ErrInvalidUpstreamAddress) Error() string {
	return "ntp: invalid upstream address " + strconv.Quote(e.Address)
}

// ErrNoListenNetworks is returned when a serving node has no allow-list.
type ErrNoListenNetworks struct{}

// Error implements the error interface.
func (ErrNoListenNetworks) Error() string {
	return "ntp: serve.listen-networks is empty; an explicit CIDR allow-list is required"
}

// ErrInvalidListenNetwork is returned when a serve allow-list entry is not a
// valid CIDR.
type ErrInvalidListenNetwork struct {
	Network string
	Cause   error
}

// Error implements the error interface.
func (e ErrInvalidListenNetwork) Error() string {
	return "ntp: invalid serve.listen-networks entry " + strconv.Quote(e.Network) + ": " + causeText(e.Cause)
}

// Unwrap returns the underlying parse failure.
func (e ErrInvalidListenNetwork) Unwrap() error { return e.Cause }

// ErrUnrestrictedListenNetwork is returned when a serve allow-list entry would
// expose the NTP server to the entire internet.
type ErrUnrestrictedListenNetwork struct{ Network string }

// Error implements the error interface.
func (e ErrUnrestrictedListenNetwork) Error() string {
	return "ntp: serve.listen-networks entry " + strconv.Quote(e.Network) +
		" is unrestricted; an explicit non-default CIDR allow-list is required"
}

// ErrInvalidLocalStratum is returned when serve.local-stratum is out of range.
type ErrInvalidLocalStratum struct{ Stratum int }

// Error implements the error interface.
func (e ErrInvalidLocalStratum) Error() string {
	return "ntp: serve.local-stratum " + strconv.Itoa(e.Stratum) + " out of range (1-15)"
}

// ErrInvalidNTSKEPort is returned when serve.nts.port is not a TCP port.
type ErrInvalidNTSKEPort struct{ Port int }

// Error implements the error interface.
func (e ErrInvalidNTSKEPort) Error() string {
	return "ntp: serve.nts.port " + strconv.Itoa(e.Port) + " out of range (1-65535)"
}

// ErrMissingNTSMaterial is returned when NTS serving is enabled without both a
// certificate and a key reference.
type ErrMissingNTSMaterial struct{ Field string }

// Error implements the error interface.
func (e ErrMissingNTSMaterial) Error() string {
	return "ntp: serve.nts.enabled requires " + e.Field
}

// ErrInvalidNTSVersionLink is returned when the material store's `current`
// symlink names something other than an internally generated version
// directory. The store never follows such a target — a tampered link must
// not lead reads or cleanup outside the material directory.
type ErrInvalidNTSVersionLink struct{ Target string }

// Error implements the error interface.
func (e ErrInvalidNTSVersionLink) Error() string {
	return "ntp: NTS material store current link names an invalid version target " +
		strconv.Quote(e.Target)
}

// ErrRotatedNTSMaterialLost is returned when the versioned NTS material
// store no longer holds the pair the last rotation deployed. The rotated
// private key is not retained in process memory, so the pair cannot be
// republished from here — a daemon restart re-resolves it from the KMS,
// which certificate renewal writes before deploying.
type ErrRotatedNTSMaterialLost struct{ Cause error }

// Error implements the error interface.
func (e ErrRotatedNTSMaterialLost) Error() string {
	msg := "ntp: rotated NTS material is no longer published in the material store; " +
		"restart the daemon to re-resolve the pair from the KMS"
	if e.Cause != nil {
		msg += ": " + causeText(e.Cause)
	}
	return msg
}

// Unwrap returns the underlying error.
func (e ErrRotatedNTSMaterialLost) Unwrap() error { return e.Cause }

// ErrNTSKeyEnclaveUnavailable is returned when the protected-memory enclave
// carrying a rotation's private key cannot be borrowed — it was destroyed,
// or its locked region was never allocated. Deployment fails closed: the
// service never falls back to an unprotected copy of the key.
type ErrNTSKeyEnclaveUnavailable struct{ Cause error }

// Error implements the error interface.
func (e ErrNTSKeyEnclaveUnavailable) Error() string {
	msg := "ntp: the rotated NTS private key enclave is unavailable"
	if e.Cause != nil {
		msg += ": " + causeText(e.Cause)
	}
	return msg
}

// Unwrap returns the underlying error.
func (e ErrNTSKeyEnclaveUnavailable) Unwrap() error { return e.Cause }

// ErrInvalidGateTimeout is returned when the startup gate would block forever
// or for a non-positive duration.
type ErrInvalidGateTimeout struct{ Seconds float64 }

// Error implements the error interface.
func (e ErrInvalidGateTimeout) Error() string {
	return "ntp: startup-gate.timeout must be positive, got " +
		strconv.FormatFloat(e.Seconds, 'f', -1, 64) + "s"
}

// ErrRenderFailed is returned when the chrony.conf template cannot be rendered.
type ErrRenderFailed struct{ Cause error }

// Error implements the error interface.
func (e ErrRenderFailed) Error() string {
	return "ntp: chrony.conf render failed: " + causeText(e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrRenderFailed) Unwrap() error { return e.Cause }

// ErrWriteConfigFailed is returned when chrony.conf cannot be written.
type ErrWriteConfigFailed struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e ErrWriteConfigFailed) Error() string {
	return "ntp: failed to write " + e.Path + ": " + causeText(e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrWriteConfigFailed) Unwrap() error { return e.Cause }

// ErrServiceCommandFailed is returned when an OpenRC service command fails.
type ErrServiceCommandFailed struct {
	Service string
	Action  string
	Output  string
	Cause   error
}

// Error implements the error interface.
func (e ErrServiceCommandFailed) Error() string {
	msg := "ntp: rc-service " + e.Service + " " + e.Action + " failed: " + causeText(e.Cause)
	if trimmed := strings.TrimSpace(e.Output); trimmed != "" {
		msg += " (" + trimmed + ")"
	}
	return msg
}

// Unwrap returns the underlying error.
func (e ErrServiceCommandFailed) Unwrap() error { return e.Cause }

// ErrControlUnavailable is returned when chronyd's control socket cannot be
// reached.
type ErrControlUnavailable struct {
	Command string
	Output  string
	Cause   error
}

// Error implements the error interface.
func (e ErrControlUnavailable) Error() string {
	msg := "ntp: chrony control command " + strconv.Quote(e.Command) + " failed: " + causeText(e.Cause)
	if trimmed := strings.TrimSpace(e.Output); trimmed != "" {
		msg += " (" + trimmed + ")"
	}
	return msg
}

// Unwrap returns the underlying error.
func (e ErrControlUnavailable) Unwrap() error { return e.Cause }

// ErrMalformedControlOutput is returned when chronyd's CSV output does not
// carry the expected number of fields.
type ErrMalformedControlOutput struct {
	Command string
	Line    string
	Want    int
	Got     int
}

// Error implements the error interface.
func (e ErrMalformedControlOutput) Error() string {
	return "ntp: malformed " + e.Command + " output: want " + strconv.Itoa(e.Want) +
		" fields, got " + strconv.Itoa(e.Got) + " in " + strconv.Quote(e.Line)
}

// ErrSyncTimeout is returned when the startup gate expires before chronyd
// reports a synchronized clock.
type ErrSyncTimeout struct{ Seconds float64 }

// Error implements the error interface.
func (e ErrSyncTimeout) Error() string {
	return "ntp: clock did not synchronize within " +
		strconv.FormatFloat(e.Seconds, 'f', -1, 64) + "s"
}

// ErrNoReachableSource is returned by Step when chronyd has no reachable
// source to step towards.
type ErrNoReachableSource struct{ Total int }

// Error implements the error interface.
func (e ErrNoReachableSource) Error() string {
	return "ntp: no reachable time source (" + strconv.Itoa(e.Total) + " configured)"
}

// ErrRTCWriteFailed is returned when the system clock cannot be written back
// to the hardware clock.
type ErrRTCWriteFailed struct {
	Output string
	Cause  error
}

// Error implements the error interface.
func (e ErrRTCWriteFailed) Error() string {
	msg := "ntp: hwclock --systohc failed: " + causeText(e.Cause)
	if trimmed := strings.TrimSpace(e.Output); trimmed != "" {
		msg += " (" + trimmed + ")"
	}
	return msg
}

// Unwrap returns the underlying error.
func (e ErrRTCWriteFailed) Unwrap() error { return e.Cause }

// ErrDisabled is returned by service operations when the ntp section is
// absent or disabled, so callers can distinguish "not configured" from
// "configured but broken".
type ErrDisabled struct{}

// Error implements the error interface.
func (ErrDisabled) Error() string { return "ntp: time synchronization is not enabled" }

// ErrUnresolvedNTSMaterial is returned when an NTS certificate or key field
// still holds a secret reference (kms://, secret://, file://) at the point
// chronyd needs the material on disk. Serving unauthenticated time instead
// would be a silent security downgrade, so this is fatal for the NTP service.
type ErrUnresolvedNTSMaterial struct {
	Field string
	Value string
}

// Error implements the error interface.
func (e ErrUnresolvedNTSMaterial) Error() string {
	return "ntp: " + e.Field + " is still an unresolved secret reference " +
		strconv.Quote(e.Value) + "; the secrets engine must resolve it before chronyd starts"
}

// ErrInvalidNTSServerName is returned when a serve.nts.server-names entry
// cannot become a DNS SAN on the served NTS-KE certificate.
type ErrInvalidNTSServerName struct {
	Name   string
	Reason string
}

// Error implements the error interface.
func (e ErrInvalidNTSServerName) Error() string {
	return "ntp: serve.nts.server-names entry " + strconv.Quote(e.Name) + " is " + e.Reason
}
