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

package provisioning

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

var (
	// ErrProfileFetchFailed is returned when the profile API request fails
	ErrProfileFetchFailed = errors.New("provisioning: failed to fetch device profile")

	// ErrActivationFailed is returned when the activation API request fails
	ErrActivationFailed = errors.New("provisioning: failed to activate device")

	// ErrHeartbeatFailed is returned when the heartbeat API request fails
	ErrHeartbeatFailed = errors.New("provisioning: failed to report device heartbeat")

	// ErrMissingCertificate is returned when IDevID certificate is not available
	ErrMissingCertificate = errors.New("provisioning: IDevID certificate not available")

	// ErrMissingPrivateKey is returned when IDevID private key is not available
	ErrMissingPrivateKey = errors.New("provisioning: IDevID private key not available")

	// ErrMissingCABundle is returned when CA bundle is not available
	ErrMissingCABundle = errors.New("provisioning: CA bundle not available")

	// ErrInvalidResponse is returned when the server response is invalid
	ErrInvalidResponse = errors.New("provisioning: invalid server response")

	// ErrServerError is returned when the server returns an error status
	ErrServerError = errors.New("provisioning: server returned error")

	// ErrConnectionFailed is returned when the connection to the server fails
	ErrConnectionFailed = errors.New("provisioning: connection to server failed")

	// ErrTimeout is returned when the request times out
	ErrTimeout = errors.New("provisioning: request timed out")

	// ErrBootCertificateFetchFailed is returned when a diskless node cannot
	// fetch its recorded IDevID chain back from the control plane
	ErrBootCertificateFetchFailed = errors.New("provisioning: failed to fetch boot certificate")

	// ErrBootDeliveryFailed is returned when the attested boot delivery fails
	ErrBootDeliveryFailed = errors.New("provisioning: boot delivery failed")

	// ErrBootIdentityRequired is returned when a boot certificate is
	// requested for no identity
	ErrBootIdentityRequired = errors.New("provisioning: boot identity is required")

	// ErrBootQuoteRequired is returned when a boot delivery is attempted
	// without a quote producer
	ErrBootQuoteRequired = errors.New("provisioning: boot delivery requires a quote producer")

	// ErrBootProofInvalid is returned when a boot-certificate proof does not
	// verify: another key, another identity, another connection, or no
	// connection value at all
	ErrBootProofInvalid = errors.New("provisioning: boot certificate proof does not verify")

	// ErrBootProofKeyUnsupported is returned when a boot-certificate proof is
	// made or checked with a key that is neither RSA nor ECDSA
	ErrBootProofKeyUnsupported = errors.New("provisioning: boot certificate proof key must be RSA or ECDSA")

	// ErrCertificateChainInvalid is returned when a PEM certificate chain
	// holds no certificate, or one that does not parse
	ErrCertificateChainInvalid = errors.New("provisioning: invalid PEM certificate chain")
)

// ErrBootChannelUnbound reports a TLS connection a boot delivery cannot be
// bound to: no connection state, a version below TLS 1.3, or an exporter
// that produced no keying material. The derivation lives in the SDK, so the
// error is the SDK's.
type ErrBootChannelUnbound = transport.ErrChannelUnbound

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
