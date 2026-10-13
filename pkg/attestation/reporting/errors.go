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

package reporting

import (
	"strconv"
	"time"
)

// ErrNoQuoteSource reports a collector constructed without a way to reach
// devices. It fails at construction rather than producing a collector that
// silently collects nothing.
type ErrNoQuoteSource struct{}

func (ErrNoQuoteSource) Error() string {
	return "attestation reporting: a quote source is required"
}

// ErrNoVerifier reports a collector constructed without a verifier. Fails
// closed: a collector that stored unverified evidence would fill the cache
// with reports asserting a verification that never ran.
type ErrNoVerifier struct{}

func (ErrNoVerifier) Error() string {
	return "attestation reporting: a verifier is required"
}

// ErrCollectionFailed reports that evidence could not be obtained from a
// device. It is deliberately DISTINCT from a failed verification: a device
// that could not be reached has not failed attestation, it has produced no
// evidence, and conflating the two quarantines healthy nodes (#197).
type ErrCollectionFailed struct {
	DeviceID string
	Cause    error
}

func (e ErrCollectionFailed) Error() string {
	return "attestation reporting: could not collect evidence from device " +
		e.DeviceID + ": " + e.Cause.Error()
}

func (e ErrCollectionFailed) Unwrap() error { return e.Cause }

// ErrVerificationUnavailable reports that the verifier could not evaluate the
// evidence at all — malformed evidence, an unknown device, no trust anchor.
// Also distinct from a negative verdict, for the same reason.
type ErrVerificationUnavailable struct {
	DeviceID string
	Cause    error
}

func (e ErrVerificationUnavailable) Error() string {
	return "attestation reporting: could not verify evidence for device " +
		e.DeviceID + ": " + e.Cause.Error()
}

func (e ErrVerificationUnavailable) Unwrap() error { return e.Cause }

// ErrCollectorStopped reports work enqueued against a collector that is not
// running.
type ErrCollectorStopped struct{}

func (ErrCollectorStopped) Error() string {
	return "attestation reporting: collector is not running"
}

// DefaultInterval is the refresh cycle when none is configured. The owner
// requirement for #226 states 15 minutes, configurable.
const DefaultInterval = 15 * time.Minute

// DefaultTTL is the freshness window when none is configured.
//
// It is deliberately LONGER than DefaultInterval. A TTL shorter than the
// refresh cycle would mark every report stale before its replacement was due,
// so the cache would report nothing fresh no matter how healthy the fleet —
// a budget that cannot be satisfied by correct behaviour. Twice the interval
// leaves room for one missed cycle before a report is called stale.
const DefaultTTL = 2 * DefaultInterval

// ErrInvalidEvidence reports a node response that is not usable as evidence.
// It is a collection failure, never a verdict.
type ErrInvalidEvidence struct {
	Reason string
}

func (e ErrInvalidEvidence) Error() string {
	return "attestation reporting: invalid evidence: " + e.Reason
}

// ErrNonceMismatch reports a node that answered with a different nonce than
// the one it was sent. The response is about some other collection, or a
// replay, and is refused before it reaches the verifier.
type ErrNonceMismatch struct{}

func (ErrNonceMismatch) Error() string {
	return "attestation reporting: node did not echo the collector's nonce"
}

// ErrNoDeviceRecords reports an address resolver built without a device
// source.
type ErrNoDeviceRecords struct{}

func (ErrNoDeviceRecords) Error() string {
	return "attestation reporting: a device record source is required to resolve addresses"
}

// ErrInvalidPort reports an out-of-range quote port.
type ErrInvalidPort struct {
	Port int
}

func (e ErrInvalidPort) Error() string {
	return "attestation reporting: invalid node quote port " + itoa(e.Port)
}

// ErrNoDialableAddress reports a device the platform has no trustworthy
// address for. The collector fails closed: it does not guess, and it does
// not read an address out of a request body.
type ErrNoDialableAddress struct {
	DeviceID string
	Reason   string
}

func (e ErrNoDialableAddress) Error() string {
	return "attestation reporting: device " + e.DeviceID + " has no dialable address: " + e.Reason
}

// ErrNoAddressResolver reports a quote source built without a resolver.
type ErrNoAddressResolver struct{}

func (ErrNoAddressResolver) Error() string {
	return "attestation reporting: an address resolver is required"
}

// ErrNoTLSDialer reports a quote source built without a TLS dialer, or a
// dialer that produced no configuration.
type ErrNoTLSDialer struct{}

func (ErrNoTLSDialer) Error() string {
	return "attestation reporting: a TLS dialer is required; the collector never dials without an identity and a trust anchor"
}

// ErrInsecureDialer reports a TLS configuration with verification disabled.
type ErrInsecureDialer struct {
	Endpoint string
}

func (e ErrInsecureDialer) Error() string {
	return "attestation reporting: refusing to dial " + e.Endpoint + " with certificate verification disabled"
}

// ErrChannelBinding reports a node connection that cannot yield a channel
// binding (TLS 1.2 without the extended master secret). The collector refuses
// to fall back to an unbound nonce: a quote it cannot tie to the session is
// not collected at all.
type ErrChannelBinding struct {
	Endpoint string
	Cause    error
}

func (e ErrChannelBinding) Error() string {
	msg := "attestation reporting: no channel binding on the connection to " + e.Endpoint
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e ErrChannelBinding) Unwrap() error { return e.Cause }

// ErrQuoteNotBound reports a node that answered with a quote over something
// other than the collector's nonce bound to this connection (#482). A node
// derives the binding from its own end of the connection, so the values
// differ exactly when the endpoint relayed the request over a connection of
// its own: the attested state is not the TLS endpoint's, and is refused.
type ErrQuoteNotBound struct {
	Endpoint string
}

func (e ErrQuoteNotBound) Error() string {
	return "attestation reporting: the quote from " + e.Endpoint +
		" is not bound to this connection"
}

// ErrConnectionSpent reports the HTTP transport asking for a second
// connection to a node. Each request rides exactly the connection its channel
// binding was derived from; a redial would silently unbind it.
type ErrConnectionSpent struct {
	Endpoint string
}

func (e ErrConnectionSpent) Error() string {
	return "attestation reporting: the connection to " + e.Endpoint + " was already used; refusing to redial"
}

// ErrNodeUnreachable reports that no candidate endpoint yielded evidence.
// Causes holds each endpoint's error, so a caller can still tell a refused
// quote (ErrQuoteNotBound) from a node that could not be reached.
type ErrNodeUnreachable struct {
	DeviceID string
	Attempts []string
	Causes   []error
}

func (e ErrNodeUnreachable) Unwrap() []error { return e.Causes }

func (e ErrNodeUnreachable) Error() string {
	msg := "attestation reporting: no endpoint of device " + e.DeviceID + " yielded evidence"
	for _, a := range e.Attempts {
		msg += "; " + a
	}
	return msg
}

// ErrNodeRefused reports a non-200 answer from a node. A 401 or 403 here
// means the node's caller-admission policy refused this reporting server.
type ErrNodeRefused struct {
	Endpoint string
	Status   int
	Body     string
}

func (e ErrNodeRefused) Error() string {
	return "attestation reporting: " + e.Endpoint + " answered HTTP " + itoa(e.Status) + ": " + e.Body
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

// ErrClockStateUnavailable reports that no candidate endpoint answered with
// the device's clock state. The collector records the state as unknown; it
// never records it as unsynced.
type ErrClockStateUnavailable struct {
	DeviceID string
	Attempts []string
}

func (e ErrClockStateUnavailable) Error() string {
	msg := "attestation reporting: no endpoint of device " + e.DeviceID + " reported clock state"
	for _, a := range e.Attempts {
		msg += "; " + a
	}
	return msg
}

// ErrInvalidClockState reports a node answer that is not a usable clock
// state. Like ErrClockStateUnavailable it yields an unknown state, never a
// negative one.
type ErrInvalidClockState struct {
	Reason string
}

func (e ErrInvalidClockState) Error() string {
	return "attestation reporting: invalid clock state: " + e.Reason
}
