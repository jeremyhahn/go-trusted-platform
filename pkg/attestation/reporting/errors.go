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

import "time"

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
