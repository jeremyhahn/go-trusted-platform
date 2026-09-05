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

// Package reporting collects device attestation evidence on a schedule,
// verifies it, and serves the cached result.
//
// # The invariant
//
// No inbound request may cause a TPM quote. The collector is the only
// component that ever asks a device for evidence; request handlers read the
// cache. This is what stops repeated requests from exhausting a device's TPM,
// and it is structural rather than a setting: a caller holding a Reader has
// no method that can reach a device, because Reader does not have one and the
// cache holds no reference to the quote source.
//
// An operator action MAY trigger fresh collection — Collector.Enqueue — but
// that goes through the collector, which applies the same TTL, de-duplication
// and per-device serialization it applies to scheduled work. What is
// forbidden is a handler talking to a device directly.
//
// # Freshness
//
// A cached report is by definition evidence about a past instant, bound to
// the nonce that was fresh when it was collected. Serving it is sound because
// every report carries CollectedAt and callers render the age beside the
// verdict: the claim is "this device attested at T", never "this device is
// attested now". Attestation cannot prove continuous integrity, and a
// consumer that hides the age converts a true statement into a false one.
package reporting

import "time"

// Report is a verified attestation result for one device at one instant.
//
// It is the collector's output and the cache's unit. Every field an operator
// or a console needs to judge the result is on it, including the checks that
// individually passed or failed — a caller must be able to say WHICH check
// failed, not merely that one did.
type Report struct {
	// DeviceID is the device this report concerns.
	DeviceID string

	// Serial and Model identify the device for display. Carried on the report
	// so a console rendering the cache needs no second lookup.
	Serial string
	Model  string

	// Verified is the overall verdict: true only when every check that ran
	// passed.
	Verified bool

	// SignatureValid, NonceValid and PCRsValid report the individual checks.
	SignatureValid bool
	NonceValid     bool
	PCRsValid      bool

	// Status is the verifier's own verdict word ("verified" / "failed").
	Status string

	// Message explains a negative verdict.
	Message string

	// CollectedAt is when the evidence was collected and verified. It is the
	// report's age, and consumers MUST render it beside the verdict: a cached
	// report presented without its age asserts a freshness it does not have.
	CollectedAt time.Time
}

// Age returns how long ago the report was collected, as of now.
func (r *Report) Age(now time.Time) time.Duration {
	return now.Sub(r.CollectedAt)
}

// Reader is the read-only view of collected reports — the whole of what a
// request handler is given.
//
// It is a separate interface from the collector, and that separation is the
// invariant rather than a convenience. There is deliberately no method here
// that collects, refreshes, or blocks: a handler holding a Reader cannot
// reach a device's TPM, because the type offers no way to and the cache it
// reads holds no reference to a quote source. Wiring a handler to something
// that can collect requires changing its dependency from Reader to something
// else, which is a visible change in a signature rather than a line added
// inside a method body.
type Reader interface {
	// Report returns the most recent verified report for a device, and
	// whether one exists. A device with no report yet returns false — never a
	// synthesised verdict, and never a fresh collection.
	Report(deviceID string) (*Report, bool)

	// Reports returns every cached report, for a fleet view.
	Reports() []*Report
}
