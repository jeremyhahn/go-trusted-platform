// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package verdict carries the outcome of a device quote verification from
// the transport-facing verifier to whoever acts on it: the attestation event
// log and the SDN quarantine observers. It is a leaf package so both the API
// daemon (which produces verdicts) and the attestation service (which
// consumes them) can depend on it without depending on each other.
package verdict

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/deviceverdict"
)

// DeviceVerdict is the result of verifying one quote from one device.
type DeviceVerdict = deviceverdict.DeviceVerdict

// RecordedDeviceVerdict is a device verdict with the event-log timestamp that
// made it durable.
type RecordedDeviceVerdict = deviceverdict.RecordedDeviceVerdict

// Sink receives device verdicts. The attestation service implements it by
// writing an event and notifying its quarantine observers.
type Sink interface {
	RecordDeviceVerdict(ctx context.Context, v DeviceVerdict) error
}

// ErrInvalidVerdict reports a verdict that violates its own invariants.
type ErrInvalidVerdict = deviceverdict.ErrInvalidVerdict
