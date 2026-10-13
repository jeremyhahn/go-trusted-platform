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

// Observer is handed every device verdict once it is in the event log: passed,
// cryptographic failure, and absence of evidence alike. Relying parties that
// withdraw service from a device on any failed verdict subscribe here; the
// quarantine loop observes the attestation service instead, which never
// reports an absence of evidence as a failure. Observers are called
// synchronously and must not block.
type Observer interface {
	OnDeviceVerdict(ctx context.Context, recorded RecordedDeviceVerdict)
}

// ObserverRegistry is implemented by a Sink that hands every verdict it
// records to its observers.
type ObserverRegistry interface {
	RegisterDeviceVerdictObserver(obs Observer)
}

// ErrInvalidVerdict reports a verdict that violates its own invariants.
type ErrInvalidVerdict = deviceverdict.ErrInvalidVerdict
