// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package verdict

import "context"

// AttestCertEvent is the audit record of one server-side attempt to record a
// device's attestation certificate on its platform record. The outcome is
// either recorded (the certificate parsed, chained to the platform CA,
// carried tcg-cap-verifiedTPMRestricted and certified the device's enrolled
// attestation key) or refused (no candidate certificate did), and a refusal
// changes nothing on the device record — unless the operator asked for a
// refused certificate to be cleared, in which case the outcome is cleared:
// the record's certificate was removed because no candidate passed.
type AttestCertEvent struct {
	// DeviceID is the platform device record the attempt was for.
	DeviceID uint64
	// HostID is the device's enrolled hostname (IDevID CN) when known.
	HostID string
	// Serial is the device serial number when known.
	Serial string
	// Recorded is true when the device record was written.
	Recorded bool
	// Source names where the recorded certificate came from ("device",
	// "ca", "reissued"); empty when refused.
	Source string
	// Subject is the recorded certificate's subject; empty when refused.
	Subject string
	// Reissued is true when the CA was asked to issue a new attestation
	// certificate during the attempt, whether or not it was then recorded.
	Reissued bool
	// Cleared is true when every candidate was refused and the operator's
	// explicit request removed the certificate the record held. Subject then
	// names the removed certificate when it parsed.
	Cleared bool
	// Reason is the refusal detail; empty when Recorded.
	Reason string
}

// Validate reports whether the event is internally consistent: a recorded
// event names its source and carries no reason, a refused one carries a
// reason, and a cleared one is not recorded and carries the refusal that
// justified the clear.
func (e AttestCertEvent) Validate() error {
	if e.DeviceID == 0 {
		return ErrInvalidVerdict{Reason: "device ID is required"}
	}
	if e.Recorded && e.Reason != "" {
		return ErrInvalidVerdict{Reason: "a recorded certificate carries no refusal reason"}
	}
	if e.Recorded && e.Cleared {
		return ErrInvalidVerdict{Reason: "a certificate is either recorded or cleared, not both"}
	}
	if e.Recorded && e.Source == "" {
		return ErrInvalidVerdict{Reason: "a recorded certificate names its source"}
	}
	if !e.Recorded && e.Reason == "" {
		return ErrInvalidVerdict{Reason: "a refused certificate carries a reason"}
	}
	return nil
}

// AttestCertSink receives attestation-certificate record events. The
// attestation service implements it by writing an event to the attestation
// store; it never notifies the quarantine observers, because recording a
// certificate is not a verdict — the collector's next sweep produces that.
type AttestCertSink interface {
	RecordAttestCert(ctx context.Context, e AttestCertEvent) error
}
