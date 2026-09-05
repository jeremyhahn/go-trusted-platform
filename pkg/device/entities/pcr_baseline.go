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

package entities

import (
	"strconv"
	"time"
)

// BaselineSource records how a PCR baseline came to be trusted. It is a
// first-class field rather than an inference because the two sources carry
// different guarantees, and the weaker one must never be invisible: a TOFU
// pass rendered identically to a signed-manifest pass is how the weaker
// level gets forgotten (docs/attestation/architecture.md, design of record).
type BaselineSource string

const (
	// BaselineSourceSigned means the expected values came from a signed
	// reference manifest published by the build that produced the image —
	// what the operator intended to ship, never what a node happened to boot.
	BaselineSourceSigned BaselineSource = "signed"

	// BaselineSourceTOFU means the expected values were captured from the
	// first successfully verified quote of a device in this profile. Trust
	// was conferred without independent evidence at that moment, which is
	// why recording a TOFU baseline is a security event.
	BaselineSourceTOFU BaselineSource = "tofu"
)

// PCRBaseline is the expected measured state for every device in a profile:
// the PCR values a quote must attest to before the platform reports the
// device Verified.
//
// The baseline is held by the platform and compared against the values a
// device reports. It is never taken from the evidence under verification —
// a baseline the attester supplies verifies only that the attester can copy
// its own PCRs into a second field (#373).
type PCRBaseline struct {
	// Values maps PCR index to the expected digest for that register.
	Values map[int][]byte `yaml:"values" json:"values"`

	// Source is how this baseline was established.
	Source BaselineSource `yaml:"source" json:"source"`

	// RecordedAt is when the baseline was established.
	RecordedAt time.Time `yaml:"recorded_at" json:"recorded_at"`

	// RecordedFromDeviceID names the device whose quote seeded a TOFU
	// baseline. Zero for a signed baseline, which has no seeding device.
	RecordedFromDeviceID uint64 `yaml:"recorded_from_device_id,omitempty" json:"recorded_from_device_id,omitempty"`
}

// maxPCRIndex is the highest PCR a TPM 2.0 exposes.
const maxPCRIndex = 23

// Validate reports whether the baseline is well-formed: a known source, at
// least one register, every index within a TPM's PCR range, and no empty
// digest. A malformed baseline must fail closed rather than compare as
// "matches nothing", so callers validate before storing and before use.
func (b *PCRBaseline) Validate() error {
	if b == nil {
		return ErrInvalidPCRBaseline{Reason: "baseline is nil", Index: -1}
	}
	switch b.Source {
	case BaselineSourceSigned, BaselineSourceTOFU:
	default:
		return ErrInvalidPCRBaseline{Reason: "unknown baseline source " + string(b.Source), Index: -1}
	}
	if len(b.Values) == 0 {
		return ErrInvalidPCRBaseline{Reason: "baseline has no PCR values", Index: -1}
	}
	for idx, v := range b.Values {
		if idx < 0 || idx > maxPCRIndex {
			return ErrInvalidPCRBaseline{Reason: "PCR index out of range", Index: idx}
		}
		if len(v) == 0 {
			return ErrInvalidPCRBaseline{Reason: "empty digest", Index: idx}
		}
	}
	if b.RecordedAt.IsZero() {
		return ErrInvalidPCRBaseline{Reason: "recorded_at is unset", Index: -1}
	}
	return nil
}

// ErrInvalidPCRBaseline reports a baseline that cannot be used for
// verification. Index is the offending register, or -1 when the defect is
// not tied to one.
type ErrInvalidPCRBaseline struct {
	Reason string
	Index  int
}

func (e ErrInvalidPCRBaseline) Error() string {
	msg := "device: invalid PCR baseline: " + e.Reason
	if e.Index >= 0 {
		msg += " (pcr " + strconv.Itoa(e.Index) + ")"
	}
	return msg
}
