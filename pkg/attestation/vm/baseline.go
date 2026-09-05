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

package vm

import (
	"crypto/subtle"
	"sort"
)

// ComparePCRBaseline reports whether the PCR values a device reported match
// the platform's expected baseline for it.
//
// This is the POLICY half of PCR verification, kept separate from the
// integrity half on purpose. VerifyQuotePCRDigest proves the reported values
// are the ones the TPM signed; this function proves they are the ones the
// platform expects. Conflating the two — using the attester's own values as
// the expectation — proves only that the attester can copy its PCRs into a
// second field (#373). TCG DevID v1 r12 §6.1 step 9 requires the verifier
// to "validate that PCRs have not changed from their expected state", and
// the expected state is the verifier's to hold.
//
// The register sets must match exactly. A baseline covering PCRs the device
// did not report has not been checked; a device reporting PCRs the baseline
// does not cover is attesting to state nobody decided was acceptable.
// Either is a mismatch, not a partial pass.
func ComparePCRBaseline(reported, baseline map[int][]byte) error {
	if len(baseline) == 0 {
		return ErrBaselineMissing{Reason: "baseline has no PCR values"}
	}
	if len(reported) == 0 {
		return ErrBaselineMismatch{Index: -1, Reason: "device reported no PCR values"}
	}
	if len(reported) != len(baseline) {
		return ErrBaselineMismatch{Index: -1, Reason: "reported PCR set does not match baseline PCR set"}
	}

	// Walk in index order so the first divergence named is deterministic.
	indices := make([]int, 0, len(baseline))
	for idx := range baseline {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	for _, idx := range indices {
		got, ok := reported[idx]
		if !ok {
			return ErrBaselineMismatch{Index: -1, Reason: "reported PCR set does not match baseline PCR set"}
		}
		want := baseline[idx]
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			return ErrBaselineMismatch{Index: idx, Reason: "value differs from baseline"}
		}
	}
	return nil
}
