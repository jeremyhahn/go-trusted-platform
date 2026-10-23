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
	"context"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/deviceverdict"
)

// OnDeviceVerdict implements verdict.Observer: every verdict the attestation
// service records becomes the device's current report, whichever path
// produced it — this collector, or a device submitting its own quote through
// AttestDevice on any transport. Without it a failed AttestDevice left the
// last collected pass in the cache, and every reader of the cache (overlay
// admission among them) kept trusting a device the platform had already
// judged failed until that pass expired (#765).
//
// A verdict carries no per-check breakdown, so the report it becomes sets
// every check on a pass and none on a failure, whose Message explains it.
// When the verdict came from this collector, the collector's own Store of
// the same verification follows and replaces it with the full report.
func (c *Cache) OnDeviceVerdict(_ context.Context, recorded deviceverdict.RecordedDeviceVerdict) {
	if recorded.Verdict.DeviceID == 0 {
		return
	}
	r := reportFromVerdict(recorded)
	c.mu.Lock()
	defer c.mu.Unlock()
	if held := c.reports[r.DeviceID]; held != nil {
		// The model is the device's, not the verification's.
		r.Model = held.Model
	}
	c.storeLocked(r)
}

// reportFromVerdict renders a recorded verdict as a report. Its verification
// time is the verifier's stamp, or the time the verdict was recorded when the
// producer did not stamp one.
func reportFromVerdict(recorded deviceverdict.RecordedDeviceVerdict) *Report {
	v := recorded.Verdict
	at := v.AttestedAt
	if at.IsZero() {
		at = recorded.RecordedAt
	}
	r := &Report{
		DeviceID:              strconv.FormatUint(v.DeviceID, 10),
		Serial:                v.Serial,
		Verified:              v.Passed,
		AKCertificateVerified: v.Passed,
		SignatureValid:        v.Passed,
		NonceValid:            v.Passed,
		PCRsValid:             v.Passed,
		Cryptographic:         !v.Passed && v.Cryptographic,
		PCRBaselineSource:     v.BaselineSource,
		PCRBaselineCaptured:   v.BaselineCaptured,
		Status:                "verified",
		Message:               "device attestation verified",
		AttestedAt:            at,
		CollectedAt:           at,
	}
	if !v.Passed {
		r.Status = "failed"
		r.Message = v.Reason
	}
	return r
}
