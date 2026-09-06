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

// Refresher is the operator-action seam: ask the collector to refresh a
// device out of cycle. It is separate from Reader on purpose — a handler
// that only reads is given a Reader; a handler that offers "attest now" is
// given a Refresher too, and the difference is visible in its signature.
//
// Refresh never blocks and never returns evidence. The request goes to the
// collector, which applies the same TTL, de-duplication and per-device
// serialization as scheduled work, so an operator cannot generate more TPM
// load than the schedule would. The caller learns the outcome the same way
// everyone does: by reading the cache later.
type Refresher interface {
	Refresh(deviceID string) error
}

// Collector satisfies Refresher through Enqueue.
func (c *Collector) Refresh(deviceID string) error {
	if deviceID == "" {
		return ErrDeviceIDRequired{}
	}
	return c.Enqueue(deviceID)
}

var _ Refresher = (*Collector)(nil)

// View is a report as a consumer renders it: the verdict AND its age, with
// freshness judged by the cache's own clock. Every transport serialises this
// shape, so the rule that a verdict is never shown without its age is
// enforced where the data is produced rather than in each client.
type View struct {
	DeviceID string `json:"device_id"`
	Serial   string `json:"serial,omitempty"`
	Model    string `json:"model,omitempty"`

	Verified              bool `json:"verified"`
	AKCertificateVerified bool `json:"ak_certificate_verified"`
	SignatureValid        bool `json:"signature_valid"`
	NonceValid            bool `json:"nonce_valid"`
	PCRsValid             bool `json:"pcrs_valid"`
	// CryptographicFailure is true when a negative verdict came from a
	// check that ran and failed, the only kind that may quarantine.
	CryptographicFailure bool `json:"cryptographic_failure"`

	PCRBaselineSource     string    `json:"pcr_baseline_source,omitempty"`
	PCRBaselineRecordedAt time.Time `json:"pcr_baseline_recorded_at,omitempty"`
	PCRBaselineCaptured   bool      `json:"pcr_baseline_captured"`

	Status  string `json:"status"`
	Message string `json:"message,omitempty"`

	// AttestedAt is the verifier's timestamp; CollectedAt the collector's.
	AttestedAt  time.Time `json:"attested_at"`
	CollectedAt time.Time `json:"collected_at"`

	// Fresh is the cache's freshness verdict at render time; AgeSeconds and
	// AsOf are the age and the instant it was computed. A consumer that
	// shows Verified without Fresh and AgeSeconds is misrepresenting the
	// report.
	Fresh      bool      `json:"fresh"`
	AgeSeconds int64     `json:"age_seconds"`
	AsOf       time.Time `json:"as_of"`

	// TimeSynced is the device's clock trust state at collection: true,
	// false, or ABSENT when the device did not answer. It is omitted
	// rather than rendered false when unknown, because "we could not ask"
	// and "its clock is wrong" are different facts about a machine whose
	// certificate windows and token validity all run on that clock.
	TimeSynced *bool `json:"time_synced,omitempty"`
}

// Views renders every cached report, ordered by device id.
func (c *Cache) Views() []View {
	reports := c.Reports()
	now := c.Now()
	out := make([]View, 0, len(reports))
	for _, r := range reports {
		out = append(out, c.viewAt(r, now))
	}
	return out
}

// View renders one device's report. ok is false when the device has never
// been collected — distinct from a failed verdict, which is a View whose
// Verified is false.
func (c *Cache) View(deviceID string) (View, bool) {
	r, ok := c.Report(deviceID)
	if !ok {
		return View{}, false
	}
	return c.viewAt(r, c.Now()), true
}

func (c *Cache) viewAt(r *Report, now time.Time) View {
	age := r.Age(now)
	return View{
		DeviceID:              r.DeviceID,
		Serial:                r.Serial,
		Model:                 r.Model,
		Verified:              r.Verified,
		AKCertificateVerified: r.AKCertificateVerified,
		SignatureValid:        r.SignatureValid,
		NonceValid:            r.NonceValid,
		PCRsValid:             r.PCRsValid,
		CryptographicFailure:  r.Cryptographic,
		PCRBaselineSource:     r.PCRBaselineSource,
		PCRBaselineRecordedAt: r.PCRBaselineRecordedAt,
		PCRBaselineCaptured:   r.PCRBaselineCaptured,
		Status:                r.Status,
		Message:               r.Message,
		AttestedAt:            r.AttestedAt,
		CollectedAt:           r.CollectedAt,
		Fresh:                 age < c.TTL(),
		AgeSeconds:            int64(age / time.Second),
		AsOf:                  now,
		TimeSynced:            r.TimeSynced,
	}
}

// Viewer is the read-only view a report transport is given: Reader plus the
// rendered form. Like Reader, no method takes a context and none can reach
// a device.
type Viewer interface {
	Reader
	Views() []View
	View(deviceID string) (View, bool)
}

var _ Viewer = (*Cache)(nil)

// ErrDeviceIDRequired reports a refresh with no device.
type ErrDeviceIDRequired struct{}

func (ErrDeviceIDRequired) Error() string {
	return "attestation reporting: a device id is required"
}
