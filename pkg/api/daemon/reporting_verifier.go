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

package daemon

import (
	"context"
	"log/slog"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
)

// DeviceQuoteVerifyFunc is the one device quote verifier in the platform,
// as the reporting collector consumes it. It evaluates evidence a caller
// supplies against the device's enrolled attestation certificate and PCR
// baseline and returns a verdict; an error means the evidence could not be
// EVALUATED, which is not a negative verdict.
type DeviceQuoteVerifyFunc func(ctx context.Context, deviceID string, evidence []byte) (*DeviceAttestationResult, error)

// ReportingVerifier adapts the platform's device quote verifier to the
// reporting collector's Verifier seam. It is the one place the collector
// touches the verifier: DeviceQuoteVerifier records the verdict (event log,
// quarantine observers) itself, and this adapter carries the same result
// onto the cached report.
type ReportingVerifier struct {
	verify DeviceQuoteVerifyFunc
}

// NewReportingVerifier wraps a verifier function. A nil function fails
// closed at construction rather than producing a verifier that cannot
// verify.
func NewReportingVerifier(verify DeviceQuoteVerifyFunc) (*ReportingVerifier, error) {
	if verify == nil {
		return nil, ErrServiceNotAvailable{Service: "device_quote_verifier"}
	}
	return &ReportingVerifier{verify: verify}, nil
}

// DeviceQuoteVerifierForReporting builds the collector's verifier from the
// same DeviceQuoteVerifier every transport uses (#405): the device's
// enrolled attestation certificate chained to the platform CA, the
// profile's PCR baseline, and the verdict sink that writes the event log
// and drives quarantine.
func DeviceQuoteVerifierForReporting(
	devices device.DeviceService,
	profiles device.DeviceProfileService,
	trust AKTrustAnchor,
	verdicts verdict.Sink,
	logger *slog.Logger,
) (*ReportingVerifier, error) {
	if devices == nil {
		return nil, ErrServiceNotAvailable{Service: "device"}
	}
	if profiles == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	return NewReportingVerifier(NewDeviceQuoteVerifier(devices, profiles, trust, verdicts, logger).Verify)
}

// VerifyDeviceQuote implements reporting.Verifier.
func (v *ReportingVerifier) VerifyDeviceQuote(ctx context.Context, deviceID string, evidence []byte) (*reporting.Report, error) {
	result, err := v.verify(ctx, deviceID, evidence)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrAttestationFailed{Reason: "verifier returned no result"}
	}
	return reportFromResult(result), nil
}

// reportFromResult maps the verifier's result onto the collector's report.
// Every check the verifier reports individually is carried, so a console
// can say which one failed.
func reportFromResult(r *DeviceAttestationResult) *reporting.Report {
	return &reporting.Report{
		DeviceID:              strconv.FormatUint(r.DeviceID, 10),
		Serial:                r.Serial,
		Model:                 r.Model,
		Verified:              r.Verified,
		AKCertificateVerified: r.AKCertificateVerified,
		SignatureValid:        r.SignatureValid,
		NonceValid:            r.NonceValid,
		PCRsValid:             r.PCRsValid,
		Cryptographic:         r.CryptographicFailure,
		PCRBaselineSource:     r.PCRBaselineSource,
		PCRBaselineRecordedAt: r.PCRBaselineRecordedAt,
		PCRBaselineCaptured:   r.PCRBaselineCaptured,
		Status:                r.Status,
		Message:               r.Message,
		AttestedAt:            r.AttestedAt,
	}
}

var _ reporting.Verifier = (*ReportingVerifier)(nil)
