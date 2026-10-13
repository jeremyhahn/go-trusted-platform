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
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
)

func TestNewReportingVerifier_FailsClosedWithoutAFunction(t *testing.T) {
	_, err := NewReportingVerifier(nil)
	require.Error(t, err)
	_, err = DeviceQuoteVerifierForReporting(nil, newMockProfileService(), nil, nil, nil)
	require.Error(t, err)
	_, err = DeviceQuoteVerifierForReporting(newSPMockDeviceService(), nil, nil, nil, nil)
	require.Error(t, err)
}

func TestReportingVerifier_MapsEveryCheck(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	v, err := NewReportingVerifier(func(_ context.Context, id string, evidence []byte) (*DeviceAttestationResult, error) {
		assert.Equal(t, "42", id)
		assert.Equal(t, []byte(`{"quote":"x"}`), evidence)
		return &DeviceAttestationResult{
			DeviceID: 42, Serial: "SN-42", Model: "X10", Verified: false,
			AKCertificateVerified: true, SignatureValid: true, NonceValid: false, PCRsValid: true,
			CryptographicFailure: true, PCRBaselineSource: "tofu", PCRBaselineRecordedAt: at, PCRBaselineCaptured: true,
			Status: "failed", Message: "nonce mismatch", AttestedAt: at,
		}, nil
	})
	require.NoError(t, err)

	report, err := v.VerifyDeviceQuote(context.Background(), "42", []byte(`{"quote":"x"}`))
	require.NoError(t, err)
	assert.Equal(t, "42", report.DeviceID)
	assert.Equal(t, "SN-42", report.Serial)
	assert.Equal(t, "X10", report.Model)
	assert.False(t, report.Verified)
	assert.True(t, report.SignatureValid)
	assert.False(t, report.NonceValid)
	assert.True(t, report.PCRsValid)
	assert.True(t, report.Cryptographic, "a check that ran and failed is a cryptographic failure")
	assert.True(t, report.AKCertificateVerified)
	assert.Equal(t, "tofu", report.PCRBaselineSource)
	assert.Equal(t, at, report.PCRBaselineRecordedAt)
	assert.True(t, report.PCRBaselineCaptured)
	assert.Equal(t, "failed", report.Status)
	assert.Equal(t, "nonce mismatch", report.Message)
	assert.Equal(t, at, report.AttestedAt)
}

func TestReportingVerifier_AbsenceIsNotCryptographicFailure(t *testing.T) {
	v, err := NewReportingVerifier(func(context.Context, string, []byte) (*DeviceAttestationResult, error) {
		return &DeviceAttestationResult{DeviceID: 1, Verified: false, Status: "failed", Message: "no attestation certificate enrolled"}, nil
	})
	require.NoError(t, err)
	report, err := v.VerifyDeviceQuote(context.Background(), "1", []byte("e"))
	require.NoError(t, err)
	assert.False(t, report.Verified)
	assert.False(t, report.Cryptographic, "a check that could not run is absence of evidence, not a failure")
}

func TestReportingVerifier_ErrorsAndNilResultsAreNotVerdicts(t *testing.T) {
	boom := errors.New("device not found")
	v, err := NewReportingVerifier(func(context.Context, string, []byte) (*DeviceAttestationResult, error) {
		return nil, boom
	})
	require.NoError(t, err)
	_, err = v.VerifyDeviceQuote(context.Background(), "1", []byte("e"))
	assert.ErrorIs(t, err, boom)

	v, err = NewReportingVerifier(func(context.Context, string, []byte) (*DeviceAttestationResult, error) {
		return nil, nil
	})
	require.NoError(t, err)
	_, err = v.VerifyDeviceQuote(context.Background(), "1", []byte("e"))
	require.Error(t, err)
}

// TestReportingEvidence_MatchesVerifierWireContract pins the JSON contract
// between the collector's Evidence and the verifier's DeviceQuoteEvidence:
// the collector must produce exactly what the verifier parses.
func TestReportingEvidence_MatchesVerifierWireContract(t *testing.T) {
	ev := &reporting.Evidence{
		Quote: []byte("q"), Signature: []byte("s"), Nonce: []byte("n"),
		PCRs: map[int][]byte{0: []byte("p0"), 7: []byte("p7")},
	}
	encoded, err := ev.Encode()
	require.NoError(t, err)

	var parsed DeviceQuoteEvidence
	require.NoError(t, json.Unmarshal(encoded, &parsed))
	assert.Equal(t, ev.Quote, parsed.Quote)
	assert.Equal(t, ev.Signature, parsed.Signature)
	assert.Equal(t, ev.Nonce, parsed.Nonce)
}

func TestDeviceQuoteVerifierForReporting_UsesThePlatformVerifier(t *testing.T) {
	f := newQuoteFixture(t)
	v, err := DeviceQuoteVerifierForReporting(f.devices, f.profiles, f.trust, f.sink, nil)
	require.NoError(t, err)
	_, err = v.VerifyDeviceQuote(context.Background(), "", []byte("e"))
	require.Error(t, err, "the platform verifier refuses an empty device id")

	// Unbound evidence is refused: the collector always binds its quotes.
	nonce := []byte("collector-nonce")
	_, err = v.VerifyDeviceQuote(context.Background(), strconv.FormatUint(f.device.ID, 10), f.evidence(t, nonce, goldenPCRs()))
	var invalid ErrInvalidAttestationEvidence
	require.ErrorAs(t, err, &invalid)

	bound := f.boundEvidence(t, nonce, xkms.PeerQualifyingData(nonce, testChannelBinding), testChannelBinding)
	report, err := v.VerifyDeviceQuote(context.Background(), strconv.FormatUint(f.device.ID, 10), bound)
	require.NoError(t, err)
	assert.True(t, report.Verified, report.Message)
	assert.True(t, report.AKCertificateVerified)
	assert.True(t, report.PCRBaselineCaptured, "first verification captures the TOFU baseline")
	assert.Equal(t, "tofu", report.PCRBaselineSource)
	assert.False(t, report.Cryptographic)
	assert.True(t, f.sink.last(t).Passed, "the verdict reached the sink")
}
