// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

func TestDeviceQuoteVerifier_FirstQuoteCapturesTOFUBaselineAndVerifies(t *testing.T) {
	f := newQuoteFixture(t)
	v := f.verifier(t)

	result, err := v.Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)

	assert.True(t, result.Verified)
	assert.True(t, result.AKCertificateVerified)
	assert.True(t, result.SignatureValid)
	assert.True(t, result.NonceValid)
	assert.True(t, result.PCRsValid)
	assert.True(t, result.PCRBaselineCaptured, "the first verified quote sets the profile baseline")
	assert.Equal(t, string(deviceentities.BaselineSourceTOFU), result.PCRBaselineSource)
	assert.Equal(t, f.now, result.PCRBaselineRecordedAt)
	assert.Equal(t, "verified", result.Status)

	stored := f.profiles.profiles[f.profile.ID].PCRBaseline
	require.NotNil(t, stored, "baseline must be persisted on the profile")
	assert.Equal(t, deviceentities.BaselineSourceTOFU, stored.Source)
	assert.Equal(t, f.device.ID, stored.RecordedFromDeviceID)
	assert.Equal(t, goldenPCRs(), stored.Values)

	dv := f.sink.last(t)
	assert.True(t, dv.Passed)
	assert.True(t, dv.BaselineCaptured)
	assert.Equal(t, f.profile.ID, dv.ProfileID)
	assert.Equal(t, f.device.Hostname, dv.HostID)
	assert.Equal(t, "tenant-a", dv.TenantID, "the verdict names the device's tenant, which decides who may stream it")
}

func TestDeviceQuoteVerifier_SecondQuoteMatchesTheCapturedBaseline(t *testing.T) {
	f := newQuoteFixture(t)
	v := f.verifier(t)

	_, err := v.Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)

	result, err := v.Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-2"), goldenPCRs()))
	require.NoError(t, err)

	assert.True(t, result.Verified)
	assert.False(t, result.PCRBaselineCaptured, "only the first quote captures")
	assert.Equal(t, string(deviceentities.BaselineSourceTOFU), result.PCRBaselineSource)
	assert.False(t, f.sink.last(t).BaselineCaptured)
}

func TestDeviceQuoteVerifier_BaselineMismatchIsACryptographicFailure(t *testing.T) {
	f := newQuoteFixture(t)
	f.profile.PCRBaseline = &deviceentities.PCRBaseline{
		Values:     goldenPCRs(),
		Source:     deviceentities.BaselineSourceSigned,
		RecordedAt: f.now,
	}
	v := f.verifier(t)

	drifted := goldenPCRs()
	drifted[7] = fillPCR(0xEE)
	result, err := v.Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), drifted))
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.True(t, result.SignatureValid, "the quote itself was genuine")
	assert.False(t, result.PCRsValid, "the values differ from the signed baseline")
	assert.Equal(t, string(deviceentities.BaselineSourceSigned), result.PCRBaselineSource)
	assert.Contains(t, result.Message, "pcr 7")

	dv := f.sink.last(t)
	assert.False(t, dv.Passed)
	assert.True(t, dv.Cryptographic, "a PCR mismatch on a genuine quote is evidence of tampering: quarantine")
	assert.Equal(t, deviceentities.BaselineSourceSigned, deviceentities.BaselineSource(dv.BaselineSource))
	assert.Equal(t, deviceentities.BaselineSourceSigned, f.profiles.profiles[f.profile.ID].PCRBaseline.Source,
		"a mismatch never overwrites the baseline")
}

func TestDeviceQuoteVerifier_SignedBaselineMatchReportsItsSource(t *testing.T) {
	f := newQuoteFixture(t)
	recorded := f.now.Add(-48 * 3600e9)
	f.profile.PCRBaseline = &deviceentities.PCRBaseline{
		Values:     goldenPCRs(),
		Source:     deviceentities.BaselineSourceSigned,
		RecordedAt: recorded,
	}
	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)

	assert.True(t, result.Verified)
	assert.False(t, result.PCRBaselineCaptured)
	assert.Equal(t, string(deviceentities.BaselineSourceSigned), result.PCRBaselineSource)
	assert.Equal(t, recorded, result.PCRBaselineRecordedAt, "operators need to see how old the expected state is")
}

func TestDeviceQuoteVerifier_NoAttestationCertificateIsAnAbsenceNotAFailure(t *testing.T) {
	f := newQuoteFixture(t)
	f.device.AttestCert = ""
	f.device.AttestPub = "-----BEGIN PUBLIC KEY-----\nignored\n-----END PUBLIC KEY-----\n"

	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.False(t, result.AKCertificateVerified)
	assert.False(t, result.SignatureValid, "a bare public key is not a trust anchor: Restricted cannot be checked")
	assert.Contains(t, result.Message, "8.2")
	assert.Nil(t, f.profiles.profiles[f.profile.ID].PCRBaseline, "nothing is captured from an unverified quote")

	dv := f.sink.last(t)
	assert.False(t, dv.Passed)
	assert.False(t, dv.Cryptographic, "absence of evidence is denied service but never quarantined")
}

func TestDeviceQuoteVerifier_CertificateWithoutRestrictedIsRejected(t *testing.T) {
	f := newQuoteFixture(t)
	f.device.AttestCert = f.ca.issueAK(t, &f.key.PublicKey, false)

	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.False(t, result.AKCertificateVerified)
	assert.Contains(t, strings.ToLower(result.Message), "restricted")
	assert.True(t, f.sink.last(t).Cryptographic, "a certificate that lacks the MUST attribute is a failed check, not a missing one")
}

func TestDeviceQuoteVerifier_CertificateFromAnotherCAIsRejected(t *testing.T) {
	f := newQuoteFixture(t)
	other := newAttestTestCA(t)
	f.device.AttestCert = other.issueAK(t, &f.key.PublicKey, true)

	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.False(t, result.AKCertificateVerified)
	assert.Contains(t, result.Message, "trusted root")
	assert.True(t, f.sink.last(t).Cryptographic)
}

func TestDeviceQuoteVerifier_ChainsThroughTheIntermediate(t *testing.T) {
	f := newQuoteFixture(t)
	f.trust.intermediate = nil

	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)

	assert.False(t, result.AKCertificateVerified,
		"the AK is issued by the intermediate; without it the chain to the root is incomplete")
}

func TestDeviceQuoteVerifier_MissingTrustAnchorIsAnAbsence(t *testing.T) {
	cases := map[string]func(f *quoteFixture){
		"nil anchor":      func(f *quoteFixture) { f.trust = nil },
		"root unreadable": func(f *quoteFixture) { f.trust.rootErr = errors.New("hsm offline") },
		"root nil":        func(f *quoteFixture) { f.trust.root = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newQuoteFixture(t)
			mutate(f)
			var v *DeviceQuoteVerifier
			if f.trust == nil {
				v = NewDeviceQuoteVerifier(f.devices, f.profiles, nil, f.sink, nil)
			} else {
				v = f.verifier(t)
			}
			result, err := v.Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
			require.NoError(t, err)
			assert.False(t, result.Verified)
			assert.Contains(t, result.Message, "trust anchor")
			assert.False(t, f.sink.last(t).Cryptographic)
		})
	}
}

func TestDeviceQuoteVerifier_BadSignatureIsCryptographicAndCapturesNothing(t *testing.T) {
	f := newQuoteFixture(t)
	otherKey, _ := newAttestTestKey(t)

	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID),
		signedEvidence(t, otherKey, []byte("nonce-1"), goldenPCRs(), goldenPCRs()))
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.True(t, result.AKCertificateVerified)
	assert.False(t, result.SignatureValid)
	assert.False(t, result.PCRsValid)
	assert.Nil(t, f.profiles.profiles[f.profile.ID].PCRBaseline, "a forged quote must never seed the baseline")
	assert.True(t, f.sink.last(t).Cryptographic)
}

func TestDeviceQuoteVerifier_NonceMismatchIsCryptographic(t *testing.T) {
	f := newQuoteFixture(t)
	quote := buildAttestTestQuote(t, []byte("nonce-issued"), goldenPCRs())
	evidence := mustJSON(t, DeviceQuoteEvidence{
		Quote:     quote,
		Signature: signAttestQuote(t, f.key, quote),
		Nonce:     []byte("nonce-replayed"),
		PCRs:      goldenPCRs(),
	})

	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID), evidence)
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.True(t, result.SignatureValid)
	assert.False(t, result.NonceValid)
	assert.True(t, f.sink.last(t).Cryptographic)
	assert.Nil(t, f.profiles.profiles[f.profile.ID].PCRBaseline)
}

func TestDeviceQuoteVerifier_ReportedPCRsMustHashToTheSignedDigest(t *testing.T) {
	f := newQuoteFixture(t)
	claimed := goldenPCRs()
	claimed[0] = fillPCR(0xAA)

	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID),
		signedEvidence(t, f.key, []byte("nonce-1"), goldenPCRs(), claimed))
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.True(t, result.SignatureValid)
	assert.True(t, result.NonceValid)
	assert.False(t, result.PCRsValid)
	assert.Contains(t, result.Message, "signed digest")
	assert.Nil(t, f.profiles.profiles[f.profile.ID].PCRBaseline, "values the TPM did not sign never become the baseline")
	assert.True(t, f.sink.last(t).Cryptographic)
}

func TestDeviceQuoteVerifier_NoMatchingProfileIsAnAbsence(t *testing.T) {
	f := newQuoteFixture(t)
	f.profile.MatchRules = &deviceentities.ProfileMatchRules{Model: "some-other-model"}

	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.True(t, result.SignatureValid)
	assert.False(t, result.PCRsValid)
	assert.Contains(t, result.Message, "profile")
	assert.False(t, f.sink.last(t).Cryptographic)
	assert.Zero(t, f.sink.last(t).ProfileID)
}

func TestDeviceQuoteVerifier_BaselineCaptureFailureFailsClosed(t *testing.T) {
	f := newQuoteFixture(t)
	f.profiles.updateErr = errors.New("datastore read-only")

	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.False(t, result.PCRsValid)
	assert.False(t, result.PCRBaselineCaptured)
	assert.Contains(t, result.Message, "could not be recorded")
	assert.False(t, f.sink.last(t).Cryptographic)
}

func TestDeviceQuoteVerifier_CapturedBaselineDoesNotAliasTheRequest(t *testing.T) {
	f := newQuoteFixture(t)
	v := f.verifier(t)
	pcrs := goldenPCRs()

	_, err := v.Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), pcrs))
	require.NoError(t, err)

	stored := f.profiles.profiles[f.profile.ID].PCRBaseline.Values
	copied := copyPCRValues(stored)
	copied[0][0] ^= 0xFF
	assert.NotEqual(t, copied[0], stored[0], "copyPCRValues must deep-copy every digest")
}

func TestDeviceQuoteVerifier_RejectsUnusableRequests(t *testing.T) {
	f := newQuoteFixture(t)
	v := f.verifier(t)
	good := f.evidence(t, []byte("nonce-1"), goldenPCRs())

	strip := func(field string) []byte {
		var e DeviceQuoteEvidence
		require.NoError(t, jsonUnmarshal(good, &e))
		switch field {
		case "quote":
			e.Quote = nil
		case "signature":
			e.Signature = nil
		case "nonce":
			e.Nonce = nil
		case "pcrs":
			e.PCRs = nil
		}
		return mustJSON(t, e)
	}

	cases := []struct {
		name     string
		deviceID string
		evidence []byte
		want     error
	}{
		{"empty device id", "", good, ErrAttestationFailed{}},
		{"empty evidence", itoa(f.device.ID), nil, ErrAttestationFailed{}},
		{"malformed device id", "not-a-number", good, &MessageError{}},
		{"not json", itoa(f.device.ID), []byte("not json"), ErrInvalidAttestationEvidence{}},
		{"no quote", itoa(f.device.ID), strip("quote"), ErrInvalidAttestationEvidence{}},
		{"no signature", itoa(f.device.ID), strip("signature"), ErrInvalidAttestationEvidence{}},
		{"no nonce", itoa(f.device.ID), strip("nonce"), ErrInvalidAttestationEvidence{}},
		{"no pcrs", itoa(f.device.ID), strip("pcrs"), ErrInvalidAttestationEvidence{}},
		{"unknown device", "424242", good, ErrDeviceNotFound{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), tc.deviceID, tc.evidence)
			require.Error(t, err)
			assert.IsType(t, tc.want, err)
		})
	}
	assert.Empty(t, f.sink.verdicts, "an unusable request reaches no verdict")
}

func TestDeviceQuoteVerifier_MissingDependenciesFailClosed(t *testing.T) {
	f := newQuoteFixture(t)
	good := f.evidence(t, []byte("nonce-1"), goldenPCRs())

	var nilVerifier *DeviceQuoteVerifier
	_, err := nilVerifier.Verify(context.Background(), itoa(f.device.ID), good)
	assert.IsType(t, ErrServiceNotAvailable{}, err)

	_, err = NewDeviceQuoteVerifier(nil, f.profiles, f.trust, f.sink, nil).Verify(context.Background(), itoa(f.device.ID), good)
	assert.IsType(t, ErrServiceNotAvailable{}, err)

	_, err = NewDeviceQuoteVerifier(f.devices, nil, f.trust, f.sink, nil).Verify(context.Background(), itoa(f.device.ID), good)
	assert.IsType(t, ErrServiceNotAvailable{}, err)
}

func TestDeviceQuoteVerifier_SinkFailureDoesNotHideTheVerdict(t *testing.T) {
	f := newQuoteFixture(t)
	f.sink.err = errors.New("event store full")

	result, err := f.verifier(t).Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)
	assert.True(t, result.Verified)
	assert.Len(t, f.sink.verdicts, 1, "the sink was still handed the verdict")
}

func TestDeviceQuoteVerifier_NilSinkOnlyLogs(t *testing.T) {
	f := newQuoteFixture(t)
	v := NewDeviceQuoteVerifier(f.devices, f.profiles, f.trust, nil, nil)
	v.now = func() time.Time { return f.now }

	result, err := v.Verify(context.Background(), itoa(f.device.ID), f.evidence(t, []byte("nonce-1"), goldenPCRs()))
	require.NoError(t, err)
	assert.True(t, result.Verified)
}
