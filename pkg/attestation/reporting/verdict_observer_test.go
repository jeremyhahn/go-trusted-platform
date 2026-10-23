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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/deviceverdict"
)

// collectedPass is a full collector report for device 7, verified at at.
func collectedPass(at time.Time) *Report {
	return &Report{
		DeviceID: "7", Serial: "SN-7", Model: "edge-1", Verified: true,
		AKCertificateVerified: true, SignatureValid: true, NonceValid: true, PCRsValid: true,
		Status: "verified", AttestedAt: at, CollectedAt: at,
	}
}

func failedVerdict(at time.Time) deviceverdict.RecordedDeviceVerdict {
	return deviceverdict.RecordedDeviceVerdict{
		Verdict: deviceverdict.DeviceVerdict{
			DeviceID: 7, Serial: "SN-7", Passed: false, Cryptographic: true,
			Reason: "quote signature invalid", BaselineSource: "signed", AttestedAt: at,
		},
		EventID:    "ev-1",
		RecordedAt: at.Add(time.Millisecond),
	}
}

func TestCacheOnDeviceVerdict_FailureReplacesTheCollectedPass(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	store := newMemStore()
	c := newCacheWithClock(time.Hour, newFakeClock(now))
	require.NoError(t, c.Persist(store, nil))
	c.Store(collectedPass(now.Add(-time.Minute)))

	c.OnDeviceVerdict(context.Background(), failedVerdict(now))

	got, ok := c.Report("7")
	require.True(t, ok)
	assert.False(t, got.Verified, "the latest verdict is the failure")
	assert.True(t, got.Cryptographic)
	assert.False(t, got.SignatureValid || got.PCRsValid, "a failure claims no check passed")
	assert.Equal(t, "failed", got.Status)
	assert.Equal(t, "quote signature invalid", got.Message)
	assert.Equal(t, "signed", got.PCRBaselineSource)
	assert.Equal(t, "edge-1", got.Model, "the device's model is kept")
	assert.Equal(t, now, got.AttestedAt)
	assert.True(t, c.Fresh("7"), "the failure is current evidence")
	assert.Same(t, got, store.reports["7"], "the failure is persisted for a restart")
}

func TestCacheOnDeviceVerdict_PassSetsEveryCheck(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	c := newCacheWithClock(time.Hour, newFakeClock(now))

	c.OnDeviceVerdict(context.Background(), deviceverdict.RecordedDeviceVerdict{
		Verdict: deviceverdict.DeviceVerdict{DeviceID: 7, Passed: true, BaselineCaptured: true, BaselineSource: "tofu"},
		// No verifier stamp: the recording time stands in for it.
		RecordedAt: now,
	})

	got, ok := c.Report("7")
	require.True(t, ok)
	assert.True(t, got.Verified && got.AKCertificateVerified && got.SignatureValid && got.NonceValid && got.PCRsValid)
	assert.False(t, got.Cryptographic)
	assert.True(t, got.PCRBaselineCaptured)
	assert.Equal(t, "verified", got.Status)
	assert.Equal(t, now, got.AttestedAt)
	assert.Equal(t, now, got.CollectedAt)
}

func TestCacheOnDeviceVerdict_IgnoresAVerdictWithoutADevice(t *testing.T) {
	c := newCacheWithClock(time.Hour, newFakeClock(time.Unix(1_700_000_000, 0)))
	c.OnDeviceVerdict(context.Background(), deviceverdict.RecordedDeviceVerdict{})
	assert.Equal(t, 0, c.Len())
}

func TestCacheStore_AnOlderVerificationNeverReplacesANewerOne(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	c := newCacheWithClock(time.Hour, newFakeClock(now))
	c.OnDeviceVerdict(context.Background(), failedVerdict(now))

	// A collection that verified before the failure finishes after it.
	c.Store(collectedPass(now.Add(-time.Second)))
	got, _ := c.Report("7")
	assert.False(t, got.Verified, "the older pass must not overwrite the newer failure")

	c.OnDeviceVerdict(context.Background(), failedVerdict(now.Add(-time.Minute)))
	got, _ = c.Report("7")
	assert.Equal(t, now, got.AttestedAt, "an older verdict is not the latest either")
}

func TestCacheStore_TheCollectorsReportReplacesItsOwnVerdict(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	c := newCacheWithClock(time.Hour, newFakeClock(now))
	c.OnDeviceVerdict(context.Background(), deviceverdict.RecordedDeviceVerdict{
		Verdict:    deviceverdict.DeviceVerdict{DeviceID: 7, Passed: true, AttestedAt: now},
		RecordedAt: now.Add(time.Millisecond),
	})

	full := collectedPass(now)
	tz := true
	full.TimeSynced = &tz
	c.Store(full)

	got, _ := c.Report("7")
	assert.Same(t, full, got, "the same verification's full report wins over the verdict it recorded")
}
