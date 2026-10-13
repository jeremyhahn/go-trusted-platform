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

package commands

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// verdictReportingFixture is a real attestation service whose store also
// persists the reporting cache, as initReportingCollector builds it, holding
// a collected pass for device 42.
type verdictReportingFixture struct {
	svcs  *attestationServices
	store reporting.Store
	cache *reporting.Cache
	at    time.Time
}

func newVerdictReportingFixture(t *testing.T) *verdictReportingFixture {
	t.Helper()
	svc := buildRealAttestationService(t)
	st, ok := svc.Store().(reporting.Store)
	require.True(t, ok, "the attestation store persists reports")
	cache := reporting.NewCache(time.Hour)
	require.NoError(t, cache.Persist(st, quietLogger()))

	at := time.Now().Add(-time.Minute)
	cache.Store(&reporting.Report{
		DeviceID: "42", Serial: "SN-42", Model: "edge-1", Verified: true,
		AKCertificateVerified: true, SignatureValid: true, NonceValid: true, PCRsValid: true,
		Status: "verified", AttestedAt: at, CollectedAt: at,
	})
	return &verdictReportingFixture{svcs: &attestationServices{Service: svc}, store: st, cache: cache, at: at}
}

// failAttestDevice records the verdict a failed AttestDevice records: the
// device-attestation verifier on every transport writes through this sink.
func (f *verdictReportingFixture) failAttestDevice(t *testing.T) {
	t.Helper()
	require.NoError(t, f.svcs.Service.RecordDeviceVerdict(context.Background(), verdict.DeviceVerdict{
		DeviceID: 42, Serial: "SN-42", Passed: false, Cryptographic: true,
		Reason: "pcr 7 differs from the signed baseline", AttestedAt: f.at.Add(30 * time.Second),
	}))
}

// deviceReport is what gatewayd's overlay admission reads.
func deviceReport(t *testing.T, cache *reporting.Cache) *platformv1.DeviceAttestationReport {
	t.Helper()
	srv := daemon.NewAttestationServiceServer(nil, quietLogger())
	srv.SetReporting(&daemon.ReportingHandles{Reports: cache})
	resp, err := srv.GetDeviceReport(context.Background(), &platformv1.GetDeviceReportRequest{DeviceId: "42"})
	require.NoError(t, err)
	return resp.GetReport()
}

func TestReportEveryVerdict_FailedAttestDeviceReplacesTheCollectedPass(t *testing.T) {
	f := newVerdictReportingFixture(t)
	reportEveryVerdict(f.svcs, f.cache)

	f.failAttestDevice(t)

	report := deviceReport(t, f.cache)
	assert.False(t, report.GetVerified(), "the failure, not the earlier pass, is the device's report")
	assert.True(t, report.GetCryptographicFailure())
	assert.Equal(t, "pcr 7 differs from the signed baseline", report.GetMessage())

	// A platformd that restarts reloads the failure, so a gatewayd that
	// starts afterwards and never saw the verdict stream still reads it.
	restarted := reporting.NewCache(time.Hour)
	require.NoError(t, restarted.Persist(f.store, quietLogger()))
	assert.False(t, deviceReport(t, restarted).GetVerified(), "the failure survives a platformd restart")
}

func TestReportEveryVerdict_WithoutAServiceObservesNothing(t *testing.T) {
	f := newVerdictReportingFixture(t)
	reportEveryVerdict(nil, f.cache)
	reportEveryVerdict(&attestationServices{}, f.cache)
	reportEveryVerdict(f.svcs, nil)

	f.failAttestDevice(t)

	assert.True(t, deviceReport(t, f.cache).GetVerified(),
		"an unregistered cache keeps the collected pass: the stale verdict #765 fixed")
}
