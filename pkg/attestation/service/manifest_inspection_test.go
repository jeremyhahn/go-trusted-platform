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

package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
)

// VerifyManifest checks no signature and no fresh quote, so a passing
// inspection is not a verdict: it must not reach the observers as a pass,
// which the quarantine loop would take as a restore (#2038).
func TestVerifyManifest_APassingInspectionDispatchesNoRestore(t *testing.T) {
	ctx := context.Background()
	svc, obs := newVerdictService(t)
	svc.SetDeviceResolver(&staticResolver{m: map[string]uint64{"host-a": 42}})

	result, err := svc.VerifyManifest(ctx, storedManifest(), nil, []byte{1, 2, 3}, nil, nil)
	require.NoError(t, err)
	require.Equal(t, manifest.VerificationStatusVerified, result.Status)

	assert.Empty(t, obs.passed, "an inspection must not dispatch a pass")
	assert.Empty(t, obs.failed)
	assert.Equal(t, []store.EventKind{store.EventKindManifestVerified}, eventKinds(t, svc, "host-a"),
		"the audit event stays")
}

// A failed inspection is no verdict either: a replayed nonce in stored
// evidence is reported and audited, but it must not reach the observers,
// which the quarantine loop would take as a cryptographic failure (#2038).
func TestVerifyManifest_AFailedInspectionDispatchesNoFailure(t *testing.T) {
	ctx := context.Background()
	svc, obs := newVerdictService(t)
	svc.SetDeviceResolver(&staticResolver{m: map[string]uint64{"host-a": 42}})

	result, err := svc.VerifyManifest(ctx, storedManifest(), nil, []byte{4}, nil, nil)
	require.NoError(t, err)
	require.Equal(t, manifest.VerificationStatusFailed, result.Status)

	assert.Empty(t, obs.failed, "an inspection must not dispatch a failure")
	assert.Empty(t, obs.passed)
	assert.Equal(t, []store.EventKind{store.EventKindManifestRejected}, eventKinds(t, svc, "host-a"),
		"the audit event stays")
}

// Stored enrollment evidence ages past the freshness window on every healthy
// host; inspecting it must report the expiry without quarantining the host
// (docs/attestation/architecture.md: expired evidence never quarantines).
func TestVerifyManifest_AStaleInspectionDispatchesNoFailure(t *testing.T) {
	ctx := context.Background()
	svc, obs := newVerdictService(t)
	svc.SetDeviceResolver(&staticResolver{m: map[string]uint64{"host-a": 42}})

	stale := storedManifest()
	stale.Timestamp = time.Now().Add(-25 * time.Hour)
	result, err := svc.VerifyManifest(ctx, stale, nil, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, manifest.VerificationStatusFailed, result.Status)
	assert.Contains(t, result.Errors, "manifest is older than 24 hours")

	assert.Empty(t, obs.failed, "an expired inspection must not dispatch a failure")
	assert.Empty(t, obs.passed)
}
