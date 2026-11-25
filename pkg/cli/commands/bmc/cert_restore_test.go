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

package bmc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// =============================================================================
// Stub restorer
// =============================================================================

// stubRestorer is an in-process stub that satisfies bmcRestorer without any
// network or gRPC dependency.
type stubRestorer struct {
	result *bmcsvc.RestoreResult
	err    error
	// lastProfileID captures the profileID argument for assertion.
	lastProfileID uint64
}

func (s *stubRestorer) RestoreFactoryCert(_ context.Context, profileID uint64) (*bmcsvc.RestoreResult, error) {
	s.lastProfileID = profileID
	return s.result, s.err
}

// goodRestoreResult returns a realistic RestoreResult for happy-path tests.
func goodRestoreResult() *bmcsvc.RestoreResult {
	now := time.Now()
	return &bmcsvc.RestoreResult{
		DeviceID: 42,
		Endpoint: "10.0.0.1:443",
		Hostname: "bmc-host",
		NewCertMeta: bmcsvc.FactoryCertMeta{
			Subject:      "CN=bmc",
			Issuer:       "CN=bmc",
			SerialNumber: "aabbcc",
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			SPKISHA256:   "deadbeef",
			SHA256:       "cafebabe",
			CapturedAt:   now,
		},
		NewCertPEM: "-----BEGIN CERTIFICATE-----\nRESTORED\n-----END CERTIFICATE-----\n",
		Steps: []bmcsvc.EnrollStep{
			{Name: "restore_cert", OK: true},
			{Name: "pin_delete", OK: true},
			{Name: "dane_unpublish", OK: false, Detail: "DANE not configured"},
			{Name: "device_state", OK: true},
		},
	}
}

// =============================================================================
// newCertRestoreCommand — flag registration
// =============================================================================

func TestNewCertRestoreCommand_Flags(t *testing.T) {
	cmd := newCertRestoreCommand(jsonGetFlags())
	require.NotNil(t, cmd)
	assert.Equal(t, "restore", cmd.Use)

	for _, name := range []string{"profile-id", "factory"} {
		flag := cmd.Flags().Lookup(name)
		require.NotNil(t, flag, "flag --%s must be registered", name)
	}
}

func TestNewCertRestoreCommand_HelpNonEmpty(t *testing.T) {
	cmd := newCertRestoreCommand(jsonGetFlags())
	assert.NotEmpty(t, cmd.Long)
	assert.Contains(t, cmd.Long, "--factory")
}

// =============================================================================
// runCertRestore — validation errors
// =============================================================================

func TestRunCertRestore_MissingProfileID(t *testing.T) {
	cmd := newCertRestoreCommand(jsonGetFlags())
	flags := &certRestoreFlags{factory: true}
	stub := &stubRestorer{}
	err := runCertRestore(cmd, flags, jsonGetFlags(), stub)
	require.Error(t, err)
	var typed ErrProfileIDRequired
	require.ErrorAs(t, err, &typed)
}

func TestRunCertRestore_MissingFactoryFlag(t *testing.T) {
	cmd := newCertRestoreCommand(jsonGetFlags())
	flags := &certRestoreFlags{profileID: "7", factory: false}
	stub := &stubRestorer{}
	err := runCertRestore(cmd, flags, jsonGetFlags(), stub)
	require.Error(t, err)
	var typed ErrFactoryFlagRequired
	require.ErrorAs(t, err, &typed)
	assert.Contains(t, typed.Error(), "--factory")
}

func TestRunCertRestore_InvalidProfileID(t *testing.T) {
	cmd := newCertRestoreCommand(jsonGetFlags())
	flags := &certRestoreFlags{profileID: "not-a-number", factory: true}
	stub := &stubRestorer{}
	err := runCertRestore(cmd, flags, jsonGetFlags(), stub)
	require.Error(t, err)
	var typed ErrProfileIDParseFailed
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, "not-a-number", typed.Value)
}

// =============================================================================
// runCertRestore — SDK error is propagated
// =============================================================================

func TestRunCertRestore_SDKError(t *testing.T) {
	cause := errors.New("grpc: connection refused")
	stub := &stubRestorer{err: cause}
	cmd := newCertRestoreCommand(jsonGetFlags())
	flags := &certRestoreFlags{profileID: "7", factory: true}
	err := runCertRestore(cmd, flags, jsonGetFlags(), stub)
	require.Error(t, err)
	assert.ErrorIs(t, err, cause)
}

// =============================================================================
// runCertRestore — happy path, table output
// =============================================================================

func TestRunCertRestore_HappyPath_TableOutput(t *testing.T) {
	stub := &stubRestorer{result: goodRestoreResult()}
	cmd := newCertRestoreCommand(tableGetFlags())
	flags := &certRestoreFlags{profileID: "42", factory: true}
	err := runCertRestore(cmd, flags, tableGetFlags(), stub)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), stub.lastProfileID)
}

// =============================================================================
// runCertRestore — happy path, JSON output
// =============================================================================

func TestRunCertRestore_HappyPath_JSONOutput(t *testing.T) {
	stub := &stubRestorer{result: goodRestoreResult()}
	cmd := newCertRestoreCommand(jsonGetFlags())
	flags := &certRestoreFlags{profileID: "42", factory: true}
	err := runCertRestore(cmd, flags, jsonGetFlags(), stub)
	require.NoError(t, err)
}

// =============================================================================
// finishCertRestore — output helpers
// =============================================================================

func TestFinishCertRestore_TableOutput(t *testing.T) {
	result := goodRestoreResult()
	err := finishCertRestore(tableGetFlags(), result)
	require.NoError(t, err)
}

func TestFinishCertRestore_JSONOutput(t *testing.T) {
	result := goodRestoreResult()
	err := finishCertRestore(jsonGetFlags(), result)
	require.NoError(t, err)
}

func TestFinishCertRestore_NilFlags(t *testing.T) {
	result := goodRestoreResult()
	// nil getFlags returns nil *cli.CommonFlags — must not panic.
	err := finishCertRestore(func() *cli.CommonFlags { return nil }, result)
	require.NoError(t, err)
}

// =============================================================================
// printRestoreSummary — smoke tests
// =============================================================================

func TestPrintRestoreSummary_WithAllFields(t *testing.T) {
	result := goodRestoreResult()
	// Must not panic regardless of output destination.
	printRestoreSummary(result)
}

func TestPrintRestoreSummary_NoSteps(t *testing.T) {
	result := goodRestoreResult()
	result.Steps = nil
	printRestoreSummary(result)
}

func TestPrintRestoreSummary_FailedStep(t *testing.T) {
	result := goodRestoreResult()
	result.Steps = []bmcsvc.EnrollStep{
		{Name: "restore_cert", OK: false, Detail: "BMC unreachable"},
	}
	printRestoreSummary(result)
}

// =============================================================================
// ErrFactoryFlagRequired
// =============================================================================

func TestErrFactoryFlagRequired_Error(t *testing.T) {
	e := ErrFactoryFlagRequired{}
	assert.Contains(t, e.Error(), "--factory")
	assert.Contains(t, e.Error(), "required")
}

// =============================================================================
// newCertCommand — restore subcommand is registered
// =============================================================================

func TestNewCertCommand_IncludesRestore(t *testing.T) {
	cmd := newCertCommand(jsonGetFlags())
	found := false
	for _, sub := range cmd.Commands() {
		if sub.Use == "restore" {
			found = true
			break
		}
	}
	assert.True(t, found, "restore subcommand must be registered on cert command")
}
