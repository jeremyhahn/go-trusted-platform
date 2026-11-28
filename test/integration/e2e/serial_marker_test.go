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

//go:build integration

package e2e_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Phases 2 and 3 pass only when the VM's serial log shows the marker
// (#374): a budget that merely elapses is not a verification.

func TestWaitForSerialMarker_FindsMarkerWrittenLater(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "serial.log")
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(logPath, []byte("booting\nplatform: services ready\n"), 0o600)
	}()

	err := waitForSerialMarker(context.Background(), logPath, "services ready", 2*time.Second, 10*time.Millisecond)
	require.NoError(t, err)
}

func TestWaitForSerialMarker_FailsWhenMarkerNeverAppears(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "serial.log")
	require.NoError(t, os.WriteFile(logPath, []byte("kernel panic\n"), 0o600))

	err := waitForSerialMarker(context.Background(), logPath, "services ready", 50*time.Millisecond, 10*time.Millisecond)
	require.ErrorIs(t, err, errSerialMarkerNotSeen)
	require.ErrorContains(t, err, "services ready")
}

func TestWaitForSerialMarker_FailsWhenLogNeverWritten(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "serial.log")

	err := waitForSerialMarker(context.Background(), logPath, "services ready", 50*time.Millisecond, 10*time.Millisecond)
	require.ErrorIs(t, err, errSerialMarkerNotSeen)
}

func TestWaitForSerialMarker_RefusesEmptyMarker(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "serial.log")
	require.NoError(t, os.WriteFile(logPath, []byte("anything\n"), 0o600))

	err := waitForSerialMarker(context.Background(), logPath, "", time.Second, 10*time.Millisecond)
	require.ErrorIs(t, err, errSerialMarkerUnset)
}

func TestProvisioningMarkersFromEnv_RequiresBoth(t *testing.T) {
	t.Setenv(envServerBootMarker, "services ready")
	t.Setenv(envClientEnrollMarker, "")

	_, _, err := provisioningMarkersFromEnv()
	require.True(t, errors.Is(err, errSerialMarkerUnset))
	require.ErrorContains(t, err, envClientEnrollMarker)

	t.Setenv(envClientEnrollMarker, "enrolled")
	server, client, err := provisioningMarkersFromEnv()
	require.NoError(t, err)
	require.Equal(t, "services ready", server)
	require.Equal(t, "enrolled", client)
}
