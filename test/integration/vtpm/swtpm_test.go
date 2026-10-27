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

package vtpm_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pkg/swtpm unit tests replace the swtpm binaries with a fake. These
// tests drive the real swtpm and swtpm_setup from the devcontainer, so a
// missing binary fails them.

// initializedSWTPM returns an swtpm whose state the real swtpm_setup created.
func initializedSWTPM(t *testing.T, ctx context.Context, pcrBanks ...string) *swtpm.SWTPM {
	t.Helper()

	sw, err := swtpm.NewSWTPM(&swtpm.Config{StateDir: t.TempDir(), PCRBanks: pcrBanks}, nil)
	require.NoError(t, err, "swtpm and swtpm_setup must be installed")
	require.False(t, sw.IsInitialized())
	require.NoError(t, sw.Initialize(ctx))
	require.True(t, sw.IsInitialized())
	return sw
}

func TestSWTPMDaemon_InitializeMultiplePCRBanks(t *testing.T) {
	initializedSWTPM(t, context.Background(), "sha256", "sha384", "sha512")
}

func TestSWTPMDaemon_StartStop(t *testing.T) {
	ctx := context.Background()
	sw := initializedSWTPM(t, ctx)

	require.NoError(t, sw.Start(ctx))
	assert.True(t, sw.IsRunning())
	assert.Greater(t, sw.PID(), 0)

	require.NoError(t, sw.WaitForSocket(5*time.Second))
	_, err := os.Stat(sw.SocketPath())
	require.NoError(t, err)

	require.NoError(t, sw.Stop())
	assert.False(t, sw.IsRunning())
	assert.Equal(t, 0, sw.PID())
}
