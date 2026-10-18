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

package initrd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitForDeviceNodes_ReturnsOnceNodesExist(t *testing.T) {
	dir := t.TempDir()
	efi := filepath.Join(dir, "sda1")
	root := filepath.Join(dir, "sda2")
	require.NoError(t, os.WriteFile(efi, nil, 0o600))

	// The root node appears while the wait is underway.
	done := make(chan error, 1)
	go func() { done <- waitForDeviceNodes(context.Background(), time.Hour, efi, root) }()
	require.NoError(t, os.WriteFile(root, nil, 0o600))

	require.NoError(t, <-done)
}

func TestWaitForDeviceNodes_TimesOutOnMissingNode(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "sda2")

	err := waitForDeviceNodes(context.Background(), 0, missing)

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, msgErr.Msg, missing)
}

func TestWaitForDeviceNodes_CancelEndsTheWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := waitForDeviceNodes(ctx, time.Hour, filepath.Join(t.TempDir(), "sda1"))

	require.ErrorIs(t, err, context.Canceled)
}
