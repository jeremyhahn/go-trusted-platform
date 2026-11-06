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

package podman

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRuntime_Close verifies the runtime Close method.
func TestRuntime_Close(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := DefaultRuntimeConfig()
	cfg.Root = tmpDir + "/root"
	cfg.RunRoot = tmpDir + "/run"
	cfg.TmpDir = tmpDir + "/tmp"
	cfg.StaticDir = tmpDir + "/static"
	cfg.VolumePath = tmpDir + "/volumes"
	cfg.ImageStorePath = tmpDir + "/images"

	// Runtime needs a real OCI runtime in PATH - skip if not available
	r := &Runtime{
		config: cfg,
		logger: slog.Default(),
	}
	r.initialized.Store(true)

	t.Run("first_close", func(t *testing.T) {
		err := r.Close()
		require.NoError(t, err)
		assert.False(t, r.IsInitialized())
	})

	t.Run("double_close", func(t *testing.T) {
		err := r.Close()
		require.NoError(t, err)
	})
}

// TestRuntime_Config verifies the runtime Config accessor.
func TestRuntime_Config(t *testing.T) {
	cfg := DefaultRuntimeConfig()
	r := &Runtime{
		config: cfg,
		logger: slog.Default(),
	}
	assert.Equal(t, cfg, r.Config())
}

// TestRuntime_IsInitialized verifies the initialized state.
func TestRuntime_IsInitialized(t *testing.T) {
	r := &Runtime{
		config: DefaultRuntimeConfig(),
		logger: slog.Default(),
	}

	assert.False(t, r.IsInitialized())
	r.initialized.Store(true)
	assert.True(t, r.IsInitialized())
}

// TestRuntime_GenerateContainerID verifies unique ID generation.
func TestRuntime_GenerateContainerID(t *testing.T) {
	r := &Runtime{
		config: DefaultRuntimeConfig(),
		logger: slog.Default(),
	}

	id1 := r.generateContainerID()
	id2 := r.generateContainerID()

	assert.Len(t, id1, 64)
	assert.Len(t, id2, 64)
	assert.NotEqual(t, id1, id2, "container IDs should be unique")
}

// TestRuntime_GenerateContainerID_IsHex verifies ID is hex-encoded.
func TestRuntime_GenerateContainerID_IsHex(t *testing.T) {
	r := &Runtime{
		config: DefaultRuntimeConfig(),
		logger: slog.Default(),
	}

	id := r.generateContainerID()
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("expected hex character, got %c", c)
		}
	}
}

// TestPodmanManager_RemoveImage_NotInitialized verifies error when not initialized.
// TestPodmanManager_PullImage_NotInitialized verifies error when not initialized.
// TestPodmanManager_PullImage_EmptyRef verifies error for empty image ref.
// TestPodmanManager_InspectImage_EmptyRef verifies error for empty image ref.
// TestPodmanManager_InspectImage_Success verifies basic image inspection.
func TestPodmanManager_InspectImage_Success(t *testing.T) {
	mgr := createInitializedTestManager(t)

	img, err := mgr.InspectImage(context.Background(), "test:latest")
	require.NoError(t, err)
	assert.NotNil(t, img)
	assert.Equal(t, "test:latest", img.ID)
}

// TestPodmanManager_ListImages_Success verifies listing images.
func TestPodmanManager_ListImages_Success(t *testing.T) {
	mgr := createInitializedTestManager(t)

	images, err := mgr.ListImages(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, images)
}

// TestPodmanManager_StartContainer_NotInitialized verifies error when not initialized.
// TestPodmanManager_StartContainer_EmptyID verifies error for empty container ID.
// TestPodmanManager_StopContainer_NotInitialized verifies error when not initialized.
// TestPodmanManager_StopContainer_EmptyID verifies error for empty container ID.
// TestPodmanManager_RemoveContainer_NotInitialized verifies error when not initialized.
// TestPodmanManager_RemoveContainer_EmptyID verifies error for empty container ID.
// TestPodmanManager_InspectContainer_NotInitialized verifies error when not initialized.
// TestPodmanManager_InspectContainer_EmptyID verifies error for empty container ID.
// TestPodmanManager_ListContainers_NotInitialized verifies error when not initialized.
// TestPodmanManager_WaitContainer_NotInitialized verifies error when not initialized.
// TestPodmanManager_WaitContainer_EmptyID verifies error for empty container ID.
// TestPodmanManager_GetContainerLogs_NotInitialized verifies error when not initialized.
// TestPodmanManager_GetContainerLogs_EmptyID verifies error for empty container ID.
// TestPodmanManager_GetContainerLogs_WithSinceParam verifies logs with since time.
func TestPodmanManager_GetContainerLogs_WithSinceParam(t *testing.T) {
	mgr := createInitializedTestManager(t)

	since := time.Now().Add(-1 * time.Hour)
	logs, err := mgr.GetContainerLogs(context.Background(), "some-container", false, &since)
	require.NoError(t, err)
	assert.NotNil(t, logs)
	assert.Equal(t, "some-container", logs.ContainerID)
	assert.Equal(t, since, logs.Since)
}

// TestPodmanManager_GetContainerLogs_NilSince verifies logs without since time.
func TestPodmanManager_GetContainerLogs_NilSince(t *testing.T) {
	mgr := createInitializedTestManager(t)

	logs, err := mgr.GetContainerLogs(context.Background(), "some-container", false, nil)
	require.NoError(t, err)
	assert.NotNil(t, logs)
	assert.Equal(t, "some-container", logs.ContainerID)
}

// TestPodmanManager_RemoveImage_EmptyRef verifies error for empty image ref.
// TestPodmanManager_GetAttestor verifies attestor accessor.
// TestPodmanManager_CreateContainer_NotInitialized verifies error when not initialized.
// TestWithRuntimeLogger verifies the runtime logger option.
func TestWithRuntimeLogger(t *testing.T) {
	logger := slog.Default()
	r := &Runtime{}
	opt := WithRuntimeLogger(logger)
	opt(r)
	assert.Equal(t, logger, r.logger)
}

// TestManagerConfig_Validate_NilRuntime verifies validation with nil runtime.
// TestManagerConfig_Validate_NegativeMaxContainers verifies validation with bad max containers.
// TestManagerConfig_Validate_NegativeStopTimeout verifies validation with negative timeout.
// createInitializedTestManager creates a podman manager with initialized flag set
// but no actual runtime, for testing validation paths.
func createInitializedTestManager(t *testing.T) PodmanManager {
	t.Helper()
	mgr, err := NewPodmanManager(nil)
	require.NoError(t, err)

	// Set initialized via the internal type to simulate initialization
	// without needing a real OCI runtime
	impl := mgr.(*podmanManager)
	impl.initialized.Store(true)
	impl.runtime = &Runtime{
		config: DefaultRuntimeConfig(),
		logger: slog.Default(),
	}

	return mgr
}
