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
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// VerifyQuote — measurement log replay path
// =============================================================================

func TestContainerAttestor_VerifyQuote_MeasurementLogReplay(t *testing.T) {
	tpm := newMockTPMExtender()
	logger := &mockLogger{}
	attestor, err := NewContainerAttestor(tpm, nil, logger)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("valid measurement log", func(t *testing.T) {
		// Build a measurement log with two 32-byte measurements
		measurement1 := sha256.Sum256([]byte("measurement-1"))
		measurement2 := sha256.Sum256([]byte("measurement-2"))

		var measurementLog []byte
		measurementLog = append(measurementLog, measurement1[:]...)
		measurementLog = append(measurementLog, measurement2[:]...)

		// Compute expected PCR value by replaying
		pcr := make([]byte, 32)
		combined1 := append(pcr, measurement1[:]...)
		hash1 := sha256.Sum256(combined1)
		pcr = hash1[:]
		combined2 := append(pcr, measurement2[:]...)
		hash2 := sha256.Sum256(combined2)
		pcr = hash2[:]

		quote := &ContainerQuote{
			ContainerID:    "test-container",
			PCRIndex:       14,
			PCRValue:       pcr,
			MeasurementLog: measurementLog,
		}

		err := attestor.VerifyQuote(ctx, quote, nil)
		assert.NoError(t, err)
	})

	t.Run("measurement log mismatch", func(t *testing.T) {
		measurement1 := sha256.Sum256([]byte("measurement-1"))

		var measurementLog []byte
		measurementLog = append(measurementLog, measurement1[:]...)

		// Use a PCR value that does NOT match the log replay
		wrongPCR := make([]byte, 32)
		wrongPCR[0] = 0xFF

		quote := &ContainerQuote{
			ContainerID:    "test-container",
			PCRIndex:       14,
			PCRValue:       wrongPCR,
			MeasurementLog: measurementLog,
		}

		err := attestor.VerifyQuote(ctx, quote, nil)
		assert.Error(t, err)
	})

	t.Run("empty expected PCR skips comparison", func(t *testing.T) {
		quote := &ContainerQuote{
			ContainerID: "test",
			PCRIndex:    14,
			PCRValue:    make([]byte, 32),
		}
		// Empty expectedPCR means skip PCR comparison
		err := attestor.VerifyQuote(ctx, quote, nil)
		assert.NoError(t, err)
	})

	t.Run("empty quote PCR skips comparison", func(t *testing.T) {
		quote := &ContainerQuote{
			ContainerID: "test",
			PCRIndex:    14,
			PCRValue:    nil,
		}
		err := attestor.VerifyQuote(ctx, quote, make([]byte, 32))
		assert.NoError(t, err)
	})
}

// =============================================================================
// OnContainerStop — additional paths
// =============================================================================

func TestContainerAttestor_OnContainerStop_NilContainer(t *testing.T) {
	tpm := newMockTPMExtender()
	attestor, err := NewContainerAttestor(tpm, nil, &mockLogger{})
	require.NoError(t, err)

	err = attestor.OnContainerStop(context.Background(), nil)
	assert.Error(t, err)
}

func TestContainerAttestor_OnContainerStop_WithTPM(t *testing.T) {
	tpm := newMockTPMExtender()
	attestor, err := NewContainerAttestor(tpm, nil, &mockLogger{})
	require.NoError(t, err)

	now := time.Now()
	container := &Container{
		ID:         "stop-test-123",
		Name:       "stop-test",
		Image:      "alpine:latest",
		ExitCode:   0,
		FinishedAt: &now,
	}

	err = attestor.OnContainerStop(context.Background(), container)
	assert.NoError(t, err)
}

func TestContainerAttestor_OnContainerStop_NilTPM(t *testing.T) {
	attestor, err := NewContainerAttestor(nil, nil, &mockLogger{})
	require.NoError(t, err)

	now := time.Now()
	container := &Container{
		ID:         "stop-nil-tpm",
		Name:       "stop-test",
		Image:      "alpine:latest",
		FinishedAt: &now,
	}

	err = attestor.OnContainerStop(context.Background(), container)
	assert.NoError(t, err)
}

// =============================================================================
// Error type — missing coverage paths
// =============================================================================

func TestContainerError_WithIDNoErr(t *testing.T) {
	err := &ContainerError{
		ContainerID: "ctr-123",
		Operation:   "start",
		Err:         nil,
	}
	assert.Equal(t, "container ctr-123: start", err.Error())
}

func TestContainerError_NoIDNoErr(t *testing.T) {
	err := &ContainerError{
		ContainerID: "",
		Operation:   "create",
		Err:         nil,
	}
	assert.Equal(t, "create", err.Error())
}

func TestImageError_WithRefNoErr(t *testing.T) {
	err := &ImageError{
		ImageRef:  "alpine:latest",
		Operation: "pull",
		Err:       nil,
	}
	assert.Equal(t, "image alpine:latest: pull", err.Error())
}

func TestImageError_NoRefNoErr(t *testing.T) {
	err := &ImageError{
		ImageRef:  "",
		Operation: "list",
		Err:       nil,
	}
	assert.Equal(t, "list", err.Error())
}

// =============================================================================
// buildContainerMeasurement — ImageDigest path
// =============================================================================

func TestBuildContainerMeasurement_WithImageDigest(t *testing.T) {
	container := &Container{
		ID:          "abc123",
		Name:        "test",
		Image:       "alpine:latest",
		ImageDigest: "sha256:abcdef1234567890",
		Command:     []string{"sh"},
		CreatedAt:   time.Now(),
	}

	data := buildContainerMeasurement(container)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "sha256:abcdef1234567890")
}

// =============================================================================
// buildStopMeasurement — nil FinishedAt
// =============================================================================

func TestBuildStopMeasurement_NilFinishedAt(t *testing.T) {
	container := &Container{
		ID:       "abc123",
		ExitCode: 1,
	}

	data := buildStopMeasurement(container)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "container_stop")
}

// =============================================================================
// Runtime — verifyOCIRuntime error path
// =============================================================================

func TestRuntime_VerifyOCIRuntime_NotFound(t *testing.T) {
	r := &Runtime{
		config: &RuntimeConfig{
			OCIRuntime: "nonexistent-oci-runtime-that-does-not-exist-12345",
		},
	}
	err := r.verifyOCIRuntime()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// =============================================================================
// Runtime — ensureDirectories with empty dir paths
// =============================================================================

func TestRuntime_EnsureDirectories_EmptyDirSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	r := &Runtime{
		config: &RuntimeConfig{
			Root:           tmpDir + "/root",
			RunRoot:        tmpDir + "/runroot",
			TmpDir:         "",
			StaticDir:      "",
			VolumePath:     "",
			ImageStorePath: "",
		},
	}
	err := r.ensureDirectories()
	assert.NoError(t, err)
}

// =============================================================================
// Manager — ManagerConfig Validate edge case
// =============================================================================

func TestManagerConfig_Validate_ZeroMaxContainers(t *testing.T) {
	cfg := &ManagerConfig{
		Runtime:            DefaultRuntimeConfig(),
		MaxContainers:      0,
		DefaultStopTimeout: DefaultStopTimeout,
	}
	err := cfg.Validate()
	require.Error(t, err)
}
