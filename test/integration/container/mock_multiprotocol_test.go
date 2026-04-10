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

// Package container provides multi-protocol integration tests using the mock adapter.
// These tests verify container operations work correctly through the ContainerCommands
// interface without requiring a real container runtime.
//
// Run tests via:
//
//	make integration-test-container
package container

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock Adapter Test Entry Point
// =============================================================================

// TestContainerMockAdapter runs the complete container test suite using the mock
// adapter. This enables testing container operations without a real container runtime.
func TestContainerMockAdapter(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewMockAdapter()
	require.NoError(t, adapter.Setup(ctx), "Mock adapter setup should succeed")
	defer adapter.Teardown()

	prefix := GenerateUniquePrefix("mock")

	t.Run("Lifecycle", func(t *testing.T) {
		runMockLifecycleTests(t, ctx, adapter, prefix)
	})

	t.Run("Listing", func(t *testing.T) {
		runMockListingTests(t, ctx, adapter, prefix)
	})

	t.Run("Logs", func(t *testing.T) {
		runMockLogsTests(t, ctx, adapter, prefix)
	})

	t.Run("Attestation", func(t *testing.T) {
		runMockAttestationTests(t, ctx, adapter, prefix)
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		runMockErrorHandlingTests(t, ctx, adapter, prefix)
	})

	t.Run("FailureInjection", func(t *testing.T) {
		runMockFailureInjectionTests(t, ctx, adapter, prefix)
	})

	t.Run("CallTracking", func(t *testing.T) {
		runMockCallTrackingTests(t, ctx, adapter, prefix)
	})

	t.Run("FullLifecycle", func(t *testing.T) {
		runMockFullLifecycleTest(t, ctx, adapter, prefix)
	})
}

// =============================================================================
// Lifecycle Tests
// =============================================================================

func runMockLifecycleTests(t *testing.T, ctx context.Context, adapter *MockAdapter, prefix string) {
	t.Run("CreateContainer", func(t *testing.T) {
		containerName := prefix + "-create"
		opts := CreateOptions{
			Name:  containerName,
			Image: TestImageAlpine,
			Labels: map[string]string{
				"test": "create",
			},
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err, "Create should succeed")
		require.NotNil(t, container)
		assert.NotEmpty(t, container.ID, "Container ID should not be empty")
		assert.Equal(t, containerName, container.Name)
		assert.Equal(t, TestImageAlpine, container.Image)
		assert.Equal(t, StateCreated, container.State)

		// Cleanup
		CleanupContainer(t, ctx, adapter, container.ID)
	})

	t.Run("CreateContainerWithEnvironment", func(t *testing.T) {
		containerName := prefix + "-create-env"
		opts := CreateOptions{
			Name:  containerName,
			Image: TestImageAlpine,
			Environment: map[string]string{
				"APP_ENV":   "test",
				"DEBUG":     "true",
				"LOG_LEVEL": "debug",
			},
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		require.NotNil(t, container)
		assert.Equal(t, "test", container.Environment["APP_ENV"])
		assert.Equal(t, "true", container.Environment["DEBUG"])

		CleanupContainer(t, ctx, adapter, container.ID)
	})

	t.Run("StartContainer", func(t *testing.T) {
		containerName := prefix + "-start"
		opts := CreateOptions{
			Name:  containerName,
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		err = adapter.Start(ctx, container.ID)
		require.NoError(t, err, "Start should succeed")

		updated, err := adapter.Get(ctx, container.ID)
		require.NoError(t, err)
		assert.Equal(t, StateRunning, updated.State)
		assert.Greater(t, updated.PID, 0, "Running container should have a PID")
	})

	t.Run("StopContainer", func(t *testing.T) {
		containerName := prefix + "-stop"
		opts := CreateOptions{
			Name:  containerName,
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		err = adapter.Start(ctx, container.ID)
		require.NoError(t, err)

		err = adapter.Stop(ctx, container.ID, 10*time.Second)
		require.NoError(t, err, "Stop should succeed")

		updated, err := adapter.Get(ctx, container.ID)
		require.NoError(t, err)
		assert.True(t, updated.State.IsStopped(), "Container should be stopped")
		assert.Equal(t, 0, updated.PID, "Stopped container should have PID 0")
	})

	t.Run("RemoveContainer", func(t *testing.T) {
		containerName := prefix + "-remove"
		opts := CreateOptions{
			Name:  containerName,
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)

		err = adapter.Remove(ctx, container.ID, false)
		require.NoError(t, err, "Remove should succeed for stopped container")

		_, err = adapter.Get(ctx, container.ID)
		require.Error(t, err, "Get should fail for removed container")
	})

	t.Run("ForceRemoveRunningContainer", func(t *testing.T) {
		containerName := prefix + "-force-remove"
		opts := CreateOptions{
			Name:  containerName,
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)

		err = adapter.Start(ctx, container.ID)
		require.NoError(t, err)

		// Remove without force should fail
		err = adapter.Remove(ctx, container.ID, false)
		require.Error(t, err, "Remove without force should fail for running container")

		// Force remove should succeed
		err = adapter.Remove(ctx, container.ID, true)
		require.NoError(t, err, "Force remove should succeed")
	})
}

// =============================================================================
// Listing Tests
// =============================================================================

func runMockListingTests(t *testing.T, ctx context.Context, adapter *MockAdapter, prefix string) {
	// Create multiple containers for listing tests
	var containerIDs []string
	listPrefix := prefix + "-list"

	for i := 0; i < 5; i++ {
		opts := CreateOptions{
			Name:  fmt.Sprintf("%s-%d", listPrefix, i),
			Image: TestImageAlpine,
			Labels: map[string]string{
				"test-group": listPrefix,
				"index":      fmt.Sprintf("%d", i),
			},
		}
		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		containerIDs = append(containerIDs, container.ID)

		// Start every other container
		if i%2 == 0 {
			require.NoError(t, adapter.Start(ctx, container.ID))
		}
	}

	defer func() {
		for _, id := range containerIDs {
			CleanupContainer(t, ctx, adapter, id)
		}
	}()

	t.Run("ListAllContainers", func(t *testing.T) {
		containers, err := adapter.List(ctx, ListOptions{All: true})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(containers), 5, "Should list at least 5 containers")
	})

	t.Run("ListWithLimit", func(t *testing.T) {
		containers, err := adapter.List(ctx, ListOptions{All: true, Limit: 3})
		require.NoError(t, err)
		assert.LessOrEqual(t, len(containers), 3, "Should respect limit")
	})

	t.Run("ListByState", func(t *testing.T) {
		containers, err := adapter.List(ctx, ListOptions{All: true, StateFilter: StateRunning})
		require.NoError(t, err)

		for _, c := range containers {
			assert.Equal(t, StateRunning, c.State, "All listed containers should be running")
		}
	})

	t.Run("ListByNameFilter", func(t *testing.T) {
		containers, err := adapter.List(ctx, ListOptions{All: true, NameFilter: listPrefix})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(containers), 5, "Should find containers matching name filter")

		for _, c := range containers {
			assert.Contains(t, c.Name, listPrefix, "Container name should contain filter prefix")
		}
	})

	t.Run("ListByLabelFilter", func(t *testing.T) {
		containers, err := adapter.List(ctx, ListOptions{
			All: true,
			Filters: map[string]string{
				"test-group": listPrefix,
			},
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(containers), 5, "Should find containers matching label filter")
	})
}

// =============================================================================
// Logs Tests
// =============================================================================

func runMockLogsTests(t *testing.T, ctx context.Context, adapter *MockAdapter, prefix string) {
	containerName := prefix + "-logs"
	opts := CreateOptions{
		Name:  containerName,
		Image: TestImageAlpine,
	}

	container, err := adapter.Create(ctx, opts)
	require.NoError(t, err)
	defer CleanupContainer(t, ctx, adapter, container.ID)

	// Add mock logs
	adapter.AddMockLogs(container.ID, []string{
		"Line 1: Starting application",
		"Line 2: Initializing components",
		"Line 3: Application ready",
		"Line 4: Processing request",
		"Line 5: Request complete",
	})

	err = adapter.Start(ctx, container.ID)
	require.NoError(t, err)

	t.Run("GetAllLogs", func(t *testing.T) {
		logs, err := adapter.Logs(ctx, container.ID, LogOptions{Stdout: true, Stderr: true})
		require.NoError(t, err)
		assert.NotEmpty(t, logs, "Should have log entries")
	})

	t.Run("GetLogsWithTail", func(t *testing.T) {
		logs, err := adapter.Logs(ctx, container.ID, LogOptions{Stdout: true, Tail: 2})
		require.NoError(t, err)
		assert.LessOrEqual(t, len(logs), 2, "Should return at most 2 lines")
	})

	t.Run("GetLogsForNonexistentContainer", func(t *testing.T) {
		_, err := adapter.Logs(ctx, "nonexistent-id", LogOptions{Stdout: true})
		require.Error(t, err, "Logs should fail for nonexistent container")
	})
}

// =============================================================================
// Attestation Tests
// =============================================================================

func runMockAttestationTests(t *testing.T, ctx context.Context, adapter *MockAdapter, prefix string) {
	containerName := prefix + "-attest"
	opts := CreateOptions{
		Name:  containerName,
		Image: TestImageAlpine,
	}

	container, err := adapter.Create(ctx, opts)
	require.NoError(t, err)
	defer CleanupContainer(t, ctx, adapter, container.ID)

	err = adapter.Start(ctx, container.ID)
	require.NoError(t, err)

	t.Run("AttestRunningContainer", func(t *testing.T) {
		report, err := adapter.Attest(ctx, container.ID)
		require.NoError(t, err)
		require.NotNil(t, report)

		assert.Equal(t, container.ID, report.ContainerID)
		assert.Equal(t, containerName, report.ContainerName)
		assert.NotEmpty(t, report.ImageDigest)
		assert.NotEmpty(t, report.ConfigDigest)
		assert.NotEmpty(t, report.Quote)
		assert.NotEmpty(t, report.Signature)
		assert.NotEmpty(t, report.PCRValues)
		assert.NotEmpty(t, report.Nonce)
		assert.False(t, report.Timestamp.IsZero())
		assert.True(t, report.Verified)
	})

	t.Run("AttestationHasMeasurementLog", func(t *testing.T) {
		report, err := adapter.Attest(ctx, container.ID)
		require.NoError(t, err)

		assert.NotEmpty(t, report.Log, "Attestation should have measurement log")

		for _, entry := range report.Log {
			assert.GreaterOrEqual(t, entry.PCRIndex, 0)
			assert.LessOrEqual(t, entry.PCRIndex, 23)
			assert.NotEmpty(t, entry.EventType)
			assert.NotEmpty(t, entry.Digest)
		}
	})

	t.Run("AttestNonexistentContainer", func(t *testing.T) {
		_, err := adapter.Attest(ctx, "nonexistent-id")
		require.Error(t, err, "Attest should fail for nonexistent container")
	})
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func runMockErrorHandlingTests(t *testing.T, ctx context.Context, adapter *MockAdapter, prefix string) {
	t.Run("CreateWithEmptyName", func(t *testing.T) {
		opts := CreateOptions{
			Name:  "",
			Image: TestImageAlpine,
		}
		_, err := adapter.Create(ctx, opts)
		require.Error(t, err, "Create should fail with empty name")
	})

	t.Run("CreateWithEmptyImage", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-no-image",
			Image: "",
		}
		_, err := adapter.Create(ctx, opts)
		require.Error(t, err, "Create should fail with empty image")
	})

	t.Run("CreateDuplicateName", func(t *testing.T) {
		containerName := prefix + "-duplicate"
		opts := CreateOptions{
			Name:  containerName,
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		_, err = adapter.Create(ctx, opts)
		require.Error(t, err, "Create should fail with duplicate name")
	})

	t.Run("StartNonexistentContainer", func(t *testing.T) {
		err := adapter.Start(ctx, "nonexistent-id")
		require.Error(t, err, "Start should fail for nonexistent container")
	})

	t.Run("StartWithEmptyID", func(t *testing.T) {
		err := adapter.Start(ctx, "")
		require.Error(t, err, "Start should fail with empty ID")
	})

	t.Run("StartAlreadyRunningContainer", func(t *testing.T) {
		containerName := prefix + "-already-running"
		opts := CreateOptions{
			Name:  containerName,
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		require.NoError(t, adapter.Start(ctx, container.ID))

		err = adapter.Start(ctx, container.ID)
		require.Error(t, err, "Start should fail for already running container")
	})

	t.Run("StopNonRunningContainer", func(t *testing.T) {
		containerName := prefix + "-not-running"
		opts := CreateOptions{
			Name:  containerName,
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		err = adapter.Stop(ctx, container.ID, 10*time.Second)
		require.Error(t, err, "Stop should fail for non-running container")
	})

	t.Run("GetWithEmptyID", func(t *testing.T) {
		_, err := adapter.Get(ctx, "")
		require.Error(t, err, "Get should fail with empty ID")
	})

	t.Run("RemoveWithEmptyID", func(t *testing.T) {
		err := adapter.Remove(ctx, "", false)
		require.Error(t, err, "Remove should fail with empty ID")
	})
}

// =============================================================================
// Failure Injection Tests
// =============================================================================

func runMockFailureInjectionTests(t *testing.T, ctx context.Context, adapter *MockAdapter, prefix string) {
	t.Run("InjectCreateFailure", func(t *testing.T) {
		adapter.SetFailure("create", true, fmt.Errorf("injected create failure"))
		defer adapter.ClearFailures()

		opts := CreateOptions{
			Name:  prefix + "-inject-create",
			Image: TestImageAlpine,
		}

		_, err := adapter.Create(ctx, opts)
		require.Error(t, err, "Create should fail with injected failure")
		assert.Contains(t, err.Error(), "injected create failure")
	})

	t.Run("InjectStartFailure", func(t *testing.T) {
		// First create a container without failure injection
		opts := CreateOptions{
			Name:  prefix + "-inject-start",
			Image: TestImageAlpine,
		}
		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		// Now inject start failure
		adapter.SetFailure("start", true, fmt.Errorf("injected start failure"))
		defer adapter.ClearFailures()

		err = adapter.Start(ctx, container.ID)
		require.Error(t, err, "Start should fail with injected failure")
		assert.Contains(t, err.Error(), "injected start failure")
	})

	t.Run("InjectGetFailure", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-inject-get",
			Image: TestImageAlpine,
		}
		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		adapter.SetFailure("get", true, fmt.Errorf("injected get failure"))
		defer adapter.ClearFailures()

		_, err = adapter.Get(ctx, container.ID)
		require.Error(t, err, "Get should fail with injected failure")
	})

	t.Run("InjectListFailure", func(t *testing.T) {
		adapter.SetFailure("list", true, fmt.Errorf("injected list failure"))
		defer adapter.ClearFailures()

		_, err := adapter.List(ctx, ListOptions{All: true})
		require.Error(t, err, "List should fail with injected failure")
	})

	t.Run("InjectAttestFailure", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-inject-attest",
			Image: TestImageAlpine,
		}
		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		adapter.SetFailure("attest", true, fmt.Errorf("injected attest failure"))
		defer adapter.ClearFailures()

		_, err = adapter.Attest(ctx, container.ID)
		require.Error(t, err, "Attest should fail with injected failure")
	})

	t.Run("ClearFailures", func(t *testing.T) {
		adapter.SetFailure("all", true, fmt.Errorf("all failures"))
		adapter.ClearFailures()

		opts := CreateOptions{
			Name:  prefix + "-clear-failures",
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err, "Create should succeed after clearing failures")
		CleanupContainer(t, ctx, adapter, container.ID)
	})
}

// =============================================================================
// Call Tracking Tests
// =============================================================================

func runMockCallTrackingTests(t *testing.T, ctx context.Context, adapter *MockAdapter, prefix string) {
	adapter.ResetCallCounters()

	containerName := prefix + "-call-tracking"
	opts := CreateOptions{
		Name:  containerName,
		Image: TestImageAlpine,
	}

	// Create
	container, err := adapter.Create(ctx, opts)
	require.NoError(t, err)
	defer CleanupContainer(t, ctx, adapter, container.ID)

	assert.Equal(t, int32(1), adapter.GetCreateCalls(), "Create should be called once")

	// Get
	_, err = adapter.Get(ctx, container.ID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), adapter.GetGetCalls(), "Get should be called once")

	// List
	_, err = adapter.List(ctx, ListOptions{All: true})
	require.NoError(t, err)
	assert.Equal(t, int32(1), adapter.GetListCalls(), "List should be called once")

	// Start
	err = adapter.Start(ctx, container.ID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), adapter.GetStartCalls(), "Start should be called once")

	// Logs
	_, err = adapter.Logs(ctx, container.ID, LogOptions{Stdout: true})
	require.NoError(t, err)
	assert.Equal(t, int32(1), adapter.GetLogsCalls(), "Logs should be called once")

	// Attest
	_, err = adapter.Attest(ctx, container.ID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), adapter.GetAttestCalls(), "Attest should be called once")

	// Stop
	err = adapter.Stop(ctx, container.ID, 10*time.Second)
	require.NoError(t, err)
	assert.Equal(t, int32(1), adapter.GetStopCalls(), "Stop should be called once")

	// Reset counters
	adapter.ResetCallCounters()
	assert.Equal(t, int32(0), adapter.GetCreateCalls(), "Counters should be reset")
	assert.Equal(t, int32(0), adapter.GetStartCalls(), "Counters should be reset")
}

// =============================================================================
// Full Lifecycle Test
// =============================================================================

func runMockFullLifecycleTest(t *testing.T, ctx context.Context, adapter *MockAdapter, prefix string) {
	containerName := prefix + "-full-lifecycle"

	t.Log("=== Phase 1: Create Container ===")
	createOpts := CreateOptions{
		Name:  containerName,
		Image: TestImageAlpine,
		Environment: map[string]string{
			"APP_ENV":   "integration-test",
			"LOG_LEVEL": "debug",
		},
		Labels: map[string]string{
			"test":     "full-lifecycle",
			"protocol": "mock",
		},
	}

	container, err := adapter.Create(ctx, createOpts)
	require.NoError(t, err, "Create should succeed")
	require.NotNil(t, container)
	assert.NotEmpty(t, container.ID)
	t.Logf("Created container: %s (%s)", container.Name, container.ID)

	containerID := container.ID

	t.Log("=== Phase 2: Verify Container Created ===")
	retrieved, err := adapter.Get(ctx, containerID)
	require.NoError(t, err)
	assert.Equal(t, containerName, retrieved.Name)
	assert.Equal(t, StateCreated, retrieved.State)
	t.Logf("Container state: %s", retrieved.State)

	t.Log("=== Phase 3: Start Container ===")
	err = adapter.Start(ctx, containerID)
	require.NoError(t, err, "Start should succeed")

	retrieved, err = adapter.Get(ctx, containerID)
	require.NoError(t, err)
	assert.Equal(t, StateRunning, retrieved.State)
	assert.Greater(t, retrieved.PID, 0)
	t.Logf("Container state after start: %s (PID: %d)", retrieved.State, retrieved.PID)

	t.Log("=== Phase 4: Add and Retrieve Logs ===")
	adapter.AddMockLogs(containerID, []string{
		"Application starting...",
		"Loading configuration",
		"Ready to accept connections",
	})

	logs, err := adapter.Logs(ctx, containerID, LogOptions{Stdout: true, Stderr: true})
	require.NoError(t, err)
	t.Logf("Retrieved %d log lines", len(logs))

	t.Log("=== Phase 5: Perform Attestation ===")
	report, err := adapter.Attest(ctx, containerID)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, containerID, report.ContainerID)
	assert.NotEmpty(t, report.Quote)
	assert.NotEmpty(t, report.Signature)
	assert.True(t, report.Verified)
	t.Logf("Attestation completed at: %s", report.Timestamp)
	t.Logf("  - Image digest: %s", report.ImageDigest[:16]+"...")
	t.Logf("  - Quote length: %d bytes", len(report.Quote))
	t.Logf("  - Signature length: %d bytes", len(report.Signature))
	t.Logf("  - PCR values: %d", len(report.PCRValues))
	t.Logf("  - Measurement log entries: %d", len(report.Log))

	t.Log("=== Phase 6: Verify Container in List ===")
	containers, err := adapter.List(ctx, ListOptions{All: true})
	require.NoError(t, err)

	found := false
	for _, c := range containers {
		if c.ID == containerID {
			found = true
			break
		}
	}
	assert.True(t, found, "Container should appear in list")
	t.Logf("Found container in list of %d containers", len(containers))

	t.Log("=== Phase 7: Stop Container ===")
	err = adapter.Stop(ctx, containerID, 10*time.Second)
	require.NoError(t, err, "Stop should succeed")

	retrieved, err = adapter.Get(ctx, containerID)
	require.NoError(t, err)
	assert.True(t, retrieved.State.IsStopped())
	assert.Equal(t, 0, retrieved.PID)
	t.Logf("Container state after stop: %s", retrieved.State)

	t.Log("=== Phase 8: Remove Container ===")
	err = adapter.Remove(ctx, containerID, false)
	require.NoError(t, err, "Remove should succeed")

	_, err = adapter.Get(ctx, containerID)
	require.Error(t, err, "Get should fail for removed container")
	t.Log("Container successfully removed")

	t.Log("=== Full Lifecycle Test Complete ===")
}

// =============================================================================
// Individual Protocol Tests (Single Adapter)
// =============================================================================

// TestContainerMock tests container operations via Mock adapter only.
func TestContainerMock(t *testing.T) {
	SkipIfNotIntegration(t)
	testSingleAdapter(t, NewMockAdapter())
}

// testSingleAdapter runs the basic test suite for a single adapter.
func testSingleAdapter(t *testing.T, adapter ContainerCommands) {
	ctx, cancel := LongRunningTestContext()
	defer cancel()

	if err := adapter.Setup(ctx); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer adapter.Teardown()

	prefix := GenerateUniquePrefix(adapter.Name())

	t.Run("BasicCreate", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-basic",
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		require.NotNil(t, container)
		assert.NotEmpty(t, container.ID)

		CleanupContainer(t, ctx, adapter, container.ID)
	})

	t.Run("BasicLifecycle", func(t *testing.T) {
		opts := CreateOptions{
			Name:    prefix + "-lifecycle",
			Image:   TestImageAlpine,
			Command: []string{"sleep", "60"},
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		require.NoError(t, adapter.Start(ctx, container.ID))

		updated, err := adapter.Get(ctx, container.ID)
		require.NoError(t, err)
		assert.True(t, updated.State.IsRunning())

		require.NoError(t, adapter.Stop(ctx, container.ID, 10*time.Second))

		updated, err = adapter.Get(ctx, container.ID)
		require.NoError(t, err)
		assert.True(t, updated.State.IsStopped())
	})

	t.Run("BasicList", func(t *testing.T) {
		containers, err := adapter.List(ctx, ListOptions{All: true})
		require.NoError(t, err)
		assert.NotNil(t, containers)
	})
}
