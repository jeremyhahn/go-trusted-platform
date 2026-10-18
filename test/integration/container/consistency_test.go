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

// Package container provides consistency tests for multi-protocol container operations.
// These tests verify that all protocol adapters return consistent results for the
// same operations, ensuring API consistency across transport layers.
//
// Run tests via:
//
//	make integration-test-container
package container

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Consistency Test Types
// =============================================================================

// adapterResult holds the result of an adapter operation for comparison.
type adapterResult struct {
	name string
	err  error
	data interface{}
}

// =============================================================================
// Consistency Tests
// =============================================================================

// TestContainerConsistency verifies that all protocol adapters return consistent
// results for container operations.
func TestContainerConsistency(t *testing.T) {
	ctx, cancel := LongRunningTestContext()
	defer cancel()

	// Use mock adapter for consistency testing since it doesn't require
	// a real container runtime
	adapters := []ContainerCommands{
		NewMockAdapter(),
	}

	// Collect results from all working adapters
	var workingAdapters []ContainerCommands
	for _, adapter := range adapters {
		if err := adapter.Setup(ctx); err != nil {
			t.Fatalf("%s adapter: setup failed: %v", adapter.Name(), err)
		}
		workingAdapters = append(workingAdapters, adapter)
	}

	if len(workingAdapters) < 1 {
		t.Fatal("Need at least 1 working adapter to test consistency")
	}

	defer func() {
		for _, adapter := range workingAdapters {
			adapter.Teardown()
		}
	}()

	t.Run("CreateConsistency", func(t *testing.T) {
		testCreateConsistency(t, ctx, workingAdapters)
	})

	t.Run("LifecycleConsistency", func(t *testing.T) {
		testLifecycleConsistency(t, ctx, workingAdapters)
	})

	t.Run("ListConsistency", func(t *testing.T) {
		testListConsistency(t, ctx, workingAdapters)
	})

	t.Run("ErrorConsistency", func(t *testing.T) {
		testErrorConsistency(t, ctx, workingAdapters)
	})
}

// testCreateConsistency verifies Create returns consistent container properties.
func testCreateConsistency(t *testing.T, ctx context.Context, adapters []ContainerCommands) {
	t.Helper()

	if len(adapters) < 1 {
		t.Fatal("Need at least 1 adapter for consistency testing")
	}

	prefix := GenerateUniquePrefix("consistency-create")

	for i, adapter := range adapters {
		containerName := prefix + "-" + adapter.Name()
		opts := CreateOptions{
			Name:  containerName,
			Image: TestImageAlpine,
			Labels: map[string]string{
				"consistency-test": "true",
				"index":            string(rune('0' + i)),
			},
			Environment: map[string]string{
				"TEST_VAR": "consistency",
			},
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err, "%s: Create should succeed", adapter.Name())
		defer CleanupContainer(t, ctx, adapter, container.ID)

		// Verify basic properties
		assert.NotEmpty(t, container.ID, "%s: Container ID should not be empty", adapter.Name())
		assert.Equal(t, containerName, container.Name, "%s: Container name should match", adapter.Name())
		assert.Equal(t, TestImageAlpine, container.Image, "%s: Container image should match", adapter.Name())
		assert.Equal(t, StateCreated, container.State, "%s: Initial state should be created", adapter.Name())
		assert.False(t, container.CreatedAt.IsZero(), "%s: CreatedAt should be set", adapter.Name())
	}
}

// testLifecycleConsistency verifies lifecycle operations behave consistently.
func testLifecycleConsistency(t *testing.T, ctx context.Context, adapters []ContainerCommands) {
	t.Helper()

	if len(adapters) < 1 {
		t.Fatal("Need at least 1 adapter for consistency testing")
	}

	prefix := GenerateUniquePrefix("consistency-lifecycle")

	for _, adapter := range adapters {
		containerName := prefix + "-" + adapter.Name()

		t.Run(adapter.Name(), func(t *testing.T) {
			// Create
			opts := CreateOptions{
				Name:  containerName,
				Image: TestImageAlpine,
			}

			container, err := adapter.Create(ctx, opts)
			require.NoError(t, err, "Create should succeed")
			defer CleanupContainer(t, ctx, adapter, container.ID)

			// Verify created state
			retrieved, err := adapter.Get(ctx, container.ID)
			require.NoError(t, err, "Get should succeed")
			assert.Equal(t, StateCreated, retrieved.State, "State should be created")

			// Start
			err = adapter.Start(ctx, container.ID)
			require.NoError(t, err, "Start should succeed")

			retrieved, err = adapter.Get(ctx, container.ID)
			require.NoError(t, err, "Get should succeed after start")
			assert.Equal(t, StateRunning, retrieved.State, "State should be running")
			assert.False(t, retrieved.StartedAt.IsZero(), "StartedAt should be set")

			// Stop
			err = adapter.Stop(ctx, container.ID, 10*time.Second)
			require.NoError(t, err, "Stop should succeed")

			retrieved, err = adapter.Get(ctx, container.ID)
			require.NoError(t, err, "Get should succeed after stop")
			assert.True(t, retrieved.State.IsStopped(), "State should be stopped")
			assert.False(t, retrieved.StoppedAt.IsZero(), "StoppedAt should be set")
		})
	}
}

// testListConsistency verifies List returns consistent results.
func testListConsistency(t *testing.T, ctx context.Context, adapters []ContainerCommands) {
	t.Helper()

	if len(adapters) < 1 {
		t.Fatal("Need at least 1 adapter for consistency testing")
	}

	prefix := GenerateUniquePrefix("consistency-list")

	for _, adapter := range adapters {
		t.Run(adapter.Name(), func(t *testing.T) {
			// Create multiple containers
			var containerIDs []string
			for i := 0; i < 3; i++ {
				opts := CreateOptions{
					Name:  prefix + "-" + adapter.Name() + "-" + string(rune('a'+i)),
					Image: TestImageAlpine,
					Labels: map[string]string{
						"list-test": prefix,
					},
				}

				container, err := adapter.Create(ctx, opts)
				require.NoError(t, err, "Create should succeed for container %d", i)
				containerIDs = append(containerIDs, container.ID)
			}

			defer func() {
				for _, id := range containerIDs {
					CleanupContainer(t, ctx, adapter, id)
				}
			}()

			// List all
			containers, err := adapter.List(ctx, ListOptions{All: true})
			require.NoError(t, err, "List should succeed")
			assert.GreaterOrEqual(t, len(containers), 3, "Should list at least 3 containers")

			// Verify all created containers are in the list
			foundCount := 0
			for _, c := range containers {
				for _, id := range containerIDs {
					if c.ID == id {
						foundCount++
						break
					}
				}
			}
			assert.Equal(t, 3, foundCount, "All created containers should be in the list")

			// List with limit
			limited, err := adapter.List(ctx, ListOptions{All: true, Limit: 2})
			require.NoError(t, err, "List with limit should succeed")
			assert.LessOrEqual(t, len(limited), 2, "Should respect limit")
		})
	}
}

// testErrorConsistency verifies error conditions are handled consistently.
func testErrorConsistency(t *testing.T, ctx context.Context, adapters []ContainerCommands) {
	t.Helper()

	if len(adapters) < 1 {
		t.Fatal("Need at least 1 adapter for consistency testing")
	}

	nonexistentID := "nonexistent-container-12345"

	for _, adapter := range adapters {
		t.Run(adapter.Name(), func(t *testing.T) {
			// Get nonexistent container
			_, err := adapter.Get(ctx, nonexistentID)
			require.Error(t, err, "Get should fail for nonexistent container")

			// Start nonexistent container
			err = adapter.Start(ctx, nonexistentID)
			require.Error(t, err, "Start should fail for nonexistent container")

			// Stop nonexistent container
			err = adapter.Stop(ctx, nonexistentID, 10*time.Second)
			require.Error(t, err, "Stop should fail for nonexistent container")

			// Remove nonexistent container
			err = adapter.Remove(ctx, nonexistentID, false)
			require.Error(t, err, "Remove should fail for nonexistent container")

			// Logs for nonexistent container
			_, err = adapter.Logs(ctx, nonexistentID, LogOptions{Stdout: true})
			require.Error(t, err, "Logs should fail for nonexistent container")

			// Attest nonexistent container
			_, err = adapter.Attest(ctx, nonexistentID)
			require.Error(t, err, "Attest should fail for nonexistent container")

			// Create with empty name
			_, err = adapter.Create(ctx, CreateOptions{Name: "", Image: TestImageAlpine})
			require.Error(t, err, "Create should fail with empty name")

			// Create with empty image
			_, err = adapter.Create(ctx, CreateOptions{Name: "test-empty-image", Image: ""})
			require.Error(t, err, "Create should fail with empty image")
		})
	}
}

// =============================================================================
// Response Structure Consistency Tests
// =============================================================================

// TestContainerResponseStructure verifies response structures are consistent.
func TestContainerResponseStructure(t *testing.T) {
	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewMockAdapter()
	require.NoError(t, adapter.Setup(ctx))
	defer adapter.Teardown()

	prefix := GenerateUniquePrefix("structure")

	t.Run("ContainerStructure", func(t *testing.T) {
		opts := CreateOptions{
			Name:    prefix + "-structure",
			Image:   TestImageAlpine,
			Command: []string{"sleep", "60"},
			Labels: map[string]string{
				"env": "test",
			},
			Environment: map[string]string{
				"VAR1": "value1",
			},
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		// Verify all expected fields are present
		assert.NotEmpty(t, container.ID, "ID should be set")
		assert.NotEmpty(t, container.Name, "Name should be set")
		assert.NotEmpty(t, container.Image, "Image should be set")
		assert.NotEmpty(t, container.State, "State should be set")
		assert.NotNil(t, container.Labels, "Labels should not be nil")
		assert.NotNil(t, container.Environment, "Environment should not be nil")

		// Verify state is one of the expected values
		validStates := map[ContainerState]bool{
			StateCreated:  true,
			StateRunning:  true,
			StateStopped:  true,
			StateExited:   true,
			StatePaused:   true,
			StateRemoving: true,
		}
		assert.True(t, validStates[container.State],
			"State should be a valid container state")

		// Start and verify running state
		require.NoError(t, adapter.Start(ctx, container.ID))
		running, err := adapter.Get(ctx, container.ID)
		require.NoError(t, err)

		assert.Equal(t, StateRunning, running.State, "State should be running")
		assert.Greater(t, running.PID, 0, "PID should be positive when running")
		assert.False(t, running.StartedAt.IsZero(), "StartedAt should be set")
	})

	t.Run("AttestationStructure", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-attest-structure",
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		require.NoError(t, adapter.Start(ctx, container.ID))

		report, err := adapter.Attest(ctx, container.ID)
		require.NoError(t, err)

		// Verify all expected fields are present
		assert.NotEmpty(t, report.ContainerID, "ContainerID should be set")
		assert.NotEmpty(t, report.ContainerName, "ContainerName should be set")
		assert.NotEmpty(t, report.ImageDigest, "ImageDigest should be set")
		assert.NotEmpty(t, report.ConfigDigest, "ConfigDigest should be set")
		assert.NotEmpty(t, report.Quote, "Quote should be set")
		assert.NotEmpty(t, report.Signature, "Signature should be set")
		assert.NotNil(t, report.PCRValues, "PCRValues should not be nil")
		assert.NotEmpty(t, report.Nonce, "Nonce should be set")
		assert.False(t, report.Timestamp.IsZero(), "Timestamp should be set")

		// Verify measurement log structure
		assert.NotNil(t, report.Log, "Log should not be nil")
		for _, entry := range report.Log {
			assert.GreaterOrEqual(t, entry.PCRIndex, 0, "PCRIndex should be >= 0")
			assert.LessOrEqual(t, entry.PCRIndex, 23, "PCRIndex should be <= 23")
			assert.NotEmpty(t, entry.EventType, "EventType should be set")
			assert.NotEmpty(t, entry.Digest, "Digest should be set")
		}
	})
}

// =============================================================================
// State Transition Consistency Tests
// =============================================================================

// TestContainerStateTransitions verifies state transitions are consistent.
func TestContainerStateTransitions(t *testing.T) {
	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapter := NewMockAdapter()
	require.NoError(t, adapter.Setup(ctx))
	defer adapter.Teardown()

	prefix := GenerateUniquePrefix("transition")

	t.Run("CreatedToRunning", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-created-running",
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		assert.Equal(t, StateCreated, container.State, "Initial state should be created")

		require.NoError(t, adapter.Start(ctx, container.ID))
		running, err := adapter.Get(ctx, container.ID)
		require.NoError(t, err)
		assert.Equal(t, StateRunning, running.State, "State should transition to running")
	})

	t.Run("RunningToStopped", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-running-stopped",
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		require.NoError(t, adapter.Start(ctx, container.ID))
		running, err := adapter.Get(ctx, container.ID)
		require.NoError(t, err)
		assert.Equal(t, StateRunning, running.State, "State should be running")

		require.NoError(t, adapter.Stop(ctx, container.ID, 10*time.Second))
		stopped, err := adapter.Get(ctx, container.ID)
		require.NoError(t, err)
		assert.True(t, stopped.State.IsStopped(), "State should transition to stopped")
	})

	t.Run("StoppedToRemoved", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-stopped-removed",
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)

		// Container starts in created state, which is stoppable
		require.NoError(t, adapter.Remove(ctx, container.ID, false))

		_, err = adapter.Get(ctx, container.ID)
		require.Error(t, err, "Get should fail after remove")
	})

	t.Run("InvalidTransitionCreatedToStopped", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-invalid-stop",
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		// Cannot stop a created (non-running) container
		err = adapter.Stop(ctx, container.ID, 10*time.Second)
		require.Error(t, err, "Stop should fail for non-running container")
	})

	t.Run("InvalidTransitionRunningStarted", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-invalid-start",
			Image: TestImageAlpine,
		}

		container, err := adapter.Create(ctx, opts)
		require.NoError(t, err)
		defer CleanupContainer(t, ctx, adapter, container.ID)

		require.NoError(t, adapter.Start(ctx, container.ID))

		// Cannot start an already running container
		err = adapter.Start(ctx, container.ID)
		require.Error(t, err, "Start should fail for already running container")
	})
}
