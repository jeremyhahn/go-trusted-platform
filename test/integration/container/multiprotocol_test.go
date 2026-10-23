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

// Package container provides multi-protocol integration tests for the container orchestrator.
// These tests verify that container operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified ContainerCommands interface.
//
// Run tests via:
//
//	make integration-test-container
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package container

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	computecontainer "github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestContainerMultiProtocol runs the complete container test suite against all
// protocol adapters. Each adapter implements the ContainerCommands interface,
// enabling unified testing across CLI, REST, and future protocols (gRPC, QUIC, MCP, Socket).
func TestContainerMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement ContainerCommands
	adapters := []ContainerCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "container", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			runContainerProtocolTests(t, ctx, adapter)
		})
	}
}

// runContainerProtocolTests runs the complete container test suite against a single
// protocol adapter.
func runContainerProtocolTests(t *testing.T, ctx context.Context, cmd ContainerCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("ErrorHandling", func(t *testing.T) {
		runContainerNotFoundTests(t, ctx, cmd, prefix)
		runContainerInvalidArgsTests(t, ctx, cmd, prefix)
	})

	if launchRefused() {
		t.Run("LaunchRefused", func(t *testing.T) {
			runContainerLaunchRefusedTests(t, ctx, cmd, prefix)
		})
		return
	}

	t.Run("Lifecycle", func(t *testing.T) {
		runContainerCreateTests(t, ctx, cmd, prefix)
		runContainerGetTests(t, ctx, cmd, prefix)
		runContainerStartTests(t, ctx, cmd, prefix)
		runContainerStopTests(t, ctx, cmd, prefix)
		runContainerRemoveTests(t, ctx, cmd, prefix)
	})

	t.Run("Listing", func(t *testing.T) {
		runContainerListTests(t, ctx, cmd, prefix)
		runContainerListWithFiltersTests(t, ctx, cmd, prefix)
	})

	t.Run("Logs", func(t *testing.T) {
		runContainerLogsTests(t, ctx, cmd, prefix)
	})

	t.Run("Attestation", func(t *testing.T) {
		runContainerAttestTests(t, ctx, cmd, prefix)
	})

	t.Run("FullLifecycle", func(t *testing.T) {
		runContainerFullLifecycleTests(t, ctx, cmd, prefix)
	})
}

// launchRefused reports whether platformd refuses every container launch.
// The devcontainer's platformd runs on a TPM (swtpm), and a host with a TPM
// never starts a workload unmeasured: with neither docker nor podman on PATH
// every Create and Start is refused with MeasuredRuntimeUnavailableError
// (docs/compute/container-orchestrator.md).
func launchRefused() bool {
	for _, runtime := range computecontainer.MeasuredRuntimes {
		if _, err := exec.LookPath(runtime); err == nil {
			return false
		}
	}
	return true
}

// requireLaunchRefused asserts err is the measured-launch refusal. The typed
// error reaches every transport as its message, which names the runtimes.
func requireLaunchRefused(t *testing.T, err error, msgAndArgs ...any) {
	t.Helper()

	require.Error(t, err, msgAndArgs...)
	assert.Contains(t, err.Error(), "container launch refused", msgAndArgs...)
	for _, runtime := range computecontainer.MeasuredRuntimes {
		assert.Contains(t, err.Error(), runtime, msgAndArgs...)
	}
}

// runContainerLaunchRefusedTests asserts that a host which cannot measure a
// launch refuses every create and start, and keeps nothing it refused.
func runContainerLaunchRefusedTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	specs := map[string]CreateOptions{
		"Basic": {
			Name:   prefix + "-refused-basic",
			Image:  "docker.io/library/alpine:latest",
			Labels: map[string]string{"test": "true"},
		},
		"Environment": {
			Name:        prefix + "-refused-env",
			Image:       "docker.io/library/alpine:latest",
			Environment: map[string]string{"APP_ENV": "test"},
		},
		"Command": {
			Name:    prefix + "-refused-cmd",
			Image:   "docker.io/library/alpine:latest",
			Command: []string{"sleep", "3600"},
		},
	}

	for name, opts := range specs {
		t.Run("Create"+name, func(t *testing.T) {
			container, err := cmd.Create(testCtx, opts)
			requireLaunchRefused(t, err, "%s create %s", cmd.Name(), opts.Name)
			assert.Nil(t, container, "a refused create returns no container")
		})
	}

	t.Run("Start", func(t *testing.T) {
		err := cmd.Start(testCtx, prefix+"-refused-start")
		requireLaunchRefused(t, err, "%s start", cmd.Name())
	})

	t.Run("NothingKept", func(t *testing.T) {
		containers, err := cmd.List(testCtx, ListOptions{All: true})
		require.NoError(t, err, "List should succeed while launches are refused")
		for _, container := range containers {
			assert.NotContains(t, container.Name, prefix+"-refused-",
				"a refused create must leave no container behind")
		}
	})
}

// surfaceProbes calls each operation a transport may lack a surface for.
var surfaceProbes = map[string]func(context.Context, ContainerCommands) error{
	opLogs: func(ctx context.Context, cmd ContainerCommands) error {
		_, err := cmd.Logs(ctx, "nonexistent-container-id-12345", LogOptions{Stdout: true})
		return err
	},
	opAttest: func(ctx context.Context, cmd ContainerCommands) error {
		_, err := cmd.Attest(ctx, "nonexistent-container-id-12345")
		return err
	},
}

// declaredMissing reports whether cmd's transport has no surface for op. When
// it has none, the adapter must return the declared ErrNoSurface, which is
// asserted and logged as a MISSING row.
func declaredMissing(t *testing.T, ctx context.Context, cmd ContainerCommands, op string) bool {
	t.Helper()

	reason, missing := missingSurface(cmd.Name(), op)
	if !missing {
		return false
	}
	var noSurface surface.ErrNoSurface
	require.ErrorAs(t, surfaceProbes[op](ctx, cmd), &noSurface,
		"%s %s has no server surface (%s): the adapter must say so", cmd.Name(), op, reason)
	assert.Equal(t, cmd.Name(), noSurface.Transport, "declared transport")
	assert.Equal(t, op, noSurface.Operation, "declared operation")
	t.Logf("MISSING: %s %s: %s", cmd.Name(), op, reason)
	return true
}

// =============================================================================
// Container Lifecycle Tests
// =============================================================================

func runContainerCreateTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CreateBasicContainer", func(t *testing.T) {
		containerName := prefix + "-create-basic"
		opts := CreateOptions{
			Name:  containerName,
			Image: "docker.io/library/alpine:latest",
			Labels: map[string]string{
				"test": "true",
			},
		}

		container, err := cmd.Create(testCtx, opts)
		require.NoError(t, err, "Create should succeed for basic container")
		require.NotNil(t, container, "Container should not be nil")
		assert.NotEmpty(t, container.ID, "Container ID should not be empty")
		assert.Equal(t, containerName, container.Name, "Container name should match")
		assert.Equal(t, opts.Image, container.Image, "Container image should match")

		// Cleanup
		multiprotoCleanupContainer(t, testCtx, cmd, container.ID)
	})

	t.Run("CreateContainerWithEnvironment", func(t *testing.T) {
		containerName := prefix + "-create-env"
		opts := CreateOptions{
			Name:  containerName,
			Image: "docker.io/library/alpine:latest",
			Environment: map[string]string{
				"APP_ENV":  "test",
				"APP_NAME": "multiprotocol-test",
			},
		}

		container, err := cmd.Create(testCtx, opts)
		require.NoError(t, err, "Create should succeed with environment variables")
		require.NotNil(t, container, "Container should not be nil")
		assert.NotEmpty(t, container.ID, "Container ID should not be empty")

		// Cleanup
		multiprotoCleanupContainer(t, testCtx, cmd, container.ID)
	})

	t.Run("CreateContainerWithCommand", func(t *testing.T) {
		containerName := prefix + "-create-cmd"
		opts := CreateOptions{
			Name:    containerName,
			Image:   "docker.io/library/alpine:latest",
			Command: []string{"sleep", "3600"},
		}

		container, err := cmd.Create(testCtx, opts)
		require.NoError(t, err, "Create should succeed with custom command")
		require.NotNil(t, container, "Container should not be nil")

		// Cleanup
		multiprotoCleanupContainer(t, testCtx, cmd, container.ID)
	})

	t.Run("CreateContainerWithLabels", func(t *testing.T) {
		containerName := prefix + "-create-labels"
		opts := CreateOptions{
			Name:  containerName,
			Image: "docker.io/library/alpine:latest",
			Labels: map[string]string{
				"app":         "test",
				"environment": "integration",
				"team":        "platform",
			},
		}

		container, err := cmd.Create(testCtx, opts)
		require.NoError(t, err, "Create should succeed with labels")
		require.NotNil(t, container, "Container should not be nil")

		// Cleanup
		multiprotoCleanupContainer(t, testCtx, cmd, container.ID)
	})

	t.Run("CreateContainerEmptyNameFails", func(t *testing.T) {
		opts := CreateOptions{
			Name:  "",
			Image: "docker.io/library/alpine:latest",
		}

		_, err := cmd.Create(testCtx, opts)
		require.Error(t, err, "Create should fail with empty name")
	})

	t.Run("CreateContainerEmptyImageFails", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-create-noimage",
			Image: "",
		}

		_, err := cmd.Create(testCtx, opts)
		require.Error(t, err, "Create should fail with empty image")
	})
}

func runContainerGetTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a container first
	containerName := prefix + "-get-test"
	opts := CreateOptions{
		Name:  containerName,
		Image: "docker.io/library/alpine:latest",
		Labels: map[string]string{
			"purpose": "get-test",
		},
	}
	created, err := cmd.Create(testCtx, opts)
	require.NoError(t, err, "Setup: Create should succeed")
	defer multiprotoCleanupContainer(t, testCtx, cmd, created.ID)

	t.Run("GetExistingContainer", func(t *testing.T) {
		container, err := cmd.Get(testCtx, created.ID)
		require.NoError(t, err, "Get should succeed for existing container")
		require.NotNil(t, container, "Container should not be nil")
		assert.Equal(t, created.ID, container.ID, "Container ID should match")
		assert.Equal(t, containerName, container.Name, "Container name should match")
	})

	t.Run("GetNonexistentContainerFails", func(t *testing.T) {
		_, err := cmd.Get(testCtx, "nonexistent-container-id-12345")
		require.Error(t, err, "Get should fail for nonexistent container")
	})

	t.Run("GetContainerWithEmptyIDFails", func(t *testing.T) {
		_, err := cmd.Get(testCtx, "")
		require.Error(t, err, "Get should fail with empty ID")
	})
}

func runContainerStartTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a container first
	containerName := prefix + "-start-test"
	opts := CreateOptions{
		Name:    containerName,
		Image:   "docker.io/library/alpine:latest",
		Command: []string{"sleep", "3600"},
	}
	created, err := cmd.Create(testCtx, opts)
	require.NoError(t, err, "Setup: Create should succeed")
	defer multiprotoCleanupContainer(t, testCtx, cmd, created.ID)

	t.Run("StartCreatedContainer", func(t *testing.T) {
		err := cmd.Start(testCtx, created.ID)
		require.NoError(t, err, "Start should succeed for created container")

		// Verify container is running
		container, err := cmd.Get(testCtx, created.ID)
		require.NoError(t, err, "Get should succeed after start")
		assert.True(t, container.State.IsRunning(), "Container should be running after start")
	})

	t.Run("StartNonexistentContainerFails", func(t *testing.T) {
		err := cmd.Start(testCtx, "nonexistent-container-id-12345")
		require.Error(t, err, "Start should fail for nonexistent container")
	})

	t.Run("StartContainerWithEmptyIDFails", func(t *testing.T) {
		err := cmd.Start(testCtx, "")
		require.Error(t, err, "Start should fail with empty ID")
	})
}

func runContainerStopTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	// Create and start a container
	containerName := prefix + "-stop-test"
	opts := CreateOptions{
		Name:    containerName,
		Image:   "docker.io/library/alpine:latest",
		Command: []string{"sleep", "3600"},
	}
	created, err := cmd.Create(testCtx, opts)
	require.NoError(t, err, "Setup: Create should succeed")
	defer multiprotoCleanupContainer(t, testCtx, cmd, created.ID)

	err = cmd.Start(testCtx, created.ID)
	require.NoError(t, err, "Setup: Start should succeed")

	t.Run("StopRunningContainer", func(t *testing.T) {
		err := cmd.Stop(testCtx, created.ID, 10*time.Second)
		require.NoError(t, err, "Stop should succeed for running container")

		// Verify container is stopped
		container, err := cmd.Get(testCtx, created.ID)
		require.NoError(t, err, "Get should succeed after stop")
		assert.True(t, container.State.IsStopped(), "Container should be stopped after stop")
	})

	t.Run("StopNonexistentContainerFails", func(t *testing.T) {
		err := cmd.Stop(testCtx, "nonexistent-container-id-12345", 10*time.Second)
		require.Error(t, err, "Stop should fail for nonexistent container")
	})

	t.Run("StopContainerWithEmptyIDFails", func(t *testing.T) {
		err := cmd.Stop(testCtx, "", 10*time.Second)
		require.Error(t, err, "Stop should fail with empty ID")
	})
}

func runContainerRemoveTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("RemoveStoppedContainer", func(t *testing.T) {
		// Create a container
		containerName := prefix + "-remove-stopped"
		opts := CreateOptions{
			Name:  containerName,
			Image: "docker.io/library/alpine:latest",
		}
		created, err := cmd.Create(testCtx, opts)
		require.NoError(t, err, "Setup: Create should succeed")

		// Remove the stopped container
		err = cmd.Remove(testCtx, created.ID, false)
		require.NoError(t, err, "Remove should succeed for stopped container")

		// Verify container is gone
		_, err = cmd.Get(testCtx, created.ID)
		require.Error(t, err, "Get should fail for removed container")
	})

	t.Run("RemoveRunningContainerWithForceFails", func(t *testing.T) {
		// Create and start a container
		containerName := prefix + "-remove-running"
		opts := CreateOptions{
			Name:    containerName,
			Image:   "docker.io/library/alpine:latest",
			Command: []string{"sleep", "3600"},
		}
		created, err := cmd.Create(testCtx, opts)
		require.NoError(t, err, "Setup: Create should succeed")

		err = cmd.Start(testCtx, created.ID)
		require.NoError(t, err, "Setup: Start should succeed")

		// Remove without force should fail
		err = cmd.Remove(testCtx, created.ID, false)
		require.Error(t, err, "Remove without force should fail for running container")

		// Force remove should succeed
		err = cmd.Remove(testCtx, created.ID, true)
		require.NoError(t, err, "Force remove should succeed for running container")
	})

	t.Run("RemoveNonexistentContainerFails", func(t *testing.T) {
		err := cmd.Remove(testCtx, "nonexistent-container-id-12345", false)
		require.Error(t, err, "Remove should fail for nonexistent container")
	})
}

// =============================================================================
// Container Listing Tests
// =============================================================================

func runContainerListTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	// Create multiple containers for listing
	containerIDs := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		containerName := fmt.Sprintf("%s-list-%d", prefix, i)
		opts := CreateOptions{
			Name:  containerName,
			Image: "docker.io/library/alpine:latest",
			Labels: map[string]string{
				"test-group": prefix,
			},
		}
		created, err := cmd.Create(testCtx, opts)
		require.NoError(t, err, "Setup: Create should succeed for container %d", i)
		containerIDs = append(containerIDs, created.ID)
	}

	// Cleanup at end
	defer func() {
		for _, id := range containerIDs {
			multiprotoCleanupContainer(t, testCtx, cmd, id)
		}
	}()

	t.Run("ListAllContainers", func(t *testing.T) {
		containers, err := cmd.List(testCtx, ListOptions{All: true})
		require.NoError(t, err, "List should succeed")
		require.NotNil(t, containers, "Containers should not be nil")
		assert.GreaterOrEqual(t, len(containers), 3, "Should have at least 3 containers")
	})

	t.Run("ListContainersWithLimit", func(t *testing.T) {
		containers, err := cmd.List(testCtx, ListOptions{All: true, Limit: 2})
		require.NoError(t, err, "List should succeed with limit")
		require.NotNil(t, containers, "Containers should not be nil")
		assert.LessOrEqual(t, len(containers), 2, "Should respect limit")
	})
}

func runContainerListWithFiltersTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	// Create containers with specific labels
	filterPrefix := prefix + "-filter"
	containerIDs := make([]string, 0, 2)

	for i := 0; i < 2; i++ {
		containerName := fmt.Sprintf("%s-%d", filterPrefix, i)
		opts := CreateOptions{
			Name:    containerName,
			Image:   "docker.io/library/alpine:latest",
			Command: []string{"sleep", "3600"},
			Labels: map[string]string{
				"filter-test": "true",
				"environment": "test",
			},
		}
		created, err := cmd.Create(testCtx, opts)
		require.NoError(t, err, "Setup: Create should succeed")
		containerIDs = append(containerIDs, created.ID)
	}

	// Start first container
	err := cmd.Start(testCtx, containerIDs[0])
	require.NoError(t, err, "Setup: Start should succeed")

	// Cleanup
	defer func() {
		for _, id := range containerIDs {
			multiprotoCleanupContainer(t, testCtx, cmd, id)
		}
	}()

	t.Run("ListByState", func(t *testing.T) {
		containers, err := cmd.List(testCtx, ListOptions{All: true, StateFilter: StateRunning})
		require.NoError(t, err, "List by state should succeed")

		// At least one container should be running
		hasRunning := false
		for _, c := range containers {
			if c.State.IsRunning() {
				hasRunning = true
				break
			}
		}
		assert.True(t, hasRunning, "Should have at least one running container")
	})

	t.Run("ListByNameFilter", func(t *testing.T) {
		containers, err := cmd.List(testCtx, ListOptions{All: true, NameFilter: filterPrefix})
		require.NoError(t, err, "List by name should succeed")
		assert.GreaterOrEqual(t, len(containers), 2, "Should find containers matching name filter")
	})

	t.Run("ListByLabelFilter", func(t *testing.T) {
		containers, err := cmd.List(testCtx, ListOptions{
			All: true,
			Filters: map[string]string{
				"filter-test": "true",
			},
		})
		require.NoError(t, err, "List by label should succeed")
		assert.GreaterOrEqual(t, len(containers), 2, "Should find containers matching label filter")
	})
}

// =============================================================================
// Container Logs Tests
// =============================================================================

func runContainerLogsTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	if declaredMissing(t, testCtx, cmd, opLogs) {
		return
	}

	// Create a container that produces output
	containerName := prefix + "-logs-test"
	opts := CreateOptions{
		Name:    containerName,
		Image:   "docker.io/library/alpine:latest",
		Command: []string{"sh", "-c", "echo 'Line 1'; echo 'Line 2'; echo 'Line 3'; sleep 5"},
	}
	created, err := cmd.Create(testCtx, opts)
	require.NoError(t, err, "Setup: Create should succeed")
	defer multiprotoCleanupContainer(t, testCtx, cmd, created.ID)

	err = cmd.Start(testCtx, created.ID)
	require.NoError(t, err, "Setup: Start should succeed")

	// Wait for container to produce output; the subtests below assert on it
	if err := WaitForContainerLogs(testCtx, cmd, created.ID); err != nil {
		t.Logf("%v", err)
	}

	t.Run("GetContainerLogs", func(t *testing.T) {
		logs, err := cmd.Logs(testCtx, created.ID, LogOptions{Stdout: true, Stderr: true})
		require.NoError(t, err, "Logs should succeed")
		require.NotNil(t, logs, "Logs should not be nil")
		assert.NotEmpty(t, logs, "Logs should not be empty")
	})

	t.Run("GetContainerLogsWithTail", func(t *testing.T) {
		logs, err := cmd.Logs(testCtx, created.ID, LogOptions{Stdout: true, Tail: 2})
		require.NoError(t, err, "Logs with tail should succeed")
		require.NotNil(t, logs, "Logs should not be nil")
		assert.LessOrEqual(t, len(logs), 2, "Should return at most 2 lines")
	})

	t.Run("GetLogsNonexistentContainerFails", func(t *testing.T) {
		_, err := cmd.Logs(testCtx, "nonexistent-container-id-12345", LogOptions{Stdout: true})
		require.Error(t, err, "Logs should fail for nonexistent container")
	})
}

// =============================================================================
// Container Attestation Tests
// =============================================================================

func runContainerAttestTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	if declaredMissing(t, testCtx, cmd, opAttest) {
		return
	}

	// Create and start a container
	containerName := prefix + "-attest-test"
	opts := CreateOptions{
		Name:           containerName,
		Image:          "docker.io/library/alpine:latest",
		Command:        []string{"sleep", "3600"},
		AttestOnCreate: true,
	}
	created, err := cmd.Create(testCtx, opts)
	require.NoError(t, err, "Setup: Create should succeed")
	defer multiprotoCleanupContainer(t, testCtx, cmd, created.ID)

	err = cmd.Start(testCtx, created.ID)
	require.NoError(t, err, "Setup: Start should succeed")

	t.Run("AttestRunningContainer", func(t *testing.T) {
		report, err := cmd.Attest(testCtx, created.ID)
		require.NoError(t, err, "Attest should succeed for running container")
		require.NotNil(t, report, "Attestation report should not be nil")

		assert.Equal(t, created.ID, report.ContainerID, "Container ID should match")
		assert.Equal(t, containerName, report.ContainerName, "Container name should match")
		assert.NotEmpty(t, report.Quote, "Quote should not be empty")
		assert.NotEmpty(t, report.Signature, "Signature should not be empty")
		assert.NotEmpty(t, report.ImageDigest, "Image digest should not be empty")
		assert.NotEmpty(t, report.ConfigDigest, "Config digest should not be empty")
		assert.False(t, report.Timestamp.IsZero(), "Timestamp should be set")
	})

	t.Run("AttestNonexistentContainerFails", func(t *testing.T) {
		_, err := cmd.Attest(testCtx, "nonexistent-container-id-12345")
		require.Error(t, err, "Attest should fail for nonexistent container")
	})
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func runContainerNotFoundTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	nonexistentID := "nonexistent-container-12345"

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := cmd.Get(testCtx, nonexistentID)
		require.Error(t, err, "Get should fail for nonexistent container")
	})

	t.Run("StartNotFound", func(t *testing.T) {
		err := cmd.Start(testCtx, nonexistentID)
		require.Error(t, err, "Start should fail for nonexistent container")
	})

	t.Run("StopNotFound", func(t *testing.T) {
		err := cmd.Stop(testCtx, nonexistentID, 10*time.Second)
		require.Error(t, err, "Stop should fail for nonexistent container")
	})

	t.Run("RemoveNotFound", func(t *testing.T) {
		err := cmd.Remove(testCtx, nonexistentID, false)
		require.Error(t, err, "Remove should fail for nonexistent container")
	})

	t.Run("LogsNotFound", func(t *testing.T) {
		_, err := cmd.Logs(testCtx, nonexistentID, LogOptions{Stdout: true})
		require.Error(t, err, "Logs should fail for nonexistent container")
	})

	t.Run("AttestNotFound", func(t *testing.T) {
		_, err := cmd.Attest(testCtx, nonexistentID)
		require.Error(t, err, "Attest should fail for nonexistent container")
	})
}

func runContainerInvalidArgsTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	t.Run("CreateEmptyName", func(t *testing.T) {
		opts := CreateOptions{
			Name:  "",
			Image: "docker.io/library/alpine:latest",
		}
		_, err := cmd.Create(testCtx, opts)
		require.Error(t, err, "Create should fail with empty name")
	})

	t.Run("CreateEmptyImage", func(t *testing.T) {
		opts := CreateOptions{
			Name:  prefix + "-invalid-image",
			Image: "",
		}
		_, err := cmd.Create(testCtx, opts)
		require.Error(t, err, "Create should fail with empty image")
	})

	t.Run("GetEmptyID", func(t *testing.T) {
		_, err := cmd.Get(testCtx, "")
		require.Error(t, err, "Get should fail with empty ID")
	})

	t.Run("StartEmptyID", func(t *testing.T) {
		err := cmd.Start(testCtx, "")
		require.Error(t, err, "Start should fail with empty ID")
	})

	t.Run("StopEmptyID", func(t *testing.T) {
		err := cmd.Stop(testCtx, "", 10*time.Second)
		require.Error(t, err, "Stop should fail with empty ID")
	})

	t.Run("RemoveEmptyID", func(t *testing.T) {
		err := cmd.Remove(testCtx, "", false)
		require.Error(t, err, "Remove should fail with empty ID")
	})
}

// =============================================================================
// Full Lifecycle Test
// =============================================================================

func runContainerFullLifecycleTests(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("CompleteLifecycle", func(t *testing.T) {
		containerName := prefix + "-full-lifecycle"

		// Phase 1: Create
		t.Log("=== Phase 1: Create Container ===")
		createOpts := CreateOptions{
			Name:    containerName,
			Image:   "docker.io/library/alpine:latest",
			Command: []string{"sh", "-c", "echo 'Hello from container'; sleep 60"},
			Environment: map[string]string{
				"TEST_VAR": "lifecycle-test",
			},
			Labels: map[string]string{
				"test":      "full-lifecycle",
				"protocol":  cmd.Name(),
				"timestamp": fmt.Sprintf("%d", time.Now().Unix()),
			},
			AttestOnCreate: true,
		}

		container, err := cmd.Create(testCtx, createOpts)
		require.NoError(t, err, "Create should succeed")
		require.NotNil(t, container, "Container should not be nil")
		assert.NotEmpty(t, container.ID, "Container ID should not be empty")
		t.Logf("Created container: %s (%s)", container.Name, container.ID)

		containerID := container.ID

		// Phase 2: Verify container is created
		t.Log("=== Phase 2: Verify Container Created ===")
		retrieved, err := cmd.Get(testCtx, containerID)
		require.NoError(t, err, "Get should succeed")
		assert.Equal(t, containerName, retrieved.Name, "Container name should match")
		assert.Equal(t, StateCreated, retrieved.State, "Container should be in created state")
		t.Logf("Container state: %s", retrieved.State)

		// Phase 3: Start container
		t.Log("=== Phase 3: Start Container ===")
		err = cmd.Start(testCtx, containerID)
		require.NoError(t, err, "Start should succeed")

		// Verify running
		retrieved, err = cmd.Get(testCtx, containerID)
		require.NoError(t, err, "Get should succeed after start")
		assert.True(t, retrieved.State.IsRunning(), "Container should be running")
		t.Logf("Container state after start: %s", retrieved.State)

		// Phase 4: Get logs
		t.Log("=== Phase 4: Get Logs ===")
		if err := WaitForContainerLogs(testCtx, cmd, containerID); err != nil {
			t.Logf("%v", err)
		}
		logs, err := cmd.Logs(testCtx, containerID, LogOptions{Stdout: true, Stderr: true})
		require.NoError(t, err, "Logs should succeed")
		t.Logf("Retrieved %d log lines", len(logs))

		// Phase 5: Perform attestation
		t.Log("=== Phase 5: Perform Attestation ===")
		report, err := cmd.Attest(testCtx, containerID)
		require.NoError(t, err, "Attest should succeed")
		require.NotNil(t, report, "Attestation report should not be nil")
		assert.NotEmpty(t, report.Quote, "Quote should not be empty")
		assert.NotEmpty(t, report.Signature, "Signature should not be empty")
		t.Logf("Attestation completed at: %s", report.Timestamp)

		// Phase 6: List containers and verify our container is there
		t.Log("=== Phase 6: Verify Container in List ===")
		containers, err := cmd.List(testCtx, ListOptions{All: true})
		require.NoError(t, err, "List should succeed")
		found := false
		for _, c := range containers {
			if c.ID == containerID {
				found = true
				break
			}
		}
		assert.True(t, found, "Container should appear in list")
		t.Logf("Found container in list of %d containers", len(containers))

		// Phase 7: Stop container
		t.Log("=== Phase 7: Stop Container ===")
		err = cmd.Stop(testCtx, containerID, 10*time.Second)
		require.NoError(t, err, "Stop should succeed")

		// Verify stopped
		retrieved, err = cmd.Get(testCtx, containerID)
		require.NoError(t, err, "Get should succeed after stop")
		assert.True(t, retrieved.State.IsStopped(), "Container should be stopped")
		t.Logf("Container state after stop: %s", retrieved.State)

		// Phase 8: Remove container
		t.Log("=== Phase 8: Remove Container ===")
		err = cmd.Remove(testCtx, containerID, false)
		require.NoError(t, err, "Remove should succeed")

		// Verify container is gone
		_, err = cmd.Get(testCtx, containerID)
		require.Error(t, err, "Get should fail for removed container")
		t.Log("Container successfully removed")

		t.Log("=== Full Lifecycle Test Complete ===")
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

// multiprotoCleanupContainer attempts to remove a container, ignoring errors.
// This is used in test cleanup to ensure containers don't accumulate.
func multiprotoCleanupContainer(t *testing.T, ctx context.Context, cmd ContainerCommands, id string) {
	t.Helper()

	// First try to stop if running
	_ = cmd.Stop(ctx, id, 5*time.Second)

	// Then force remove
	if err := cmd.Remove(ctx, id, true); err != nil {
		// Only log, don't fail - this is cleanup
		t.Logf("Warning: failed to cleanup container %s: %v", id, err)
	}
}
