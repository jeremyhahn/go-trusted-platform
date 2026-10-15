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

package container

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Main Test Entry Point
// =============================================================================

// TestContainerOrchestrator runs the complete container orchestrator test suite.
func TestContainerOrchestrator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTestTimeout)
	defer cancel()

	t.Run("Lifecycle", func(t *testing.T) {
		testContainerLifecycle(t, ctx)
	})

	t.Run("Policy", func(t *testing.T) {
		testPolicyEvaluation(t, ctx)
	})

	t.Run("Attestation", func(t *testing.T) {
		testAttestationWorkflow(t, ctx)
	})
}

// =============================================================================
// Container Lifecycle Tests
// =============================================================================

func testContainerLifecycle(t *testing.T, ctx context.Context) {
	t.Run("CreateContainer", testCreateContainer)
	t.Run("CreateContainerInvalidSpec", testCreateContainerInvalidSpec)
	t.Run("CreateContainerDuplicate", testCreateContainerDuplicate)
	t.Run("StartContainer", testStartContainer)
	t.Run("StartContainerAlreadyRunning", testStartContainerAlreadyRunning)
	t.Run("StartContainerNotFound", testStartContainerNotFound)
	t.Run("StopContainer", testStopContainer)
	t.Run("StopContainerNotRunning", testStopContainerNotRunning)
	t.Run("StopContainerNotFound", testStopContainerNotFound)
	t.Run("RemoveContainer", testRemoveContainer)
	t.Run("RemoveContainerForce", testRemoveContainerForce)
	t.Run("RemoveContainerNotFound", testRemoveContainerNotFound)
	t.Run("GetContainer", testGetContainer)
	t.Run("GetContainerNotFound", testGetContainerNotFound)
	t.Run("ListContainers", testListContainers)
	t.Run("ListContainersWithFilters", testListContainersWithFilters)
	t.Run("ContainerLogs", testContainerLogs)
	t.Run("FullLifecycle", testFullLifecycle)
	t.Run("MultipleContainers", testMultipleContainers)
	t.Run("OrchestratorClose", testOrchestratorClose)
}

func testCreateContainer(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("test-create", "docker.io/library/alpine:latest")

	container, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err, "Create should succeed")
	require.NotNil(t, container)

	assert.NotEmpty(t, container.ID, "Container ID should not be empty")
	assert.Equal(t, spec.Name, container.Name, "Container name should match")
	assert.Equal(t, spec.Image, container.Image, "Container image should match")

	// Verify Podman backend was called
	assert.Equal(t, int32(1), fixtures.Podman.GetCreateCalls(), "Podman Create should be called once")
}

func testCreateContainerInvalidSpec(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("NilSpec", func(t *testing.T) {
		_, err := orchestrator.Create(ctx, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, container.ErrInvalidSpec)
	})

	t.Run("EmptyName", func(t *testing.T) {
		spec := &container.OrchestratorContainerSpec{
			Name:  "",
			Image: "alpine:latest",
		}
		_, err := orchestrator.Create(ctx, spec)
		require.Error(t, err)
	})

	t.Run("EmptyImage", func(t *testing.T) {
		spec := &container.OrchestratorContainerSpec{
			Name:  "test-container",
			Image: "",
		}
		_, err := orchestrator.Create(ctx, spec)
		require.Error(t, err)
	})
}

func testCreateContainerDuplicate(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("duplicate-test", "alpine:latest")

	// Create first container
	_, err = orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	// Try to create duplicate
	_, err = orchestrator.Create(ctx, spec)
	require.Error(t, err, "Creating duplicate container should fail")
}

func testStartContainer(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("test-start", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err, "Start should succeed")

	// Verify container state
	updated, err := orchestrator.Get(ctx, c.ID)
	require.NoError(t, err)
	assert.True(t, updated.State.IsRunning(), "Container should be running")

	// Verify Podman backend was called
	assert.Equal(t, int32(1), fixtures.Podman.GetStartCalls(), "Podman Start should be called once")
}

func testStartContainerAlreadyRunning(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("test-start-running", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	// Start once
	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err)

	// Try to start again
	err = orchestrator.Start(ctx, c.ID)
	require.Error(t, err, "Starting an already running container should fail")
}

func testStartContainerNotFound(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = orchestrator.Start(ctx, "nonexistent-id")
	require.Error(t, err, "Starting nonexistent container should fail")
	assert.ErrorIs(t, err, container.ErrContainerNotFound)

	err = orchestrator.Start(ctx, "")
	require.Error(t, err, "Starting with empty ID should fail")
	assert.ErrorIs(t, err, container.ErrInvalidContainerID)
}

func testStopContainer(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("test-stop", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err)

	err = orchestrator.Stop(ctx, c.ID, 10*time.Second)
	require.NoError(t, err, "Stop should succeed")

	// Verify container state
	updated, err := orchestrator.Get(ctx, c.ID)
	require.NoError(t, err)
	assert.True(t, updated.State.IsStopped(), "Container should be stopped")

	// Verify Podman backend was called
	assert.Equal(t, int32(1), fixtures.Podman.GetStopCalls(), "Podman Stop should be called once")
}

func testStopContainerNotRunning(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("test-stop-not-running", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	// Try to stop without starting
	err = orchestrator.Stop(ctx, c.ID, 10*time.Second)
	require.Error(t, err, "Stopping a non-running container should fail")
}

func testStopContainerNotFound(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = orchestrator.Stop(ctx, "nonexistent-id", 10*time.Second)
	require.Error(t, err, "Stopping nonexistent container should fail")
	assert.ErrorIs(t, err, container.ErrContainerNotFound)
}

func testRemoveContainer(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("test-remove", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	err = orchestrator.Remove(ctx, c.ID, false)
	require.NoError(t, err, "Remove should succeed")

	// Verify container is gone
	_, err = orchestrator.Get(ctx, c.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, container.ErrContainerNotFound)

	// Verify Podman backend was called
	assert.Equal(t, int32(1), fixtures.Podman.GetRemoveCalls(), "Podman Remove should be called once")
}

func testRemoveContainerForce(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("test-remove-force", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	// Start the container
	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err)

	// Try to remove without force (should fail)
	err = orchestrator.Remove(ctx, c.ID, false)
	require.Error(t, err, "Remove without force should fail for running container")

	// Force remove
	err = orchestrator.Remove(ctx, c.ID, true)
	require.NoError(t, err, "Force remove should succeed")
}

func testRemoveContainerNotFound(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = orchestrator.Remove(ctx, "nonexistent-id", false)
	require.Error(t, err, "Removing nonexistent container should fail")
	assert.ErrorIs(t, err, container.ErrContainerNotFound)
}

func testGetContainer(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("test-get", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	// Get by ID
	retrieved, err := orchestrator.Get(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, c.ID, retrieved.ID)
	assert.Equal(t, c.Name, retrieved.Name)
}

func testGetContainerNotFound(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = orchestrator.Get(ctx, "nonexistent-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, container.ErrContainerNotFound)

	_, err = orchestrator.Get(ctx, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, container.ErrInvalidContainerID)
}

func testListContainers(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create multiple containers
	for i := 0; i < 3; i++ {
		spec := CreateTestContainerSpec(fmt.Sprintf("test-list-%d", i), "alpine:latest")
		_, err := orchestrator.Create(ctx, spec)
		require.NoError(t, err)
	}

	// List all
	containers, err := orchestrator.List(ctx, container.ListOptions{All: true})
	require.NoError(t, err)
	assert.Len(t, containers, 3, "Should list all containers")
}

func testListContainersWithFilters(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create and start some containers
	var runningIDs []string
	for i := 0; i < 2; i++ {
		spec := CreateTestContainerSpec(fmt.Sprintf("test-filter-running-%d", i), "alpine:latest")
		c, err := orchestrator.Create(ctx, spec)
		require.NoError(t, err)
		err = orchestrator.Start(ctx, c.ID)
		require.NoError(t, err)
		runningIDs = append(runningIDs, c.ID)
	}

	// Create stopped containers
	for i := 0; i < 2; i++ {
		spec := CreateTestContainerSpec(fmt.Sprintf("test-filter-stopped-%d", i), "alpine:latest")
		_, err := orchestrator.Create(ctx, spec)
		require.NoError(t, err)
	}

	// List with limit
	containers, err := orchestrator.List(ctx, container.ListOptions{All: true, Limit: 2})
	require.NoError(t, err)
	assert.Len(t, containers, 2, "Should respect limit")
}

func testContainerLogs(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("test-logs", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err)

	logs, err := orchestrator.Logs(ctx, c.ID, container.LogOptions{Stdout: true, Stderr: true})
	require.NoError(t, err)
	require.NotNil(t, logs)
	defer logs.Close()
}

func testFullLifecycle(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Log("=== Phase 1: Create Container ===")
	spec := CreateTestContainerSpec("lifecycle-test", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)
	t.Logf("Created container: %s", c.ID)

	t.Log("=== Phase 2: Start Container ===")
	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err)

	updated, err := orchestrator.Get(ctx, c.ID)
	require.NoError(t, err)
	assert.True(t, updated.State.IsRunning())
	t.Log("Container started")

	t.Log("=== Phase 3: Get Logs ===")
	logs, err := orchestrator.Logs(ctx, c.ID, container.LogOptions{Stdout: true})
	require.NoError(t, err)
	logs.Close()
	t.Log("Retrieved logs")

	t.Log("=== Phase 4: Stop Container ===")
	err = orchestrator.Stop(ctx, c.ID, 10*time.Second)
	require.NoError(t, err)

	updated, err = orchestrator.Get(ctx, c.ID)
	require.NoError(t, err)
	assert.True(t, updated.State.IsStopped())
	t.Log("Container stopped")

	t.Log("=== Phase 5: Remove Container ===")
	err = orchestrator.Remove(ctx, c.ID, false)
	require.NoError(t, err)
	t.Log("Container removed")

	// Verify gone
	_, err = orchestrator.Get(ctx, c.ID)
	assert.ErrorIs(t, err, container.ErrContainerNotFound)

	t.Log("=== Lifecycle Test Complete ===")
}

func testMultipleContainers(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	containerCount := 5
	var ids []string

	// Create all containers
	for i := 0; i < containerCount; i++ {
		spec := CreateTestContainerSpec(fmt.Sprintf("multi-%d", i), "alpine:latest")
		c, err := orchestrator.Create(ctx, spec)
		require.NoError(t, err)
		ids = append(ids, c.ID)
	}

	// Start all
	for _, id := range ids {
		err := orchestrator.Start(ctx, id)
		require.NoError(t, err)
	}

	// Verify all running
	for _, id := range ids {
		c, err := orchestrator.Get(ctx, id)
		require.NoError(t, err)
		assert.True(t, c.State.IsRunning())
	}

	// Stop all
	for _, id := range ids {
		err := orchestrator.Stop(ctx, id, 10*time.Second)
		require.NoError(t, err)
	}

	// Remove all
	for _, id := range ids {
		err := orchestrator.Remove(ctx, id, false)
		require.NoError(t, err)
	}

	// Verify all gone
	containers, err := orchestrator.List(ctx, container.ListOptions{All: true})
	require.NoError(t, err)
	assert.Len(t, containers, 0)
}

func testOrchestratorClose(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a container
	spec := CreateTestContainerSpec("close-test", "alpine:latest")
	_, err = orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	// Close orchestrator
	err = orchestrator.Close()
	require.NoError(t, err)

	// Operations should fail after close
	_, err = orchestrator.Create(ctx, spec)
	require.Error(t, err)
	assert.ErrorIs(t, err, container.ErrOrchestratorClosed)
}

// =============================================================================
// Policy Evaluation Tests
// =============================================================================

func testPolicyEvaluation(t *testing.T, ctx context.Context) {
	t.Run("PolicyAllow", testPolicyAllow)
	t.Run("PolicyDeny", testPolicyDeny)
	t.Run("PolicyDenyImage", testPolicyDenyImage)
	t.Run("PolicyDenyPrivileged", testPolicyDenyPrivileged)
	t.Run("PolicyEvaluationError", testPolicyEvaluationError)
	t.Run("PolicyDisabled", testPolicyDisabled)
}

func testPolicyAllow(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestratorWithPolicy()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("policy-allow", "alpine:latest")

	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err, "Create should succeed when policy allows")
	require.NotNil(t, c)

	// Verify policy was evaluated
	assert.Equal(t, int32(1), fixtures.Policy.GetEvalCalls())
}

func testPolicyDeny(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	// Configure policy to deny all
	fixtures.Policy.SetDefaultAllow(false)

	orchestrator, err := fixtures.CreateOrchestratorWithPolicy()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("policy-deny", "alpine:latest")

	_, err = orchestrator.Create(ctx, spec)
	require.Error(t, err, "Create should fail when policy denies")
}

func testPolicyDenyImage(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	// Deny specific image
	fixtures.Policy.DenyImage("untrusted:latest")

	orchestrator, err := fixtures.CreateOrchestratorWithPolicy()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Trusted image should succeed
	spec := CreateTestContainerSpec("policy-trusted", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)
	require.NotNil(t, c)

	// Untrusted image should fail
	untrustedSpec := CreateTestContainerSpec("policy-untrusted", "untrusted:latest")
	_, err = orchestrator.Create(ctx, untrustedSpec)
	require.Error(t, err, "Create should fail for denied image")
}

func testPolicyDenyPrivileged(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestratorWithPolicy()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Privileged container should be denied by default mock policy
	spec := CreatePrivilegedContainerSpec("policy-privileged", "alpine:latest")

	_, err = orchestrator.Create(ctx, spec)
	require.Error(t, err, "Create should fail for privileged container")
}

func testPolicyEvaluationError(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	// Configure policy to return error
	fixtures.Policy.SetFailure(errors.New("policy evaluation failed"))

	orchestrator, err := fixtures.CreateOrchestratorWithPolicy()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("policy-error", "alpine:latest")

	_, err = orchestrator.Create(ctx, spec)
	require.Error(t, err, "Create should fail when policy evaluation errors")
}

func testPolicyDisabled(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	// Create orchestrator with policy disabled
	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("policy-disabled", "alpine:latest")

	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err, "Create should succeed when policy is disabled")
	require.NotNil(t, c)

	// Verify policy was not evaluated
	assert.Equal(t, int32(0), fixtures.Policy.GetEvalCalls())
}

// =============================================================================
// Attestation Workflow Tests
// =============================================================================

func testAttestationWorkflow(t *testing.T, ctx context.Context) {
	t.Run("AttestationOnCreate", testAttestationOnCreate)
	t.Run("AttestationOnStart", testAttestationOnStart)
	t.Run("AttestationOnStop", testAttestationOnStop)
	t.Run("AttestationOnRemove", testAttestationOnRemove)
	t.Run("GenerateAttestation", testGenerateAttestation)
	t.Run("AttestationDisabled", testAttestationDisabled)
	t.Run("AttestationTPMError", testAttestationTPMError)
	t.Run("FullAttestationWorkflow", testFullAttestationWorkflow)
}

func testAttestationOnCreate(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestratorWithAttestation()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("attest-create", "alpine:latest")

	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)
	require.NotNil(t, c)

	// Verify TPM was extended (once for create event)
	assert.GreaterOrEqual(t, fixtures.TPM.GetExtendCalls(), int32(1), "TPM ExtendPCR should be called on create")
}

func testAttestationOnStart(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestratorWithAttestation()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("attest-start", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	initialExtends := fixtures.TPM.GetExtendCalls()

	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err)

	// Verify TPM was extended for start event
	assert.Greater(t, fixtures.TPM.GetExtendCalls(), initialExtends, "TPM ExtendPCR should be called on start")
}

func testAttestationOnStop(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestratorWithAttestation()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("attest-stop", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err)

	extendsAfterStart := fixtures.TPM.GetExtendCalls()

	err = orchestrator.Stop(ctx, c.ID, 10*time.Second)
	require.NoError(t, err)

	// Verify TPM was extended for stop event
	assert.Greater(t, fixtures.TPM.GetExtendCalls(), extendsAfterStart, "TPM ExtendPCR should be called on stop")
}

func testAttestationOnRemove(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestratorWithAttestation()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("attest-remove", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	extendsAfterCreate := fixtures.TPM.GetExtendCalls()

	err = orchestrator.Remove(ctx, c.ID, false)
	require.NoError(t, err)

	// Verify TPM was extended for remove event
	assert.Greater(t, fixtures.TPM.GetExtendCalls(), extendsAfterCreate, "TPM ExtendPCR should be called on remove")
}

func testGenerateAttestation(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestratorWithAttestation()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("attest-generate", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err)

	// Generate attestation report
	report, err := orchestrator.Attest(ctx, c.ID)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, c.ID, report.ContainerID)
	assert.Equal(t, spec.Name, report.ContainerName)
	assert.NotNil(t, report.Quote)
	assert.NotNil(t, report.Signature)
	assert.NotNil(t, report.Log)
	assert.NotEmpty(t, report.ImageDigest)
	assert.NotEmpty(t, report.ConfigDigest)
	assert.False(t, report.Timestamp.IsZero())

	// Verify TPM quote was generated
	assert.GreaterOrEqual(t, fixtures.TPM.GetQuoteCalls(), int32(1))
}

func testAttestationDisabled(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	// Create orchestrator without attestation
	orchestrator, err := fixtures.CreateOrchestrator(false, false)
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("no-attest", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)

	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err)

	// Verify no TPM calls were made
	assert.Equal(t, int32(0), fixtures.TPM.GetExtendCalls())

	// Attest should fail without attestor
	_, err = orchestrator.Attest(ctx, c.ID)
	require.Error(t, err)
}

func testAttestationTPMError(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	// Configure TPM to fail
	fixtures.TPM.SetFailure(errors.New("TPM error"))

	orchestrator, err := fixtures.CreateOrchestratorWithAttestation()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := CreateTestContainerSpec("tpm-error", "alpine:latest")

	// Create should still succeed (TPM errors are logged but not fatal)
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)
	require.NotNil(t, c)
}

func testFullAttestationWorkflow(t *testing.T) {
	fixtures := NewTestFixtures()
	defer fixtures.Reset()

	orchestrator, err := fixtures.CreateOrchestratorWithAttestation()
	require.NoError(t, err)
	defer orchestrator.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Log("=== Phase 1: Create Container with Attestation ===")
	spec := CreateTestContainerSpec("full-attest", "alpine:latest")
	c, err := orchestrator.Create(ctx, spec)
	require.NoError(t, err)
	t.Logf("Created container: %s", c.ID)

	initialExtends := fixtures.TPM.GetExtendCalls()
	t.Logf("TPM extends after create: %d", initialExtends)

	t.Log("=== Phase 2: Start Container ===")
	err = orchestrator.Start(ctx, c.ID)
	require.NoError(t, err)

	extendsAfterStart := fixtures.TPM.GetExtendCalls()
	t.Logf("TPM extends after start: %d", extendsAfterStart)
	assert.Greater(t, extendsAfterStart, initialExtends)

	t.Log("=== Phase 3: Generate Attestation ===")
	report, err := orchestrator.Attest(ctx, c.ID)
	require.NoError(t, err)
	require.NotNil(t, report)

	t.Logf("Attestation report generated at: %s", report.Timestamp)
	t.Logf("Quote length: %d bytes", len(report.Quote))
	t.Logf("Signature length: %d bytes", len(report.Signature))

	t.Log("=== Phase 4: Verify Measurement Log ===")
	measurementLog := orchestrator.GetMeasurementLog()
	require.NotNil(t, measurementLog)

	entries := measurementLog.GetEntries()
	assert.NotEmpty(t, entries, "Measurement log should have entries")
	t.Logf("Measurement log has %d entries", len(entries))

	t.Log("=== Phase 5: Stop Container ===")
	err = orchestrator.Stop(ctx, c.ID, 10*time.Second)
	require.NoError(t, err)

	extendsAfterStop := fixtures.TPM.GetExtendCalls()
	t.Logf("TPM extends after stop: %d", extendsAfterStop)
	assert.Greater(t, extendsAfterStop, extendsAfterStart)

	t.Log("=== Phase 6: Remove Container ===")
	err = orchestrator.Remove(ctx, c.ID, false)
	require.NoError(t, err)

	finalExtends := fixtures.TPM.GetExtendCalls()
	t.Logf("Total TPM extends: %d", finalExtends)
	assert.Greater(t, finalExtends, extendsAfterStop)

	t.Log("=== Full Attestation Workflow Complete ===")
}
