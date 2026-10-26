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

// Package container provides integration test helpers for container operations.
// These helpers provide reusable functions for testing container lifecycle
// across all protocol adapters (CLI, REST, gRPC, QUIC, MCP, Unix).
package container

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// Test Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a reasonable timeout for integration tests.
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// LongRunningTestContext returns a context with a longer timeout for tests
// that may take more time (e.g., pulling images, complex lifecycles).
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// ShortTestContext returns a context with a short timeout for quick operations.
func ShortTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// =============================================================================
// Endpoint Configuration
// =============================================================================

// ServiceEndpoints contains all configured service endpoints for testing.
type ServiceEndpoints struct {
	PlatformdSocket string
	PlatformAPI     string
	PlatformGRPC    string
	PlatformQUIC    string
	PlatformMCP     string
	PlatformctlBin  string
}

// GetServiceEndpoints returns service endpoints from environment
// variables with sensible defaults.
func GetServiceEndpoints() ServiceEndpoints {
	return ServiceEndpoints{
		PlatformdSocket: getEnvOrDefault(EnvPlatformdSocket, DefaultPlatformdSocket),
		PlatformAPI:     getEnvOrDefault(EnvPlatformAPIEndpoint, DefaultPlatformAPIEndpoint),
		PlatformGRPC:    getEnvOrDefault(EnvPlatformdGRPCEndpoint, DefaultPlatformdGRPCEndpoint),
		PlatformQUIC:    getEnvOrDefault(EnvPlatformdQUICEndpoint, DefaultPlatformdQUICEndpoint),
		PlatformMCP:     getEnvOrDefault(EnvPlatformdMCPEndpoint, DefaultPlatformdMCPEndpoint),
		PlatformctlBin:  getEnvOrDefault(EnvPlatformctlBinary, DefaultPlatformctlBinary),
	}
}

// getEnvOrDefault returns the environment variable value or the default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// =============================================================================
// Test Name Generator
// =============================================================================

// testNameCounter provides unique container names across tests.
var testNameCounter int64

// GenerateTestContainerName generates a unique container name for tests.
// The name includes the test name and a unique counter to avoid collisions.
func GenerateTestContainerName(t *testing.T, prefix string) string {
	t.Helper()
	counter := atomic.AddInt64(&testNameCounter, 1)
	timestamp := time.Now().Unix()
	return fmt.Sprintf("%s-%s-%d-%d", prefix, t.Name(), timestamp, counter)
}

// GenerateUniquePrefix generates a unique test prefix for a protocol run.
func GenerateUniquePrefix(protocolName string) string {
	counter := atomic.AddInt64(&testNameCounter, 1)
	timestamp := time.Now().Unix()
	return fmt.Sprintf("int-%s-%d-%d", protocolName, timestamp, counter)
}

// =============================================================================
// Test Container Options
// =============================================================================

// TestContainerOpts provides options for creating test containers.
type TestContainerOpts struct {
	Name           string
	Image          string
	Command        []string
	Environment    map[string]string
	Labels         map[string]string
	Privileged     bool
	AttestOnCreate bool
}

// DefaultTestContainerOpts returns default options for a test container.
func DefaultTestContainerOpts(name string) TestContainerOpts {
	return TestContainerOpts{
		Name:    name,
		Image:   "docker.io/library/alpine:latest",
		Command: []string{"sleep", "3600"},
		Labels: map[string]string{
			"integration-test": "true",
			"created-by":       "go-trusted-platform-integration-tests",
		},
	}
}

// ToCreateOptions converts TestContainerOpts to CreateOptions.
func (o TestContainerOpts) ToCreateOptions() CreateOptions {
	return CreateOptions{
		Name:           o.Name,
		Image:          o.Image,
		Command:        o.Command,
		Environment:    o.Environment,
		Labels:         o.Labels,
		Privileged:     o.Privileged,
		AttestOnCreate: o.AttestOnCreate,
	}
}

// =============================================================================
// Cleanup Helpers
// =============================================================================

// CleanupContainer attempts to remove a container, stopping it first if running.
// Errors are logged but not returned - this is for test cleanup where we want
// best-effort cleanup without failing the test.
func CleanupContainer(t *testing.T, ctx context.Context, cmd ContainerCommands, id string) {
	t.Helper()
	if id == "" {
		return
	}

	// First try to stop if running (ignore errors)
	_ = cmd.Stop(ctx, id, 5*time.Second)

	// Then force remove
	if err := cmd.Remove(ctx, id, true); err != nil {
		t.Logf("Warning: cleanup failed for container %s: %v", id, err)
	}
}

// CleanupContainers cleans up multiple containers.
func CleanupContainers(t *testing.T, ctx context.Context, cmd ContainerCommands, ids []string) {
	t.Helper()
	for _, id := range ids {
		CleanupContainer(t, ctx, cmd, id)
	}
}

// CleanupContainersByPrefix removes all containers with names matching the prefix.
func CleanupContainersByPrefix(t *testing.T, ctx context.Context, cmd ContainerCommands, prefix string) {
	t.Helper()

	containers, err := cmd.List(ctx, ListOptions{All: true, NameFilter: prefix})
	if err != nil {
		t.Logf("Warning: failed to list containers for cleanup: %v", err)
		return
	}

	for _, c := range containers {
		CleanupContainer(t, ctx, cmd, c.ID)
	}
}

// =============================================================================
// Assertion Helpers
// =============================================================================

// AssertContainerExists verifies a container exists with the expected name.
func AssertContainerExists(t *testing.T, ctx context.Context, cmd ContainerCommands, id, expectedName string) {
	t.Helper()
	container, err := cmd.Get(ctx, id)
	if err != nil {
		t.Fatalf("Container %s does not exist: %v", id, err)
	}
	if expectedName != "" && container.Name != expectedName {
		t.Errorf("Container name mismatch: expected %s, got %s", expectedName, container.Name)
	}
}

// AssertContainerNotExists verifies a container does not exist.
func AssertContainerNotExists(t *testing.T, ctx context.Context, cmd ContainerCommands, id string) {
	t.Helper()
	_, err := cmd.Get(ctx, id)
	if err == nil {
		t.Errorf("Container %s should not exist", id)
	}
}

// AssertContainerState verifies a container is in the expected state.
func AssertContainerState(t *testing.T, ctx context.Context, cmd ContainerCommands, id string, expectedState ContainerState) {
	t.Helper()
	container, err := cmd.Get(ctx, id)
	if err != nil {
		t.Fatalf("Failed to get container %s: %v", id, err)
	}
	if container.State != expectedState {
		t.Errorf("Container state mismatch: expected %s, got %s", expectedState, container.State)
	}
}

// =============================================================================
// Protocol Adapter Helpers
// =============================================================================

// CreateAllAdapters creates all protocol adapters for multi-protocol testing.
func CreateAllAdapters() []ContainerCommands {
	return []ContainerCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}
}

// CreateImplementedAdapters creates only adapters that are fully implemented.
// This skips adapters with TODO implementations.
func CreateImplementedAdapters() []ContainerCommands {
	return []ContainerCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewUnixAdapter(),
	}
}

// SetupAdapter sets up an adapter and returns a cleanup function.
// Returns an error if setup fails.
func SetupAdapter(ctx context.Context, adapter ContainerCommands) (cleanup func(), err error) {
	if err := adapter.Setup(ctx); err != nil {
		return nil, err
	}
	return func() {
		adapter.Teardown()
	}, nil
}

// =============================================================================
// Test Image Constants
// =============================================================================

const (
	// TestImageAlpine is the default test image (small and fast).
	TestImageAlpine = "docker.io/library/alpine:latest"

	// TestImageBusybox is an alternative small test image.
	TestImageBusybox = "docker.io/library/busybox:latest"

	// TestImageNginx is a web server test image.
	TestImageNginx = "docker.io/library/nginx:alpine"

	// TestImageNonexistent is an image that should not exist (for error testing).
	TestImageNonexistent = "nonexistent-registry.invalid/nonexistent:v999"
)

// =============================================================================
// Error Checking Helpers
// =============================================================================

// IsContainerNotFoundError returns true if the error indicates container not found.
func IsContainerNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(ErrContainerNotFound)
	return ok
}

// IsAdapterConnectionError returns true if the error indicates adapter connection failure.
func IsAdapterConnectionError(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(ErrAdapterConnectionFailed)
	return ok
}

// =============================================================================
// Benchmark Helpers
// =============================================================================

// RunContainerCreateBenchmark runs container creation benchmark for a given adapter.
func RunContainerCreateBenchmark(b *testing.B, cmd ContainerCommands, prefix string) {
	ctx := context.Background()

	if err := cmd.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer cmd.Teardown()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("%s-bench-%d", prefix, i)
		opts := CreateOptions{
			Name:  name,
			Image: TestImageAlpine,
		}

		container, err := cmd.Create(ctx, opts)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}

		// Cleanup
		cmd.Remove(ctx, container.ID, true)
	}
}

// RunContainerLifecycleBenchmark runs full container lifecycle benchmark for a given adapter.
func RunContainerLifecycleBenchmark(b *testing.B, cmd ContainerCommands, prefix string) {
	ctx := context.Background()

	if err := cmd.Setup(ctx); err != nil {
		b.Fatalf("Setup failed: %v", err)
	}
	defer cmd.Teardown()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("%s-lifecycle-%d", prefix, i)
		opts := CreateOptions{
			Name:    name,
			Image:   TestImageAlpine,
			Command: []string{"sleep", "1"},
		}

		container, err := cmd.Create(ctx, opts)
		if err != nil {
			b.Fatalf("Create failed: %v", err)
		}

		if err := cmd.Start(ctx, container.ID); err != nil {
			b.Fatalf("Start failed: %v", err)
		}

		if err := cmd.Stop(ctx, container.ID, 5*time.Second); err != nil {
			b.Fatalf("Stop failed: %v", err)
		}

		if err := cmd.Remove(ctx, container.ID, false); err != nil {
			b.Fatalf("Remove failed: %v", err)
		}
	}
}
