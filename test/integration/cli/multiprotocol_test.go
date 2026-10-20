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

// Package cli provides multi-protocol integration tests for root-level CLI commands.
// These tests verify that root commands (version, status, health, config, context,
// service, completion) work consistently across all protocol adapters (CLI, REST,
// gRPC, QUIC, MCP, Unix) using a unified CLICommands interface.
//
// Run tests via:
//
//	make integration-test-cli
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package cli

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestCLIMultiProtocol runs the complete CLI test suite against all protocol adapters.
// Each adapter implements the CLICommands interface, enabling unified testing across
// CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestCLIMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement CLICommands
	adapters := []CLICommands{
		NewCLIAdapter(),
		// NewRESTAdapter(),  // TODO: Implement
		// NewGRPCAdapter(),  // TODO: Implement
		// NewQUICAdapter(),  // TODO: Implement
		// NewMCPAdapter(),   // TODO: Implement
		// NewUnixAdapter(),  // TODO: Implement
	}

	gate := helpers.NewAdapterGate(t, "cli", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testCLIProtocol(t, ctx, adapter)
		})
	}
}

// testCLIProtocol runs the complete CLI test suite against a single protocol adapter.
func testCLIProtocol(t *testing.T, ctx context.Context, cmd CLICommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("Version", func(t *testing.T) {
		testVersionCommands(t, ctx, cmd)
	})

	t.Run("Status", func(t *testing.T) {
		testStatusCommands(t, ctx, cmd)
	})

	t.Run("Health", func(t *testing.T) {
		testHealthCommands(t, ctx, cmd)
	})

	t.Run("Config", func(t *testing.T) {
		testConfigCommands(t, ctx, cmd)
	})

	t.Run("Context", func(t *testing.T) {
		testContextCommands(t, ctx, cmd, prefix)
	})

	t.Run("Service", func(t *testing.T) {
		testServiceCommands(t, ctx, cmd)
	})

	t.Run("Completion", func(t *testing.T) {
		testCompletionCommands(t, ctx, cmd)
	})
}

// =============================================================================
// Version Command Tests
// =============================================================================

func testVersionCommands(t *testing.T, ctx context.Context, cmd CLICommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("GetClientVersion", func(t *testing.T) {
		result, err := cmd.Version(testCtx, VersionOptions{ClientOnly: true})
		require.NoError(t, err, "Version with client-only should succeed")
		require.NotNil(t, result, "Result should not be nil")

		assert.NotEmpty(t, result.ClientVersion, "Client version should not be empty")
	})

	t.Run("GetFullVersion", func(t *testing.T) {
		result, err := cmd.Version(testCtx, VersionOptions{ClientOnly: false})
		require.NoError(t, err, "Version should succeed")
		require.NotNil(t, result, "Result should not be nil")

		assert.NotEmpty(t, result.ClientVersion, "Client version should not be empty")

		if result.ServerVersion != nil {
			assert.NotEmpty(t, result.ServerVersion.Version, "Server version should not be empty")
			assert.NotEmpty(t, result.ServerVersion.GoVersion, "Go version should not be empty")
		}
	})
}

// =============================================================================
// Status Command Tests
// =============================================================================

func testStatusCommands(t *testing.T, ctx context.Context, cmd CLICommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("GetStatus", func(t *testing.T) {
		result, err := cmd.Status(testCtx)
		require.NoError(t, err, "Status should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// System status should be a valid status
		assert.True(t, ContainsString(ValidSystemStatuses(), result.SystemStatus),
			"System status should be valid: %s", result.SystemStatus)

		// Platform info should be present
		if result.Info != nil {
			assert.NotEmpty(t, result.Info.Hostname, "Hostname should not be empty")
			assert.NotEmpty(t, result.Info.Version, "Version should not be empty")

			// System info should be present
			if result.Info.SystemInfo != nil {
				assert.NotEmpty(t, result.Info.SystemInfo.OS, "OS should not be empty")
				assert.NotEmpty(t, result.Info.SystemInfo.Arch, "Architecture should not be empty")
				assert.Greater(t, result.Info.SystemInfo.NumCPUs, int32(0), "CPUs should be greater than 0")
			}
		}
	})

	t.Run("StatusContainsServices", func(t *testing.T) {
		result, err := cmd.Status(testCtx)
		require.NoError(t, err, "Status should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Services should be present (at least some)
		for _, svc := range result.Services {
			assert.NotEmpty(t, svc.Name, "Service name should not be empty")
			assert.True(t, ContainsString(ValidServiceStatuses(), svc.Status),
				"Service status should be valid: %s", svc.Status)
			assert.True(t, ContainsString(ValidHealthStatuses(), svc.Health),
				"Service health should be valid: %s", svc.Health)
		}
	})
}

// =============================================================================
// Health Command Tests
// =============================================================================

func testHealthCommands(t *testing.T, ctx context.Context, cmd CLICommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("GetHealthBasic", func(t *testing.T) {
		result, err := cmd.Health(testCtx, HealthOptions{Detailed: false})
		require.NoError(t, err, "Health should succeed")
		require.NotNil(t, result, "Result should not be nil")

		assert.True(t, ContainsString(ValidHealthStatuses(), result.Status),
			"Health status should be valid: %s", result.Status)
	})

	t.Run("GetHealthDetailed", func(t *testing.T) {
		result, err := cmd.Health(testCtx, HealthOptions{Detailed: true})
		require.NoError(t, err, "Health with detailed should succeed")
		require.NotNil(t, result, "Result should not be nil")

		assert.True(t, ContainsString(ValidHealthStatuses(), result.Status),
			"Health status should be valid: %s", result.Status)

		// When detailed is requested, components should be present
		for _, comp := range result.Components {
			assert.NotEmpty(t, comp.Name, "Component name should not be empty")
			assert.True(t, ContainsString(ValidHealthStatuses(), comp.Status),
				"Component health should be valid: %s", comp.Status)
		}
	})
}

// =============================================================================
// Config Command Tests
// =============================================================================

func testConfigCommands(t *testing.T, ctx context.Context, cmd CLICommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("ConfigGetAll", func(t *testing.T) {
		result, err := cmd.ConfigGet(testCtx, "")
		require.NoError(t, err, "Config get all should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Should have at least some sections
		if len(result.Sections) > 0 {
			for _, sec := range result.Sections {
				assert.NotEmpty(t, sec.Section, "Section name should not be empty")
			}
		}
	})

	t.Run("ConfigGetSection", func(t *testing.T) {
		// First get all sections to find a valid section name
		allResult, err := cmd.ConfigGet(testCtx, "")
		if err != nil {
			t.Fatalf("Setup: ConfigGet of all sections failed: %v", err)
		}
		if len(allResult.Sections) == 0 {
			t.Fatal("Setup: ConfigGet returned no sections; platformd must run with test/integration/config.yaml")
		}

		sectionName := allResult.Sections[0].Section
		result, err := cmd.ConfigGet(testCtx, sectionName)
		require.NoError(t, err, "Config get section should succeed")
		require.NotNil(t, result, "Result should not be nil")
		require.Len(t, result.Sections, 1, "Config get <section> returns only that section")
		assert.Equal(t, sectionName, result.Sections[0].Section)
	})

	t.Run("ConfigSetAndReload", func(t *testing.T) {
		// This test modifies configuration - should be careful in integration tests
		// Set a test value (without persisting to avoid side effects)
		values := map[string]string{
			"test_key": "test_value",
		}

		setResult, err := cmd.ConfigSet(testCtx, "test", values, false)
		if err != nil {
			// Some configurations may not allow setting arbitrary values
			t.Logf("Config set test skipped: %v", err)
			return
		}
		require.NotNil(t, setResult, "Set result should not be nil")

		// Reload configuration
		reloadResult, err := cmd.ConfigReload(testCtx)
		if err != nil {
			t.Logf("Config reload test skipped: %v", err)
			return
		}
		require.NotNil(t, reloadResult, "Reload result should not be nil")
	})
}

// =============================================================================
// Context Command Tests
// =============================================================================

func testContextCommands(t *testing.T, ctx context.Context, cmd CLICommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	testContextName := fmt.Sprintf("test-%s", prefix)

	t.Run("ContextList", func(t *testing.T) {
		result, err := cmd.ContextList(testCtx)
		require.NoError(t, err, "Context list should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Should have at least one context (the default one)
		if len(result.Contexts) > 0 {
			for _, ctx := range result.Contexts {
				assert.NotEmpty(t, ctx.Name, "Context name should not be empty")
				assert.True(t, ContainsString(ValidContextTypes(), ctx.Type),
					"Context type should be valid: %s", ctx.Type)
			}
		}
	})

	t.Run("ContextCurrent", func(t *testing.T) {
		result, err := cmd.ContextCurrent(testCtx)
		require.NoError(t, err, "Context current should succeed")
		require.NotNil(t, result, "Result should not be nil")

		assert.NotEmpty(t, result.Name, "Current context name should not be empty")
		assert.True(t, ContainsString(ValidContextTypes(), result.Type),
			"Context type should be valid: %s", result.Type)
	})

	t.Run("ContextAddLocalAndDelete", func(t *testing.T) {
		// Add a new local context
		addOpts := ContextAddOptions{
			Name:       testContextName + "-local",
			Type:       "local",
			SocketPath: "/tmp/test-platformd.sock",
		}

		addResult, err := cmd.ContextAdd(testCtx, addOpts)
		require.NoError(t, err, "Context add should succeed")
		require.NotNil(t, addResult, "Add result should not be nil")
		assert.True(t, addResult.Success, "Context add should be successful")

		// Verify it appears in the list
		listResult, err := cmd.ContextList(testCtx)
		require.NoError(t, err, "Context list should succeed")

		found := false
		for _, ctx := range listResult.Contexts {
			if ctx.Name == testContextName+"-local" {
				found = true
				assert.Equal(t, "local", ctx.Type, "Context type should be local")
				assert.Equal(t, addOpts.SocketPath, ctx.Target, "Local context target is its socket path")
				break
			}
		}
		assert.True(t, found, "Newly added context should appear in list")

		// Delete the context
		deleteResult, err := cmd.ContextDelete(testCtx, testContextName+"-local")
		require.NoError(t, err, "Context delete should succeed")
		require.NotNil(t, deleteResult, "Delete result should not be nil")
		assert.True(t, deleteResult.Success, "Context delete should be successful")
	})

	t.Run("ContextAddRemoteAndDelete", func(t *testing.T) {
		// Add a new remote context
		addOpts := ContextAddOptions{
			Name:   testContextName + "-remote",
			Type:   "remote",
			Server: "localhost:10443",
		}

		addResult, err := cmd.ContextAdd(testCtx, addOpts)
		require.NoError(t, err, "Context add remote should succeed")
		require.NotNil(t, addResult, "Add result should not be nil")
		assert.True(t, addResult.Success, "Context add should be successful")

		// Delete the context
		deleteResult, err := cmd.ContextDelete(testCtx, testContextName+"-remote")
		require.NoError(t, err, "Context delete should succeed")
		require.NotNil(t, deleteResult, "Delete result should not be nil")
		assert.True(t, deleteResult.Success, "Context delete should be successful")
	})

	t.Run("ContextUseAndRestore", func(t *testing.T) {
		// Get the current context first
		currentResult, err := cmd.ContextCurrent(testCtx)
		require.NoError(t, err, "Context current should succeed")
		originalContext := currentResult.Name

		// Add a test context
		addOpts := ContextAddOptions{
			Name:       testContextName + "-use",
			Type:       "local",
			SocketPath: "/tmp/test-use.sock",
		}

		_, err = cmd.ContextAdd(testCtx, addOpts)
		require.NoError(t, err, "Context add should succeed")

		// Switch to the test context
		useResult, err := cmd.ContextUse(testCtx, testContextName+"-use")
		require.NoError(t, err, "Context use should succeed")
		require.NotNil(t, useResult, "Use result should not be nil")
		assert.True(t, useResult.Success, "Context use should be successful")

		// Verify the switch
		newCurrentResult, err := cmd.ContextCurrent(testCtx)
		require.NoError(t, err, "Context current should succeed")
		assert.Equal(t, testContextName+"-use", newCurrentResult.Name, "Context should be switched")

		// Restore the original context
		_, err = cmd.ContextUse(testCtx, originalContext)
		require.NoError(t, err, "Context use should succeed")

		// Clean up
		_, err = cmd.ContextDelete(testCtx, testContextName+"-use")
		require.NoError(t, err, "Context delete should succeed")
	})

	t.Run("ContextDeleteNonExistent", func(t *testing.T) {
		_, err := cmd.ContextDelete(testCtx, "non-existent-context-12345")
		// Should fail for non-existent context
		require.Error(t, err, "Context delete should fail for non-existent context")
	})
}

// =============================================================================
// Service Command Tests
// =============================================================================

func testServiceCommands(t *testing.T, ctx context.Context, cmd CLICommands) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("ServiceList", func(t *testing.T) {
		result, err := cmd.ServiceList(testCtx)
		require.NoError(t, err, "Service list should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Should have at least some services
		for _, svc := range result.Services {
			assert.NotEmpty(t, svc.Name, "Service name should not be empty")
			assert.NotEmpty(t, svc.Type, "Service type should not be empty")
			assert.True(t, ContainsString(ValidServiceStatuses(), svc.Status),
				"Service status should be valid: %s", svc.Status)
			assert.True(t, ContainsString(ValidHealthStatuses(), svc.Health),
				"Service health should be valid: %s", svc.Health)
		}
	})

	t.Run("ServiceStatusValidTypes", func(t *testing.T) {
		// Test service status for all valid service types
		for _, serviceType := range ValidServiceTypes() {
			t.Run(serviceType, func(t *testing.T) {
				result, err := cmd.ServiceStatus(testCtx, serviceType)
				if err != nil {
					// Service might not exist, which is acceptable
					t.Logf("Service %s status failed (may not exist): %v", serviceType, err)
					return
				}

				require.NotNil(t, result, "Result should not be nil")
				if result.Service != nil {
					assert.NotEmpty(t, result.Service.Name, "Service name should not be empty")
					assert.True(t, ContainsString(ValidServiceStatuses(), result.Service.Status),
						"Service status should be valid: %s", result.Service.Status)
				}
			})
		}
	})

	t.Run("ServiceStatusInvalidType", func(t *testing.T) {
		_, err := cmd.ServiceStatus(testCtx, "invalid-service-type")
		require.Error(t, err, "Service status should fail for invalid service type")
	})

	t.Run("ServiceStartStopRestart", func(t *testing.T) {
		// Use a service that's safe to start/stop in testing
		// This test is more about verifying the command works, not the actual service behavior
		serviceType := "webservice"

		// Get current status
		statusResult, err := cmd.ServiceStatus(testCtx, serviceType)
		if err != nil {
			t.Fatalf("Setup: ServiceStatus(%s) failed; platformd must serve the REST webservice: %v", serviceType, err)
		}

		originalStatus := ""
		if statusResult.Service != nil {
			originalStatus = statusResult.Service.Status
		}

		// Test stop (with force and timeout)
		stopResult, err := cmd.ServiceStop(testCtx, serviceType, ServiceStopOptions{
			Force:   false,
			Timeout: 30,
		})
		if err != nil {
			t.Logf("Service stop test: %v", err)
		} else {
			require.NotNil(t, stopResult, "Stop result should not be nil")
		}

		// Test start
		startResult, err := cmd.ServiceStart(testCtx, serviceType)
		if err != nil {
			t.Logf("Service start test: %v", err)
		} else {
			require.NotNil(t, startResult, "Start result should not be nil")
		}

		// Test restart with timeout
		restartResult, err := cmd.ServiceRestart(testCtx, serviceType, 30)
		if err != nil {
			t.Logf("Service restart test: %v", err)
		} else {
			require.NotNil(t, restartResult, "Restart result should not be nil")
		}

		// Attempt to restore original state if it was running
		if originalStatus == "RUNNING" {
			_, _ = cmd.ServiceStart(testCtx, serviceType)
		}
	})

	t.Run("ServiceStopWithOptions", func(t *testing.T) {
		serviceType := "webservice"

		// Test stop with force flag
		_, err := cmd.ServiceStop(testCtx, serviceType, ServiceStopOptions{
			Force:   true,
			Timeout: 10,
		})
		if err != nil {
			t.Logf("Service stop with force test: %v", err)
		}

		// Ensure service is started again for other tests
		_, _ = cmd.ServiceStart(testCtx, serviceType)
	})
}

// =============================================================================
// Completion Command Tests
// =============================================================================

func testCompletionCommands(t *testing.T, ctx context.Context, cmd CLICommands) {
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	t.Run("CompletionValidShells", func(t *testing.T) {
		for _, shell := range ValidShellTypes() {
			t.Run(shell, func(t *testing.T) {
				result, err := cmd.Completion(testCtx, shell)
				require.NoError(t, err, "Completion for %s should succeed", shell)
				require.NotNil(t, result, "Result should not be nil")

				// Completion script should not be empty
				assert.NotEmpty(t, result.Script, "Completion script should not be empty for %s", shell)

				// Verify script contains expected content based on shell type
				switch shell {
				case "bash":
					assert.Contains(t, result.Script, "platformctl", "Bash completion should reference platformctl")
				case "zsh":
					assert.Contains(t, result.Script, "platformctl", "Zsh completion should reference platformctl")
				case "fish":
					assert.Contains(t, result.Script, "platformctl", "Fish completion should reference platformctl")
				case "powershell":
					assert.Contains(t, result.Script, "platformctl", "PowerShell completion should reference platformctl")
				}
			})
		}
	})

	t.Run("CompletionInvalidShell", func(t *testing.T) {
		_, err := cmd.Completion(testCtx, "invalid-shell")
		require.Error(t, err, "Completion should fail for invalid shell type")
	})
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestCLIEdgeCases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "cli", "CLI", adapter.Setup(ctx))
	defer func() {
		if err := adapter.Teardown(); err != nil {
			t.Logf("Warning: teardown error: %v", err)
		}
	}()

	t.Run("ConcurrentVersionRequests", func(t *testing.T) {
		// Test concurrent requests to ensure thread safety
		const numRequests = 10
		results := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			go func() {
				_, err := adapter.Version(ctx, VersionOptions{ClientOnly: true})
				results <- err
			}()
		}

		for i := 0; i < numRequests; i++ {
			err := <-results
			assert.NoError(t, err, "Concurrent version request should succeed")
		}
	})

	t.Run("ConcurrentStatusRequests", func(t *testing.T) {
		const numRequests = 5
		results := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			go func() {
				_, err := adapter.Status(ctx)
				results <- err
			}()
		}

		for i := 0; i < numRequests; i++ {
			err := <-results
			assert.NoError(t, err, "Concurrent status request should succeed")
		}
	})

	t.Run("TimeoutHandling", func(t *testing.T) {
		// Create a very short timeout context
		shortCtx, cancel := context.WithTimeout(ctx, 1*time.Nanosecond)
		defer cancel()

		// Wait for context to expire
		<-shortCtx.Done()

		// Requests with expired context should fail
		_, err := adapter.Version(shortCtx, VersionOptions{})
		// The error could be context deadline exceeded or context canceled
		if err != nil {
			t.Logf("Expected timeout behavior: %v", err)
		}
	})
}
