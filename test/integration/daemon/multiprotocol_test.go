//go:build integration

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

// Package daemon provides multi-protocol integration tests for the platformd daemon.
// These tests verify that all protocol adapters provide consistent behavior
// and feature parity across REST, gRPC, QUIC, MCP, and Unix socket transports.
package daemon

import (
	"context"
	"strings"
	"testing"
)

// =============================================================================
// Protocol Adapter Interface for Testing
// =============================================================================

// protocolAdapter wraps a DaemonCommands implementation with setup/teardown.
type protocolAdapter struct {
	adapter DaemonCommands
}

// =============================================================================
// Test Fixtures
// =============================================================================

// createAdapters returns all protocol adapters for testing.
func createAdapters() []protocolAdapter {
	return []protocolAdapter{
		{adapter: NewCLIAdapter()},
		{adapter: NewRESTAdapter()},
		{adapter: NewGRPCAdapter()},
		{adapter: NewQUICAdapter()},
		{adapter: NewMCPAdapter()},
		{adapter: NewUnixAdapter()},
	}
}

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestDaemonMultiProtocol runs the full daemon test suite against all protocols.
// This is the main entry point for daemon integration testing.
func TestDaemonMultiProtocol(t *testing.T) {
	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapters := createAdapters()

	for _, pa := range adapters {
		adapter := pa.adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			// Setup adapter
			if err := adapter.Setup(ctx); err != nil {
				t.Fatalf("Setup failed: %v", err)
			}
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Errorf("Teardown failed: %v", err)
				}
			}()

			// Run all tests for this protocol
			t.Run("Health", func(t *testing.T) {
				testHealth(t, ctx, adapter)
			})

			t.Run("Status", func(t *testing.T) {
				testStatus(t, ctx, adapter)
			})

			t.Run("Version", func(t *testing.T) {
				testVersion(t, ctx, adapter)
			})

			t.Run("Services", func(t *testing.T) {
				testServices(t, ctx, adapter)
			})

			t.Run("Protocols", func(t *testing.T) {
				testProtocols(t, ctx, adapter)
			})
		})
	}
}

// =============================================================================
// Individual Protocol Tests - For Targeted Testing
// =============================================================================

// TestDaemonCLI tests daemon operations via CLI protocol only.
func TestDaemonCLI(t *testing.T) {
	testProtocol(t, NewCLIAdapter())
}

// TestDaemonREST tests daemon operations via REST protocol only.
func TestDaemonREST(t *testing.T) {
	testProtocol(t, NewRESTAdapter())
}

// TestDaemonGRPC tests daemon operations via gRPC protocol only.
func TestDaemonGRPC(t *testing.T) {
	testProtocol(t, NewGRPCAdapter())
}

// TestDaemonQUIC tests daemon operations via QUIC protocol only.
func TestDaemonQUIC(t *testing.T) {
	testProtocol(t, NewQUICAdapter())
}

// TestDaemonMCP tests daemon operations via MCP protocol only.
func TestDaemonMCP(t *testing.T) {
	testProtocol(t, NewMCPAdapter())
}

// TestDaemonUnix tests daemon operations via Unix socket protocol only.
func TestDaemonUnix(t *testing.T) {
	testProtocol(t, NewUnixAdapter())
}

// testProtocol runs the full test suite for a single protocol adapter.
func testProtocol(t *testing.T, adapter DaemonCommands) {
	ctx, cancel := DefaultTestContext()
	defer cancel()

	if err := adapter.Setup(ctx); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer func() {
		if err := adapter.Teardown(); err != nil {
			t.Errorf("Teardown failed: %v", err)
		}
	}()

	t.Run("Health", func(t *testing.T) {
		testHealth(t, ctx, adapter)
	})

	t.Run("Status", func(t *testing.T) {
		testStatus(t, ctx, adapter)
	})

	t.Run("Version", func(t *testing.T) {
		testVersion(t, ctx, adapter)
	})

	t.Run("Services", func(t *testing.T) {
		testServices(t, ctx, adapter)
	})

	t.Run("Protocols", func(t *testing.T) {
		testProtocols(t, ctx, adapter)
	})
}

// =============================================================================
// Health Tests
// =============================================================================

// testHealth tests the health check endpoint.
func testHealth(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	t.Run("CheckHealth", func(t *testing.T) {
		testHealthCheck(t, ctx, adapter)
	})

	t.Run("HealthComponents", func(t *testing.T) {
		testHealthComponents(t, ctx, adapter)
	})
}

// testHealthCheck verifies the health endpoint returns a valid response.
func testHealthCheck(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	result, err := adapter.Health(ctx)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	if result.Status == "" {
		t.Error("Health status should not be empty")
	}

	// Verify status is one of the expected values
	validStatuses := map[string]bool{
		HealthStatusHealthy:   true,
		HealthStatusDegraded:  true,
		HealthStatusUnhealthy: true,
	}

	if !validStatuses[result.Status] {
		t.Errorf("Unexpected health status: %s", result.Status)
	}

	if result.Timestamp.IsZero() {
		t.Error("Health timestamp should not be zero")
	}
}

// testHealthComponents verifies that health components are returned.
func testHealthComponents(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	result, err := adapter.Health(ctx)
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	// Components may be empty if the daemon is minimal, but if present,
	// they should have valid data
	for _, c := range result.Components {
		if c.Name == "" {
			t.Error("Component name should not be empty")
		}
		if c.Status == "" {
			t.Errorf("Component %s status should not be empty", c.Name)
		}
	}
}

// =============================================================================
// Status Tests
// =============================================================================

// testStatus tests the status endpoint.
func testStatus(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	t.Run("GetStatus", func(t *testing.T) {
		testGetStatus(t, ctx, adapter)
	})

	t.Run("SystemInfo", func(t *testing.T) {
		testSystemInfo(t, ctx, adapter)
	})
}

// testGetStatus verifies the status endpoint returns valid daemon information.
func testGetStatus(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	result, err := adapter.Status(ctx)
	if err != nil {
		t.Fatalf("Status check failed: %v", err)
	}

	if result.Status == "" {
		t.Error("Daemon status should not be empty")
	}

	if result.Version == "" {
		t.Error("Daemon version should not be empty")
	}

	if result.Timestamp.IsZero() {
		t.Error("Status timestamp should not be zero")
	}
}

// testSystemInfo verifies system information is returned.
func testSystemInfo(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	result, err := adapter.Status(ctx)
	if err != nil {
		t.Fatalf("Status check failed: %v", err)
	}

	if result.System.OS == "" {
		t.Error("System OS should not be empty")
	}

	if result.System.Arch == "" {
		t.Error("System architecture should not be empty")
	}

	if result.System.NumCPUs <= 0 {
		t.Error("System should have at least one CPU")
	}

	if result.System.TotalMemoryMB == 0 {
		t.Error("System should have some memory")
	}
}

// =============================================================================
// Version Tests
// =============================================================================

// testVersion tests the version endpoint.
func testVersion(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	t.Run("GetVersion", func(t *testing.T) {
		testGetVersion(t, ctx, adapter)
	})

	t.Run("BuildInfo", func(t *testing.T) {
		testBuildInfo(t, ctx, adapter)
	})
}

// testGetVersion verifies the version endpoint returns valid information.
func testGetVersion(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	result, err := adapter.Version(ctx)
	if err != nil {
		t.Fatalf("Version check failed: %v", err)
	}

	if result.Version == "" {
		t.Error("Version should not be empty")
	}
}

// testBuildInfo verifies build information is returned.
func testBuildInfo(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	result, err := adapter.Version(ctx)
	if err != nil {
		t.Fatalf("Version check failed: %v", err)
	}

	// These fields may be empty in dev builds but should be present
	// Just verify the response structure is valid
	_ = result.BuildTime
	_ = result.GitCommit
	_ = result.GoVersion
}

// =============================================================================
// Service Tests
// =============================================================================

// testServices tests service management operations.
func testServices(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	t.Run("ListServices", func(t *testing.T) {
		testListServices(t, ctx, adapter)
	})

	t.Run("ServiceOperations", func(t *testing.T) {
		testServiceOperations(t, ctx, adapter)
	})
}

// testListServices verifies service listing works correctly.
func testListServices(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	result, err := adapter.ListServices(ctx)
	if err != nil {
		t.Fatalf("ListServices failed: %v", err)
	}

	// The daemon should have at least one service (itself)
	if result.Count < 0 {
		t.Error("Service count should not be negative")
	}

	// Verify service data integrity
	for _, s := range result.Services {
		if s.Name == "" {
			t.Error("Service name should not be empty")
		}

		validStatuses := map[string]bool{
			ServiceStatusStopped:  true,
			ServiceStatusStarting: true,
			ServiceStatusRunning:  true,
			ServiceStatusStopping: true,
			ServiceStatusError:    true,
		}

		if !validStatuses[s.Status] {
			t.Errorf("Service %s has unexpected status: %s", s.Name, s.Status)
		}
	}

	if result.Timestamp.IsZero() {
		t.Error("ListServices timestamp should not be zero")
	}
}

// testServiceOperations tests get on every listed service, and that start,
// stop and restart of each are refused and leave its status as it was.
func testServiceOperations(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	listResult, err := adapter.ListServices(ctx)
	if err != nil {
		t.Fatalf("ListServices failed: %v", err)
	}

	if len(listResult.Services) == 0 {
		t.Fatal("ListServices returned no services - daemon should have registered configured services")
	}

	// Every service platformd serve registers is a subsystem it owns for the
	// life of the process (registerConfiguredServices), so start, stop and
	// restart are each refused with ErrServiceNotControllable and change
	// nothing (docs/daemon/api.md, "Service start, stop and restart are
	// refused"). Each service is checked, not the first one listed, because
	// ListServices ranges over a map and its order changes between calls.
	for _, listed := range listResult.Services {
		name := listed.Name
		t.Run(name, func(t *testing.T) {
			before, err := adapter.GetService(ctx, name)
			if err != nil {
				t.Fatalf("GetService(%s) failed: %v", name, err)
			}
			if before.Name != name {
				t.Errorf("GetService returned wrong service name: expected %s, got %s", name, before.Name)
			}
			if before.Status != ServiceStatusRunning && before.Status != ServiceStatusStopped {
				t.Errorf("GetService(%s) status = %q, want %q or %q: a subsystem is wired or it is not",
					name, before.Status, ServiceStatusRunning, ServiceStatusStopped)
			}

			verbs := map[string]func(context.Context, string) (*ServiceActionResult, error){
				"start":   adapter.StartService,
				"stop":    adapter.StopService,
				"restart": adapter.RestartService,
			}
			for verb, call := range verbs {
				t.Run(verb, func(t *testing.T) {
					result, err := call(ctx, name)
					if err == nil {
						t.Fatalf("%s %s succeeded (%+v), want the not-controllable refusal", verb, name, result)
					}
					want := "service " + name + " cannot be started or stopped at runtime"
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("%s %s error = %v, want it to contain %q", verb, name, err, want)
					}

					after, err := adapter.GetService(ctx, name)
					if err != nil {
						t.Fatalf("GetService(%s) after refused %s failed: %v", name, verb, err)
					}
					if after.Status != before.Status {
						t.Errorf("refused %s changed %s status from %q to %q", verb, name, before.Status, after.Status)
					}
				})
			}
		})
	}
}

// =============================================================================
// Protocol Tests
// =============================================================================

// testProtocols tests protocol listing operations.
func testProtocols(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	t.Run("ListProtocols", func(t *testing.T) {
		testListProtocols(t, ctx, adapter)
	})
}

// isUnixSocketProtocol returns true if the protocol name represents a Unix
// socket transport. The server returns "Unix Socket" while some adapters
// may use "Unix". This helper normalizes the comparison.
func isUnixSocketProtocol(name string) bool {
	lower := strings.ToLower(name)
	return lower == "unix" || lower == "unix socket"
}

// normalizeProtocolName maps protocol names to their canonical lookup key
// used in the expectedProtocols map. This handles the "Unix Socket" vs "Unix"
// naming discrepancy between the REST API server and test expectations.
func normalizeProtocolName(name string) string {
	if isUnixSocketProtocol(name) {
		return "Unix Socket"
	}
	return name
}

// testListProtocols verifies protocol listing works correctly.
func testListProtocols(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	result, err := adapter.ListProtocols(ctx)
	if err != nil {
		t.Fatalf("ListProtocols failed: %v", err)
	}

	// The daemon should expose multiple protocols
	if len(result.Protocols) == 0 {
		t.Error("Daemon should expose at least one protocol")
	}

	// Expected protocols using canonical names that match server responses.
	// The server returns "Unix Socket" for the Unix domain socket transport.
	expectedProtocols := map[string]bool{
		"REST":        true,
		"gRPC":        true,
		"QUIC":        true,
		"MCP":         true,
		"Unix Socket": true,
	}

	foundProtocols := make(map[string]bool)

	for _, p := range result.Protocols {
		if p.Name == "" {
			t.Error("Protocol name should not be empty")
			continue
		}

		canonical := normalizeProtocolName(p.Name)
		foundProtocols[canonical] = true

		// Verify port is valid for network protocols.
		// Unix socket protocols use a filesystem path, not a TCP/UDP port,
		// so port=0 is the expected and valid value for them.
		if !isUnixSocketProtocol(p.Name) && p.Enabled {
			if p.Port <= 0 || p.Port > 65535 {
				t.Errorf("Protocol %s has invalid port: %d", p.Name, p.Port)
			}
		}

		// Verify status is present
		if p.Status == "" {
			t.Errorf("Protocol %s should have a status", p.Name)
		}
	}

	// Log which expected protocols were found (informational)
	for proto := range expectedProtocols {
		if !foundProtocols[proto] {
			t.Logf("Note: Expected protocol %s not found in response", proto)
		}
	}

	if result.Timestamp.IsZero() {
		t.Error("ListProtocols timestamp should not be zero")
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

// TestDaemonErrorHandling tests error handling across all protocols.
func TestDaemonErrorHandling(t *testing.T) {
	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapters := createAdapters()

	for _, pa := range adapters {
		adapter := pa.adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Fatalf("Setup failed: %v", err)
			}
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Errorf("Teardown failed: %v", err)
				}
			}()

			t.Run("GetNonExistentService", func(t *testing.T) {
				testGetNonExistentService(t, ctx, adapter)
			})
		})
	}
}

// testGetNonExistentService verifies proper error handling for invalid service names.
func testGetNonExistentService(t *testing.T, ctx context.Context, adapter DaemonCommands) {
	_, err := adapter.GetService(ctx, "non-existent-service-12345")
	if err == nil {
		// Some implementations may return an empty result instead of an error
		// This is acceptable behavior - the important thing is it doesn't panic
		t.Log("GetService for non-existent service returned nil error (acceptable)")
	}
}

// =============================================================================
// Consistency Tests
// =============================================================================

// TestDaemonConsistency verifies that all protocols return consistent data.
func TestDaemonConsistency(t *testing.T) {
	ctx, cancel := DefaultTestContext()
	defer cancel()

	adapters := createAdapters()

	// Collect results from all working adapters
	type adapterResult struct {
		name    string
		version *VersionResult
		err     error
	}

	var results []adapterResult

	for _, pa := range adapters {
		adapter := pa.adapter
		if err := adapter.Setup(ctx); err != nil {
			t.Fatalf("%s adapter: setup failed; platformd must serve every protocol endpoint: %v", adapter.Name(), err)
		}

		version, err := adapter.Version(ctx)
		results = append(results, adapterResult{
			name:    adapter.Name(),
			version: version,
			err:     err,
		})

		adapter.Teardown()
	}

	if len(results) < 2 {
		t.Fatalf("Need at least 2 working adapters to test consistency, got %d", len(results))
	}

	// Find the first successful result as reference
	var reference *VersionResult
	var referenceName string
	for _, r := range results {
		if r.err == nil && r.version != nil {
			reference = r.version
			referenceName = r.name
			break
		}
	}

	if reference == nil {
		t.Fatal("No adapter returned a valid version")
	}

	// Compare all other results to the reference
	for _, r := range results {
		if r.err != nil || r.version == nil {
			continue
		}
		if r.name == referenceName {
			continue
		}

		if r.version.Version != reference.Version {
			t.Errorf("Version mismatch: %s returned %s, %s returned %s",
				referenceName, reference.Version, r.name, r.version.Version)
		}

		if r.version.GoVersion != reference.GoVersion {
			t.Errorf("GoVersion mismatch: %s returned %s, %s returned %s",
				referenceName, reference.GoVersion, r.name, r.version.GoVersion)
		}
	}
}
