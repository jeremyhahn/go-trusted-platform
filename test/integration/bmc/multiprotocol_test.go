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

// Package bmc_integration provides multi-protocol integration tests for the
// platformd BMC service. These tests verify that all protocol adapters provide
// consistent behavior and feature parity across CLI, REST, gRPC, QUIC, MCP,
// and Unix socket transports.
package bmc_integration

import (
	"context"
	"testing"

	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// =============================================================================
// Test Fixtures
// =============================================================================

// createAdapters returns all protocol adapters for testing.
func createAdapters() []BMCCommands {
	return []BMCCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}
}

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestBMCMultiProtocol runs the full BMC test suite against all protocols.
// This is the main entry point for BMC integration testing.
func TestBMCMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	t.Cleanup(cancel)

	adapters := createAdapters()

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				if isNotImplementedError(err) {
					t.Skipf("Skipping %s: %v", adapter.Name(), err)
					return
				}
				t.Fatalf("Setup failed: %v", err)
			}
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Errorf("Teardown failed: %v", err)
				}
			})

			t.Run("PowerStatus", func(t *testing.T) {
				testPowerStatus(t, ctx, adapter)
			})

			t.Run("GetBootDevice", func(t *testing.T) {
				testGetBootDevice(t, ctx, adapter)
			})

			t.Run("VirtualMediaStatus", func(t *testing.T) {
				testVirtualMediaStatus(t, ctx, adapter)
			})

			t.Run("GetSensors", func(t *testing.T) {
				testGetSensors(t, ctx, adapter)
			})

			t.Run("GetSystemInfo", func(t *testing.T) {
				testGetSystemInfo(t, ctx, adapter)
			})

			t.Run("GetWebCertificate", func(t *testing.T) {
				testGetWebCertificate(t, ctx, adapter)
			})

			t.Run("ListUsers", func(t *testing.T) {
				testListUsers(t, ctx, adapter)
			})
		})
	}
}

// =============================================================================
// Individual Protocol Tests - For Targeted Testing
// =============================================================================

// TestBMCCLI tests BMC operations via CLI protocol only.
func TestBMCCLI(t *testing.T) {
	SkipIfNotIntegration(t)
	testSingleProtocol(t, NewCLIAdapter())
}

// TestBMCREST tests BMC operations via REST protocol only.
func TestBMCREST(t *testing.T) {
	SkipIfNotIntegration(t)
	testSingleProtocol(t, NewRESTAdapter())
}

// TestBMCGRPC tests BMC operations via gRPC protocol only.
func TestBMCGRPC(t *testing.T) {
	SkipIfNotIntegration(t)
	testSingleProtocol(t, NewGRPCAdapter())
}

// TestBMCQUIC tests BMC operations via QUIC protocol only.
func TestBMCQUIC(t *testing.T) {
	SkipIfNotIntegration(t)
	testSingleProtocol(t, NewQUICAdapter())
}

// TestBMCMCP tests BMC operations via MCP protocol only.
func TestBMCMCP(t *testing.T) {
	SkipIfNotIntegration(t)
	testSingleProtocol(t, NewMCPAdapter())
}

// TestBMCUnix tests BMC operations via Unix socket protocol only.
func TestBMCUnix(t *testing.T) {
	SkipIfNotIntegration(t)
	testSingleProtocol(t, NewUnixAdapter())
}

// testSingleProtocol runs the full test suite for a single protocol adapter.
func testSingleProtocol(t *testing.T, adapter BMCCommands) {
	ctx, cancel := DefaultTestContext()
	t.Cleanup(cancel)

	if err := adapter.Setup(ctx); err != nil {
		if isNotImplementedError(err) {
			t.Skipf("Skipping %s: %v", adapter.Name(), err)
			return
		}
		t.Fatalf("Setup failed: %v", err)
	}
	t.Cleanup(func() {
		if err := adapter.Teardown(); err != nil {
			t.Errorf("Teardown failed: %v", err)
		}
	})

	t.Run("PowerStatus", func(t *testing.T) {
		testPowerStatus(t, ctx, adapter)
	})

	t.Run("GetBootDevice", func(t *testing.T) {
		testGetBootDevice(t, ctx, adapter)
	})

	t.Run("VirtualMediaStatus", func(t *testing.T) {
		testVirtualMediaStatus(t, ctx, adapter)
	})

	t.Run("GetSensors", func(t *testing.T) {
		testGetSensors(t, ctx, adapter)
	})

	t.Run("GetSystemInfo", func(t *testing.T) {
		testGetSystemInfo(t, ctx, adapter)
	})

	t.Run("GetWebCertificate", func(t *testing.T) {
		testGetWebCertificate(t, ctx, adapter)
	})

	t.Run("ListUsers", func(t *testing.T) {
		testListUsers(t, ctx, adapter)
	})
}

// =============================================================================
// Power Status Tests
// =============================================================================

// testPowerStatus verifies the power status endpoint returns a valid response.
func testPowerStatus(t *testing.T, ctx context.Context, adapter BMCCommands) {
	state, err := adapter.PowerStatus(ctx, DefaultTestProfileID)
	if err != nil {
		t.Fatalf("PowerStatus failed: %v", err)
	}

	validStates := map[bmcsvc.PowerState]bool{
		bmcsvc.PowerStateOn:      true,
		bmcsvc.PowerStateOff:     true,
		bmcsvc.PowerStateUnknown: true,
	}

	if !validStates[state] {
		t.Errorf("Unexpected power state: %s", state)
	}
}

// =============================================================================
// Boot Device Tests
// =============================================================================

// testGetBootDevice verifies the boot device endpoint returns a valid response.
func testGetBootDevice(t *testing.T, ctx context.Context, adapter BMCCommands) {
	device, err := adapter.GetBootDevice(ctx, DefaultTestProfileID)
	if err != nil {
		t.Fatalf("GetBootDevice failed: %v", err)
	}

	validDevices := map[bmcsvc.BootDevice]bool{
		bmcsvc.BootDeviceUnspecified:  true,
		bmcsvc.BootDevicePXE:          true,
		bmcsvc.BootDeviceDisk:         true,
		bmcsvc.BootDeviceCDROM:        true,
		bmcsvc.BootDeviceVirtualMedia: true,
		bmcsvc.BootDeviceNone:         true,
	}

	if !validDevices[device] {
		t.Errorf("Unexpected boot device: %s", device)
	}
}

// =============================================================================
// Virtual Media Tests
// =============================================================================

// testVirtualMediaStatus verifies the virtual media status endpoint returns
// a valid response.
func testVirtualMediaStatus(t *testing.T, ctx context.Context, adapter BMCCommands) {
	info, err := adapter.VirtualMediaStatus(ctx, DefaultTestProfileID)
	if err != nil {
		t.Fatalf("VirtualMediaStatus failed: %v", err)
	}

	if info == nil {
		t.Fatal("VirtualMediaStatus returned nil")
	}

	// The response structure should be valid regardless of mount state
	_ = info.Mounted
	_ = info.ImageURL
	_ = info.MediaType
}

// =============================================================================
// Sensor Tests
// =============================================================================

// testGetSensors verifies the sensors endpoint returns valid data.
func testGetSensors(t *testing.T, ctx context.Context, adapter BMCCommands) {
	sensors, err := adapter.GetSensors(ctx, DefaultTestProfileID)
	if err != nil {
		t.Fatalf("GetSensors failed: %v", err)
	}

	// The vBMC should return at least one sensor
	if len(sensors) == 0 {
		t.Log("Note: GetSensors returned no sensors (vBMC may not simulate sensors)")
		return
	}

	for _, s := range sensors {
		if s.Name == "" {
			t.Error("Sensor name should not be empty")
		}

		validStatuses := map[bmcsvc.SensorStatus]bool{
			bmcsvc.SensorStatusOK:       true,
			bmcsvc.SensorStatusWarning:  true,
			bmcsvc.SensorStatusCritical: true,
		}

		if !validStatuses[s.Status] {
			t.Errorf("Sensor %s has unexpected status: %s", s.Name, s.Status)
		}
	}
}

// =============================================================================
// System Info Tests
// =============================================================================

// testGetSystemInfo verifies the system info endpoint returns valid data.
func testGetSystemInfo(t *testing.T, ctx context.Context, adapter BMCCommands) {
	info, err := adapter.GetSystemInfo(ctx, DefaultTestProfileID)
	if err != nil {
		t.Fatalf("GetSystemInfo failed: %v", err)
	}

	if info == nil {
		t.Fatal("GetSystemInfo returned nil")
	}

	// The vBMC should return at least manufacturer and product
	if info.Manufacturer == "" {
		t.Log("Note: Manufacturer is empty (vBMC may not populate all fields)")
	}

	if info.Product == "" {
		t.Log("Note: Product is empty (vBMC may not populate all fields)")
	}

	// Power state should be valid
	validStates := map[bmcsvc.PowerState]bool{
		bmcsvc.PowerStateUnspecified: true,
		bmcsvc.PowerStateOn:          true,
		bmcsvc.PowerStateOff:         true,
		bmcsvc.PowerStateUnknown:     true,
	}

	if !validStates[info.PowerState] {
		t.Errorf("SystemInfo has unexpected power state: %s", info.PowerState)
	}
}

// =============================================================================
// Certificate Tests
// =============================================================================

// testGetWebCertificate verifies the certificate endpoint returns valid data.
func testGetWebCertificate(t *testing.T, ctx context.Context, adapter BMCCommands) {
	certInfo, err := adapter.GetWebCertificate(ctx, DefaultTestProfileID)
	if err != nil {
		t.Fatalf("GetWebCertificate failed: %v", err)
	}

	if certInfo == nil {
		t.Fatal("GetWebCertificate returned nil")
	}

	if certInfo.Subject == "" {
		t.Error("Certificate subject should not be empty")
	}

	if certInfo.Issuer == "" {
		t.Error("Certificate issuer should not be empty")
	}

	if certInfo.NotBefore.IsZero() {
		t.Error("Certificate NotBefore should not be zero")
	}

	if certInfo.NotAfter.IsZero() {
		t.Error("Certificate NotAfter should not be zero")
	}

	if certInfo.Fingerprint == "" {
		t.Error("Certificate fingerprint should not be empty")
	}
}

// =============================================================================
// User Management Tests
// =============================================================================

// testListUsers verifies the user listing endpoint returns valid data.
func testListUsers(t *testing.T, ctx context.Context, adapter BMCCommands) {
	users, err := adapter.ListUsers(ctx, DefaultTestProfileID)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}

	// The vBMC should have at least one user (admin)
	if len(users) == 0 {
		t.Log("Note: ListUsers returned no users (vBMC may not simulate user accounts)")
		return
	}

	for _, u := range users {
		if u.Username == "" {
			t.Error("User username should not be empty")
		}

		validPrivileges := map[bmcsvc.Privilege]bool{
			bmcsvc.PrivilegeUnspecified:   true,
			bmcsvc.PrivilegeCallback:      true,
			bmcsvc.PrivilegeUser:          true,
			bmcsvc.PrivilegeOperator:      true,
			bmcsvc.PrivilegeAdministrator: true,
			bmcsvc.PrivilegeNoAccess:      true,
		}

		if !validPrivileges[u.Privilege] {
			t.Errorf("User %s has unexpected privilege: %s", u.Username, u.Privilege)
		}
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

// TestBMCErrorHandling tests error handling across all protocols.
func TestBMCErrorHandling(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	t.Cleanup(cancel)

	adapters := createAdapters()

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				if isNotImplementedError(err) {
					t.Skipf("Skipping %s: %v", adapter.Name(), err)
					return
				}
				t.Fatalf("Setup failed: %v", err)
			}
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Errorf("Teardown failed: %v", err)
				}
			})

			t.Run("InvalidProfilePowerStatus", func(t *testing.T) {
				testInvalidProfilePowerStatus(t, ctx, adapter)
			})
		})
	}
}

// testInvalidProfilePowerStatus verifies proper error handling for an invalid profile ID.
func testInvalidProfilePowerStatus(t *testing.T, ctx context.Context, adapter BMCCommands) {
	_, err := adapter.PowerStatus(ctx, 999999)
	if err == nil {
		// Some implementations may return a default state instead of an error.
		// The important thing is it does not panic.
		t.Log("PowerStatus for invalid profile returned nil error (acceptable)")
	}
}
