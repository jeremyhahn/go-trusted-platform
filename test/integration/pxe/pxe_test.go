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

// Package pxe provides multi-protocol integration tests for PXE provisioning services.
// These tests verify that PXE provisioning operations work consistently across all
// protocol adapters (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified PXECommands interface.
//
// Run tests via:
//
//	make integration-test-pxe
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package pxe

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

// TestPXEMultiProtocol runs the complete PXE provisioning test suite against all
// protocol adapters. Each adapter implements the PXECommands interface, enabling
// unified testing across CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestPXEMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement PXECommands
	adapters := []PXECommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "pxe", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testPXEProtocol(t, ctx, adapter)
		})
	}
}

// testPXEProtocol runs the complete PXE provisioning test suite against a single
// protocol adapter.
func testPXEProtocol(t *testing.T, ctx context.Context, cmd PXECommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	// platformctl pxe covers six verbs; registration and state writes stay
	// API-only, so the CLI leg seeds through gRPC and drives those six. On
	// every other transport the assertions below are unchanged.
	if cliAdapter, ok := cmd.(*CLIAdapter); ok {
		testPXECLI(t, ctx, cliAdapter, prefix)
		return
	}

	t.Run("DeviceManagement", func(t *testing.T) {
		testDeviceRegister(t, ctx, cmd, prefix)
		testDeviceGet(t, ctx, cmd, prefix)
		testDeviceGetByMAC(t, ctx, cmd, prefix)
		testDeviceList(t, ctx, cmd, prefix)
		testDeviceRemove(t, ctx, cmd, prefix)
	})

	t.Run("StateTransitions", func(t *testing.T) {
		testStateUpdate(t, ctx, cmd, prefix)
		testSetEnrolled(t, ctx, cmd, prefix)
		testAuthorize(t, ctx, cmd, prefix)
		testQuarantine(t, ctx, cmd, prefix)
		testRetry(t, ctx, cmd, prefix)
	})

	t.Run("Events", func(t *testing.T) {
		testGetEvents(t, ctx, cmd, prefix)
	})

	t.Run("ServiceStatus", func(t *testing.T) {
		testGetStatus(t, ctx, cmd, prefix)
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		testInvalidMACAddress(t, ctx, cmd, prefix)
		testNonexistentDevice(t, ctx, cmd, prefix)
		testInvalidStateTransition(t, ctx, cmd, prefix)
		testDuplicateRegistration(t, ctx, cmd, prefix)
	})
}

// =============================================================================
// CLI Declared Gap: the PXE device lifecycle is API-only
// =============================================================================

// testPXECLI is the CLI leg of TestPXEMultiProtocol. platformctl pxe has six
// verbs (docs/provisioning/cli.md §5): get, list, authorize, quarantine,
// retry and events, and every assertion on them goes through the real
// binary. Registration and raw state writes stay API-only, so devices are
// seeded through the gRPC adapter. The verbs with no CLI counterpart assert
// their typed refusal (CA m588 (1)): green on declared behaviour, red when
// the gap closes, never skipped.
func testPXECLI(t *testing.T, ctx context.Context, cli *CLIAdapter, prefix string) {
	t.Helper()
	testCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	seed := NewGRPCAdapter()
	require.NoError(t, seed.Setup(testCtx), "Setup: gRPC seed adapter")
	defer func() { _ = seed.Teardown() }()

	register := func(t *testing.T, name string, states ...string) (string, RegisterDeviceOptions) {
		t.Helper()
		opts := DefaultRegisterOptions(prefix + "-" + name)
		dev, err := seed.RegisterDevice(testCtx, opts)
		require.NoError(t, err, "Setup: RegisterDevice")
		t.Cleanup(func() { _ = CleanupDevice(testCtx, seed, dev.ID) })
		for _, s := range states {
			_, err := seed.UpdateDeviceState(testCtx, UpdateStateOptions{
				DeviceID: dev.ID, State: s, Reason: "Setup progression",
			})
			require.NoError(t, err, "Setup: UpdateDeviceState to %s", s)
		}
		return dev.ID, opts
	}
	seededState := func(t *testing.T, id string) string {
		t.Helper()
		dev, err := seed.GetDevice(testCtx, id)
		require.NoError(t, err, "GetDevice through gRPC")
		return dev.State
	}

	t.Run("Get", func(t *testing.T) {
		id, opts := register(t, "get")
		got, err := cli.GetDevice(testCtx, id)
		require.NoError(t, err, "platformctl pxe get")
		assert.Equal(t, id, got.ID)
		assert.Equal(t, opts.MACAddress, got.MACAddress)
		assert.Equal(t, opts.PortID, got.PortID)
		assert.Equal(t, StateDiscovered, got.State)
	})

	t.Run("GetNonexistentFails", func(t *testing.T) {
		_, err := cli.GetDevice(testCtx, "nonexistent-device-id")
		var failed ErrCLICommandFailed
		require.ErrorAs(t, err, &failed, "platformctl pxe get of an unknown device must exit non-zero")
	})

	t.Run("List", func(t *testing.T) {
		id, opts := register(t, "list", StateBooting)
		byMAC, err := cli.ListDevices(testCtx, ListDevicesOptions{MACAddress: opts.MACAddress})
		require.NoError(t, err, "platformctl pxe list --mac")
		require.Len(t, byMAC.Devices, 1, "--mac selects the one device")
		assert.Equal(t, id, byMAC.Devices[0].ID)
		assert.Equal(t, StateBooting, byMAC.Devices[0].State)

		byState, err := cli.ListDevices(testCtx, ListDevicesOptions{State: StateBooting, Limit: 1000})
		require.NoError(t, err, "platformctl pxe list --state")
		var ids []string
		for _, d := range byState.Devices {
			assert.Equal(t, StateBooting, d.State, "--state returns only booting devices")
			ids = append(ids, d.ID)
		}
		assert.Contains(t, ids, id)
	})

	t.Run("ListRejectsOutOfRangeVLAN", func(t *testing.T) {
		_, err := cli.ListDevices(testCtx, ListDevicesOptions{VLAN: 4095})
		var failed ErrCLICommandFailed
		require.ErrorAs(t, err, &failed, "--vlan 4095 must be refused")
		assert.Contains(t, failed.Output, "out of range")
	})

	t.Run("AuthorizeEnrolledDevice", func(t *testing.T) {
		id, _ := register(t, "authorize",
			StateBooting, StateInstalling, StateInstallComplete, StateEnrolling)
		_, err := seed.SetDeviceEnrolled(testCtx, id, GenerateTestCertSerial())
		require.NoError(t, err, "Setup: SetDeviceEnrolled")

		got, err := cli.AuthorizeDevice(testCtx, id, 100)
		require.NoError(t, err, "platformctl pxe authorize of an enrolled device")
		assert.Equal(t, StateAuthorized, got.State)
		assert.Equal(t, uint16(100), got.TargetVLAN)
		assert.Equal(t, StateAuthorized, seededState(t, id))
	})

	t.Run("AuthorizeRefusesUnenrolledDevice", func(t *testing.T) {
		id, _ := register(t, "authorize-early", StateBooting)
		_, err := cli.AuthorizeDevice(testCtx, id, 100)
		var failed ErrCLICommandFailed
		require.ErrorAs(t, err, &failed, "authorize of a booting device must be refused")
		assert.Equal(t, StateBooting, seededState(t, id), "a refused authorize leaves the state")
	})

	t.Run("Quarantine", func(t *testing.T) {
		id, _ := register(t, "quarantine", StateBooting)
		reason := "Security policy violation"
		got, err := cli.QuarantineDevice(testCtx, id, reason)
		require.NoError(t, err, "platformctl pxe quarantine")
		assert.Equal(t, StateQuarantined, got.State)
		assert.Equal(t, reason, got.Reason)
		assert.Equal(t, StateQuarantined, seededState(t, id))
	})

	t.Run("Retry", func(t *testing.T) {
		id, _ := register(t, "retry", StateBooting, StateFailed)
		got, err := cli.RetryDevice(testCtx, id)
		require.NoError(t, err, "platformctl pxe retry")
		assert.Equal(t, StateDiscovered, got.State)
		assert.Greater(t, got.RetryCount, 0)
	})

	t.Run("Events", func(t *testing.T) {
		id, _ := register(t, "events", StateBooting)
		got, err := cli.GetEvents(testCtx, id)
		require.NoError(t, err, "platformctl pxe events")
		assert.Equal(t, id, got.DeviceID)
		require.GreaterOrEqual(t, len(got.Events), 2, "register and the state change")
		var toBooting bool
		for _, e := range got.Events {
			assert.Equal(t, id, e.DeviceID)
			toBooting = toBooting || e.ToState == StateBooting
		}
		assert.True(t, toBooting, "an event records the move to booting")
	})

	t.Run("APIOnlyVerbsRefuse", func(t *testing.T) {
		calls := map[string]func() error{
			"RegisterDevice": func() error {
				_, err := cli.RegisterDevice(testCtx, DefaultRegisterOptions(prefix+"-refused"))
				return err
			},
			"GetDeviceByMAC": func() error { _, err := cli.GetDeviceByMAC(testCtx, "00:00:00:00:00:01"); return err },
			"RemoveDevice":   func() error { _, err := cli.RemoveDevice(testCtx, "any"); return err },
			"UpdateDeviceState": func() error {
				_, err := cli.UpdateDeviceState(testCtx, UpdateStateOptions{DeviceID: "any", State: StateBooting})
				return err
			},
			"SetDeviceEnrolled": func() error { _, err := cli.SetDeviceEnrolled(testCtx, "any", "serial"); return err },
			"GetStatus":         func() error { _, err := cli.GetStatus(testCtx); return err },
		}
		for method, call := range calls {
			var notImpl ErrCLIPXENotImplemented
			require.ErrorAs(t, call(), &notImpl, "%s: want the declared API-only refusal", method)
			assert.Equal(t, method, notImpl.Method)
		}
	})
}

// =============================================================================
// Device Management Tests
// =============================================================================

func testDeviceRegister(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("RegisterDeviceWithDefaults", func(t *testing.T) {
		opts := RegisterDeviceOptions{
			MACAddress: GenerateTestMAC(prefix),
			PortID:     GenerateTestPortID(prefix),
		}

		result, err := cmd.RegisterDevice(testCtx, opts)
		require.NoError(t, err, "RegisterDevice should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.ID, "Device ID should not be empty")
		assert.Equal(t, opts.MACAddress, result.MACAddress, "MAC address should match")
		assert.Equal(t, opts.PortID, result.PortID, "Port ID should match")
		assert.Equal(t, StateDiscovered, result.State, "Initial state should be discovered")
		assert.Greater(t, result.CurrentVLAN, uint16(0), "Device should be assigned to a VLAN")

		// Cleanup
		defer CleanupDevice(testCtx, cmd, result.ID)
	})

	t.Run("RegisterDeviceEmptyMACFails", func(t *testing.T) {
		opts := RegisterDeviceOptions{
			MACAddress: "",
			PortID:     GenerateTestPortID(prefix),
		}

		_, err := cmd.RegisterDevice(testCtx, opts)
		require.Error(t, err, "RegisterDevice should fail with empty MAC address")
	})
}

func testDeviceGet(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device first
	regOpts := DefaultRegisterOptions(prefix + "-get")
	registered, err := cmd.RegisterDevice(testCtx, regOpts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	defer CleanupDevice(testCtx, cmd, registered.ID)

	t.Run("GetExistingDevice", func(t *testing.T) {
		result, err := cmd.GetDevice(testCtx, registered.ID)
		require.NoError(t, err, "GetDevice should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, registered.ID, result.ID, "Device ID should match")
		assert.Equal(t, regOpts.MACAddress, result.MACAddress, "MAC address should match")
		assert.Equal(t, regOpts.PortID, result.PortID, "Port ID should match")
		assert.Equal(t, StateDiscovered, result.State, "State should be discovered")
	})

	t.Run("GetNonexistentDeviceFails", func(t *testing.T) {
		_, err := cmd.GetDevice(testCtx, "nonexistent-device-id")
		require.Error(t, err, "GetDevice should fail for nonexistent device")
	})
}

func testDeviceGetByMAC(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device first
	regOpts := DefaultRegisterOptions(prefix + "-getmac")
	registered, err := cmd.RegisterDevice(testCtx, regOpts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	defer CleanupDevice(testCtx, cmd, registered.ID)

	t.Run("GetDeviceByValidMAC", func(t *testing.T) {
		result, err := cmd.GetDeviceByMAC(testCtx, regOpts.MACAddress)
		require.NoError(t, err, "GetDeviceByMAC should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, registered.ID, result.ID, "Device ID should match")
		assert.Equal(t, regOpts.MACAddress, result.MACAddress, "MAC address should match")
	})

	t.Run("GetDeviceByNonexistentMACFails", func(t *testing.T) {
		_, err := cmd.GetDeviceByMAC(testCtx, "ff:ff:ff:ff:ff:ff")
		require.Error(t, err, "GetDeviceByMAC should fail for nonexistent MAC")
	})

	t.Run("GetDeviceByInvalidMACFails", func(t *testing.T) {
		_, err := cmd.GetDeviceByMAC(testCtx, "invalid-mac")
		require.Error(t, err, "GetDeviceByMAC should fail for invalid MAC format")
	})
}

func testDeviceList(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create multiple devices for listing
	var deviceIDs []string
	for i := 0; i < 3; i++ {
		opts := RegisterDeviceOptions{
			MACAddress: GenerateTestMAC(fmt.Sprintf("%s-list-%d", prefix, i)),
			PortID:     GenerateTestPortID(fmt.Sprintf("%s-list-%d", prefix, i)),
		}
		result, err := cmd.RegisterDevice(testCtx, opts)
		require.NoError(t, err, "Setup: RegisterDevice should succeed")
		deviceIDs = append(deviceIDs, result.ID)
	}
	defer CleanupDevices(testCtx, cmd, deviceIDs)

	t.Run("ListAllDevices", func(t *testing.T) {
		result, err := cmd.ListDevices(testCtx, ListDevicesOptions{Limit: 100})
		require.NoError(t, err, "ListDevices should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Devices), 3, "Should have at least 3 devices")
	})

	t.Run("ListDevicesWithPagination", func(t *testing.T) {
		result, err := cmd.ListDevices(testCtx, ListDevicesOptions{Limit: 2})
		require.NoError(t, err, "ListDevices should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, int32(len(result.Devices)), int32(2), "Should respect limit")
	})

	t.Run("ListDevicesByState", func(t *testing.T) {
		result, err := cmd.ListDevices(testCtx, ListDevicesOptions{
			State: StateDiscovered,
			Limit: 100,
		})
		require.NoError(t, err, "ListDevices should succeed for state filter")
		require.NotNil(t, result, "Result should not be nil")

		for _, device := range result.Devices {
			assert.Equal(t, StateDiscovered, device.State, "All devices should be in discovered state")
		}
	})
}

func testDeviceRemove(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device for removal
	regOpts := DefaultRegisterOptions(prefix + "-remove")
	registered, err := cmd.RegisterDevice(testCtx, regOpts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")

	t.Run("RemoveExistingDevice", func(t *testing.T) {
		result, err := cmd.RemoveDevice(testCtx, registered.ID)
		require.NoError(t, err, "RemoveDevice should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, registered.ID, result.ID, "Device ID should match")
		assert.True(t, result.Removed, "Device should be removed")
	})

	t.Run("VerifyDeviceIsRemoved", func(t *testing.T) {
		_, err := cmd.GetDevice(testCtx, registered.ID)
		require.Error(t, err, "GetDevice should fail for removed device")
	})

	t.Run("RemoveNonexistentDeviceFails", func(t *testing.T) {
		_, err := cmd.RemoveDevice(testCtx, "nonexistent-device-id")
		require.Error(t, err, "RemoveDevice should fail for nonexistent device")
	})
}

// =============================================================================
// State Transition Tests
// =============================================================================

func testStateUpdate(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device for state updates
	regOpts := DefaultRegisterOptions(prefix + "-state")
	registered, err := cmd.RegisterDevice(testCtx, regOpts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	defer CleanupDevice(testCtx, cmd, registered.ID)

	t.Run("UpdateStateToBooting", func(t *testing.T) {
		opts := UpdateStateOptions{
			DeviceID: registered.ID,
			State:    StateBooting,
			Reason:   "PXE boot initiated",
		}

		result, err := cmd.UpdateDeviceState(testCtx, opts)
		require.NoError(t, err, "UpdateDeviceState should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, StateDiscovered, result.FromState, "FromState should be discovered")
		assert.Equal(t, StateBooting, result.ToState, "ToState should be booting")
	})

	t.Run("UpdateStateThroughWorkflow", func(t *testing.T) {
		// Progress through the workflow: booting -> installing -> install_complete
		states := []string{StateInstalling, StateInstallComplete}
		for _, targetState := range states {
			opts := UpdateStateOptions{
				DeviceID: registered.ID,
				State:    targetState,
				Reason:   "Test workflow progression",
			}

			result, err := cmd.UpdateDeviceState(testCtx, opts)
			require.NoError(t, err, "UpdateDeviceState to %s should succeed", targetState)
			assert.Equal(t, targetState, result.ToState, "ToState should match")
		}
	})
}

func testSetEnrolled(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device and progress to enrolling state
	regOpts := DefaultRegisterOptions(prefix + "-enrolled")
	registered, err := cmd.RegisterDevice(testCtx, regOpts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	defer CleanupDevice(testCtx, cmd, registered.ID)

	// Progress to enrolling state
	for _, state := range []string{StateBooting, StateInstalling, StateInstallComplete, StateEnrolling} {
		_, err := cmd.UpdateDeviceState(testCtx, UpdateStateOptions{
			DeviceID: registered.ID,
			State:    state,
			Reason:   "Setup progression",
		})
		require.NoError(t, err, "Setup: UpdateDeviceState to %s should succeed", state)
	}

	t.Run("SetDeviceEnrolled", func(t *testing.T) {
		certSerial := GenerateTestCertSerial()
		result, err := cmd.SetDeviceEnrolled(testCtx, registered.ID, certSerial)
		require.NoError(t, err, "SetDeviceEnrolled should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, StateEnrolled, result.State, "State should be enrolled")
		assert.Equal(t, certSerial, result.CertificateSerial, "Certificate serial should match")
	})
}

func testAuthorize(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device and progress to authorizing state
	regOpts := DefaultRegisterOptions(prefix + "-authorize")
	registered, err := cmd.RegisterDevice(testCtx, regOpts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	defer CleanupDevice(testCtx, cmd, registered.ID)

	// Progress to authorizing state
	for _, state := range []string{StateBooting, StateInstalling, StateInstallComplete, StateEnrolling} {
		_, err := cmd.UpdateDeviceState(testCtx, UpdateStateOptions{
			DeviceID: registered.ID,
			State:    state,
			Reason:   "Setup progression",
		})
		require.NoError(t, err, "Setup: UpdateDeviceState to %s should succeed", state)
	}

	// Set enrolled with certificate
	_, err = cmd.SetDeviceEnrolled(testCtx, registered.ID, GenerateTestCertSerial())
	require.NoError(t, err, "Setup: SetDeviceEnrolled should succeed")

	// Move to authorizing
	_, err = cmd.UpdateDeviceState(testCtx, UpdateStateOptions{
		DeviceID: registered.ID,
		State:    StateAuthorizing,
		Reason:   "Setup progression",
	})
	require.NoError(t, err, "Setup: UpdateDeviceState to authorizing should succeed")

	t.Run("AuthorizeDevice", func(t *testing.T) {
		targetVLAN := uint16(100)
		result, err := cmd.AuthorizeDevice(testCtx, registered.ID, targetVLAN)
		require.NoError(t, err, "AuthorizeDevice should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, StateAuthorized, result.State, "State should be authorized")
		assert.Equal(t, targetVLAN, result.TargetVLAN, "Target VLAN should match")
	})
}

func testQuarantine(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device for quarantine testing
	regOpts := DefaultRegisterOptions(prefix + "-quarantine")
	registered, err := cmd.RegisterDevice(testCtx, regOpts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	defer CleanupDevice(testCtx, cmd, registered.ID)

	// Progress to booting state first
	_, err = cmd.UpdateDeviceState(testCtx, UpdateStateOptions{
		DeviceID: registered.ID,
		State:    StateBooting,
		Reason:   "Setup progression",
	})
	require.NoError(t, err, "Setup: UpdateDeviceState to booting should succeed")

	t.Run("QuarantineDevice", func(t *testing.T) {
		reason := "Security policy violation"
		result, err := cmd.QuarantineDevice(testCtx, registered.ID, reason)
		require.NoError(t, err, "QuarantineDevice should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, StateQuarantined, result.State, "State should be quarantined")
		assert.Equal(t, reason, result.Reason, "Reason should match")
	})
}

func testRetry(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device and move to failed state
	regOpts := DefaultRegisterOptions(prefix + "-retry")
	registered, err := cmd.RegisterDevice(testCtx, regOpts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	defer CleanupDevice(testCtx, cmd, registered.ID)

	// Progress to booting and then fail
	_, err = cmd.UpdateDeviceState(testCtx, UpdateStateOptions{
		DeviceID: registered.ID,
		State:    StateBooting,
		Reason:   "Setup progression",
	})
	require.NoError(t, err, "Setup: UpdateDeviceState to booting should succeed")

	_, err = cmd.UpdateDeviceState(testCtx, UpdateStateOptions{
		DeviceID: registered.ID,
		State:    StateFailed,
		Reason:   "Simulated failure",
	})
	require.NoError(t, err, "Setup: UpdateDeviceState to failed should succeed")

	t.Run("RetryDevice", func(t *testing.T) {
		result, err := cmd.RetryDevice(testCtx, registered.ID)
		require.NoError(t, err, "RetryDevice should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, StateDiscovered, result.State, "State should be reset to discovered")
		assert.Greater(t, result.RetryCount, 0, "Retry count should be incremented")
	})
}

// =============================================================================
// Event Tests
// =============================================================================

func testGetEvents(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device and perform some state transitions to generate events
	regOpts := DefaultRegisterOptions(prefix + "-events")
	registered, err := cmd.RegisterDevice(testCtx, regOpts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	defer CleanupDevice(testCtx, cmd, registered.ID)

	// Generate events via state transitions
	_, err = cmd.UpdateDeviceState(testCtx, UpdateStateOptions{
		DeviceID: registered.ID,
		State:    StateBooting,
		Reason:   "Event test",
	})
	require.NoError(t, err, "Setup: UpdateDeviceState should succeed")

	t.Run("GetEventsForDevice", func(t *testing.T) {
		result, err := cmd.GetEvents(testCtx, registered.ID)
		require.NoError(t, err, "GetEvents should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, registered.ID, result.DeviceID, "Device ID should match")
		assert.GreaterOrEqual(t, len(result.Events), 2, "Should have at least 2 events (register + state change)")
	})

	t.Run("GetEventsForNonexistentDeviceFails", func(t *testing.T) {
		_, err := cmd.GetEvents(testCtx, "nonexistent-device-id")
		require.Error(t, err, "GetEvents should fail for nonexistent device")
	})
}

// =============================================================================
// Service Status Tests
// =============================================================================

func testGetStatus(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("GetServiceStatus", func(t *testing.T) {
		result, err := cmd.GetStatus(testCtx)
		require.NoError(t, err, "GetStatus should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Running, "Service should be running")
		assert.Greater(t, result.QuarantineVLAN, uint16(0), "Quarantine VLAN should be configured")
		assert.Greater(t, result.ProvisioningVLAN, uint16(0), "Provisioning VLAN should be configured")
	})
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func testInvalidMACAddress(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("RegisterWithInvalidMAC", func(t *testing.T) {
		opts := RegisterDeviceOptions{
			MACAddress: "invalid-mac-address",
			PortID:     GenerateTestPortID(prefix),
		}

		_, err := cmd.RegisterDevice(testCtx, opts)
		require.Error(t, err, "RegisterDevice should fail with invalid MAC address")
	})

	t.Run("RegisterWithMalformedMAC", func(t *testing.T) {
		opts := RegisterDeviceOptions{
			MACAddress: "12:34:56:78:90", // Missing octet
			PortID:     GenerateTestPortID(prefix),
		}

		_, err := cmd.RegisterDevice(testCtx, opts)
		require.Error(t, err, "RegisterDevice should fail with malformed MAC address")
	})
}

func testNonexistentDevice(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	nonexistentID := "device-that-does-not-exist"

	t.Run("GetNonexistentDevice", func(t *testing.T) {
		_, err := cmd.GetDevice(testCtx, nonexistentID)
		require.Error(t, err, "GetDevice should fail for nonexistent device")
	})

	t.Run("UpdateStateNonexistentDevice", func(t *testing.T) {
		opts := UpdateStateOptions{
			DeviceID: nonexistentID,
			State:    StateBooting,
			Reason:   "Test",
		}

		_, err := cmd.UpdateDeviceState(testCtx, opts)
		require.Error(t, err, "UpdateDeviceState should fail for nonexistent device")
	})

	t.Run("AuthorizeNonexistentDevice", func(t *testing.T) {
		_, err := cmd.AuthorizeDevice(testCtx, nonexistentID, 100)
		require.Error(t, err, "AuthorizeDevice should fail for nonexistent device")
	})

	t.Run("QuarantineNonexistentDevice", func(t *testing.T) {
		_, err := cmd.QuarantineDevice(testCtx, nonexistentID, "test")
		require.Error(t, err, "QuarantineDevice should fail for nonexistent device")
	})

	t.Run("RetryNonexistentDevice", func(t *testing.T) {
		_, err := cmd.RetryDevice(testCtx, nonexistentID)
		require.Error(t, err, "RetryDevice should fail for nonexistent device")
	})
}

func testInvalidStateTransition(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device
	regOpts := DefaultRegisterOptions(prefix + "-invalid-state")
	registered, err := cmd.RegisterDevice(testCtx, regOpts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	defer CleanupDevice(testCtx, cmd, registered.ID)

	t.Run("InvalidStateTransitionDiscoveredToEnrolled", func(t *testing.T) {
		// Try to skip directly to enrolled state (should fail)
		opts := UpdateStateOptions{
			DeviceID: registered.ID,
			State:    StateEnrolled,
			Reason:   "Attempting invalid transition",
		}

		_, err := cmd.UpdateDeviceState(testCtx, opts)
		require.Error(t, err, "UpdateDeviceState should fail for invalid transition")
	})

	t.Run("InvalidStateTransitionDiscoveredToAuthorized", func(t *testing.T) {
		// Try to skip directly to authorized state (should fail)
		opts := UpdateStateOptions{
			DeviceID: registered.ID,
			State:    StateAuthorized,
			Reason:   "Attempting invalid transition",
		}

		_, err := cmd.UpdateDeviceState(testCtx, opts)
		require.Error(t, err, "UpdateDeviceState should fail for invalid transition")
	})
}

func testDuplicateRegistration(t *testing.T, ctx context.Context, cmd PXECommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a device
	opts := DefaultRegisterOptions(prefix + "-duplicate")
	registered, err := cmd.RegisterDevice(testCtx, opts)
	require.NoError(t, err, "Setup: RegisterDevice should succeed")
	defer CleanupDevice(testCtx, cmd, registered.ID)

	t.Run("DuplicateMACRegistrationFails", func(t *testing.T) {
		// Try to register the same MAC address again
		duplicateOpts := RegisterDeviceOptions{
			MACAddress: opts.MACAddress,
			PortID:     GenerateTestPortID(prefix + "-duplicate2"),
		}

		_, err := cmd.RegisterDevice(testCtx, duplicateOpts)
		require.Error(t, err, "RegisterDevice should fail for duplicate MAC address")
	})
}
