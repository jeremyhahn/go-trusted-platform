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

// Package fido2 provides multi-protocol integration tests for FIDO2 services.
// These tests verify that FIDO2 operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified FIDO2Commands interface.
//
// Run tests via:
//
//	make integration-test-fido2
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
//
// IMPORTANT: FIDO2 tests require:
//   - Root privileges (for LUKS operations)
//   - A LUKS-encrypted device
//   - Optionally, a physical FIDO2 device for enrollment/test operations
package fido2

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestFIDO2MultiProtocol runs the complete FIDO2 test suite against all protocol adapters.
// Each adapter implements the FIDO2Commands interface, enabling unified testing across
// CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestFIDO2MultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement FIDO2Commands
	adapters := []FIDO2Commands{
		NewCLIAdapter(),
		// NewRESTAdapter(),  // TODO: Implement
		// NewGRPCAdapter(),  // TODO: Implement
		// NewQUICAdapter(),  // TODO: Implement
		// NewMCPAdapter(),   // TODO: Implement
		// NewUnixAdapter(),  // TODO: Implement
	}

	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Skipf("Skipping %s: setup failed: %v", adapter.Name(), err)
			}
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testFIDO2Protocol(t, ctx, adapter)
		})
	}
}

// testFIDO2Protocol runs the complete FIDO2 test suite against a single protocol adapter.
func testFIDO2Protocol(t *testing.T, ctx context.Context, cmd FIDO2Commands) {
	config := GetTestConfig()

	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	// Read-only tests (don't require FIDO2 device or modify state)
	t.Run("List", func(t *testing.T) {
		testFIDO2List(t, ctx, cmd, config)
	})

	t.Run("Info", func(t *testing.T) {
		testFIDO2Info(t, ctx, cmd, config)
	})

	// Tests requiring LUKS device availability
	t.Run("ListWithDevice", func(t *testing.T) {
		testFIDO2ListWithDevice(t, ctx, cmd, config)
	})

	t.Run("InfoWithDevice", func(t *testing.T) {
		testFIDO2InfoWithDevice(t, ctx, cmd, config)
	})

	// Tests requiring FIDO2 device (may be skipped)
	t.Run("Test", func(t *testing.T) {
		testFIDO2Test(t, ctx, cmd, config)
	})

	// Destructive tests (enroll/remove) - run last
	t.Run("EnrollRemove", func(t *testing.T) {
		testFIDO2EnrollRemove(t, ctx, cmd, config, prefix)
	})
}

// =============================================================================
// FIDO2 List Tests
// =============================================================================

func testFIDO2List(t *testing.T, ctx context.Context, cmd FIDO2Commands, config *TestConfig) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("ListWithoutDevice", func(t *testing.T) {
		// Test with auto-detection (may fail if no LUKS device)
		opts := ListOptions{
			Debug: false,
		}

		_, err := cmd.List(testCtx, opts)
		// This may fail on systems without LUKS devices - that's expected
		if err != nil {
			t.Logf("List without device failed (expected on systems without LUKS): %v", err)
		}
	})

	t.Run("ListWithInvalidDevice", func(t *testing.T) {
		opts := ListOptions{
			Device: "/dev/nonexistent-device",
			Debug:  false,
		}

		_, err := cmd.List(testCtx, opts)
		require.Error(t, err, "List with invalid device should fail")
	})
}

func testFIDO2ListWithDevice(t *testing.T, ctx context.Context, cmd FIDO2Commands, config *TestConfig) {
	SkipIfNoLUKSDevice(t)
	SkipIfNotRoot(t)

	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("ListTokensOnDevice", func(t *testing.T) {
		opts := ListOptions{
			Device: config.Device,
			Debug:  false,
		}

		result, err := cmd.List(testCtx, opts)
		require.NoError(t, err, "List should succeed on valid LUKS device")
		require.NotNil(t, result, "Result should not be nil")

		// Device should be set in result
		assert.NotEmpty(t, result.Device, "Device should be returned")

		// Log token count for debugging
		t.Logf("Found %d FIDO2 tokens on %s", len(result.Tokens), result.Device)

		// Validate token structure if any exist
		for _, token := range result.Tokens {
			assert.NotEmpty(t, token.TokenID, "Token ID should not be empty")
			assert.NotEmpty(t, token.Type, "Token type should not be empty")
		}
	})

	t.Run("ListWithDebug", func(t *testing.T) {
		opts := ListOptions{
			Device: config.Device,
			Debug:  true,
		}

		result, err := cmd.List(testCtx, opts)
		require.NoError(t, err, "List with debug should succeed")
		require.NotNil(t, result, "Result should not be nil")
	})
}

// =============================================================================
// FIDO2 Info Tests
// =============================================================================

func testFIDO2Info(t *testing.T, ctx context.Context, cmd FIDO2Commands, config *TestConfig) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("InfoWithoutDevice", func(t *testing.T) {
		// Test with auto-detection (may fail if no LUKS device)
		opts := InfoOptions{
			Debug: false,
		}

		_, err := cmd.Info(testCtx, opts)
		// This may fail on systems without LUKS devices - that's expected
		if err != nil {
			t.Logf("Info without device failed (expected on systems without LUKS): %v", err)
		}
	})

	t.Run("InfoWithInvalidDevice", func(t *testing.T) {
		opts := InfoOptions{
			Device: "/dev/nonexistent-device",
			Debug:  false,
		}

		_, err := cmd.Info(testCtx, opts)
		require.Error(t, err, "Info with invalid device should fail")
	})
}

func testFIDO2InfoWithDevice(t *testing.T, ctx context.Context, cmd FIDO2Commands, config *TestConfig) {
	SkipIfNoLUKSDevice(t)
	SkipIfNotRoot(t)

	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("InfoOnValidDevice", func(t *testing.T) {
		opts := InfoOptions{
			Device: config.Device,
			Debug:  false,
		}

		result, err := cmd.Info(testCtx, opts)
		require.NoError(t, err, "Info should succeed on valid LUKS device")
		require.NotNil(t, result, "Result should not be nil")

		// LUKS2 devices should have these fields
		assert.NotEmpty(t, result.UUID, "UUID should not be empty")
		assert.True(t, result.Version >= 2, "Version should be LUKS2 or higher")
		assert.NotEmpty(t, result.Cipher, "Cipher should not be empty")
		assert.True(t, result.KeySize > 0, "KeySize should be positive")
		assert.True(t, result.SectorSize > 0, "SectorSize should be positive")

		t.Logf("Device info: UUID=%s, Version=LUKS%d, Cipher=%s",
			result.UUID, result.Version, result.Cipher)
	})

	t.Run("InfoShowsKeyslots", func(t *testing.T) {
		opts := InfoOptions{
			Device: config.Device,
			Debug:  false,
		}

		result, err := cmd.Info(testCtx, opts)
		require.NoError(t, err, "Info should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Should have at least one active keyslot
		t.Logf("Found %d active keyslots", len(result.ActiveKeyslots))

		for _, ks := range result.ActiveKeyslots {
			assert.NotEmpty(t, ks.Type, "Keyslot type should not be empty")
			assert.True(t, ks.KeySize > 0, "Keyslot key size should be positive")
			t.Logf("  Keyslot %d: type=%s, keysize=%d", ks.SlotNumber, ks.Type, ks.KeySize)
		}
	})

	t.Run("InfoShowsSegments", func(t *testing.T) {
		opts := InfoOptions{
			Device: config.Device,
			Debug:  true,
		}

		result, err := cmd.Info(testCtx, opts)
		require.NoError(t, err, "Info should succeed")
		require.NotNil(t, result, "Result should not be nil")

		t.Logf("Found %d segments", len(result.Segments))

		for _, seg := range result.Segments {
			assert.NotEmpty(t, seg.Type, "Segment type should not be empty")
			t.Logf("  Segment %s: type=%s", seg.SegmentID, seg.Type)
		}
	})
}

// =============================================================================
// FIDO2 Test (Unlock) Tests
// =============================================================================

func testFIDO2Test(t *testing.T, ctx context.Context, cmd FIDO2Commands, config *TestConfig) {
	SkipIfNoFIDO2Device(t)
	SkipIfNoLUKSDevice(t)
	SkipIfNotRoot(t)

	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("TestUnlockWithFIDO2", func(t *testing.T) {
		opts := TestOptions{
			Device: config.Device,
			Debug:  false,
		}

		result, err := cmd.Test(testCtx, opts)
		if err != nil {
			// May fail if no FIDO2 token enrolled
			t.Logf("FIDO2 test failed (may be expected if no token enrolled): %v", err)
			return
		}

		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "FIDO2 test should succeed")

		if result.TokenInfo != nil {
			assert.NotEmpty(t, result.TokenInfo.FIDO2RP, "Relying party should not be empty")
			t.Logf("Token info: RP=%s, Keyslots=%v",
				result.TokenInfo.FIDO2RP, result.TokenInfo.Keyslots)
		}
	})

	t.Run("TestUnlockWithDebug", func(t *testing.T) {
		opts := TestOptions{
			Device: config.Device,
			Debug:  true,
		}

		result, err := cmd.Test(testCtx, opts)
		if err != nil {
			t.Logf("FIDO2 test with debug failed: %v", err)
			return
		}

		require.NotNil(t, result, "Result should not be nil")
	})
}

// =============================================================================
// FIDO2 Enroll/Remove Tests (Destructive)
// =============================================================================

func testFIDO2EnrollRemove(t *testing.T, ctx context.Context, cmd FIDO2Commands, config *TestConfig, prefix string) {
	SkipIfNoFIDO2Device(t)
	SkipIfNoLUKSDevice(t)
	SkipIfNotRoot(t)
	SkipDestructiveTest(t)

	if config.Passphrase == "" {
		t.Skip("Skipping enrollment test: FIDO2_TEST_PASSPHRASE not set")
	}

	testCtx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()

	// Use a test-specific slot to avoid conflicts
	testSlot := 7

	t.Run("EnrollCredential", func(t *testing.T) {
		opts := EnrollOptions{
			Device:     config.Device,
			Passphrase: config.Passphrase,
			Slot:       testSlot,
			RP:         fmt.Sprintf("test-%s", prefix),
			User:       "integration-test",
			FIPS:       false,
			Debug:      true,
		}

		result, err := cmd.Enroll(testCtx, opts)
		if err != nil {
			t.Logf("Enrollment failed: %v", err)
			t.Skip("FIDO2 enrollment requires physical device interaction")
		}

		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Enrollment should succeed")
		assert.Equal(t, testSlot, result.Slot, "Slot should match requested")

		t.Logf("Enrolled credential: device=%s, slot=%d, rp=%s",
			result.Device, result.Slot, result.RelyingParty)
	})

	t.Run("EnrollWithMissingPassphrase", func(t *testing.T) {
		opts := EnrollOptions{
			Device: config.Device,
			Slot:   testSlot,
			RP:     "test-rp",
		}

		_, err := cmd.Enroll(testCtx, opts)
		require.Error(t, err, "Enroll without passphrase should fail")
	})

	t.Run("EnrollWithFIPS", func(t *testing.T) {
		opts := EnrollOptions{
			Device:     config.Device,
			Passphrase: config.Passphrase,
			Slot:       testSlot + 1,
			RP:         fmt.Sprintf("test-fips-%s", prefix),
			User:       "integration-test-fips",
			FIPS:       true,
			Debug:      true,
		}

		result, err := cmd.Enroll(testCtx, opts)
		if err != nil {
			t.Logf("FIPS enrollment failed: %v", err)
			t.Skip("FIDO2 FIPS enrollment requires physical device interaction")
		}

		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "FIPS enrollment should succeed")
	})

	t.Run("RemoveBySlot", func(t *testing.T) {
		opts := RemoveOptions{
			Device: config.Device,
			Slot:   testSlot,
			Force:  true, // Skip confirmation for automated tests
			Debug:  true,
		}

		result, err := cmd.Remove(testCtx, opts)
		if err != nil {
			t.Logf("Remove by slot failed: %v", err)
			// May fail if enrollment didn't complete
			return
		}

		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Removal should succeed")
		assert.Equal(t, testSlot, result.SlotRemoved, "Removed slot should match")

		t.Logf("Removed token: slot=%d", result.SlotRemoved)
	})

	t.Run("RemoveByToken", func(t *testing.T) {
		// First, list tokens to find one to remove
		listOpts := ListOptions{
			Device: config.Device,
		}

		listResult, err := cmd.List(testCtx, listOpts)
		if err != nil || len(listResult.Tokens) == 0 {
			t.Skip("No FIDO2 tokens to remove")
		}

		// Remove the first token found
		tokenID := listResult.Tokens[0].TokenID

		opts := RemoveOptions{
			Device:  config.Device,
			TokenID: tokenID,
			Slot:    -1, // Not using slot
			Force:   true,
			Debug:   true,
		}

		result, err := cmd.Remove(testCtx, opts)
		if err != nil {
			t.Logf("Remove by token failed: %v", err)
			return
		}

		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Removal should succeed")
		assert.Equal(t, tokenID, result.TokenIDRemoved, "Removed token ID should match")
	})

	t.Run("RemoveWithoutForce", func(t *testing.T) {
		// This test verifies the non-force path works (will be cancelled due to no stdin)
		opts := RemoveOptions{
			Device: config.Device,
			Slot:   99, // Unlikely to exist
			Force:  false,
			Debug:  true,
		}

		_, err := cmd.Remove(testCtx, opts)
		// Should fail because no confirmation can be provided in automated tests
		// or because slot doesn't exist
		require.Error(t, err, "Remove without force should fail in automated context")
	})

	t.Run("RemoveNonExistentSlot", func(t *testing.T) {
		opts := RemoveOptions{
			Device: config.Device,
			Slot:   99, // Unlikely to exist
			Force:  true,
			Debug:  true,
		}

		_, err := cmd.Remove(testCtx, opts)
		require.Error(t, err, "Remove non-existent slot should fail")
	})

	t.Run("RemoveNonExistentToken", func(t *testing.T) {
		opts := RemoveOptions{
			Device:  config.Device,
			TokenID: "999", // Unlikely to exist
			Slot:    -1,
			Force:   true,
			Debug:   true,
		}

		_, err := cmd.Remove(testCtx, opts)
		require.Error(t, err, "Remove non-existent token should fail")
	})

	t.Run("RemoveRequiresTokenOrSlot", func(t *testing.T) {
		opts := RemoveOptions{
			Device: config.Device,
			Slot:   -1, // Neither token nor slot specified
			Force:  true,
			Debug:  true,
		}

		_, err := cmd.Remove(testCtx, opts)
		require.Error(t, err, "Remove without token or slot should fail")
	})
}

// =============================================================================
// Edge Case and Error Handling Tests
// =============================================================================

func TestFIDO2ErrorHandling(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	if err := adapter.Setup(ctx); err != nil {
		t.Skipf("CLI adapter setup failed: %v", err)
	}
	defer adapter.Teardown()

	t.Run("ListInvalidDevice", func(t *testing.T) {
		opts := ListOptions{
			Device: "/dev/null",
		}

		_, err := adapter.List(ctx, opts)
		require.Error(t, err, "List on /dev/null should fail")
	})

	t.Run("InfoInvalidDevice", func(t *testing.T) {
		opts := InfoOptions{
			Device: "/dev/null",
		}

		_, err := adapter.Info(ctx, opts)
		require.Error(t, err, "Info on /dev/null should fail")
	})

	t.Run("EnrollInvalidDevice", func(t *testing.T) {
		opts := EnrollOptions{
			Device:     "/dev/null",
			Passphrase: "test",
		}

		_, err := adapter.Enroll(ctx, opts)
		require.Error(t, err, "Enroll on /dev/null should fail")
	})

	t.Run("TestInvalidDevice", func(t *testing.T) {
		opts := TestOptions{
			Device: "/dev/null",
		}

		_, err := adapter.Test(ctx, opts)
		require.Error(t, err, "Test on /dev/null should fail")
	})

	t.Run("RemoveInvalidDevice", func(t *testing.T) {
		opts := RemoveOptions{
			Device: "/dev/null",
			Slot:   0,
			Force:  true,
		}

		_, err := adapter.Remove(ctx, opts)
		require.Error(t, err, "Remove on /dev/null should fail")
	})
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkFIDO2List(b *testing.B) {
	ctx := context.Background()

	adapter := NewCLIAdapter()
	if err := adapter.Setup(ctx); err != nil {
		b.Skipf("CLI adapter setup failed: %v", err)
	}
	defer adapter.Teardown()

	config := GetTestConfig()
	if config.Device == "" {
		b.Skip("No LUKS device configured")
	}

	opts := ListOptions{
		Device: config.Device,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = adapter.List(ctx, opts)
	}
}

func BenchmarkFIDO2Info(b *testing.B) {
	ctx := context.Background()

	adapter := NewCLIAdapter()
	if err := adapter.Setup(ctx); err != nil {
		b.Skipf("CLI adapter setup failed: %v", err)
	}
	defer adapter.Teardown()

	config := GetTestConfig()
	if config.Device == "" {
		b.Skip("No LUKS device configured")
	}

	opts := InfoOptions{
		Device: config.Device,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = adapter.Info(ctx, opts)
	}
}
