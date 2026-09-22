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

// Package tpm provides multi-protocol integration tests for TPM services.
// These tests verify that TPM operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified TPMCommands interface.
//
// Run tests via:
//
//	make integration-test-tpm
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package tpm

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

// TestTPMMultiProtocol runs the complete TPM test suite against all protocol adapters.
// Each adapter implements the TPMCommands interface, enabling unified testing across
// CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestTPMMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement TPMCommands
	adapters := []TPMCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "tpm", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testTPMProtocol(t, ctx, adapter)
		})
	}
}

// testTPMProtocol runs the complete TPM test suite against a single protocol adapter.
func testTPMProtocol(t *testing.T, ctx context.Context, cmd TPMCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("Info", func(t *testing.T) {
		testTPMInfo(t, ctx, cmd)
	})

	t.Run("Provision", func(t *testing.T) {
		testTPMProvision(t, ctx, cmd)
	})

	t.Run("EK", func(t *testing.T) {
		testEKOperations(t, ctx, cmd)
	})

	t.Run("SRK", func(t *testing.T) {
		testSRKOperations(t, ctx, cmd)
	})

	t.Run("SealUnseal", func(t *testing.T) {
		testSealUnseal(t, ctx, cmd, prefix)
	})

	t.Run("EventLog", func(t *testing.T) {
		testEventLog(t, ctx, cmd)
	})

	t.Run("Clear", func(t *testing.T) {
		testTPMClear(t, ctx, cmd)
	})
}

// =============================================================================
// TPM Info Tests
// =============================================================================

func testTPMInfo(t *testing.T, ctx context.Context, cmd TPMCommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("GetTPMInfo", func(t *testing.T) {
		result, err := cmd.Info(testCtx)
		require.NoError(t, err, "Info should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// TPM 2.0 is expected
		assert.Contains(t, result.Version, "2.0", "TPM should be version 2.0")

		// Manufacturer info should be present
		if result.Manufacturer != nil {
			assert.NotEmpty(t, result.Manufacturer.Name, "Manufacturer name should not be empty")
		}

		// PCR banks should be present
		assert.NotEmpty(t, result.PCRBanks, "PCR banks should be present")
	})
}

// =============================================================================
// TPM Provision Tests
// =============================================================================

func testTPMProvision(t *testing.T, ctx context.Context, cmd TPMCommands) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("ProvisionWithDefaults", func(t *testing.T) {
		opts := ProvisionOptions{
			CreateEK:  true,
			CreateSRK: true,
			CreateAK:  true,
		}

		result, err := cmd.Provision(testCtx, opts)
		require.NoError(t, err, "Provision should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Provision should be successful")
	})

	t.Run("ProvisionWithPassword", func(t *testing.T) {
		opts := ProvisionOptions{
			CreateEK:      true,
			CreateSRK:     true,
			CreateAK:      true,
			OwnerPassword: "test-password",
		}

		result, err := cmd.Provision(testCtx, opts)
		require.NoError(t, err, "Provision with password should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Provision should be successful")
	})
}

// =============================================================================
// EK Tests
// =============================================================================

func testEKOperations(t *testing.T, ctx context.Context, cmd TPMCommands) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("EKCreateRSA", func(t *testing.T) {
		opts := EKCreateOptions{
			Algorithm:  "RSA-2048",
			Persistent: true,
		}

		result, err := cmd.EKCreate(testCtx, opts)
		require.NoError(t, err, "EK create should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "EK creation should be successful")
		assert.NotZero(t, result.Handle, "Handle should be set")
	})

	t.Run("EKInfo", func(t *testing.T) {
		// TCG recommended EK handle
		handle := uint32(0x81010001)

		result, err := cmd.EKInfo(testCtx, handle)
		require.NoError(t, err, "EK info should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, handle, result.Handle, "Handle should match")
		assert.NotEmpty(t, result.Algorithm, "Algorithm should be set")
	})

	t.Run("EKCertificate", func(t *testing.T) {
		result, err := cmd.EKCertificate(testCtx)
		require.NoError(t, err, "EK certificate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.Certificate, "Certificate should not be empty")
	})

	t.Run("EKDelete", func(t *testing.T) {
		handle := uint32(0x81010001)

		result, err := cmd.EKDelete(testCtx, handle, "")
		require.NoError(t, err, "EK delete should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "EK deletion should be successful")
	})
}

// =============================================================================
// SRK Tests
// =============================================================================

func testSRKOperations(t *testing.T, ctx context.Context, cmd TPMCommands) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("SRKCreateRSA", func(t *testing.T) {
		opts := SRKCreateOptions{
			Algorithm:  "RSA-2048",
			Handle:     0x81000005,
			Persistent: true,
			Policy:     true,
		}

		result, err := cmd.SRKCreate(testCtx, opts)
		require.NoError(t, err, "SRK create should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "SRK creation should be successful")
		assert.NotZero(t, result.Handle, "Handle should be set")
	})

	t.Run("SRKCreateECDSA", func(t *testing.T) {
		opts := SRKCreateOptions{
			Algorithm:  "ECDSA-P256",
			Handle:     0x81000006,
			Persistent: true,
			Policy:     false,
		}

		result, err := cmd.SRKCreate(testCtx, opts)
		require.NoError(t, err, "SRK create ECDSA should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "SRK creation should be successful")
	})

	t.Run("SRKInfo", func(t *testing.T) {
		handle := uint32(0x81000005)

		result, err := cmd.SRKInfo(testCtx, handle)
		require.NoError(t, err, "SRK info should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, handle, result.Handle, "Handle should match")
	})

	t.Run("SRKDelete", func(t *testing.T) {
		handle := uint32(0x81000005)

		result, err := cmd.SRKDelete(testCtx, handle, "")
		require.NoError(t, err, "SRK delete should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "SRK deletion should be successful")
	})
}

// =============================================================================
// Seal/Unseal Tests
// =============================================================================

func testSealUnseal(t *testing.T, ctx context.Context, cmd TPMCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("SealAndUnsealBasic", func(t *testing.T) {
		cn := fmt.Sprintf("%s-basic", prefix)
		secret := []byte("my-secret-data")

		// Seal the secret
		sealOpts := SealOptions{
			CN:   cn,
			Data: secret,
		}

		sealResult, err := cmd.Seal(testCtx, sealOpts)
		require.NoError(t, err, "Seal should succeed")
		require.NotNil(t, sealResult, "Result should not be nil")
		assert.True(t, sealResult.Success, "Seal should be successful")

		// Unseal the secret
		unsealOpts := UnsealOptions{
			CN: cn,
		}

		unsealResult, err := cmd.Unseal(testCtx, unsealOpts)
		require.NoError(t, err, "Unseal should succeed")
		require.NotNil(t, unsealResult, "Result should not be nil")
		assert.True(t, unsealResult.Success, "Unseal should be successful")
		assert.Equal(t, secret, unsealResult.Data, "Unsealed data should match")
	})

	t.Run("SealAndUnsealWithPassword", func(t *testing.T) {
		cn := fmt.Sprintf("%s-password", prefix)
		secret := []byte("password-protected-secret")
		password := "my-password"

		// Seal with password
		sealOpts := SealOptions{
			CN:       cn,
			Data:     secret,
			Password: password,
		}

		sealResult, err := cmd.Seal(testCtx, sealOpts)
		require.NoError(t, err, "Seal with password should succeed")
		require.NotNil(t, sealResult, "Result should not be nil")

		// Unseal with password
		unsealOpts := UnsealOptions{
			CN:       cn,
			Password: password,
		}

		unsealResult, err := cmd.Unseal(testCtx, unsealOpts)
		require.NoError(t, err, "Unseal with password should succeed")
		require.NotNil(t, unsealResult, "Result should not be nil")
		assert.Equal(t, secret, unsealResult.Data, "Unsealed data should match")
	})

	t.Run("UnsealNonExistent", func(t *testing.T) {
		unsealOpts := UnsealOptions{
			CN: fmt.Sprintf("%s-nonexistent", prefix),
		}

		_, err := cmd.Unseal(testCtx, unsealOpts)
		require.Error(t, err, "Unseal nonexistent should fail")
	})
}

// =============================================================================
// Event Log Tests
// =============================================================================

func testEventLog(t *testing.T, ctx context.Context, cmd TPMCommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("ReadEventLogNonExistent", func(t *testing.T) {
		_, err := cmd.EventLog(testCtx, "/tmp/nonexistent_event_log")
		// Should fail gracefully for non-existent path
		require.Error(t, err, "EventLog should fail for non-existent path")
	})

	t.Run("ReadEventLogDefaultPath", func(t *testing.T) {
		// This may fail on systems without TPM or in containers
		result, err := cmd.EventLog(testCtx, "/sys/kernel/security/tpm0/binary_bios_measurements")
		if err != nil {
			// Expected on systems without TPM access
			t.Logf("EventLog read failed (expected in containers): %v", err)
			return
		}

		// If successful, verify the result structure
		require.NotNil(t, result, "Result should not be nil")
	})
}

// =============================================================================
// TPM Clear Tests
// =============================================================================

func testTPMClear(t *testing.T, ctx context.Context, cmd TPMCommands) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("ClearWithConfirmation", func(t *testing.T) {
		opts := ClearOptions{
			Confirm: true,
		}

		result, err := cmd.Clear(testCtx, opts)
		require.NoError(t, err, "Clear should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Clear should be successful")
	})

	t.Run("ClearWithPassword", func(t *testing.T) {
		opts := ClearOptions{
			OwnerPassword: "test-password",
			Confirm:       true,
		}

		result, err := cmd.Clear(testCtx, opts)
		require.NoError(t, err, "Clear with password should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Clear should be successful")
	})
}
