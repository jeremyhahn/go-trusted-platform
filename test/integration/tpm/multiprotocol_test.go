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

// The persistent handles the daemon keeps its keys at: the TCG
// recommended EK handle, and the SSRK handle that CreateSRK always
// creates at, whatever algorithm the request names.
const (
	ekHandle   uint32 = 0x81010001
	ssrkHandle uint32 = 0x81000001
)

// TestTPMMultiProtocol runs the complete TPM test suite against all protocol adapters.
// Each adapter implements the TPMCommands interface, enabling unified testing across
// CLI, REST, gRPC, QUIC, MCP, and Unix protocols.
func TestTPMMultiProtocol(t *testing.T) {
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
	var ready []TPMCommands
	defer func() {
		for _, adapter := range ready {
			if err := adapter.Teardown(); err != nil {
				t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
			}
		}
	}()

	// Every adapter shares the daemon's one TPM. The read-only tests run
	// for every adapter first, against the TPM the daemon provisioned at
	// start; the lifecycle, which clears it, runs after. Interleaved, an
	// adapter's lifecycle would leave every later adapter's read-only
	// tests facing a cleared TPM.
	t.Run("ReadOnly", func(t *testing.T) {
		for _, adapter := range adapters {
			t.Run(adapter.Name(), func(t *testing.T) {
				gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
				ready = append(ready, adapter)
				testTPMReadOnly(t, ctx, adapter)
			})
		}
	})

	t.Run("Lifecycle", func(t *testing.T) {
		for _, adapter := range ready {
			t.Run(adapter.Name(), func(t *testing.T) {
				testTPMLifecycle(t, ctx, adapter)
			})
		}
	})
}

// testTPMReadOnly runs the tests that leave the TPM as they found it
// against a single protocol adapter.
func testTPMReadOnly(t *testing.T, ctx context.Context, cmd TPMCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("Info", func(t *testing.T) {
		testTPMInfo(t, ctx, cmd)
	})

	t.Run("EK", func(t *testing.T) {
		testEKReadOnly(t, ctx, cmd)
	})

	t.Run("SRK", func(t *testing.T) {
		testSRKInfo(t, ctx, cmd)
	})

	t.Run("SealUnseal", func(t *testing.T) {
		testSealUnseal(t, ctx, cmd, prefix)
	})

	t.Run("EventLog", func(t *testing.T) {
		testEventLog(t, ctx, cmd)
	})
}

// testTPMLifecycle clears the TPM, creates the EK and SRK on the cleared
// TPM, then clears it again and provisions it. A failed Clear ends the
// sequence: every step after it would fail against a TPM in an unknown
// state, and those failures would only hide the one that matters. The
// next adapter's lifecycle starts with its own Clear.
func testTPMLifecycle(t *testing.T, ctx context.Context, cmd TPMCommands) {
	testCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	if !t.Run("ClearWithEmptyLockoutAuth", func(t *testing.T) {
		testTPMClear(t, testCtx, cmd)
	}) {
		return
	}

	// A cleared TPM holds no EK and no SRK, and its endorsement and owner
	// auth are empty, so both create.
	t.Run("EK", func(t *testing.T) {
		testEKCreateDelete(t, testCtx, cmd)
	})

	t.Run("SRKCreateRSA", func(t *testing.T) {
		testSRKCreate(t, testCtx, cmd, "RSA-2048", true)
	})

	t.Run("SRKDelete", func(t *testing.T) {
		result, err := cmd.SRKDelete(testCtx, ssrkHandle, "")
		require.NoError(t, err, "SRK delete should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "SRK deletion should be successful")
	})

	// The daemon creates its configured SSRK at the one SSRK handle, so
	// the handle must be free again for a second create.
	if !t.Run("ClearBeforeSRKCreateECDSA", func(t *testing.T) {
		testTPMClear(t, testCtx, cmd)
	}) {
		return
	}

	t.Run("SRKCreateECDSA", func(t *testing.T) {
		testSRKCreate(t, testCtx, cmd, "ECDSA-P256", false)
	})

	if !t.Run("ClearBeforeProvision", func(t *testing.T) {
		testTPMClear(t, testCtx, cmd)
	}) {
		return
	}

	t.Run("Provision", func(t *testing.T) {
		testTPMProvision(t, testCtx, cmd)
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
	// TPM2_Clear (TPM 2.0 Part 3 §24.6) emptied the owner auth, so a
	// Provision presenting an owner password, the SO PIN included, is
	// refused by the TPM. The refusal is what keeps the empty auth
	// visible: a daemon that accepted it would be hiding which auth the
	// TPM actually holds.
	t.Run("ProvisionWithPasswordRefusedOnClearedTPM", func(t *testing.T) {
		opts := ProvisionOptions{
			CreateEK:      true,
			CreateSRK:     true,
			CreateAK:      true,
			OwnerPassword: "test-password",
		}

		_, err := cmd.Provision(ctx, opts)
		require.Error(t, err, "Provision with an owner password on a cleared TPM should be refused")
		assert.Contains(t, err.Error(), "TPM_RC_BAD_AUTH", "the TPM should refuse the owner password")
	})

	t.Run("ProvisionWithDefaults", func(t *testing.T) {
		opts := ProvisionOptions{
			CreateEK:  true,
			CreateSRK: true,
			CreateAK:  true,
		}

		result, err := cmd.Provision(ctx, opts)
		require.NoError(t, err, "Provision should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "Provision should be successful")
	})
}

// =============================================================================
// EK Tests
// =============================================================================

func testEKReadOnly(t *testing.T, ctx context.Context, cmd TPMCommands) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("EKInfo", func(t *testing.T) {
		result, err := cmd.EKInfo(testCtx, ekHandle)
		require.NoError(t, err, "EK info should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, ekHandle, result.Handle, "Handle should match")
		assert.NotEmpty(t, result.Algorithm, "Algorithm should be set")
	})

	t.Run("EKCertificate", func(t *testing.T) {
		result, err := cmd.EKCertificate(testCtx)
		require.NoError(t, err, "EK certificate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.Certificate, "Certificate should not be empty")
	})
}

func testEKCreateDelete(t *testing.T, ctx context.Context, cmd TPMCommands) {
	t.Run("EKCreateRSA", func(t *testing.T) {
		opts := EKCreateOptions{
			Algorithm:  "RSA-2048",
			Persistent: true,
		}

		result, err := cmd.EKCreate(ctx, opts)
		require.NoError(t, err, "EK create should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "EK creation should be successful")
		assert.NotZero(t, result.Handle, "Handle should be set")
	})

	t.Run("EKDelete", func(t *testing.T) {
		result, err := cmd.EKDelete(ctx, ekHandle, "")
		require.NoError(t, err, "EK delete should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Success, "EK deletion should be successful")
	})
}

// =============================================================================
// SRK Tests
// =============================================================================

func testSRKInfo(t *testing.T, ctx context.Context, cmd TPMCommands) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("SRKInfo", func(t *testing.T) {
		result, err := cmd.SRKInfo(testCtx, ssrkHandle)
		require.NoError(t, err, "SRK info should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, ssrkHandle, result.Handle, "Handle should match")
	})
}

// testSRKCreate creates the SRK on a TPM whose SSRK handle is free.
func testSRKCreate(t *testing.T, ctx context.Context, cmd TPMCommands, algorithm string, policy bool) {
	opts := SRKCreateOptions{
		Algorithm:  algorithm,
		Handle:     ssrkHandle,
		Persistent: true,
		Policy:     policy,
	}

	result, err := cmd.SRKCreate(ctx, opts)
	require.NoError(t, err, "SRK create %s should succeed", algorithm)
	require.NotNil(t, result, "Result should not be nil")
	assert.True(t, result.Success, "SRK creation should be successful")
	assert.NotZero(t, result.Handle, "Handle should be set")
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

// testTPMClear clears the TPM with the empty lockout auth, which is the
// lockout auth the daemon leaves in place. The suite never sends a wrong
// one: the lockout hierarchy is dictionary-attack protected, and a single
// refused lockoutAuth locks it until lockoutRecovery expires, so every
// later Clear, on every adapter, fails with TPM_RC_LOCKOUT.
func testTPMClear(t *testing.T, ctx context.Context, cmd TPMCommands) {
	result, err := cmd.Clear(ctx, ClearOptions{Confirm: true})
	require.NoError(t, err, "Clear should succeed")
	require.NotNil(t, result, "Result should not be nil")
	assert.True(t, result.Success, "Clear should be successful")
}
