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

package attestation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	attestsvc "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/service"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// TestAttestationMultiProtocol runs all attestation tests across multiple protocols
func TestAttestationMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	adapters := []AttestationCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "attestation", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown failed: %v", err)
				}
			}()

			// Run all test suites
			t.Run("VMAttestation", func(t *testing.T) {
				testVMAttestation(t, ctx, adapter)
			})
			t.Run("Manifest", func(t *testing.T) {
				testManifest(t, ctx, adapter)
			})
			t.Run("Reporting", func(t *testing.T) {
				testReporting(t, ctx, adapter)
			})
		})
	}
}

// =============================================================================
// VM Attestation Tests
// =============================================================================

func testVMAttestation(t *testing.T, ctx context.Context, adapter AttestationCommands) {
	testID := uuid.New().String()[:8]

	// VM attestation is a declared MISSING capability: the daemon holds no
	// TPM session for a guest's vTPM, so CollectVMAttestation produces no
	// evidence and every transport must say why instead of answering an
	// empty quote (docs/attestation/engineering.md, the TPM-session table).

	t.Run("GenerateVMQuote", func(t *testing.T) {
		vmID := GenerateTestVMID(testID)
		nonce := GenerateTestNonce()

		opts := GenerateVMQuoteOptions{
			VMID:          vmID,
			Nonce:         nonce,
			PCRIndices:    DefaultPCRIndices(),
			HashAlgorithm: DefaultHashAlgorithm(),
		}

		result, err := adapter.GenerateVMQuote(ctx, opts)
		if adapter.Name() == "QUIC" {
			var noSurface surface.ErrNoSurface
			if !errors.As(err, &noSurface) {
				t.Errorf("GenerateVMQuote over QUIC: got %v, want surface.ErrNoSurface", err)
			}
			return
		}
		expectVMAttestationRefused(t, adapter, "GenerateVMQuote", err)
		if result != nil {
			t.Errorf("GenerateVMQuote returned a result alongside its refusal: %+v", result)
		}
	})

	t.Run("GetVMAttestation", func(t *testing.T) {
		vmID := GenerateTestVMID(testID + "-attest")
		result, err := adapter.GetVMAttestation(ctx, vmAttestationOptions(vmID, GenerateTestNonce()))
		expectVMAttestationRefused(t, adapter, "GetVMAttestation", err)
		if result != nil {
			t.Errorf("GetVMAttestation returned a result alongside its refusal: %+v", result)
		}
	})

	t.Run("VerifyVMAttestation", func(t *testing.T) {
		testVMVerifyRefused(t, ctx, adapter, GenerateTestVMID(testID+"-verify"))
	})

	t.Run("VerifyVMAttestation_InvalidNonce", func(t *testing.T) {
		testVMVerifyRefused(t, ctx, adapter, GenerateTestVMID(testID+"-invalid"))
	})
}

// vmAttestationOptions is the GetVMAttestation request every VM subtest sends.
func vmAttestationOptions(vmID string, nonce []byte) GetVMAttestationOptions {
	return GetVMAttestationOptions{
		VMID:          vmID,
		Nonce:         nonce,
		PCRIndices:    DefaultPCRIndices(),
		HashAlgorithm: DefaultHashAlgorithm(),
	}
}

// testVMVerifyRefused covers the verify subtests while VM attestation is
// MISSING: the evidence a verify would judge cannot be collected, so the
// collect step must be refused with its reason. Over QUIC the verify call
// itself has no surface, which is checked on its own.
func testVMVerifyRefused(t *testing.T, ctx context.Context, adapter AttestationCommands, vmID string) {
	t.Helper()
	nonce := GenerateTestNonce()

	attestResult, err := adapter.GetVMAttestation(ctx, vmAttestationOptions(vmID, nonce))
	expectVMAttestationRefused(t, adapter, "GetVMAttestation", err)
	if attestResult != nil {
		t.Errorf("GetVMAttestation returned a result alongside its refusal: %+v", attestResult)
	}

	if adapter.Name() == "QUIC" {
		_, err := adapter.VerifyVMAttestation(ctx, VerifyVMAttestationOptions{ExpectedNonce: nonce})
		expectNoVerifySurface(t, adapter, err)
	}
}

// expectVMAttestationRefused asserts that a VM evidence call was refused with
// the reason the transport is documented to carry. Every transport that
// reaches the attestation service carries ErrTPMSessionNotConfigured for
// CollectVMAttestation, QUIC's OpAttestVMWorkload (0x7F) included: the daemon
// serves it from the same gRPC servicer (docs/attestation/api.md §2).
func expectVMAttestationRefused(t *testing.T, adapter AttestationCommands, op string, err error) {
	t.Helper()
	want := attestsvc.ErrTPMSessionNotConfigured{Op: "CollectVMAttestation"}.Error()
	if err == nil {
		t.Fatalf("%s over %s succeeded, want refusal %q", op, adapter.Name(), want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%s over %s: got %q, want it to carry %q", op, adapter.Name(), err.Error(), want)
	}
}

// expectNoVerifySurface reports whether adapter serves no quote verification
// (QUIC: no attestation opcode verifies VM evidence, docs/attestation/api.md §2).
// There it asserts the call answered surface.ErrNoSurface.
func expectNoVerifySurface(t *testing.T, adapter AttestationCommands, err error) bool {
	t.Helper()
	if adapter.Name() != "QUIC" {
		return false
	}
	var noSurface surface.ErrNoSurface
	if !errors.As(err, &noSurface) {
		t.Errorf("VerifyVMAttestation over QUIC: got %v, want surface.ErrNoSurface", err)
	}
	return true
}

// =============================================================================
// Manifest Tests
// =============================================================================

func testManifest(t *testing.T, ctx context.Context, adapter AttestationCommands) {
	testID := uuid.New().String()[:8]

	t.Run("BuildManifest", func(t *testing.T) {
		hostID := GenerateTestHostID(testID)
		hostAttest := CreateTestHostAttestation(hostID)
		vmAttest := CreateTestVMAttestation(GenerateTestVMID(testID+"-vm"), hostID)

		opts := BuildManifestOptions{
			HostID:          hostID,
			HostAttestation: hostAttest,
			VMAttestations:  []*VMAttestationInput{vmAttest},
			HashAlgorithm:   DefaultHashAlgorithm(),
			Version:         "1.0.0",
		}

		result, err := adapter.BuildManifest(ctx, opts)
		if err != nil {
			t.Fatalf("BuildManifest failed: %v", err)
		}

		if result == nil {
			t.Fatal("BuildManifest returned nil result")
		}

		if result.ManifestID == "" {
			t.Error("ManifestID is empty")
		}

		if result.HostID != hostID {
			t.Errorf("HostID mismatch: got %s, want %s", result.HostID, hostID)
		}

		if len(result.MerkleRoot) == 0 {
			t.Error("MerkleRoot is empty")
		}

		if result.VMCount != 1 {
			t.Errorf("VMCount mismatch: got %d, want 1", result.VMCount)
		}
	})

	t.Run("BuildManifest_WithContainers", func(t *testing.T) {
		hostID := GenerateTestHostID(testID + "-containers")
		hostAttest := CreateTestHostAttestation(hostID)
		containerAttest := CreateTestContainerAttestation(
			GenerateTestContainerID(testID),
			"nginx:latest",
		)

		opts := BuildManifestOptions{
			HostID:                hostID,
			HostAttestation:       hostAttest,
			ContainerAttestations: []*ContainerAttestationInput{containerAttest},
			HashAlgorithm:         DefaultHashAlgorithm(),
		}

		result, err := adapter.BuildManifest(ctx, opts)
		if err != nil {
			t.Fatalf("BuildManifest failed: %v", err)
		}

		if result.ContainerCount != 1 {
			t.Errorf("ContainerCount mismatch: got %d, want 1", result.ContainerCount)
		}
	})

	t.Run("VerifyManifest", func(t *testing.T) {
		// Build a manifest; every transport's build signs it.
		hostID := GenerateTestHostID(testID + "-verify")
		hostAttest := CreateTestHostAttestation(hostID)

		buildOpts := BuildManifestOptions{
			HostID:          hostID,
			HostAttestation: hostAttest,
			HashAlgorithm:   DefaultHashAlgorithm(),
		}

		buildResult, err := adapter.BuildManifest(ctx, buildOpts)
		if err != nil {
			t.Fatalf("BuildManifest failed: %v", err)
		}

		// Verify the manifest
		verifyOpts := VerifyManifestOptions{
			ManifestID:     buildResult.ManifestID,
			ExpectedHostID: hostID,
		}

		verifyResult, err := adapter.VerifyManifest(ctx, verifyOpts)
		if err != nil {
			t.Fatalf("VerifyManifest failed: %v", err)
		}

		if !verifyResult.Valid {
			t.Errorf("Manifest should be valid, errors: %v", verifyResult.Errors)
		}

		if !verifyResult.SignatureValid {
			t.Error("Signature should be valid")
		}

		if !verifyResult.MerkleRootValid {
			t.Error("MerkleRoot should be valid")
		}

		if !verifyResult.HostIDMatch {
			t.Error("HostID should match")
		}
	})

	t.Run("GetManifest", func(t *testing.T) {
		// Build a manifest
		hostID := GenerateTestHostID(testID + "-get")
		hostAttest := CreateTestHostAttestation(hostID)

		buildOpts := BuildManifestOptions{
			HostID:          hostID,
			HostAttestation: hostAttest,
			HashAlgorithm:   DefaultHashAlgorithm(),
			Version:         "1.0.0",
		}

		buildResult, err := adapter.BuildManifest(ctx, buildOpts)
		if err != nil {
			t.Fatalf("BuildManifest failed: %v", err)
		}

		// Get it back
		getOpts := GetManifestOptions{
			ManifestID: buildResult.ManifestID,
		}

		getResult, err := adapter.GetManifest(ctx, getOpts)
		if err != nil {
			t.Fatalf("GetManifest failed: %v", err)
		}

		if getResult.ManifestID != buildResult.ManifestID {
			t.Errorf("ManifestID mismatch: got %s, want %s", getResult.ManifestID, buildResult.ManifestID)
		}

		if getResult.HostID != hostID {
			t.Errorf("HostID mismatch: got %s, want %s", getResult.HostID, hostID)
		}
	})

	t.Run("GetManifest_NotFound", func(t *testing.T) {
		getOpts := GetManifestOptions{
			ManifestID: "non-existent-manifest-" + testID,
		}

		_, err := adapter.GetManifest(ctx, getOpts)
		if err == nil {
			t.Error("GetManifest should fail for non-existent manifest")
		}
	})
}

// =============================================================================
// Push Tests
// =============================================================================

// =============================================================================
// Workload Chain Tests
// =============================================================================

// =============================================================================
// Protocol-Specific Tests
// =============================================================================

func TestAttestationCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "attestation", "CLI", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testVMAttestation(t, ctx, adapter)
	testManifest(t, ctx, adapter)
}

func TestAttestationREST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewRESTAdapter()
	helpers.RequireAdapterSetup(t, "attestation", "REST", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testVMAttestation(t, ctx, adapter)
	testManifest(t, ctx, adapter)
}

func TestAttestationGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewGRPCAdapter()
	helpers.RequireAdapterSetup(t, "attestation", "gRPC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testVMAttestation(t, ctx, adapter)
	testManifest(t, ctx, adapter)
}

func TestAttestationQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewQUICAdapter()
	helpers.RequireAdapterSetup(t, "attestation", "QUIC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testVMAttestation(t, ctx, adapter)
	testManifest(t, ctx, adapter)
}

func TestAttestationMCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewMCPAdapter()
	helpers.RequireAdapterSetup(t, "attestation", "MCP", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testVMAttestation(t, ctx, adapter)
	testManifest(t, ctx, adapter)
}

func TestAttestationUnix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapter := NewUnixAdapter()
	helpers.RequireAdapterSetup(t, "attestation", "Unix", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testVMAttestation(t, ctx, adapter)
	testManifest(t, ctx, adapter)
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestAttestationMultiProtocol_ErrorHandling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapters := []AttestationCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewMCPAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "attestation", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				_ = adapter.Teardown(ctx)
			}()

			t.Run("GetManifest_NotFound", func(t *testing.T) {
				opts := GetManifestOptions{
					ManifestID: "non-existent-manifest-12345",
				}

				_, err := adapter.GetManifest(ctx, opts)
				if err == nil {
					t.Error("GetManifest should return error for non-existent manifest")
				}
			})

			t.Run("VerifyVMAttestation_InvalidID", func(t *testing.T) {
				opts := VerifyVMAttestationOptions{
					AttestationID: "invalid-attestation-12345",
					ExpectedNonce: GenerateTestNonce(),
				}

				_, err := adapter.VerifyVMAttestation(ctx, opts)
				if err == nil {
					t.Error("VerifyVMAttestation should return error for invalid attestation ID")
				}
			})
		})
	}
}
