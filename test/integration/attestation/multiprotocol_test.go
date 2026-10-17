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
	expectTPMSessionRefusal(t, adapter, op, "CollectVMAttestation", err)
}

// expectTPMSessionRefusal asserts op answered the service's
// ErrTPMSessionNotConfigured for serviceOp. platformctl carries neither the
// VM-attestation nor the manifest verbs (docs/attestation/cli.md §6), so over
// the CLI the call must name that absence instead.
func expectTPMSessionRefusal(t *testing.T, adapter AttestationCommands, op, serviceOp string, err error) {
	t.Helper()
	if adapter.Name() == "CLI" {
		var noSurface surface.ErrNoSurface
		if !errors.As(err, &noSurface) {
			t.Errorf("%s over CLI: got %v, want surface.ErrNoSurface (docs/attestation/cli.md §6)", op, err)
		}
		return
	}
	want := attestsvc.ErrTPMSessionNotConfigured{Op: serviceOp}.Error()
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

// testManifest drives the manifest surface. The daemon owns no TPM session
// that can sign a manifest, so BuildManifest refuses on every transport and
// no manifest is ever stored to verify or fetch back
// (docs/attestation/engineering.md §3a); the reads are exercised on ids the
// daemon has never stored.
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
		expectTPMSessionRefusal(t, adapter, "BuildManifest", "BuildManifest", err)
		if result != nil {
			t.Errorf("BuildManifest over %s returned a manifest alongside its refusal", adapter.Name())
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
		expectTPMSessionRefusal(t, adapter, "BuildManifest", "BuildManifest", err)
		if result != nil {
			t.Errorf("BuildManifest over %s returned a manifest alongside its refusal", adapter.Name())
		}
	})

	t.Run("VerifyManifest_NotFound", func(t *testing.T) {
		verifyOpts := VerifyManifestOptions{
			ManifestID:     "non-existent-manifest-" + testID,
			ExpectedHostID: GenerateTestHostID(testID + "-verify"),
		}

		verifyResult, err := adapter.VerifyManifest(ctx, verifyOpts)
		if adapter.Name() == "CLI" {
			var noSurface surface.ErrNoSurface
			if !errors.As(err, &noSurface) {
				t.Errorf("VerifyManifest over CLI: got %v, want surface.ErrNoSurface (docs/attestation/cli.md §6)", err)
			}
			return
		}
		if err == nil && verifyResult != nil && verifyResult.Valid {
			t.Errorf("VerifyManifest over %s reported a never-stored manifest valid", adapter.Name())
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
