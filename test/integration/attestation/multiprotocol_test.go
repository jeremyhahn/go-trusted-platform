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
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// TestAttestationMultiProtocol runs all attestation tests across multiple protocols
func TestAttestationMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

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
			t.Run("Push", func(t *testing.T) {
				testPush(t, ctx, adapter)
			})
			t.Run("WorkloadChain", func(t *testing.T) {
				testWorkloadChain(t, ctx, adapter)
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
		if err != nil {
			t.Fatalf("GenerateVMQuote failed: %v", err)
		}

		if result == nil {
			t.Fatal("GenerateVMQuote returned nil result")
		}

		if len(result.QuoteData) == 0 {
			t.Error("QuoteData is empty")
		}

		if len(result.Signature) == 0 {
			t.Error("Signature is empty")
		}

		if len(result.PCRDigest) == 0 {
			t.Error("PCRDigest is empty")
		}

		if len(result.AIKPublicKey) == 0 {
			t.Error("AIKPublicKey is empty")
		}
	})

	t.Run("GetVMIdentity", func(t *testing.T) {
		vmID := GenerateTestVMID(testID + "-identity")

		opts := GetVMIdentityOptions{
			VMID: vmID,
		}

		result, err := adapter.GetVMIdentity(ctx, opts)
		if err != nil {
			t.Fatalf("GetVMIdentity failed: %v", err)
		}

		if result == nil {
			t.Fatal("GetVMIdentity returned nil result")
		}

		if result.VMID != vmID {
			t.Errorf("VMID mismatch: got %s, want %s", result.VMID, vmID)
		}

		if result.HostID == "" {
			t.Error("HostID is empty")
		}

		if result.EKCertPEM == "" {
			t.Error("EKCertPEM is empty")
		}
	})

	t.Run("GetVMAttestation", func(t *testing.T) {
		vmID := GenerateTestVMID(testID + "-attest")
		nonce := GenerateTestNonce()

		opts := GetVMAttestationOptions{
			VMID:          vmID,
			Nonce:         nonce,
			PCRIndices:    DefaultPCRIndices(),
			HashAlgorithm: DefaultHashAlgorithm(),
		}

		result, err := adapter.GetVMAttestation(ctx, opts)
		if err != nil {
			t.Fatalf("GetVMAttestation failed: %v", err)
		}

		if result == nil {
			t.Fatal("GetVMAttestation returned nil result")
		}

		if result.AttestationID == "" {
			t.Error("AttestationID is empty")
		}

		if result.VMID != vmID {
			t.Errorf("VMID mismatch: got %s, want %s", result.VMID, vmID)
		}

		if result.HostID == "" {
			t.Error("HostID is empty")
		}

		if len(result.QuoteData) == 0 {
			t.Error("QuoteData is empty")
		}

		if len(result.PCRs) == 0 {
			t.Error("PCRs list is empty")
		}
	})

	t.Run("VerifyVMAttestation", func(t *testing.T) {
		vmID := GenerateTestVMID(testID + "-verify")
		nonce := GenerateTestNonce()

		// First generate an attestation
		attestOpts := GetVMAttestationOptions{
			VMID:          vmID,
			Nonce:         nonce,
			PCRIndices:    DefaultPCRIndices(),
			HashAlgorithm: DefaultHashAlgorithm(),
		}

		attestResult, err := adapter.GetVMAttestation(ctx, attestOpts)
		if err != nil {
			t.Fatalf("GetVMAttestation failed: %v", err)
		}

		// Now verify it
		verifyOpts := VerifyVMAttestationOptions{
			AttestationID: attestResult.AttestationID,
			ExpectedNonce: nonce,
		}

		verifyResult, err := adapter.VerifyVMAttestation(ctx, verifyOpts)
		if err != nil {
			t.Fatalf("VerifyVMAttestation failed: %v", err)
		}

		if verifyResult == nil {
			t.Fatal("VerifyVMAttestation returned nil result")
		}

		if !verifyResult.Valid {
			t.Errorf("Attestation should be valid, errors: %v", verifyResult.Errors)
		}

		if !verifyResult.NonceMatch {
			t.Error("Nonce should match")
		}

		if !verifyResult.SignatureValid {
			t.Error("Signature should be valid")
		}
	})

	t.Run("VerifyVMAttestation_InvalidNonce", func(t *testing.T) {
		vmID := GenerateTestVMID(testID + "-invalid")
		nonce := GenerateTestNonce()

		attestOpts := GetVMAttestationOptions{
			VMID:          vmID,
			Nonce:         nonce,
			PCRIndices:    DefaultPCRIndices(),
			HashAlgorithm: DefaultHashAlgorithm(),
		}

		attestResult, err := adapter.GetVMAttestation(ctx, attestOpts)
		if err != nil {
			t.Fatalf("GetVMAttestation failed: %v", err)
		}

		// Verify with wrong nonce
		wrongNonce := GenerateTestNonce()
		verifyOpts := VerifyVMAttestationOptions{
			AttestationID: attestResult.AttestationID,
			ExpectedNonce: wrongNonce,
		}

		verifyResult, err := adapter.VerifyVMAttestation(ctx, verifyOpts)
		if err != nil {
			t.Fatalf("VerifyVMAttestation failed: %v", err)
		}

		if verifyResult.Valid {
			t.Error("Attestation should be invalid with wrong nonce")
		}

		if verifyResult.NonceMatch {
			t.Error("Nonce should not match")
		}
	})
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

	t.Run("SignManifest", func(t *testing.T) {
		// First build a manifest
		hostID := GenerateTestHostID(testID + "-sign")
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

		// Now sign it
		signOpts := SignManifestOptions{
			ManifestID:    buildResult.ManifestID,
			HashAlgorithm: DefaultHashAlgorithm(),
		}

		signResult, err := adapter.SignManifest(ctx, signOpts)
		if err != nil {
			t.Fatalf("SignManifest failed: %v", err)
		}

		if signResult == nil {
			t.Fatal("SignManifest returned nil result")
		}

		if signResult.ManifestID != buildResult.ManifestID {
			t.Errorf("ManifestID mismatch: got %s, want %s", signResult.ManifestID, buildResult.ManifestID)
		}

		if len(signResult.Signature) == 0 {
			t.Error("Signature is empty")
		}

		if signResult.SignatureAlgorithm == "" {
			t.Error("SignatureAlgorithm is empty")
		}

		if len(signResult.SignerPublicKey) == 0 {
			t.Error("SignerPublicKey is empty")
		}
	})

	t.Run("VerifyManifest", func(t *testing.T) {
		// Build and sign a manifest
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

		signOpts := SignManifestOptions{
			ManifestID:    buildResult.ManifestID,
			HashAlgorithm: DefaultHashAlgorithm(),
		}

		_, err = adapter.SignManifest(ctx, signOpts)
		if err != nil {
			t.Fatalf("SignManifest failed: %v", err)
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

func testPush(t *testing.T, ctx context.Context, adapter AttestationCommands) {
	testID := uuid.New().String()[:8]

	t.Run("PushAttestation", func(t *testing.T) {
		// First build a manifest
		hostID := GenerateTestHostID(testID + "-push")
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

		// Push to a test target
		pushOpts := PushAttestationOptions{
			ManifestID:  buildResult.ManifestID,
			TargetID:    "test-target-" + testID,
			Endpoint:    "https://localhost:8443/api/v1/attestation/receive",
			Transport:   "http",
			ContentType: "application/json",
			Timeout:     30 * time.Second,
		}

		pushResult, err := adapter.PushAttestation(ctx, pushOpts)
		if err != nil {
			t.Fatalf("PushAttestation failed: %v", err)
		}

		if pushResult == nil {
			t.Fatal("PushAttestation returned nil result")
		}

		if pushResult.TargetID != pushOpts.TargetID {
			t.Errorf("TargetID mismatch: got %s, want %s", pushResult.TargetID, pushOpts.TargetID)
		}

		if pushResult.Endpoint != pushOpts.Endpoint {
			t.Errorf("Endpoint mismatch: got %s, want %s", pushResult.Endpoint, pushOpts.Endpoint)
		}

		// Status could be success, failed, or pending depending on target availability
		validStatuses := map[string]bool{"success": true, "failed": true, "pending": true, "canceled": true}
		if !validStatuses[pushResult.Status] {
			t.Errorf("Unexpected status: %s", pushResult.Status)
		}
	})

	t.Run("PushAttestationBatch", func(t *testing.T) {
		// Build a manifest
		hostID := GenerateTestHostID(testID + "-batch")
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

		// Push to multiple targets
		batchOpts := PushAttestationBatchOptions{
			ManifestID: buildResult.ManifestID,
			Targets: []*PushAttestationOptions{
				{
					TargetID:  "target-1-" + testID,
					Endpoint:  "https://localhost:8443/api/v1/attestation/receive",
					Transport: "http",
					Timeout:   30 * time.Second,
				},
				{
					TargetID:  "target-2-" + testID,
					Endpoint:  "https://localhost:8444/api/v1/attestation/receive",
					Transport: "http",
					Timeout:   30 * time.Second,
				},
			},
		}

		batchResult, err := adapter.PushAttestationBatch(ctx, batchOpts)
		if err != nil {
			t.Fatalf("PushAttestationBatch failed: %v", err)
		}

		if batchResult == nil {
			t.Fatal("PushAttestationBatch returned nil result")
		}

		if batchResult.ManifestID != buildResult.ManifestID {
			t.Errorf("ManifestID mismatch: got %s, want %s", batchResult.ManifestID, buildResult.ManifestID)
		}

		if batchResult.TotalTargets != 2 {
			t.Errorf("TotalTargets mismatch: got %d, want 2", batchResult.TotalTargets)
		}

		if len(batchResult.Results) != 2 {
			t.Errorf("Results count mismatch: got %d, want 2", len(batchResult.Results))
		}
	})

	t.Run("GetPushStatus", func(t *testing.T) {
		// Build and push a manifest
		hostID := GenerateTestHostID(testID + "-status")
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

		pushOpts := PushAttestationOptions{
			ManifestID:  buildResult.ManifestID,
			TargetID:    "status-target-" + testID,
			Endpoint:    "https://localhost:8443/api/v1/attestation/receive",
			Transport:   "http",
			ContentType: "application/json",
		}

		pushResult, err := adapter.PushAttestation(ctx, pushOpts)
		if err != nil {
			t.Fatalf("PushAttestation failed: %v", err)
		}

		// Get push status
		statusOpts := GetPushStatusOptions{
			PushID: pushResult.PushID,
		}

		statusResult, err := adapter.GetPushStatus(ctx, statusOpts)
		if err != nil {
			t.Fatalf("GetPushStatus failed: %v", err)
		}

		if statusResult.PushID != pushResult.PushID {
			t.Errorf("PushID mismatch: got %s, want %s", statusResult.PushID, pushResult.PushID)
		}

		if statusResult.ManifestID != buildResult.ManifestID {
			t.Errorf("ManifestID mismatch: got %s, want %s", statusResult.ManifestID, buildResult.ManifestID)
		}
	})
}

// =============================================================================
// Workload Chain Tests
// =============================================================================

func testWorkloadChain(t *testing.T, ctx context.Context, adapter AttestationCommands) {
	testID := uuid.New().String()[:8]

	t.Run("ExtendWorkloadChain_VM", func(t *testing.T) {
		vmID := GenerateTestVMID(testID + "-chain")
		imageDigest := GenerateTestImageDigest("test-vm-image")

		opts := ExtendWorkloadChainOptions{
			WorkloadType: "vm",
			WorkloadID:   vmID,
			ImageDigest:  imageDigest,
			ConfigHash:   GenerateTestPCRValue(1),
			RuntimeHash:  GenerateTestPCRValue(2),
		}

		result, err := adapter.ExtendWorkloadChain(ctx, opts)
		if err != nil {
			t.Fatalf("ExtendWorkloadChain failed: %v", err)
		}

		if result == nil {
			t.Fatal("ExtendWorkloadChain returned nil result")
		}

		if result.WorkloadID != vmID {
			t.Errorf("WorkloadID mismatch: got %s, want %s", result.WorkloadID, vmID)
		}

		if len(result.Digest) == 0 {
			t.Error("Digest is empty")
		}

		if len(result.PCRValue) == 0 {
			t.Error("PCRValue is empty")
		}

		if result.ChainLength < 1 {
			t.Errorf("ChainLength should be >= 1, got %d", result.ChainLength)
		}
	})

	t.Run("ExtendWorkloadChain_Container", func(t *testing.T) {
		containerID := GenerateTestContainerID(testID + "-chain")
		imageDigest := GenerateTestImageDigest("nginx:latest")

		opts := ExtendWorkloadChainOptions{
			WorkloadType: "container",
			WorkloadID:   containerID,
			ImageDigest:  imageDigest,
		}

		result, err := adapter.ExtendWorkloadChain(ctx, opts)
		if err != nil {
			t.Fatalf("ExtendWorkloadChain failed: %v", err)
		}

		if result == nil {
			t.Fatal("ExtendWorkloadChain returned nil result")
		}

		if result.WorkloadID != containerID {
			t.Errorf("WorkloadID mismatch: got %s, want %s", result.WorkloadID, containerID)
		}
	})

	t.Run("GetWorkloadChainHistory", func(t *testing.T) {
		// Extend the chain a few times
		for i := 0; i < 3; i++ {
			opts := ExtendWorkloadChainOptions{
				WorkloadType: "container",
				WorkloadID:   GenerateTestContainerID(testID + "-hist-" + string(rune('a'+i))),
				ImageDigest:  GenerateTestImageDigest("test-image-" + string(rune('a'+i))),
			}
			_, err := adapter.ExtendWorkloadChain(ctx, opts)
			if err != nil {
				t.Fatalf("ExtendWorkloadChain failed: %v", err)
			}
		}

		// Get history
		histOpts := GetWorkloadChainHistoryOptions{
			Limit: 10,
		}

		histResult, err := adapter.GetWorkloadChainHistory(ctx, histOpts)
		if err != nil {
			t.Fatalf("GetWorkloadChainHistory failed: %v", err)
		}

		if histResult == nil {
			t.Fatal("GetWorkloadChainHistory returned nil result")
		}

		if len(histResult.Entries) == 0 {
			t.Error("Chain history is empty")
		}

		// Verify entries have required fields
		for i, entry := range histResult.Entries {
			if entry.WorkloadID == "" {
				t.Errorf("Entry %d: WorkloadID is empty", i)
			}
			if entry.WorkloadType == "" {
				t.Errorf("Entry %d: WorkloadType is empty", i)
			}
			if len(entry.Digest) == 0 {
				t.Errorf("Entry %d: Digest is empty", i)
			}
			if len(entry.PCRValue) == 0 {
				t.Errorf("Entry %d: PCRValue is empty", i)
			}
		}
	})

	t.Run("VerifyWorkloadChain", func(t *testing.T) {
		// Get current stats to know expected PCR
		statsOpts := GetWorkloadChainStatsOptions{}
		statsResult, err := adapter.GetWorkloadChainStats(ctx, statsOpts)
		if err != nil {
			t.Fatalf("GetWorkloadChainStats failed: %v", err)
		}

		// Verify chain
		verifyOpts := VerifyWorkloadChainOptions{
			ExpectedPCRValue: statsResult.CurrentPCRValue,
		}

		verifyResult, err := adapter.VerifyWorkloadChain(ctx, verifyOpts)
		if err != nil {
			t.Fatalf("VerifyWorkloadChain failed: %v", err)
		}

		if verifyResult == nil {
			t.Fatal("VerifyWorkloadChain returned nil result")
		}

		if !verifyResult.Valid {
			t.Errorf("Chain should be valid, errors: %v", verifyResult.Errors)
		}

		if len(verifyResult.ComputedPCR) == 0 {
			t.Error("ComputedPCR is empty")
		}
	})

	t.Run("VerifyWorkloadChain_InvalidPCR", func(t *testing.T) {
		// Verify with wrong PCR
		wrongPCR := GenerateTestPCRValue(99) // Some random value

		verifyOpts := VerifyWorkloadChainOptions{
			ExpectedPCRValue: wrongPCR,
		}

		verifyResult, err := adapter.VerifyWorkloadChain(ctx, verifyOpts)
		if err != nil {
			t.Fatalf("VerifyWorkloadChain failed: %v", err)
		}

		if verifyResult.Valid {
			t.Error("Chain should be invalid with wrong PCR")
		}
	})

	t.Run("GetWorkloadChainStats", func(t *testing.T) {
		opts := GetWorkloadChainStatsOptions{}

		result, err := adapter.GetWorkloadChainStats(ctx, opts)
		if err != nil {
			t.Fatalf("GetWorkloadChainStats failed: %v", err)
		}

		if result == nil {
			t.Fatal("GetWorkloadChainStats returned nil result")
		}

		// Stats should reflect what we've extended
		if result.TotalEntries < 1 {
			t.Error("TotalEntries should be >= 1")
		}

		if len(result.CurrentPCRValue) == 0 {
			t.Error("CurrentPCRValue is empty")
		}
	})
}

// =============================================================================
// Protocol-Specific Tests
// =============================================================================

func TestAttestationCLI(t *testing.T) {
	SkipIfNotIntegration(t)

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
	SkipIfNotIntegration(t)

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
	SkipIfNotIntegration(t)

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
	SkipIfNotIntegration(t)

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
	SkipIfNotIntegration(t)

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
	SkipIfNotIntegration(t)

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
	SkipIfNotIntegration(t)

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

			t.Run("GetVMIdentity_NotFound", func(t *testing.T) {
				opts := GetVMIdentityOptions{
					VMID: "non-existent-vm-12345",
				}

				_, err := adapter.GetVMIdentity(ctx, opts)
				if err == nil {
					t.Error("GetVMIdentity should return error for non-existent VM")
				}
			})

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
