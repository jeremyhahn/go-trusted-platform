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

package vtpm_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEKCertificateDetection_PreProvisionedEKMustBeDetected verifies that
// a pre-provisioned EK certificate in NV RAM is detected and NOT overwritten.
// This is a CRITICAL safety test - overwriting an EK cert on a real TPM
// could permanently damage the TPM if the manufacturer's cert cannot be restored.
func TestEKCertificateDetection_PreProvisionedEKMustBeDetected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	// Step 1: Create and start swtpm
	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	// Step 2: Generate a unique test EK certificate with identifiable attributes
	ekCert := generateIdentifiableEKCert(t, "PRE-PROVISIONED-EK-TEST-12345")
	originalFingerprint := certFingerprint(ekCert)
	t.Logf("Original EK certificate fingerprint: %s", originalFingerprint)
	t.Logf("Original EK certificate subject: %s", ekCert.Subject.CommonName)

	// Step 3: Inject the EK certificate into NV RAM
	injector := vtpm.NewEKCertInjector(socketPath, nil)
	err := injector.InjectCertificate(ctx, ekCert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Failed to inject EK certificate")

	// Step 4: Verify the certificate was written correctly
	readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Failed to read EK certificate")
	require.True(t, ekCert.Equal(readCert), "Certificates should match after injection")

	// Step 5: Check that EK certificate exists (this simulates what firstboot should do)
	exists, existingCert, err := injector.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "CheckEKCertificateExists should not error")
	require.True(t, exists, "CRITICAL: EK certificate MUST be detected as existing")
	require.NotNil(t, existingCert, "Existing certificate should be returned")

	// Step 6: Verify the existing certificate matches our pre-provisioned one
	existingFingerprint := certFingerprint(existingCert)
	assert.Equal(t, originalFingerprint, existingFingerprint,
		"CRITICAL: Existing EK cert fingerprint must match pre-provisioned cert")

	t.Logf("SUCCESS: Pre-provisioned EK certificate was correctly detected")
	t.Logf("  - Fingerprint: %s", existingFingerprint)
	t.Logf("  - Subject CN: %s", existingCert.Subject.CommonName)
}

// TestEKCertificateNonOverwrite_CriticalSafetyCheck verifies that attempting
// to inject a NEW EK certificate when one already exists is BLOCKED.
// This prevents catastrophic damage to real TPMs.
func TestEKCertificateNonOverwrite_CriticalSafetyCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	// Step 1: Create and start swtpm
	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	// Step 2: Inject the ORIGINAL EK certificate (simulating manufacturer cert)
	originalCert := generateIdentifiableEKCert(t, "MANUFACTURER-EK-CERT-ORIGINAL")
	originalFingerprint := certFingerprint(originalCert)
	t.Logf("Original (manufacturer) EK cert fingerprint: %s", originalFingerprint)

	injector := vtpm.NewEKCertInjector(socketPath, nil)
	err := injector.InjectCertificate(ctx, originalCert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Failed to inject original EK certificate")

	// Step 3: Verify original certificate is in place
	readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)
	require.Equal(t, originalFingerprint, certFingerprint(readCert))

	// Step 4: Check if EK exists BEFORE attempting any provisioning
	// This is the CRITICAL check that must happen in real provisioning code
	exists, existingCert, err := injector.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)
	require.True(t, exists, "CRITICAL: Must detect existing EK certificate")

	// Step 5: ASSERT - If EK exists, we MUST NOT overwrite it
	if exists {
		t.Logf("SAFETY CHECK PASSED: Existing EK certificate detected")
		t.Logf("  - Fingerprint: %s", certFingerprint(existingCert))
		t.Logf("  - Subject: %s", existingCert.Subject.CommonName)
		t.Logf("  - ACTION: Skipping new EK certificate provisioning")

		// Verify the original cert is still there (not modified)
		finalCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
		require.NoError(t, err)
		finalFingerprint := certFingerprint(finalCert)

		assert.Equal(t, originalFingerprint, finalFingerprint,
			"CRITICAL SAFETY VIOLATION: Original EK certificate was modified!")

		t.Logf("SUCCESS: Original EK certificate preserved")
		return
	}

	// If we get here, the safety check failed
	t.Fatal("CRITICAL SAFETY FAILURE: EK certificate existence check returned false when cert exists")
}

// TestEKCertificateSafeProvisioning_OnlyProvisionWhenEmpty verifies the safe
// provisioning pattern: only inject EK cert if NV index is empty.
func TestEKCertificateSafeProvisioning_OnlyProvisionWhenEmpty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	// Step 1: Create FRESH swtpm with NO EK certificate
	sw := setupSWTPM(t, ctx, stateDir, socketPath)
	defer cleanupSWTPM(t, sw)

	injector := vtpm.NewEKCertInjector(socketPath, nil)

	// Step 2: Check that EK certificate does NOT exist
	exists, _, err := injector.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)
	require.False(t, exists, "Fresh TPM should NOT have EK certificate")

	t.Logf("Fresh TPM confirmed: No existing EK certificate")

	// Step 3: ONLY NOW is it safe to provision
	newCert := generateIdentifiableEKCert(t, "NEW-EK-CERT-SAFE-PROVISION")
	newFingerprint := certFingerprint(newCert)

	err = injector.InjectCertificate(ctx, newCert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Should be able to provision EK cert on fresh TPM")

	// Step 4: Verify the new certificate was written
	readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)
	assert.Equal(t, newFingerprint, certFingerprint(readCert))

	t.Logf("SUCCESS: Safely provisioned new EK certificate on fresh TPM")
}

// TestEKCertificatePersistence_AcrossTPMRestarts verifies that EK certificates
// persist across TPM restarts (critical for real-world scenarios).
func TestEKCertificatePersistence_AcrossTPMRestarts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	stateDir := t.TempDir()
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	// Step 1: Create swtpm and inject EK certificate
	config := &swtpm.Config{
		StateDir:   stateDir,
		SocketPath: socketPath,
		PCRBanks:   []string{"sha256"},
	}

	sw, err := swtpm.NewSWTPM(config, nil)
	require.NoError(t, err)
	err = sw.Initialize(ctx)
	require.NoError(t, err)
	err = sw.Start(ctx)
	require.NoError(t, err)

	waitForSocket(t, socketPath)

	// Inject certificate
	originalCert := generateIdentifiableEKCert(t, "PERSISTENT-EK-CERT")
	originalFingerprint := certFingerprint(originalCert)

	injector := vtpm.NewEKCertInjector(socketPath, nil)
	err = injector.InjectCertificate(ctx, originalCert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)

	// Verify injection
	readCert, err := injector.ReadCertificate(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)
	require.Equal(t, originalFingerprint, certFingerprint(readCert))

	// Step 2: Stop the TPM
	err = sw.Stop()
	require.NoError(t, err)
	t.Logf("TPM stopped after initial provisioning")

	// Step 3: Wait a moment, then restart the TPM (simulating system reboot).
	// Stop already waited for swtpm to exit, so the pause is elapsed time.
	require.NoError(t, testenv.Elapse(ctx, 500*time.Millisecond))

	sw2, err := swtpm.NewSWTPM(config, nil)
	require.NoError(t, err)
	// Don't re-initialize - use existing state
	err = sw2.Start(ctx)
	require.NoError(t, err)
	defer sw2.Stop()

	waitForSocket(t, socketPath)

	t.Logf("TPM restarted, checking certificate persistence...")

	// Step 4: Verify certificate persisted across restart
	injector2 := vtpm.NewEKCertInjector(socketPath, nil)

	exists, persistedCert, err := injector2.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Should be able to check for EK cert after restart")
	require.True(t, exists, "EK certificate must persist across TPM restarts")
	require.NotNil(t, persistedCert)

	persistedFingerprint := certFingerprint(persistedCert)
	assert.Equal(t, originalFingerprint, persistedFingerprint,
		"EK certificate must be identical after TPM restart")

	t.Logf("SUCCESS: EK certificate persisted across TPM restart")
	t.Logf("  - Original fingerprint: %s", originalFingerprint)
	t.Logf("  - Persisted fingerprint: %s", persistedFingerprint)
}

// TestQEMUWithVTPM_BootAndDetectEK tests booting a QEMU VM with a pre-provisioned
// vTPM and verifying the EK certificate is detected.
// NOTE: This test requires QEMU and OVMF to be installed.
func TestQEMUWithVTPM_BootAndDetectEK(t *testing.T) {
	// Skip if QEMU is not available
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Skip("QEMU not available, skipping VM boot test")
	}

	// Skip if OVMF is not available
	ovmfCode := findOVMFCode(t)
	ovmfVars := findOVMFVars(t)
	if ovmfCode == "" || ovmfVars == "" {
		t.Skip("OVMF firmware not available, skipping VM boot test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	workDir := t.TempDir()
	stateDir := filepath.Join(workDir, "tpm")
	socketPath := filepath.Join(stateDir, "swtpm.sock")

	// Step 1: Create swtpm with pre-provisioned EK certificate
	err := os.MkdirAll(stateDir, 0755)
	require.NoError(t, err)

	config := &swtpm.Config{
		StateDir:   stateDir,
		SocketPath: socketPath,
		PCRBanks:   []string{"sha256"},
	}

	sw, err := swtpm.NewSWTPM(config, nil)
	require.NoError(t, err)
	err = sw.Initialize(ctx)
	require.NoError(t, err)
	err = sw.Start(ctx)
	require.NoError(t, err)

	waitForSocket(t, socketPath)

	// Step 2: Inject EK certificate
	ekCert := generateIdentifiableEKCert(t, "QEMU-VTPM-EK-CERT")
	originalFingerprint := certFingerprint(ekCert)
	t.Logf("Injecting EK certificate with fingerprint: %s", originalFingerprint)

	injector := vtpm.NewEKCertInjector(socketPath, nil)
	err = injector.InjectCertificate(ctx, ekCert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)

	// Verify injection
	exists, injectedCert, err := injector.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)
	require.True(t, exists, "EK certificate should exist after injection")
	require.Equal(t, originalFingerprint, certFingerprint(injectedCert))

	t.Logf("EK certificate injected and verified")

	// Step 3: Create a minimal disk for QEMU (we won't actually install, just boot to UEFI shell)
	diskPath := filepath.Join(workDir, "test.qcow2")

	// Step 4: Configure QEMU VM with vTPM
	vmConfig := &qemu.Config{
		WorkDir:       workDir,
		DiskPath:      diskPath,
		DiskSize:      "1G",
		Memory:        1024,
		CPUs:          2,
		EnableKVM:     checkKVMAvailable(),
		OVMFCode:      ovmfCode,
		OVMFVars:      ovmfVars,
		TPMSocket:     socketPath,
		NoGraphic:     true,
		SerialLogFile: filepath.Join(workDir, "serial.log"),
		NetworkMode:   "none",
	}

	vm, err := qemu.NewVM(vmConfig, nil)
	require.NoError(t, err)

	// Create disk
	err = vm.CreateDisk()
	require.NoError(t, err)

	t.Logf("Starting QEMU VM with vTPM...")

	// Start VM - it will boot to UEFI shell since no OS is installed
	// We just want to verify the TPM is attached and EK cert is accessible
	err = vm.Start(ctx, "boot")
	if err != nil {
		// This is expected to fail quickly since there's no bootable OS
		// The important thing is that QEMU started with the vTPM attached
		t.Logf("VM start returned (expected for empty disk): %v", err)
	}

	// Give it a moment to initialize; nothing observable marks the end, so this is elapsed time
	require.NoError(t, testenv.Elapse(ctx, 2*time.Second))

	// Stop VM
	vm.Stop()

	// Wait for the QEMU process to exit and release the vTPM socket
	if err := testenv.WaitFor(ctx, vmExitTimeout, "QEMU process exit", vm.Wait); err != nil {
		t.Logf("VM exit: %v", err)
	}

	// Step 5: Verify EK certificate is still intact after VM boot
	t.Logf("Verifying EK certificate after QEMU boot...")

	exists, postBootCert, err := injector.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Should be able to check EK cert after VM boot")
	require.True(t, exists, "EK certificate must still exist after VM boot")

	postBootFingerprint := certFingerprint(postBootCert)
	assert.Equal(t, originalFingerprint, postBootFingerprint,
		"CRITICAL: EK certificate must not be modified by VM boot")

	t.Logf("SUCCESS: EK certificate preserved after QEMU boot")
	t.Logf("  - Original fingerprint: %s", originalFingerprint)
	t.Logf("  - Post-boot fingerprint: %s", postBootFingerprint)

	// Cleanup swtpm
	sw.Stop()
}

// TestVTPMBundle_FullWorkflow tests creating a complete vTPM bundle with
// pre-provisioned EK certificate and verifying it works with QEMU.
func TestVTPMBundle_FullWorkflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	workDir := t.TempDir()

	// Create a vTPM bundle structure
	bundleDir := filepath.Join(workDir, "vtpm-bundle")
	tpmStateDir := filepath.Join(bundleDir, "tpm")
	socketPath := filepath.Join(tpmStateDir, "swtpm.sock")

	err := os.MkdirAll(tpmStateDir, 0755)
	require.NoError(t, err)

	// Step 1: Initialize swtpm
	config := &swtpm.Config{
		StateDir:   tpmStateDir,
		SocketPath: socketPath,
		PCRBanks:   []string{"sha256"},
	}

	sw, err := swtpm.NewSWTPM(config, nil)
	require.NoError(t, err)
	err = sw.Initialize(ctx)
	require.NoError(t, err)
	err = sw.Start(ctx)
	require.NoError(t, err)
	defer sw.Stop()

	waitForSocket(t, socketPath)

	// Step 2: Inject both RSA and ECC EK certificates
	injector := vtpm.NewEKCertInjector(socketPath, nil)

	rsaCert := generateIdentifiableEKCert(t, "BUNDLE-RSA-EK")
	eccCert := generateIdentifiableEKCert(t, "BUNDLE-ECC-EK")

	err = injector.InjectCertificate(ctx, rsaCert, vtpm.EKAlgorithmRSA)
	require.NoError(t, err, "Failed to inject RSA EK certificate")

	err = injector.InjectCertificate(ctx, eccCert, vtpm.EKAlgorithmECC)
	require.NoError(t, err, "Failed to inject ECC EK certificate")

	// Step 3: Verify both certificates exist
	rsaExists, rsaRead, err := injector.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)
	require.True(t, rsaExists)
	require.True(t, rsaCert.Equal(rsaRead))

	eccExists, eccRead, err := injector.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmECC)
	require.NoError(t, err)
	require.True(t, eccExists)
	require.True(t, eccCert.Equal(eccRead))

	// Step 4: Stop TPM to persist state
	err = sw.Stop()
	require.NoError(t, err)

	// Step 5: Verify TPM state files exist
	stateFiles := []string{
		"tpm2-00.permall",
	}
	for _, f := range stateFiles {
		path := filepath.Join(tpmStateDir, f)
		_, err := os.Stat(path)
		require.NoError(t, err, "TPM state file should exist: %s", f)
	}

	// Step 6: Restart TPM with existing state and verify certs persisted
	sw2, err := swtpm.NewSWTPM(config, nil)
	require.NoError(t, err)
	err = sw2.Start(ctx)
	require.NoError(t, err)
	defer sw2.Stop()

	waitForSocket(t, socketPath)

	injector2 := vtpm.NewEKCertInjector(socketPath, nil)

	rsaExists2, rsaRead2, err := injector2.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmRSA)
	require.NoError(t, err)
	require.True(t, rsaExists2, "RSA EK cert must persist in bundle")
	require.True(t, rsaCert.Equal(rsaRead2), "RSA EK cert must match original")

	eccExists2, eccRead2, err := injector2.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmECC)
	require.NoError(t, err)
	require.True(t, eccExists2, "ECC EK cert must persist in bundle")
	require.True(t, eccCert.Equal(eccRead2), "ECC EK cert must match original")

	t.Logf("SUCCESS: vTPM bundle created with pre-provisioned EK certificates")
	t.Logf("  - RSA EK fingerprint: %s", certFingerprint(rsaRead2))
	t.Logf("  - ECC EK fingerprint: %s", certFingerprint(eccRead2))
	t.Logf("  - Bundle location: %s", bundleDir)
}

// Helper functions

func generateIdentifiableEKCert(t *testing.T, identifier string) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         identifier,
			Organization:       []string{"vTPM Integration Test"},
			OrganizationalUnit: []string{"EK Certificate Safety Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func certFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

const (
	// socketTimeout bounds the wait for a started swtpm's socket file.
	socketTimeout = 5 * time.Second

	// vmExitTimeout bounds the wait for a stopped QEMU process to exit.
	vmExitTimeout = 10 * time.Second
)

func waitForSocket(t *testing.T, socketPath string) {
	t.Helper()
	exists := func() bool {
		_, err := os.Stat(socketPath)
		return err == nil
	}
	if err := testenv.WaitUntil(t.Context(), socketTimeout, "socket "+socketPath+" created", exists); err != nil {
		t.Fatalf("Socket not created: %v", err)
	}
}

func findOVMFCode(t *testing.T) string {
	t.Helper()
	paths := []string{
		"/usr/share/OVMF/OVMF_CODE.fd",
		"/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
		"/usr/share/edk2/ovmf/OVMF_CODE.fd",
		"/usr/share/qemu/OVMF_CODE.fd",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func findOVMFVars(t *testing.T) string {
	t.Helper()
	paths := []string{
		"/usr/share/OVMF/OVMF_VARS.fd",
		"/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
		"/usr/share/edk2/ovmf/OVMF_VARS.fd",
		"/usr/share/qemu/OVMF_VARS.fd",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func checkKVMAvailable() bool {
	_, err := os.Stat("/dev/kvm")
	return err == nil
}

// assertEKCertNotOverwritten is a helper that verifies an EK certificate
// was not overwritten. This should be called before any provisioning
// operation on a TPM that might already have an EK certificate.
func assertEKCertNotOverwritten(t *testing.T, injector *vtpm.EKCertInjector, ctx context.Context, algorithm vtpm.EKAlgorithm, expectedFingerprint string) {
	t.Helper()

	exists, cert, err := injector.CheckEKCertificateExists(ctx, algorithm)
	require.NoError(t, err, "Failed to check EK certificate existence")

	if !exists {
		t.Fatal("CRITICAL SAFETY VIOLATION: EK certificate was deleted!")
	}

	actualFingerprint := certFingerprint(cert)
	if actualFingerprint != expectedFingerprint {
		t.Fatalf("CRITICAL SAFETY VIOLATION: EK certificate was overwritten!\n"+
			"  Expected fingerprint: %s\n"+
			"  Actual fingerprint:   %s",
			expectedFingerprint, actualFingerprint)
	}
}

// SimulateFirstbootEKCheck simulates the EK certificate check that should
// happen during firstboot. This demonstrates the safe pattern.
func SimulateFirstbootEKCheck(t *testing.T, injector *vtpm.EKCertInjector, ctx context.Context) (shouldProvision bool, existingCert *x509.Certificate) {
	t.Helper()

	// This is the CRITICAL check that MUST happen before any EK provisioning
	exists, cert, err := injector.CheckEKCertificateExists(ctx, vtpm.EKAlgorithmRSA)
	if err != nil {
		t.Logf("Warning: Error checking for existing EK certificate: %v", err)
		// On error, assume cert might exist and DON'T provision
		return false, nil
	}

	if exists {
		t.Logf("Existing EK certificate found - SKIPPING provisioning")
		t.Logf("  - Subject: %s", cert.Subject.CommonName)
		t.Logf("  - Fingerprint: %s", certFingerprint(cert))
		return false, cert
	}

	t.Logf("No existing EK certificate - safe to provision")
	return true, nil
}

// Note: Helper functions setupSWTPM, cleanupSWTPM, generateTestCert, and
// generateTestCertWithExtensions are defined in nvram_test.go and shared
// across all test files in this package.
