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
	vtpmit "github.com/jeremyhahn/go-trusted-platform/test/integration/vtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQEMUWithVTPM_BootAndDetectEK tests booting a QEMU VM with a pre-provisioned
// vTPM and verifying the EK certificate is detected.
// NOTE: This test requires QEMU and OVMF to be installed.
func TestQEMUWithVTPM_BootAndDetectEK(t *testing.T) {
	ovmfCode, ovmfVars, firmwareErr := vmFirmware(t)
	if firmwareErr != nil {
		t.Fatal(firmwareErr)
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

// vmFirmware returns the OVMF code and vars images the VM boot test uses,
// or ErrMissingPrerequisite when QEMU or OVMF is absent. The devcontainer
// installs both (build/docker/devcontainer/Dockerfile: qemu-system-x86, ovmf).
func vmFirmware(t *testing.T) (string, string, error) {
	t.Helper()
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		return "", "", vtpmit.ErrMissingPrerequisite{
			Name:    "qemu-system-x86_64",
			Provide: "run the suite in the devcontainer, which installs qemu-system-x86",
		}
	}
	ovmfCode := findOVMFCode(t)
	ovmfVars := findOVMFVars(t)
	if ovmfCode == "" || ovmfVars == "" {
		return "", "", vtpmit.ErrMissingPrerequisite{
			Name:    "OVMF firmware (OVMF_CODE and OVMF_VARS)",
			Provide: "run the suite in the devcontainer, which installs ovmf",
		}
	}
	return ovmfCode, ovmfVars, nil
}

func findOVMFCode(t *testing.T) string {
	t.Helper()
	paths := []string{
		"/usr/share/OVMF/OVMF_CODE_4M.fd",
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
		"/usr/share/OVMF/OVMF_VARS_4M.fd",
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
