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

package installer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// withTPMDeviceCandidates swaps the package-level TPM device candidates for
// the duration of the test. Used to drive both "present" and "absent" paths
// without modifying real /dev entries.
func withTPMDeviceCandidates(t *testing.T, paths []string) {
	t.Helper()
	orig := tpmDeviceCandidates
	tpmDeviceCandidates = paths
	t.Cleanup(func() { tpmDeviceCandidates = orig })
}

// stubTPMModprobe replaces the production modprobe caller with a no-op so
// tests never mutate host kernel module state. Returns the list of modules
// the code under test asked for so assertions can verify the exact set.
func stubTPMModprobe(t *testing.T) *[]string {
	t.Helper()
	var requested []string
	orig := tpmModprobe
	tpmModprobe = func(module string) (string, error) {
		requested = append(requested, module)
		return "stubbed: skipping real modprobe", nil
	}
	t.Cleanup(func() { tpmModprobe = orig })
	return &requested
}

// withoutHostTPM makes the code under test see no TPM, whatever the host
// has: the device candidates are missing temp paths, modprobe is stubbed,
// and the device wait is zero so the post-modprobe poll does not wait out
// its 2s for a node that cannot appear (#284). Returns the modules the code
// asked modprobe for.
func withoutHostTPM(t *testing.T) *[]string {
	t.Helper()
	dir := t.TempDir()
	withTPMDeviceCandidates(t, []string{filepath.Join(dir, "missing-tpmrm0"), filepath.Join(dir, "missing-tpm0")})
	requested := stubTPMModprobe(t)
	origTimeout := tpmDeviceWaitTimeout
	tpmDeviceWaitTimeout = 0
	t.Cleanup(func() { tpmDeviceWaitTimeout = origTimeout })
	return requested
}

// TestResolveTPMDevice_NoDevice verifies that resolveTPMDevice returns the
// empty string when none of the candidate paths exist. This is the trigger
// for clearTPM's modprobe fallback — if this helper lies, clearTPM runs
// against a phantom path and panics later.
func TestResolveTPMDevice_NoDevice(t *testing.T) {
	dir := t.TempDir()
	withTPMDeviceCandidates(t, []string{
		filepath.Join(dir, "missing-tpmrm0"),
		filepath.Join(dir, "missing-tpm0"),
	})

	inst := &installer{logger: createTestLogger()}
	device := inst.resolveTPMDevice()
	if device != "" {
		t.Fatalf("expected empty device, got %q", device)
	}
}

// TestResolveTPMDevice_PrefersResourceManager verifies the resolution order:
// when both candidates exist, the preferred in-kernel resource-manager entry
// wins. This matters because TPM2_Clear through /dev/tpm0 bypasses the RM
// and can serialize badly against other processes; /dev/tpmrm0 is the right
// path whenever the kernel provides it.
func TestResolveTPMDevice_PrefersResourceManager(t *testing.T) {
	dir := t.TempDir()
	rmPath := filepath.Join(dir, "tpmrm0")
	rawPath := filepath.Join(dir, "tpm0")
	writeFile(t, rmPath, "")
	writeFile(t, rawPath, "")
	withTPMDeviceCandidates(t, []string{rmPath, rawPath})

	inst := &installer{logger: createTestLogger()}
	if got := inst.resolveTPMDevice(); got != rmPath {
		t.Fatalf("expected resource-manager device %q, got %q", rmPath, got)
	}
}

// TestResolveTPMDevice_FallsBackToRaw verifies that when only /dev/tpm0 is
// present (kernels without in-kernel RM support) resolveTPMDevice returns
// the raw device rather than giving up.
func TestResolveTPMDevice_FallsBackToRaw(t *testing.T) {
	dir := t.TempDir()
	rmPath := filepath.Join(dir, "tpmrm0")
	rawPath := filepath.Join(dir, "tpm0")
	writeFile(t, rawPath, "")
	withTPMDeviceCandidates(t, []string{rmPath, rawPath})

	inst := &installer{logger: createTestLogger()}
	if got := inst.resolveTPMDevice(); got != rawPath {
		t.Fatalf("expected raw device %q, got %q", rawPath, got)
	}
}

// TestClearTPM_NoDevice_ReturnsTypedError verifies the public failure path
// used by Install(): when no TPM device is found even after modprobe, the
// caller receives a typed *InstallerError with ErrorTypeTPM so higher
// layers can branch on it rather than string-matching the message.
//
// Drives the candidate paths into a tempdir so the test is deterministic
// regardless of whether the host has a real TPM, and stubs the modprobe
// call so it doesn't mutate host kernel modules.
func TestClearTPM_NoDevice_ReturnsTypedError(t *testing.T) {
	requested := withoutHostTPM(t)

	inst := &installer{logger: createTestLogger()}
	err := inst.clearTPM()
	if err == nil {
		t.Fatal("expected ErrTPM when no TPM device present, got nil")
	}

	var ierr *InstallerError
	if !errors.As(err, &ierr) {
		t.Fatalf("expected *InstallerError, got %T: %v", err, err)
	}
	if ierr.Type != ErrorTypeTPM {
		t.Fatalf("expected Type=%q, got %q", ErrorTypeTPM, ierr.Type)
	}
	// The modprobe fallback must have been attempted for the standard
	// set of TPM modules — otherwise the ISO environment can't recover
	// when kernel modules weren't autoloaded.
	// tpm_tis_spi is the transport a Raspberry Pi's discrete TPM sits on;
	// modprobe of an absent module is logged and ignored elsewhere.
	want := []string{"tpm", "tpm_tis_core", "tpm_tis", "tpm_crb", "tpm_tis_spi"}
	if !stringSliceEqual(*requested, want) {
		t.Fatalf("expected modprobe of %v, got %v", want, *requested)
	}
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
