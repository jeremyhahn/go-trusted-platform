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

package secureboot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

const (
	// bootMarker is printed by the signed EFI payload when the firmware
	// executes it.
	bootMarker = "TRUSTED-PLATFORM-SB-OK"

	// accessDenied is what edk2's boot manager prints on the console when
	// image verification rejects a boot option.
	accessDenied = "Access Denied"

	// vmBootTimeout bounds each firmware boot under TCG emulation.
	vmBootTimeout = 4 * time.Minute

	// sbverifyTimeout bounds each sbverify invocation.
	sbverifyTimeout = 30 * time.Second
)

// enrollOVMFVars generates a Secure Boot key set with the platform generator,
// enrolls PK/KEK/DB into a fresh OVMF variable store via the pkg/uefi
// OVMF-file enrollment path, and returns (varsPath, keysDir).
func enrollOVMFVars(t *testing.T, ctx context.Context) (string, string) {
	t.Helper()

	_, varsTemplate := findOVMF(t)

	keysDir := filepath.Join(t.TempDir(), "sb-keys")
	generateSecureBootKeys(t, ctx, keysDir)

	varsPath := filepath.Join(t.TempDir(), "OVMF_VARS_enrolled.fd")
	enroller, err := uefi.NewSecureBootEnroller(&uefi.SecureBootEnrollerConfig{
		NVRAMPath:    varsPath,
		KeysDir:      keysDir,
		TemplatePath: varsTemplate,
	}, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("create Secure Boot enroller: %v", err)
	}
	if err := enroller.EnrollKeys(ctx); err != nil {
		t.Fatalf("enroll keys into OVMF vars: %v", err)
	}

	status, err := enroller.GetEnrollmentStatus()
	if err != nil {
		t.Fatalf("read enrollment status: %v", err)
	}
	if !status.KeysEnrolled {
		t.Fatalf("keys not enrolled after EnrollKeys: %s", status)
	}
	return varsPath, keysDir
}

// stageESP writes payload as EFI/BOOT/BOOTX64.EFI under a fresh directory
// served to QEMU as a virtual FAT drive, and returns the directory.
func stageESP(t *testing.T, payload []byte) string {
	t.Helper()
	esp := t.TempDir()
	bootDir := filepath.Join(esp, "EFI", "BOOT")
	if err := os.MkdirAll(bootDir, 0755); err != nil {
		t.Fatalf("create ESP layout: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bootDir, "BOOTX64.EFI"), payload, 0644); err != nil {
		t.Fatalf("write BOOTX64.EFI: %v", err)
	}
	return esp
}

// copyFile duplicates the enrolled variable store so each boot starts from
// the same firmware state (the firmware writes to its varstore at runtime).
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

// bootWithSecureBoot boots OVMF (Secure Boot build) with the enrolled vars
// and the given ESP directory, watching for the markers.
func bootWithSecureBoot(t *testing.T, ctx context.Context, enrolledVars, esp string, markers ...string) serialResult {
	t.Helper()

	code, _ := findOVMF(t)
	vars := filepath.Join(t.TempDir(), "vars.fd")
	copyFile(t, enrolledVars, vars)

	bctx, cancel := context.WithTimeout(ctx, vmBootTimeout)
	defer cancel()

	args := []string{
		"-machine", "q35",
		"-accel", "tcg",
		"-m", "512",
		"-display", "none",
		"-serial", "stdio",
		"-net", "none",
		"-no-reboot",
		"-drive", "if=pflash,format=raw,readonly=on,file=" + code,
		"-drive", "if=pflash,format=raw,file=" + vars,
		"-drive", "format=raw,file=fat:rw:" + esp,
	}
	return runQEMU(t, bctx, args, markers...)
}

// TestOVMFSecureBootEnforcement runs the full enforce cycle against real OVMF
// firmware: platform-generated keys are enrolled into the variable store, a
// DB-signed EFI payload boots (its serial marker is observed), and the same
// payload unsigned or signed by the wrong key is rejected by the firmware
// with Access Denied.
func TestOVMFSecureBootEnforcement(t *testing.T) {
	ctx := context.Background()

	enrolledVars, keysDir := enrollOVMFVars(t, ctx)
	dbKey, dbCert := loadPEMKeypair(t,
		filepath.Join(keysDir, "DB.key"),
		filepath.Join(keysDir, "DB.crt"))

	workDir := t.TempDir()
	unsignedPath := filepath.Join(workDir, "unsigned.efi")
	signedPath := filepath.Join(workDir, "signed.efi")
	wrongSignedPath := filepath.Join(workDir, "wrong-signed.efi")

	payload := buildMarkerEFIApp(bootMarker)
	if err := os.WriteFile(unsignedPath, payload, 0644); err != nil {
		t.Fatalf("write unsigned payload: %v", err)
	}

	// Sign with the enrolled DB key using the platform Authenticode signer
	// (the same signer the installer uses for UKIs).
	authenticodeSign(t, ctx, unsignedPath, signedPath, dbKey, dbCert)

	// Sign a second copy with a DIFFERENT, unenrolled DB key.
	wrongKeysDir := filepath.Join(t.TempDir(), "wrong-keys")
	generateSecureBootKeys(t, ctx, wrongKeysDir)
	wrongKey, wrongCert := loadPEMKeypair(t,
		filepath.Join(wrongKeysDir, "DB.key"),
		filepath.Join(wrongKeysDir, "DB.crt"))
	authenticodeSign(t, ctx, unsignedPath, wrongSignedPath, wrongKey, wrongCert)

	// Independent cross-check with sbsigntool before booting firmware.
	t.Run("SbverifyCrossCheck", func(t *testing.T) {
		requireTool(t, "sbverify", "independently verify Authenticode signatures")
		dbCertPEM := filepath.Join(keysDir, "DB.crt")

		vctx, cancel := context.WithTimeout(ctx, sbverifyTimeout)
		defer cancel()
		if _, err := runCommand(t, vctx, false, "sbverify", "--cert", dbCertPEM, signedPath); err != nil {
			t.Fatalf("sbverify rejected the DB-signed payload: %v", err)
		}
		if _, err := runCommand(t, vctx, true, "sbverify", "--cert", dbCertPEM, unsignedPath); err == nil {
			t.Fatal("sbverify accepted an unsigned payload")
		}
		if _, err := runCommand(t, vctx, true, "sbverify", "--cert", dbCertPEM, wrongSignedPath); err == nil {
			t.Fatal("sbverify accepted a payload signed by the wrong key")
		}
	})

	signedESP := stageESP(t, mustRead(t, signedPath))
	unsignedESP := stageESP(t, payload)
	wrongESP := stageESP(t, mustRead(t, wrongSignedPath))

	// Positive control: the DB-signed payload boots and prints its marker.
	t.Run("SignedPayloadBoots", func(t *testing.T) {
		res := bootWithSecureBoot(t, ctx, enrolledVars, signedESP, bootMarker)
		if res.Marker != bootMarker {
			t.Fatal(ErrSerialTimeout{Markers: []string{bootMarker}, Output: res.Output})
		}
	})

	// The unsigned payload must be rejected by firmware image verification.
	t.Run("UnsignedPayloadRejected", func(t *testing.T) {
		res := bootWithSecureBoot(t, ctx, enrolledVars, unsignedESP, bootMarker, accessDenied)
		if res.Marker == bootMarker {
			t.Fatalf("firmware BOOTED an unsigned payload under Secure Boot; transcript:\n%s", res.Output)
		}
		if !strings.Contains(res.Output, accessDenied) {
			t.Fatal(ErrSerialTimeout{Markers: []string{accessDenied}, Output: res.Output})
		}
	})

	// A payload signed by a key NOT in db must equally be rejected.
	t.Run("WrongKeyPayloadRejected", func(t *testing.T) {
		res := bootWithSecureBoot(t, ctx, enrolledVars, wrongESP, bootMarker, accessDenied)
		if res.Marker == bootMarker {
			t.Fatalf("firmware BOOTED a wrongly-signed payload under Secure Boot; transcript:\n%s", res.Output)
		}
		if !strings.Contains(res.Output, accessDenied) {
			t.Fatal(ErrSerialTimeout{Markers: []string{accessDenied}, Output: res.Output})
		}
	})
}

// mustRead reads a file or fails the test.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
