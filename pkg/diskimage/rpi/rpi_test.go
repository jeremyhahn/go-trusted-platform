package rpi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// writeAPK writes an Alpine-style package: two gzip members (a control
// stream without a tar trailer, then the data stream), to prove the
// extractor walks multistream gzip exactly as `tar -xzf` does.
func writeAPK(t *testing.T, path string, files map[string]string) {
	t.Helper()
	var out bytes.Buffer
	// control member: .PKGINFO, trailer deliberately omitted
	var control bytes.Buffer
	gz := gzip.NewWriter(&control)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: ".PKGINFO", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("pkg=x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	out.Write(control.Bytes())
	// data member
	var data bytes.Buffer
	gz = gzip.NewWriter(&data)
	tw = tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	out.Write(data.Bytes())
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// prefetchDir lays out the three packages the target extracts from.
func prefetchDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeAPK(t, filepath.Join(dir, "raspberrypi-bootloader-1.20260619-r0.apk"), map[string]string{
		"boot/start4.elf": "start4", "boot/fixup4.dat": "fixup4", "boot/start.elf": "start", "boot/fixup.dat": "fixup",
	})
	writeAPK(t, filepath.Join(dir, "raspberrypi-bootloader-common-1.20260619-r0.apk"), map[string]string{
		"boot/bootcode.bin": "bootcode", "usr/sbin/update-raspberrypi-bootloader": "#!/bin/sh",
	})
	writeAPK(t, filepath.Join(dir, "linux-rpi-6.12.85-r0.apk"), map[string]string{
		"boot/vmlinuz-rpi": "kernel", "boot/bcm2711-rpi-4-b.dtb": "dtb4", "boot/bcm2710-rpi-3-b-plus.dtb": "dtb3",
		"boot/bcm2712-rpi-5-b.dtb": "dtb5", "boot/bcm2711-rpi-cm4.dtb": "dtbcm4", "boot/bcm2711-rpi-400.dtb": "dtb400",
		"boot/overlays/disable-bt.dtbo": "disable-bt", "boot/overlays/tpm-slb9670.dtbo": "hw-spi", "boot/config-6.12.85-0-rpi": "CONFIG",
	})
	return dir
}

func ubootArtifacts(t *testing.T) uboot.Artifacts {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "overlays"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "u-boot.bin"), []byte("u-boot"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "overlays", "tpm-soft-spi.dtbo"), []byte("soft-spi"), 0o644); err != nil {
		t.Fatal(err)
	}
	return uboot.Artifacts{Board: uboot.BoardRPiArm64, Dir: dir, Binary: filepath.Join(dir, "u-boot.bin"), OverlaysDir: filepath.Join(dir, "overlays")}
}

func TestModels(t *testing.T) {
	if got := Models(); strings.Join(got, ",") != "cm4,rpi3b+,rpi4,rpi400,rpi5" { // lab-string-ok
		t.Errorf("Models() = %v", got)
	}
	m, err := LookupModel("")
	if err != nil || m.Name != DefaultModel || m.DTB != "bcm2711-rpi-4-b.dtb" {
		t.Errorf("LookupModel(\"\") = %+v, %v", m, err)
	}
	// The rpi5 is experimental, and its description is the board name the
	// image carries as hardware-model, not a status note.
	if m, err := LookupModel("rpi5"); err != nil || !m.Experimental || m.Description != "Raspberry Pi 5" || len(m.Firmware) != 0 {
		t.Errorf("rpi5 = %+v, %v; want experimental, \"Raspberry Pi 5\", no GPU firmware", m, err)
	}
	_, err = LookupModel("rpi2")
	var unknown *UnknownModelError
	if !errors.As(err, &unknown) || !strings.Contains(err.Error(), "rpi4") {
		t.Errorf("LookupModel(rpi2) error = %v", err)
	}
	if _, err := New("nope"); err == nil {
		t.Error("New accepted an unknown model")
	}
}

// TestModelSoC pins which boards HTTP-boot: the 2711 and 2712 EEPROMs do; the
// 3B+'s boot ROM has no EEPROM to fetch or verify boot.img.
func TestModelSoC(t *testing.T) {
	want := map[string]string{"rpi4": "2711", "rpi400": "2711", "cm4": "2711", "rpi5": "2712", "rpi3b+": ""} // lab-string-ok
	for name, soc := range want {
		m, err := LookupModel(name)
		if err != nil || m.SoC != soc {
			t.Errorf("%s: SoC = %q, %v; want %q", name, m.SoC, err, soc)
		}
	}
}

func TestTargetContract(t *testing.T) {
	tgt, err := New("cm4")
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Name() != "rpi" || tgt.Architecture() != uki.ArchAArch64 || tgt.KernelPackage() != "linux-rpi" || tgt.UBootBoard() != uboot.BoardRPiArm64 {
		t.Errorf("contract = %s %s %s %s", tgt.Name(), tgt.Architecture(), tgt.KernelPackage(), tgt.UBootBoard())
	}
	if got := tgt.ExtraPackages(); len(got) < 2 || got[0] != "raspberrypi-bootloader" || got[1] != "raspberrypi-bootloader-common" {
		t.Errorf("ExtraPackages = %v, want the bootloader packages first", got)
	}
	if tgt.BuiltKernel() {
		t.Error("the Pi boots the linux-rpi package, not a built kernel")
	}
	if err := tgt.StageKernel(context.Background(), t.TempDir(), nil); err != nil {
		t.Errorf("StageKernel is a no-op for a packaged kernel: %v", err)
	}
	if ov := tgt.InstallerOverrides(); ov.KernelArtifactsDir != "" {
		t.Errorf("a packaged kernel names no artifacts directory: %s", ov.KernelArtifactsDir)
	}
	ov := tgt.InstallerOverrides()
	if ov.Device != "/dev/mmcblk0" || ov.PartitionTable != "mbr" || ov.KernelPackage != "linux-rpi" || ov.Target != "image" || ov.BootFirmware != "uboot" ||
		ov.HardwareManufacturer != "Raspberry Pi" || ov.HardwareModel != "Raspberry Pi Compute Module 4" {
		t.Errorf("InstallerOverrides = %+v", ov)
	}
}

// TestTargetCarriesTheTokenStack: every Pi image installs the smart-card
// stack a YubiKey or a Nitrokey HSM needs for PKCS#11, and the offline
// repository the media is built from carries it, so the install does not
// need upstream egress to find it.
func TestTargetCarriesTheTokenStack(t *testing.T) {
	tokenStack := []string{"pcsc-lite", "pcsc-lite-openrc", "ccid", "opensc", "yubico-piv-tool-libs"}
	for _, model := range Models() {
		t.Run(model, func(t *testing.T) {
			tgt, err := New(model)
			if err != nil {
				t.Fatal(err)
			}
			want := append([]string{"raspberrypi-bootloader", "raspberrypi-bootloader-common"}, tokenStack...)
			if got := tgt.ExtraPackages(); !slices.Equal(got, want) {
				t.Errorf("ExtraPackages = %v, want %v", got, want)
			}

			ov := tgt.InstallerOverrides()
			if !slices.Equal(ov.ExtraServices, []string{"pcscd"}) {
				t.Errorf("ExtraServices = %v, want pcscd started at boot", ov.ExtraServices)
			}
			offline := iso.CollectRequiredPackages(&iso.PreFetchConfig{KernelPackage: ov.KernelPackage, ExtraPackages: ov.ExtraPackages})
			for _, pkg := range tokenStack {
				if !slices.Contains(ov.ExtraPackages, pkg) {
					t.Errorf("installer overrides do not install %q: %v", pkg, ov.ExtraPackages)
				}
				if !slices.Contains(offline, pkg) {
					t.Errorf("offline repository does not carry %q", pkg)
				}
			}
		})
	}
}

func TestConfigTxt(t *testing.T) {
	m, _ := LookupModel("rpi4")
	got := ConfigTxt(m)
	for _, line := range []string{"arm_64bit=1", "enable_uart=1", "uart_2ndstage=1", "dtoverlay=disable-bt", "dtoverlay=tpm-soft-spi", "kernel=kernel8.img", "# Board: Raspberry Pi 4 Model B"} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("config.txt lacks %q:\n%s", line, got)
		}
	}
	for _, bad := range []string{"dtparam=spi=on", "tpm-slb9670", "cmdline"} {
		if strings.Contains(got, bad) {
			t.Errorf("config.txt must not carry %q", bad)
		}
	}
}

func TestStageBootFirmware(t *testing.T) {
	tgt, _ := New("rpi4")
	media := t.TempDir()
	if err := tgt.StageBootFirmware(context.Background(), media, prefetchDir(t), ubootArtifacts(t)); err != nil {
		t.Fatalf("StageBootFirmware: %v", err)
	}
	dest := filepath.Join(media, "boot-firmware")
	want := map[string]string{
		"kernel8.img":                "u-boot",
		"overlays/tpm-soft-spi.dtbo": "soft-spi",
		"overlays/disable-bt.dtbo":   "disable-bt",
		"start4.elf":                 "start4",
		"fixup4.dat":                 "fixup4",
		"bootcode.bin":               "bootcode",
		"bcm2711-rpi-4-b.dtb":        "dtb4",
		"bcm2712-rpi-5-b.dtb":        "dtb5",
	}
	for rel, body := range want {
		got, err := os.ReadFile(filepath.Join(dest, rel))
		if err != nil || string(got) != body {
			t.Errorf("%s = %q, %v; want %q", rel, got, err, body)
		}
	}
	for _, absent := range []string{"vmlinuz-rpi", "overlays/tpm-slb9670.dtbo", "config-6.12.85-0-rpi", "usr"} {
		if _, err := os.Stat(filepath.Join(dest, absent)); err == nil {
			t.Errorf("%s must not be staged", absent)
		}
	}
	cfg, err := os.ReadFile(filepath.Join(dest, "config.txt"))
	if err != nil || !strings.Contains(string(cfg), "kernel=kernel8.img") {
		t.Errorf("config.txt = %q, %v", cfg, err)
	}
	// Re-staging replaces a stale tree.
	if err := os.WriteFile(filepath.Join(dest, "stale.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tgt.StageBootFirmware(context.Background(), media, prefetchDir(t), ubootArtifacts(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "stale.bin")); err == nil {
		t.Error("stale file survived re-staging")
	}
}

func TestStageBootFirmwareFailures(t *testing.T) {
	tgt, _ := New("rpi4")
	media := t.TempDir()

	// Missing firmware package.
	empty := t.TempDir()
	err := tgt.StageBootFirmware(context.Background(), media, empty, ubootArtifacts(t))
	var missing *PackageMissingError
	if !errors.As(err, &missing) || missing.Package != "raspberrypi-bootloader" {
		t.Errorf("missing package error = %v", err)
	}

	// The -common package must not satisfy the bare name.
	onlyCommon := t.TempDir()
	writeAPK(t, filepath.Join(onlyCommon, "raspberrypi-bootloader-common-1.0-r0.apk"), map[string]string{"boot/bootcode.bin": "b"})
	if _, err := findAPK(onlyCommon, "raspberrypi-bootloader"); !errors.As(err, &missing) {
		t.Errorf("findAPK matched the -common package: %v", err)
	}

	// A kernel package without the model's DTB is refused.
	noDTB := t.TempDir()
	writeAPK(t, filepath.Join(noDTB, "raspberrypi-bootloader-1.0-r0.apk"), map[string]string{"boot/start4.elf": "s", "boot/fixup4.dat": "f"})
	writeAPK(t, filepath.Join(noDTB, "raspberrypi-bootloader-common-1.0-r0.apk"), map[string]string{"boot/bootcode.bin": "b"})
	writeAPK(t, filepath.Join(noDTB, "linux-rpi-6.12-r0.apk"), map[string]string{"boot/overlays/disable-bt.dtbo": "d"})
	var fw *FirmwareMissingError
	if err := tgt.StageBootFirmware(context.Background(), media, noDTB, ubootArtifacts(t)); !errors.As(err, &fw) || fw.File != "bcm2711-rpi-4-b.dtb" {
		t.Errorf("missing DTB error = %v", err)
	}

	// A corrupt apk is a PackageError.
	corrupt := t.TempDir()
	if err := os.WriteFile(filepath.Join(corrupt, "raspberrypi-bootloader-1.0-r0.apk"), []byte("not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	var pkgErr *PackageError
	if err := tgt.StageBootFirmware(context.Background(), media, corrupt, ubootArtifacts(t)); !errors.As(err, &pkgErr) {
		t.Errorf("corrupt apk error = %v", err)
	}

	// Missing U-Boot artifacts.
	var stage *StageError
	if err := tgt.StageBootFirmware(context.Background(), media, prefetchDir(t), uboot.Artifacts{Binary: "/nonexistent/u-boot.bin"}); !errors.As(err, &stage) {
		t.Errorf("missing U-Boot error = %v", err)
	}
}

// The GPU firmware a model needs is its own: the Pi 5's bootloader EEPROM
// loads U-Boot itself, so a bootloader package without start4.elf still
// stages it, while the Pi 4 and the 3B+ (which reads bootcode.bin from the
// card) are refused without theirs.
func TestStageBootFirmwareGPUFirmwarePerModel(t *testing.T) {
	noGPUFirmware := t.TempDir()
	writeAPK(t, filepath.Join(noGPUFirmware, "raspberrypi-bootloader-1.0-r0.apk"), map[string]string{"boot/LICENCE.broadcom": "l"})
	writeAPK(t, filepath.Join(noGPUFirmware, "raspberrypi-bootloader-common-1.0-r0.apk"), map[string]string{"boot/cmdline.txt": "c"})
	writeAPK(t, filepath.Join(noGPUFirmware, "linux-rpi-6.12-r0.apk"), map[string]string{
		"boot/bcm2711-rpi-4-b.dtb": "dtb4", "boot/bcm2710-rpi-3-b-plus.dtb": "dtb3", "boot/bcm2712-rpi-5-b.dtb": "dtb5",
		"boot/overlays/disable-bt.dtbo": "d",
	})

	cases := map[string]string{"rpi5": "", "rpi4": "start4.elf", "rpi3b+": "bootcode.bin"}
	for model, wantMissing := range cases {
		t.Run(model, func(t *testing.T) {
			tgt, err := New(model)
			if err != nil {
				t.Fatal(err)
			}
			err = tgt.StageBootFirmware(context.Background(), t.TempDir(), noGPUFirmware, ubootArtifacts(t))
			if wantMissing == "" {
				if err != nil {
					t.Fatalf("StageBootFirmware(%s) = %v, want no GPU firmware required", model, err)
				}
				return
			}
			var fw *FirmwareMissingError
			if !errors.As(err, &fw) || fw.File != wantMissing {
				t.Errorf("StageBootFirmware(%s) = %v, want %s missing", model, err, wantMissing)
			}
		})
	}
}

func TestErrorMessages(t *testing.T) {
	inner := errors.New("inner")
	for err, want := range map[error]string{
		&UnknownModelError{Model: "x", Models: []string{"a", "b"}}: "rpi: unknown model x (known: a b)",
		&PackageMissingError{Package: "p", Dir: "/d"}:              "rpi: package p is not in the prefetched repository /d (is it in the target's extra packages?)",
		&PackageError{Package: "p", Err: inner}:                    "rpi: package p: inner",
		&FirmwareMissingError{File: "f"}:                           "rpi: boot firmware file f was not produced",
		&StageError{Step: "s", Err: inner}:                         "rpi: s: inner",
	} {
		if err.Error() != want {
			t.Errorf("%T.Error() = %q, want %q", err, err.Error(), want)
		}
	}
	if !errors.Is(&PackageError{Err: inner}, inner) || !errors.Is(&StageError{Err: inner}, inner) {
		t.Error("errors do not unwrap")
	}
}

func TestExtractAndCopyErrorPaths(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "pkg-1.0-r0.apk")
	writeAPK(t, apk, map[string]string{"boot/a": "x"})
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var pkgErr *PackageError

	if err := copyFile(filepath.Join(dir, "missing"), filepath.Join(dir, "out")); err == nil {
		t.Error("copyFile of a missing source succeeded")
	}
	if err := copyFile(apk, filepath.Join(blocker, "out")); err == nil {
		t.Error("copyFile into an unwritable destination succeeded")
	}

	// A glob-invalid package name is reported, not swallowed.
	if _, err := findAPK(dir, "["); !errors.As(err, &pkgErr) {
		t.Errorf("findAPK with a bad pattern error = %v", err)
	}
}

// TestStageBootFirmwareIntoStepFailures asserts that each staging step that
// can fail reports itself: the step name or the offending package, so a
// failed image build points at the input that broke it.
func TestStageBootFirmwareIntoStepFailures(t *testing.T) {
	tgt, err := New("rpi4")
	if err != nil {
		t.Fatal(err)
	}
	kernelAPK := "linux-rpi-6.12.85-r0.apk"

	cases := []struct {
		name  string
		setup func(t *testing.T) (dest, prefetch string, art uboot.Artifacts)
		check func(t *testing.T, prefetch string, err error)
	}{
		{
			name: "staging directory under a regular file",
			setup: func(t *testing.T) (string, string, uboot.Artifacts) {
				file := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(file, nil, 0o644); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(file, "boot-firmware"), prefetchDir(t), ubootArtifacts(t)
			},
			check: wantStep("clearing the boot-firmware staging directory"),
		},
		{
			name: "U-Boot binary is a directory",
			setup: func(t *testing.T) (string, string, uboot.Artifacts) {
				art := ubootArtifacts(t)
				art.Binary = art.OverlaysDir
				return filepath.Join(t.TempDir(), "boot-firmware"), prefetchDir(t), art
			},
			check: wantStep("staging U-Boot as kernel8.img"),
		},
		{
			name: "U-Boot build without the TPM overlay",
			setup: func(t *testing.T) (string, string, uboot.Artifacts) {
				art := ubootArtifacts(t)
				if err := os.Remove(filepath.Join(art.OverlaysDir, "tpm-soft-spi.dtbo")); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(t.TempDir(), "boot-firmware"), prefetchDir(t), art
			},
			check: wantStep("staging the TPM overlay"),
		},
		{
			name: "kernel package not prefetched",
			setup: func(t *testing.T) (string, string, uboot.Artifacts) {
				prefetch := prefetchDir(t)
				if err := os.Remove(filepath.Join(prefetch, kernelAPK)); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(t.TempDir(), "boot-firmware"), prefetch, ubootArtifacts(t)
			},
			check: func(t *testing.T, _ string, err error) {
				var missing *PackageMissingError
				if !errors.As(err, &missing) || missing.Package != KernelPackage {
					t.Errorf("error = %v, want PackageMissingError for %s", err, KernelPackage)
				}
			},
		},
		{
			name: "corrupt kernel package",
			setup: func(t *testing.T) (string, string, uboot.Artifacts) {
				prefetch := prefetchDir(t)
				if err := os.WriteFile(filepath.Join(prefetch, kernelAPK), []byte("not gzip"), 0o644); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(t.TempDir(), "boot-firmware"), prefetch, ubootArtifacts(t)
			},
			check: func(t *testing.T, prefetch string, err error) {
				var pkgErr *PackageError
				if !errors.As(err, &pkgErr) || pkgErr.Package != filepath.Join(prefetch, kernelAPK) {
					t.Errorf("error = %v, want PackageError for the kernel apk", err)
				}
			},
		},
		{
			name: "bootloader package occupies config.txt",
			setup: func(t *testing.T) (string, string, uboot.Artifacts) {
				prefetch := prefetchDir(t)
				writeAPK(t, filepath.Join(prefetch, "raspberrypi-bootloader-1.20260619-r0.apk"), map[string]string{
					"boot/start4.elf": "start4", "boot/fixup4.dat": "fixup4", "boot/config.txt/stale": "x",
				})
				return filepath.Join(t.TempDir(), "boot-firmware"), prefetch, ubootArtifacts(t)
			},
			check: wantStep("writing config.txt"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest, prefetch, art := tc.setup(t)
			err := tgt.StageBootFirmwareInto(context.Background(), dest, prefetch, art)
			if err == nil {
				t.Fatal("StageBootFirmwareInto succeeded")
			}
			tc.check(t, prefetch, err)
		})
	}
}

// wantStep returns a check that the error is a StageError for step.
func wantStep(step string) func(t *testing.T, prefetch string, err error) {
	return func(t *testing.T, _ string, err error) {
		t.Helper()
		var stage *StageError
		if !errors.As(err, &stage) || stage.Step != step {
			t.Errorf("error = %v, want StageError for %q", err, step)
		}
		if stage != nil && stage.Err == nil {
			t.Errorf("StageError for %q carries no cause", step)
		}
	}
}
