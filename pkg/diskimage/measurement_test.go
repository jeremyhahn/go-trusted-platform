package diskimage

import (
	"context"
	"crypto"
	_ "crypto/sha512"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/diskimagetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure/measuretest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
)

const testOwnerGUID = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"

// writeSecureBootCerts writes PK.crt, KEK.crt and DB.crt to a directory.
func writeSecureBootCerts(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, role := range []string{"PK", "KEK", "DB"} {
		_, certPath := authenticodetest.WriteKeyPair(t, t.TempDir())
		data, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, role+".crt"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// writeUBootBuild lays out a qemu_arm64 U-Boot build whose manifest names
// owner as the SignatureOwner of its preseeded lists.
func writeUBootBuild(t *testing.T, owner string) uboot.Artifacts {
	t.Helper()
	out := t.TempDir()
	dir := filepath.Join(out, string(uboot.BoardQEMUArm64))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "u-boot.bin")
	if err := os.WriteFile(binary, measuretest.UBoot(), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := json.Marshal(uboot.Manifest{Version: uboot.DefaultVersion, CacheKey: "k", OwnerGUID: owner})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, uboot.ManifestName), m, 0o644); err != nil {
		t.Fatal(err)
	}
	return uboot.Artifacts{Board: uboot.BoardQEMUArm64, Dir: dir, Binary: binary}
}

// measuredStaging is a Secure Boot build for qemu-virt and an image whose
// EFI partition carries the UKI.
func measuredStaging(t *testing.T, owner string, ukiData []byte) (*StagedMedia, string, *mtoolsRunner) {
	t.Helper()
	target, err := NewTarget("qemu-virt", "")
	if err != nil {
		t.Fatal(err)
	}
	staged := &StagedMedia{Target: target, WorkDir: t.TempDir(), UBoot: writeUBootBuild(t, owner),
		SecureBoot: &iso.SecureBootMaterial{CertDir: writeSecureBootCerts(t)}}
	files := map[string][]byte{"config.txt": []byte("arm_64bit=1\n")}
	if ukiData != nil {
		files["EFI/BOOT/BOOTAA64.EFI"] = ukiData
	}
	return staged, writeImage(t, false), &mtoolsRunner{files: files}
}

// predicted is what measure predicts from the same files.
func predicted(t *testing.T, staged *StagedMedia, owner string, ukiData []byte, banks ...crypto.Hash) []measure.Bank {
	t.Helper()
	ukiPath := filepath.Join(t.TempDir(), "BOOTAA64.EFI")
	if err := os.WriteFile(ukiPath, ukiData, 0o644); err != nil {
		t.Fatal(err)
	}
	img, err := measure.ReadImage(measure.ImageFiles{UBoot: staged.UBoot.Binary, UKI: ukiPath, CertDir: staged.SecureBoot.CertDir, OwnerGUID: owner})
	if err != nil {
		t.Fatal(err)
	}
	want, err := measure.Predict(img, banks...)
	if err != nil {
		t.Fatal(err)
	}
	return want
}

func TestMeasureImagePredictsTheFinishedImage(t *testing.T) {
	ukiData := measuretest.UKI("root=/dev/mapper/root ro")
	staged, image, esp := measuredStaging(t, testOwnerGUID, ukiData)
	cfg := &BuildConfig{Runner: esp.run, MeasurementBanks: []crypto.Hash{crypto.SHA256, crypto.SHA384}}

	banks, unmeasured, err := cfg.measureImage(context.Background(), image, staged)
	if err != nil || unmeasured != "" {
		t.Fatalf("measureImage: %v (unmeasured %q)", err, unmeasured)
	}
	if want := predicted(t, staged, testOwnerGUID, ukiData, crypto.SHA256, crypto.SHA384); !reflect.DeepEqual(banks, want) {
		t.Fatalf("banks %+v, want %+v", banks, want)
	}
	// Only the UKI is copied out, and the scratch copy is gone afterwards.
	for _, call := range esp.calls {
		if call[0] == "mcopy" && !strings.Contains(strings.Join(call, " "), "::/EFI/BOOT/BOOTAA64.EFI") {
			t.Errorf("copied more than the UKI: %v", call)
		}
	}
	if left, _ := os.ReadDir(staged.WorkDir); len(left) != 0 {
		t.Errorf("the scratch directory was left in the work dir: %v", left)
	}

	// The owner GUID is the U-Boot manifest's: another owner predicts another
	// PCR 7, and a manifest without one means U-Boot's default.
	other, _, err := cfg.measureImage(context.Background(), image, &StagedMedia{Target: staged.Target, WorkDir: staged.WorkDir,
		UBoot: writeUBootBuild(t, ""), SecureBoot: staged.SecureBoot})
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(other[0].PCRs[7], banks[0].PCRs[7]) {
		t.Error("PCR 7 does not depend on the U-Boot manifest's owner GUID")
	}
	defaulted := &StagedMedia{UBoot: uboot.Artifacts{Binary: staged.UBoot.Binary}, SecureBoot: staged.SecureBoot}
	if want := predicted(t, defaulted, uboot.DefaultOwnerGUID, ukiData, crypto.SHA256, crypto.SHA384); !reflect.DeepEqual(other, want) {
		t.Errorf("no owner GUID in the manifest: %+v, want U-Boot's default owner %+v", other, want)
	}
}

func TestMeasureImageSkipsASecureBootOffBuild(t *testing.T) {
	staged, image, esp := measuredStaging(t, testOwnerGUID, measuretest.UKI("ro"))
	staged.SecureBoot = nil
	banks, unmeasured, err := (&BuildConfig{Runner: esp.run}).measureImage(context.Background(), image, staged)
	if err != nil || banks != nil || unmeasured != UnmeasuredSecureBootOff {
		t.Fatalf("banks %v, unmeasured %q, err %v", banks, unmeasured, err)
	}
	if len(esp.calls) != 0 {
		t.Errorf("an unmeasured image was read: %v", esp.calls)
	}
}

func TestMeasureImageFailsOnAMissingInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, staged *StagedMedia, esp *mtoolsRunner)
		pcr  int
		step string
	}{
		{"no UKI on the EFI partition", func(_ *testing.T, _ *StagedMedia, esp *mtoolsRunner) {
			delete(esp.files, "EFI/BOOT/BOOTAA64.EFI")
		}, 4, "reading the image's inputs"},
		{"no DB certificate", func(t *testing.T, staged *StagedMedia, _ *mtoolsRunner) {
			if err := os.Remove(filepath.Join(staged.SecureBoot.CertDir, "DB.crt")); err != nil {
				t.Fatal(err)
			}
		}, 7, "reading the image's inputs"},
		{"a UKI without an initrd", func(_ *testing.T, _ *StagedMedia, esp *mtoolsRunner) {
			uki := esp.files["EFI/BOOT/BOOTAA64.EFI"]
			i := strings.Index(string(uki), ".initrd")
			copy(uki[i:], ".rodata")
		}, 9, "predicting the PCRs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			staged, image, esp := measuredStaging(t, testOwnerGUID, measuretest.UKI("ro"))
			tc.edit(t, staged, esp)
			banks, _, err := (&BuildConfig{Runner: esp.run}).measureImage(context.Background(), image, staged)
			var me *MeasureError
			var missing *measure.MissingInputError
			if !errors.As(err, &me) || me.Step != tc.step || !errors.As(err, &missing) || missing.PCR != tc.pcr {
				t.Fatalf("err %v, want step %q missing a PCR %d input", err, tc.step, tc.pcr)
			}
			if banks != nil {
				t.Errorf("a failed measurement returned banks %v", banks)
			}
		})
	}

	staged, image, esp := measuredStaging(t, testOwnerGUID, measuretest.UKI("ro"))
	if err := os.Remove(filepath.Join(filepath.Dir(staged.UBoot.Dir), uboot.ManifestName)); err != nil {
		t.Fatal(err)
	}
	var me *MeasureError
	if _, _, err := (&BuildConfig{Runner: esp.run}).measureImage(context.Background(), image, staged); !errors.As(err, &me) || me.Step != "reading the U-Boot manifest" {
		t.Fatalf("no U-Boot manifest: err %v", err)
	}
	staged, image, esp = measuredStaging(t, testOwnerGUID, measuretest.UKI("ro"))
	esp.fail = "mdir"
	if _, _, err := (&BuildConfig{Runner: esp.run}).measureImage(context.Background(), image, staged); !errors.As(err, &me) || me.Step != "copying the UKI out of the EFI partition" {
		t.Fatalf("an unreadable EFI partition: err %v", err)
	}
}

// Create measures the image it built: a Secure Boot off build says it is
// unmeasured, and a Secure Boot build whose image cannot be measured fails.
func TestCreateMeasuresTheImage(t *testing.T) {
	t.Parallel()
	res, err := Create(context.Background(), buildConfigForTest(t, "qemu-virt", &diskimagetest.Runner{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Measurements != nil || res.Unmeasured != UnmeasuredSecureBootOff {
		t.Errorf("Secure Boot off: measurements %v, unmeasured %q", res.Measurements, res.Unmeasured)
	}

	cfg := buildConfigForTest(t, "qemu-virt", &diskimagetest.Runner{})
	cfg.ISO.SecureBoot = true
	cfg.ISO.GenerateKeys = false
	authenticodetest.WriteKeyPair(t, cfg.ISO.KeysDir)
	for _, role := range []string{"PK", "KEK"} {
		_, certPath := authenticodetest.WriteKeyPair(t, t.TempDir())
		data, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg.ISO.KeysDir, role+".crt"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The stand-in container writes an image with no partition table, so
	// there is no EFI partition to copy the UKI from.
	var me *MeasureError
	if res, err := Create(context.Background(), cfg); !errors.As(err, &me) || res != nil {
		t.Fatalf("an image that cannot be measured: result %+v, err %v", res, err)
	}
}
