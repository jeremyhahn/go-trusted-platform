package diskimage

import (
	"context"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure/measuretest"
)

// preseedUBoot rewrites the staged u-boot.bin as a U-Boot build for the staged
// certificates would leave it: the binary followed by the PK, KEK and db
// signature lists it seeds its EFI variables from.
func preseedUBoot(t *testing.T, staged *StagedMedia, ukiData []byte) {
	t.Helper()
	ukiPath := filepath.Join(t.TempDir(), "BOOTAA64.EFI")
	if err := os.WriteFile(ukiPath, ukiData, 0o644); err != nil {
		t.Fatal(err)
	}
	img, err := measure.ReadImage(measure.ImageFiles{UBoot: staged.UBoot.Binary, UKI: ukiPath, CertDir: staged.SecureBoot.CertDir, OwnerGUID: testOwnerGUID})
	if err != nil {
		t.Fatal(err)
	}
	bin := append([]byte{}, measuretest.UBoot()...)
	bin = append(bin, img.SecureBoot.PK...)
	bin = append(bin, img.SecureBoot.KEK...)
	bin = append(bin, img.SecureBoot.DB...)
	if err := os.WriteFile(staged.UBoot.Binary, bin, 0o644); err != nil {
		t.Fatal(err)
	}
}

// rotateCert replaces role's certificate in dir with a fresh one.
func rotateCert(t *testing.T, dir, role string) {
	t.Helper()
	_, certPath := authenticodetest.WriteKeyPair(t, t.TempDir())
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, role+".crt"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMeasureImageChecksThePrebuiltUBootKeys(t *testing.T) {
	ukiData := measuretest.UKI("root=/dev/mapper/root ro")
	refused := func(t *testing.T, banks []measure.Bank, err error) {
		t.Helper()
		if banks != nil {
			t.Errorf("banks %+v from a refused U-Boot, want none", banks)
		}
		var me *MeasureError
		if !errors.As(err, &me) {
			t.Fatalf("err %v, want a *MeasureError", err)
		}
		var mismatch *PreseededKeysMismatchError
		if !errors.As(err, &mismatch) {
			t.Fatalf("err %v, want a *PreseededKeysMismatchError", err)
		}
		if mismatch.Variable != "PK" {
			t.Errorf("mismatch names %q, want PK", mismatch.Variable)
		}
	}

	t.Run("matching keys", func(t *testing.T) {
		staged, image, esp := measuredStaging(t, testOwnerGUID, ukiData)
		preseedUBoot(t, staged, ukiData)
		cfg := &BuildConfig{Runner: esp.run, UBootDir: filepath.Dir(staged.UBoot.Dir), MeasurementBanks: []crypto.Hash{crypto.SHA256}}
		banks, _, err := cfg.measureImage(context.Background(), image, staged)
		if err != nil {
			t.Fatalf("measureImage: %v", err)
		}
		if want := predicted(t, staged, testOwnerGUID, ukiData, crypto.SHA256); !reflect.DeepEqual(banks, want) {
			t.Fatalf("banks %+v, want %+v", banks, want)
		}
	})

	t.Run("rotated PK and KEK, same DB", func(t *testing.T) {
		staged, image, esp := measuredStaging(t, testOwnerGUID, ukiData)
		preseedUBoot(t, staged, ukiData)
		rotateCert(t, staged.SecureBoot.CertDir, "PK")
		rotateCert(t, staged.SecureBoot.CertDir, "KEK")
		cfg := &BuildConfig{Runner: esp.run, UBootDir: filepath.Dir(staged.UBoot.Dir), MeasurementBanks: []crypto.Hash{crypto.SHA256}}
		banks, _, err := cfg.measureImage(context.Background(), image, staged)
		refused(t, banks, err)
	})

	t.Run("prebuilt without lists", func(t *testing.T) {
		staged, image, esp := measuredStaging(t, testOwnerGUID, ukiData)
		cfg := &BuildConfig{Runner: esp.run, UBootDir: filepath.Dir(staged.UBoot.Dir), MeasurementBanks: []crypto.Hash{crypto.SHA256}}
		banks, _, err := cfg.measureImage(context.Background(), image, staged)
		refused(t, banks, err)
	})

	t.Run("built locally", func(t *testing.T) {
		staged, image, esp := measuredStaging(t, testOwnerGUID, ukiData)
		cfg := &BuildConfig{Runner: esp.run, MeasurementBanks: []crypto.Hash{crypto.SHA256}}
		banks, _, err := cfg.measureImage(context.Background(), image, staged)
		if err != nil {
			t.Fatalf("measureImage: %v", err)
		}
		if want := predicted(t, staged, testOwnerGUID, ukiData, crypto.SHA256); !reflect.DeepEqual(banks, want) {
			t.Fatalf("banks %+v, want %+v", banks, want)
		}
	})
}
