package diskimage

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uki"
)

// UnmeasuredSecureBootOff is Result.Unmeasured for a build with Secure Boot
// off: no db authority verifies the UKI, so PCR 7 has no value to predict
// and the image gets no measurement manifest.
const UnmeasuredSecureBootOff = "Secure Boot is off: PCR 7 has no db authority to predict, so the image has no measurement manifest"

// MeasureError reports a finished image whose PCRs could not be predicted.
// A missing input unwraps to a measure.MissingInputError naming its PCR.
type MeasureError struct {
	Step string
	Err  error
}

// Error implements error.
func (e *MeasureError) Error() string {
	return "diskimage: measuring the image: " + e.Step + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *MeasureError) Unwrap() error { return e.Err }

// measureImage predicts measure.ManifestPCRs of the finished image for every
// configured bank. The UKI is the signed one copied out of the image's EFI
// partition; U-Boot, its owner GUID and the PK/KEK/DB certificates are the
// build's. A build with Secure Boot off is not measured: it returns no banks
// and the reason. Any missing input fails the build, so no bank is partial.
func (c *BuildConfig) measureImage(ctx context.Context, image string, staged *StagedMedia) ([]measure.Bank, string, error) {
	if staged.SecureBoot == nil {
		return nil, UnmeasuredSecureBootOff, nil
	}
	name, err := uki.BootFileName(staged.Target.Architecture())
	if err != nil {
		return nil, "", &MeasureError{Step: "naming the UKI", Err: err}
	}
	want := path.Join("EFI", "BOOT", name)
	dir, err := os.MkdirTemp(staged.WorkDir, "measure-")
	if err != nil {
		return nil, "", &MeasureError{Step: "creating a scratch directory", Err: err}
	}
	defer os.RemoveAll(dir)
	ukiPath := filepath.Join(dir, filepath.FromSlash(want))
	copied, err := ExtractESP(ctx, image, dir, func(n string) bool { return strings.EqualFold(n, want) }, c.Runner)
	if err != nil {
		return nil, "", &MeasureError{Step: "copying the UKI out of the EFI partition", Err: err}
	}
	if len(copied) == 1 {
		ukiPath = filepath.Join(dir, filepath.FromSlash(copied[0]))
	}
	manifest, err := uboot.ReadManifest(filepath.Dir(staged.UBoot.Dir))
	if err != nil {
		return nil, "", &MeasureError{Step: "reading the U-Boot manifest", Err: err}
	}
	owner := manifest.OwnerGUID
	if owner == "" {
		owner = uboot.DefaultOwnerGUID
	}
	img, err := measure.ReadImage(measure.ImageFiles{UBoot: staged.UBoot.Binary, UKI: ukiPath, CertDir: staged.SecureBoot.CertDir, OwnerGUID: owner})
	if err != nil {
		return nil, "", &MeasureError{Step: "reading the image's inputs", Err: err}
	}
	banks, err := measure.Predict(img, c.MeasurementBanks...)
	if err != nil {
		return nil, "", &MeasureError{Step: "predicting the PCRs", Err: err}
	}
	return banks, "", nil
}
