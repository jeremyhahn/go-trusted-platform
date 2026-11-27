package measure

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CheckManifestEventLog checks a boot's TCG event log against the signed
// measurement manifest the build wrote for an image. The predicted PCRs come
// from the signed manifest, the measured ones from the boot's own log, so a
// match shows that a boot of this image extends the PCRs its manifest
// predicts (the factory-image row of docs/SPEC.md).
//
// The caller supplies the image's SHA-256, the platform CA roots the
// manifest's signature must verify to, and the log a booted guest exposes as
// binary_bios_measurements. In order: the signature is verified at at
// (VerifyManifest's error is returned as is); the manifest's TagID must be
// the image's (a *ManifestImageError otherwise, before the log is read); then
// the log is checked against the manifest's banks and CheckEventLog's error
// is returned as is (a *MalformedEventLogError, a *MissingBankError, or the
// joined *PCRMismatchError values). The SignedManifest is returned on every
// path after a good signature.
func CheckManifestEventLog(signed, imageSHA256 []byte, roots *x509.CertPool, at time.Time, eventLog []byte) (SignedManifest, error) {
	sm, err := VerifyManifest(signed, roots, at)
	if err != nil {
		return SignedManifest{}, err
	}
	id, err := ManifestTagID(imageSHA256)
	if err != nil {
		return sm, err
	}
	if id != sm.Manifest.TagID {
		return sm, &ManifestImageError{Want: id, Got: sm.Manifest.TagID}
	}
	return sm, CheckEventLog(eventLog, sm.Manifest.Banks)
}

// ManifestImageError reports that the manifest describes another image: its
// TagID (Got) is not the ManifestTagID of the image checked (Want).
type ManifestImageError struct {
	Want, Got uuid.UUID
}

func (e *ManifestImageError) Error() string {
	return fmt.Sprintf("measure: the manifest is for image tag %s, not %s (this image's)", e.Got, e.Want)
}
