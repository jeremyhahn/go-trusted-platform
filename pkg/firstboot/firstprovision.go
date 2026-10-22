package firstboot

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// ekCertificateSetting is the installer config key that accepts a TPM
// without an EK certificate (disk.encryption.tpm).
const ekCertificateSetting = "disk.encryption.tpm.allow-missing-ek-certificate"

// ErrEKCertificateMissing is the sentinel an EKCertificateMissingError
// matches with errors.Is.
var ErrEKCertificateMissing = errors.New("TPM has no EK certificate")

// EKCertificateMissingError refuses a TPM without an EK certificate when the
// admin has not relaxed the EK requirement
// (docs/installer/architecture.md "First provision, the EK and recovery").
type EKCertificateMissingError struct {
	// Cause is the SDK's report of the failed lookup.
	Cause error
}

func (e *EKCertificateMissingError) Error() string {
	return fmt.Sprintf("%v: the EK certificate is required unless %s is true: %v",
		ErrEKCertificateMissing, ekCertificateSetting, e.Cause)
}

// Is matches ErrEKCertificateMissing.
func (e *EKCertificateMissingError) Is(target error) bool {
	return target == ErrEKCertificateMissing
}

// Unwrap returns the SDK's lookup error.
func (e *EKCertificateMissingError) Unwrap() error { return e.Cause }

// ekCertificateReader is the part of the TPM the EK gate reads.
type ekCertificateReader interface {
	EKCertificate() (*x509.Certificate, error)
}

// requireEKCertificate decides whether firstboot may provision this TPM. A
// TPM with an EK certificate proceeds. A TPM without one is refused with an
// EKCertificateMissingError, unless allowMissing is set, in which case it
// proceeds and a warning naming the relaxation is written to log. Any other
// lookup failure is returned wrapped: the TPM is not provisioned on an EK
// state firstboot could not read.
func requireEKCertificate(tpm ekCertificateReader, allowMissing bool, log io.Writer) error {
	cert, err := tpm.EKCertificate()
	if err == nil && cert != nil {
		return nil
	}
	if err != nil && !errors.Is(err, xkmssdk.ErrTPMEndorsementCertNotFound) {
		return &WrappedError{Msg: "EK certificate lookup failed", Err: err}
	}
	if err == nil {
		err = xkmssdk.ErrTPMEndorsementCertNotFound
	}
	if !allowMissing {
		return &EKCertificateMissingError{Cause: err}
	}
	fmt.Fprintf(log, "[FIRSTBOOT-SEAL] WARNING: TPM has no EK certificate; provisioning it anyway because %s is true\n", ekCertificateSetting)
	return nil
}

// provisioningState is what firstboot finds on the ESP before it touches
// the TPM.
type provisioningState int

const (
	// firstProvision: no sealed object on the ESP. The TPM never held this
	// node's seal, so firstboot provisions it and seals.
	firstProvision provisioningState = iota
	// sealPresent: a sealed object exists, so a seal was made before. A
	// failure from here on is recovery, never first provision.
	sealPresent
)

// classifyProvisioning applies the contract in docs/installer/architecture.md
// "First provision, the EK and recovery": no seal-platform.pub on the ESP is
// first provision; a seal-platform.pub is a seal that existed. It returns the
// state and, for sealPresent, the file that decided it. The installer's
// pcr-banks file is never a marker: it exists on every install boot.
func classifyProvisioning(efiPath string) (provisioningState, string) {
	marker := filepath.Join(efiPath, strategySealPub)
	if _, err := os.Stat(marker); err == nil {
		return sealPresent, marker
	}
	return firstProvision, ""
}
