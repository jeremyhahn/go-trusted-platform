package firstboot

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/require"
)

// fakeEKReader returns a fixed EK certificate lookup result.
type fakeEKReader struct {
	cert *x509.Certificate
	err  error
}

func (f fakeEKReader) EKCertificate() (*x509.Certificate, error) { return f.cert, f.err }

// lookupErr is a lookup failure that is not "no certificate".
type lookupErr struct{}

func (lookupErr) Error() string { return "TPM_RC_FAILURE" }

func TestRequireEKCertificate_Present(t *testing.T) {
	for _, allow := range []bool{false, true} {
		var log bytes.Buffer
		err := requireEKCertificate(fakeEKReader{cert: &x509.Certificate{}}, allow, &log)
		require.NoError(t, err)
		require.Empty(t, log.String(), "a TPM with an EK certificate logs no relaxation")
	}
}

func TestRequireEKCertificate_AbsentRefusedByDefault(t *testing.T) {
	notFound := &WrappedError{Msg: "NV read", Err: xkmssdk.ErrTPMEndorsementCertNotFound}
	var log bytes.Buffer
	err := requireEKCertificate(fakeEKReader{err: notFound}, false, &log)

	var refused *EKCertificateMissingError
	require.ErrorAs(t, err, &refused)
	require.ErrorIs(t, err, ErrEKCertificateMissing)
	require.ErrorIs(t, err, xkmssdk.ErrTPMEndorsementCertNotFound)
	require.Contains(t, err.Error(), "EK certificate")
	require.Contains(t, err.Error(), ekCertificateSetting)
	require.Empty(t, log.String())
}

// A lookup that returns neither a certificate nor an error is a missing
// certificate, not a present one.
func TestRequireEKCertificate_NilCertificateRefused(t *testing.T) {
	err := requireEKCertificate(fakeEKReader{}, false, &bytes.Buffer{})
	require.ErrorIs(t, err, ErrEKCertificateMissing)
}

func TestRequireEKCertificate_AbsentRelaxedWarns(t *testing.T) {
	var log bytes.Buffer
	err := requireEKCertificate(fakeEKReader{err: xkmssdk.ErrTPMEndorsementCertNotFound}, true, &log)
	require.NoError(t, err)
	require.Contains(t, log.String(), "WARNING")
	require.Contains(t, log.String(), "no EK certificate")
	require.Contains(t, log.String(), ekCertificateSetting)
}

// A lookup that failed for another reason is not a missing certificate:
// the relaxation does not cover it.
func TestRequireEKCertificate_LookupFailure(t *testing.T) {
	for _, allow := range []bool{false, true} {
		err := requireEKCertificate(fakeEKReader{err: lookupErr{}}, allow, &bytes.Buffer{})
		require.Error(t, err)
		require.False(t, errors.Is(err, ErrEKCertificateMissing))
		require.ErrorAs(t, err, new(lookupErr))
	}
}

func TestEKCertificateMissingError_IsOnlyItsSentinel(t *testing.T) {
	err := &EKCertificateMissingError{Cause: xkmssdk.ErrTPMEndorsementCertNotFound}
	require.ErrorIs(t, err, ErrEKCertificateMissing)
	require.False(t, errors.Is(err, ErrTPMNotAvailable))
}

func TestAllowMissingEKCertificate_DefaultsToRequired(t *testing.T) {
	// No installer container is mounted in a unit test, so no config is
	// found and the default applies.
	s := NewFirstbootSealStrategy(nil, nil, testLogger())
	require.False(t, s.allowMissingEKCertificate())
}

func TestClassifyProvisioning_FirstProvision(t *testing.T) {
	efi := t.TempDir()
	// pcr-banks exists on every install boot; it is not a seal.
	require.NoError(t, os.MkdirAll(filepath.Join(efi, "tpm2"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(efi, "tpm2", "pcr-banks"), []byte("sha256"), 0600))

	state, marker := classifyProvisioning(efi)
	require.Equal(t, firstProvision, state)
	require.Empty(t, marker)
}

func TestClassifyProvisioning_SealPresent(t *testing.T) {
	efi := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(efi, "tpm2"), 0700))
	sealPub := filepath.Join(efi, "tpm2", "seal-platform.pub")
	require.NoError(t, os.WriteFile(sealPub, []byte("pub"), 0600))

	state, marker := classifyProvisioning(efi)
	require.Equal(t, sealPresent, state)
	require.Equal(t, sealPub, marker)
}

func TestClassifyProvisioning_MissingESP(t *testing.T) {
	state, _ := classifyProvisioning(filepath.Join(t.TempDir(), "absent"))
	require.Equal(t, firstProvision, state)
}
