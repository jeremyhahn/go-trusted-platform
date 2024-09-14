package tpm2

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Creates a new RSA child key using the provided key attributes
func (tpm *TPM2) CreateSecretKey(
	keyAttrs *keystore.KeyAttributes,
	backend keystore.KeyBackend) error {

	if keyAttrs.Parent == nil {
		return keystore.ErrInvalidKeyAttributes
	}

	// Get the persisted SRK
	srkHandle := tpm2.TPMHandle(keyAttrs.Parent.TPMAttributes.Handle)
	srkName, _, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		return err
	}

	// Create new AES key under the SRK, optionally protected by the
	// platform auth policy that requires the platform PCR value with
	// the Golden Integrity Measurements to release.
	aesTemplate := AES256CFBTemplate

	// Attach platform PCR policy digest if configured
	if keyAttrs.PlatformPolicy {
		aesTemplate.AuthPolicy = tpm.PlatformPolicyDigest()
	}

	// Create the parent key authorization session
	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return err
	}
	defer closer()

	response, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2B(aesTemplate),
	}.Execute(tpm.transport)
	if err != nil {
		return err
	}

	// Save the public and private areas to blob storage
	if err := tpm.SaveKeyPair(
		keyAttrs,
		response.OutPrivate,
		response.OutPublic,
		backend); err != nil {

		return err
	}

	return nil
}
