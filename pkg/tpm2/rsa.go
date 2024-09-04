package tpm2

import (
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Creates a new RSA child key using the provided key attributes
func (tpm *TPM2) CreateRSA(
	keyAttrs *keystore.KeyAttributes,
	backend keystore.KeyBackend) (*rsa.PublicKey, error) {

	if keyAttrs.Parent == nil {
		return nil, keystore.ErrInvalidKeyAttributes
	}

	// var keyUserAuth, secretBytes []byte
	var keyUserAuth []byte

	// Get the persisted SRK
	srkHandle := tpm2.TPMHandle(keyAttrs.Parent.TPMAttributes.Handle)
	srkName, _, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		return nil, err
	}

	// Set the key password authorization value if provided
	if keyAttrs.Password != nil {
		keyUserAuth, err = keyAttrs.Password.Bytes()
		if err != nil {
			return nil, err
		}
	}

	// Create new RSA key under the SRK, optionally sealing a secret
	// protected by the platform auth policy that requires the platform
	// PCR value with the Golden Integrity Measurements to release.
	rsaTemplate := RSASSATemplate
	if keystore.IsRSAPSS(keyAttrs.SignatureAlgorithm) {
		rsaTemplate = RSAPSSTemplate
	}

	// Attach platform PCR policy digest if configured
	if keyAttrs.PlatformPolicy {
		rsaTemplate.AuthPolicy = tpm.policyDigest
	}

	// if keyAttrs.Secret == nil {
	// 	tpm.logger.Info("Generating RSA seal secret")
	// 	secretBytes = aesgcm.NewAESGCM(
	// 		tpm.logger, tpm.debugSecrets, tpm).GenerateKey()

	// 	if keyAttrs.PlatformPolicy {
	// 		// keyAttrs.Secret = NewPlatformSecret(tpm, keyAttrs)
	// 		keyAttrs.Secret = keystore.NewClearPassword(secretBytes)
	// 	} else {
	// 		keyAttrs.Secret = keystore.NewClearPassword(secretBytes)
	// 	}

	// } else {
	// 	secretBytes, err = keyAttrs.Secret.Bytes()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	// Create the parent key authorization session
	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return nil, err
	}
	defer closer()

	response, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2BTemplate(&rsaTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyUserAuth,
				},
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer tpm.Flush(response.ObjectHandle)

	tpm.logger.Debugf(
		"tpm: Key loaded to transient handle 0x%x",
		response.ObjectHandle)

	tpm.logger.Debugf(
		"tpm: Key Name: %s",
		Encode(response.Name.Buffer))

	tpm.logger.Debugf(
		"tpm: Parent (SRK) Name: %s",
		Encode(srkName.Buffer))

	if keyAttrs.TPMAttributes == nil {
		keyAttrs.TPMAttributes = &keystore.TPMAttributes{
			Name:   response.Name,
			Handle: response.ObjectHandle,
		}
	} else {
		keyAttrs.TPMAttributes.Name = response.Name
		keyAttrs.TPMAttributes.Handle = response.ObjectHandle
	}

	// Save the public and private areas to blob storage
	if err := tpm.SaveKeyPair(
		keyAttrs,
		response.OutPrivate,
		response.OutPublic,
		backend); err != nil {

		return nil, err
	}

	pub, err := response.OutPublic.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	return rsaPub, nil
}

// Decrypts an encrypted blob using the requested Attestation Key (AK)
// pointed to by akHandle.
func (tpm *TPM2) RSADecrypt(
	akHandle tpm2.TPMHandle,
	blob []byte) ([]byte, error) {

	response, err := tpm2.RSADecrypt{
		KeyHandle:  akHandle,
		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: blob},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	return response.Message.Buffer, nil
}

// Encrypts the message using the requested Attestation Key (AK)
// pointed to by akHandle.
func (tpm *TPM2) RSAEncrypt(
	akHandle tpm2.TPMHandle,
	message []byte) ([]byte, error) {

	response, err := tpm2.RSAEncrypt{
		KeyHandle: akHandle,
		Message:   tpm2.TPM2BPublicKeyRSA{Buffer: message},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	return response.OutData.Buffer, nil
}
