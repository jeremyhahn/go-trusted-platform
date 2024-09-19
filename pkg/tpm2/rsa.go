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
	var handle tpm2.TPMHandle
	var name tpm2.TPM2BName
	var private tpm2.TPM2BPrivate
	var public tpm2.TPM2BPublic

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
		rsaTemplate.AuthPolicy = tpm.PlatformPolicyDigest()
	}

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
		if err == ErrCommandNotSupported {
			// Perform create and load using logacy command sequence
			createRsp, err := tpm2.Create{
				ParentHandle: tpm2.AuthHandle{
					Handle: srkHandle,
					Name:   srkName,
					Auth:   session,
				},
				InPublic: tpm2.New2B(rsaTemplate),
				InSensitive: tpm2.TPM2BSensitiveCreate{
					Sensitive: &tpm2.TPMSSensitiveCreate{
						UserAuth: tpm2.TPM2BAuth{
							Buffer: keyUserAuth,
						},
					},
				},
			}.Execute(tpm.transport)
			if err != nil {
				return nil, err
			}

			session2, closer, err := tpm.CreateSession(keyAttrs)
			if err != nil {
				return nil, err
			}
			defer closer()

			loadResponse, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: keyAttrs.Parent.TPMAttributes.Handle,
					Name:   keyAttrs.Parent.TPMAttributes.Name,
					Auth:   session2,
				},
				InPrivate: tpm2.TPM2BPrivate{
					Buffer: createRsp.OutPrivate.Buffer,
				},
				InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](createRsp.OutPublic.Bytes()),
			}.Execute(tpm.transport)
			if err != nil {
				tpm.logger.Errorf("%s: %s", err, keyAttrs.CN)
				return nil, err
			}
			handle = loadResponse.ObjectHandle
			name = loadResponse.Name
			private = createRsp.OutPrivate
			public = createRsp.OutPublic
			defer tpm.Flush(loadResponse.ObjectHandle)
		} else {
			tpm.logger.Error(err)
			return nil, err
		}
	} else {
		handle = response.ObjectHandle
		name = response.Name
		private = response.OutPrivate
		public = response.OutPublic
		defer tpm.Flush(response.ObjectHandle)
	}

	tpm.logger.Debugf("tpm: RSA Key loaded to transient handle 0x%x", handle)
	tpm.logger.Debugf("tpm: RSA Key Name: %s", Encode(name.Buffer))
	tpm.logger.Debugf("tpm: RSA Parent (SRK) Name: %s", Encode(srkName.Buffer))

	if keyAttrs.TPMAttributes == nil {
		keyAttrs.TPMAttributes = &keystore.TPMAttributes{
			Name:   name,
			Handle: handle,
		}
	} else {
		keyAttrs.TPMAttributes.Name = name
		keyAttrs.TPMAttributes.Handle = handle
	}

	// Save the public and private areas to blob storage
	if err := tpm.SaveKeyPair(keyAttrs, private, public, backend); err != nil {
		return nil, err
	}

	pub, err := public.Contents()
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

// Performs RSA decryption
func (tpm *TPM2) RSADecrypt(handle tpm2.TPMHandle, blob []byte) ([]byte, error) {
	response, err := tpm2.RSADecrypt{
		KeyHandle:  handle,
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

// Performs RSA encryption
func (tpm *TPM2) RSAEncrypt(handle tpm2.TPMHandle, message []byte) ([]byte, error) {

	response, err := tpm2.RSAEncrypt{
		KeyHandle: handle,
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
