package tpm2

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Creates a new ECDSA child key using the provided key attributes
func (tpm *TPM2) CreateECDSA(
	keyAttrs *keystore.KeyAttributes,
	backend keystore.KeyBackend,
	overwrite bool) (*ecdsa.PublicKey, error) {

	if keyAttrs.Parent == nil {
		return nil, keystore.ErrInvalidParentAttributes
	}

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

	// Get the key password
	if keyAttrs.Password != nil {
		keyUserAuth, err = keyAttrs.Password.Bytes()
		if err != nil {
			return nil, err
		}
	}

	// Create the parent key authorization session
	session, closer, err := tpm.CreateSession(keyAttrs)
	if err != nil {
		return nil, err
	}
	defer closer()

	eccTemplate := ECCP256Template
	if keyAttrs.PlatformPolicy {
		// Attach platform PCR policy digest if configured
		eccTemplate.AuthPolicy = tpm.PlatformPolicyDigest()
	}

	// Create ECC key
	response, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2BTemplate(&eccTemplate),
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
				InPublic: tpm2.New2B(eccTemplate),
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

			session2, closer, err := tpm.CreateKeySession(keyAttrs)
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

	tpm.logger.Debugf("tpm: ECC Key loaded to transient handle 0x%x", handle)
	tpm.logger.Debugf("tpm: ECC Key Name: %s", Encode(name.Buffer))
	tpm.logger.Debugf("tpm: ECC Parent (SRK) Name: %s", Encode(srkName.Buffer))

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
	if err := tpm.SaveKeyPair(keyAttrs, private, public, backend, overwrite); err != nil {
		return nil, err
	}

	outPub, err := public.Contents()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	ecDetail, err := outPub.Parameters.ECCDetail()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	curve, err := ecDetail.CurveID.Curve()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	eccUnique, err := outPub.Unique.ECC()
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	eccPub := &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	return eccPub, nil
}
