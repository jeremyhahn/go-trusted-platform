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
	backend keystore.KeyBackend) (*ecdsa.PublicKey, error) {

	if keyAttrs.Parent == nil {
		return nil, keystore.ErrInvalidParentAttributes
	}

	var keyUserAuth []byte

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
		eccTemplate.AuthPolicy = tpm.policyDigest
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

	outPub, err := response.OutPublic.Contents()
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
