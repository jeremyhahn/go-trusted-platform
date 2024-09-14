package tpm2

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

// Creates a new key under the provided Storage Root Key (SRK),
// optionally sealing a provided secret to the current Platform
// Golden Integrity Measurements. If a secret is not provided, a
// random AES-256 key will be generated. If the
// HandleType is marked as TPMHTTransient, the created objects handles
// are left unflushed and the caller is responsible for flushing it when
// done.
func (tpm *TPM2) Seal(
	keyAttrs *keystore.KeyAttributes,
	backend keystore.KeyBackend) (*tpm2.CreateResponse, error) {

	if keyAttrs.Parent == nil {
		return nil, keystore.ErrInvalidParentAttributes
	}

	var session tpm2.Session
	var closer func() error
	var err error
	var keyUserAuth, secretBytes []byte

	srkHandle := tpm2.TPMHandle(keyAttrs.Parent.TPMAttributes.Handle)
	srkName, _, err := tpm.ReadHandle(srkHandle)
	if err != nil {
		return nil, err
	}

	// Set the key password authorization value if provided
	if keyAttrs.Password != nil && !keyAttrs.PlatformPolicy {
		keyUserAuth, err = keyAttrs.Password.Bytes()
		if err != nil {
			return nil, err
		}
	}

	if keyAttrs.TPMAttributes == nil {
		keyAttrs.TPMAttributes = &keystore.TPMAttributes{
			Template: KeyedHashTemplate,
		}
	}
	if keyAttrs.TPMAttributes.Template.Type == 0 {
		keyAttrs.TPMAttributes.Template = KeyedHashTemplate
	}

	if keyAttrs.PlatformPolicy {
		// Attach platform PCR policy digest if configured
		keyAttrs.TPMAttributes.Template.AuthPolicy = tpm.PlatformPolicyDigest()
	}

	if keyAttrs.Secret == nil {
		tpm.logger.Infof("Generating %s HMAC seal secret", keyAttrs.CN)
		secretBytes = aesgcm.NewAESGCM(
			tpm.logger, tpm.debugSecrets, tpm).GenerateKey()

		if keyAttrs.PlatformPolicy {
			// keyAttrs.Secret = NewPlatformSecret(tpm, keyAttrs)
			keyAttrs.Secret = keystore.NewClearPassword(secretBytes)
		} else {
			keyAttrs.Secret = keystore.NewClearPassword(secretBytes)
		}
	} else {
		secretBytes, err = keyAttrs.Secret.Bytes()
		if err != nil {
			return nil, err
		}
		if secretBytes == nil {
			return nil, keystore.ErrInvalidKeyedHashSecret
		}
	}

	if tpm.debugSecrets {
		tpm.logger.Debugf(
			"tpm: sealing %s HMAC secret: %s",
			keyAttrs.CN, secretBytes)
	}

	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Create a new seal key under the persisted SRK
	sealKeyResponse, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic: tpm2.New2B(keyAttrs.TPMAttributes.Template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: keyUserAuth,
				},
				Data: tpm2.NewTPMUSensitiveCreate(
					&tpm2.TPM2BSensitiveData{
						Buffer: secretBytes,
					},
				),
			},
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	closer() // tpm2.Create CreateSession

	// Create a new tpm2.Load session
	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer closer()

	var loadResponse *tpm2.LoadResponse
	loadResponse, err = tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Name:   srkName,
			Auth:   session,
		},
		InPublic:  sealKeyResponse.OutPublic,
		InPrivate: sealKeyResponse.OutPrivate,
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer tpm.Flush(loadResponse.ObjectHandle)

	tpm.logger.Debugf(
		"tpm: %s key loaded to transient handle 0x%x",
		keyAttrs.CN, loadResponse.ObjectHandle)

	tpm.logger.Debugf(
		"tpm: %s key Name: %s",
		keyAttrs.CN, Encode(loadResponse.Name.Buffer))

	if keyAttrs.TPMAttributes == nil {
		keyAttrs.TPMAttributes = &keystore.TPMAttributes{
			Name:   loadResponse.Name,
			Handle: loadResponse.ObjectHandle,
		}
	} else {
		keyAttrs.TPMAttributes.Name = loadResponse.Name
		keyAttrs.TPMAttributes.Handle = loadResponse.ObjectHandle
	}

	// Save the public and private areas to blob storage
	if err := tpm.SaveKeyPair(
		keyAttrs,
		sealKeyResponse.OutPrivate,
		sealKeyResponse.OutPublic,
		backend); err != nil {

		return nil, err
	}

	return sealKeyResponse, nil
}

// Returns sealed data for a keyed hash using the platform
// PCR Policy Session to satisfy the TPM to release the secret.
func (tpm *TPM2) Unseal(
	keyAttrs *keystore.KeyAttributes,
	backend keystore.KeyBackend) ([]byte, error) {

	if keyAttrs.Parent == nil {
		return nil, keystore.ErrInvalidParentAttributes
	}

	var session tpm2.Session
	var closer func() error
	var err error

	// Create session from parent key attributes
	session, closer, err = tpm.CreateSession(keyAttrs)
	if err != nil {
		return nil, err
	}
	defer closer()

	// Load the key pair from disk using the parent session
	sealKey, err := tpm.LoadKeyPair(keyAttrs, &session, backend)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer tpm.Flush(sealKey.ObjectHandle)

	// Create key session
	session2, closer2, err2 := tpm.CreateKeySession(keyAttrs)
	if err2 != nil {
		tpm.logger.Error(err)
		return nil, err
	}
	defer closer2()

	// Unseal the data using the key session
	unseal, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: sealKey.ObjectHandle,
			Name:   sealKey.Name,
			Auth:   session2,
		},
	}.Execute(tpm.transport)
	if err != nil {
		tpm.logger.Error(err)
		return nil, err
	}

	// Set TPM attributes
	if keyAttrs.TPMAttributes == nil {
		keyAttrs.TPMAttributes = &keystore.TPMAttributes{
			Handle: sealKey.ObjectHandle,
			Name:   sealKey.Name,
		}
	} else {
		keyAttrs.TPMAttributes.Name = sealKey.Name
		keyAttrs.TPMAttributes.Handle = sealKey.ObjectHandle
	}

	secret := unseal.OutData.Buffer

	if tpm.debugSecrets {
		tpm.logger.Debugf(
			"Retrieved sealed HMAC secret: %s:%s",
			keyAttrs.CN, secret)
	}

	return secret, nil
}
