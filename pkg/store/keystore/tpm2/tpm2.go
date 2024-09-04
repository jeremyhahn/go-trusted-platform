package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/logger"

	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/aesgcm"
	tptpm2 "github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/op/go-logging"
)

type KeyStore struct {
	backend      keystore.KeyBackend
	config       *tptpm2.KeyStoreConfig
	debugSecrets bool
	logger       *logging.Logger
	platformKS   PlatformKeyStorer
	signerStore  keystore.SignerStorer
	tpm          tptpm2.TrustedPlatformModule
	PlatformKeyStorer
}

type Params struct {
	Backend          keystore.KeyBackend
	Logger           *logging.Logger
	DebugSecrets     bool
	Config           *tptpm2.KeyStoreConfig
	PlatformKeyStore PlatformKeyStorer
	SignerStore      keystore.SignerStorer
	TPM              tptpm2.TrustedPlatformModule
}

func NewKeyStore(params *Params) (PlatformKeyStorer, error) {

	ks := &KeyStore{
		logger:       params.Logger,
		backend:      params.Backend,
		config:       params.Config,
		debugSecrets: params.DebugSecrets,
		platformKS:   params.PlatformKeyStore,
		signerStore:  params.SignerStore,
		tpm:          params.TPM}

	// Try to read the key store key from it's persistent handle.
	// Return keystore.ErrNotInitialized if it can't be found.
	persistedAttrs, err := ks.tpm.TPMAttributes(tpm2.TPMHandle(params.Config.SRKHandle))
	if err != nil {
		if err == tpm2.TPMRC(0x184) {
			// TPM_RC_VALUE (handle 1): value is out of range or is not correct for the context
			return ks, keystore.ErrNotInitalized
		} else if err == tpm2.TPMRC(0x18b) {
			// TPM_RC_HANDLE (handle 1): the handle is not correct for the use
			return ks, keystore.ErrNotInitalized
		} else {
			logger.Fatal(err)
		}
	}

	srkAttrs := ks.SRKAttributes()
	srkAttrs.TPMAttributes.Name = persistedAttrs.TPMAttributes.Name
	srkAttrs.TPMAttributes.Public = persistedAttrs.TPMAttributes.Public

	return ks, nil
}

// Returns the key store backend
func (ks *KeyStore) Backend() keystore.KeyBackend {
	return ks.backend
}

// Closes the TPM connection
func (ks *KeyStore) Close() error {
	return ks.tpm.Close()
}

// Returns the underlying TPM 2.0 connection
func (ks *KeyStore) TPM2() tptpm2.TrustedPlatformModule {
	return ks.tpm
}

// Initializes the key store by provisioning the underlying TPM
// and creating a new Storage Root Key. The secret parameter
// is used as the SRK primary key password authorization. A fatal
// error is produced if the TPM hasn't been provisioned with a
// persistent EK.
func (ks *KeyStore) Initialize(soPIN, userPIN keystore.Password) error {

	ks.logger.Info("Initializing TPM 2.0 Key Store")

	if ks.config.CN == "" {
		ks.logger.Errorf("%s: %s",
			tptpm2.ErrInvalidKeyStoreConfiguration,
			"missing required CN")
		return tptpm2.ErrInvalidKeyStoreConfiguration
	}

	ekAttrs, err := ks.tpm.EKAttributes()
	if err != nil {
		return err
	}

	ekAttrs.TPMAttributes.HierarchyAuth = soPIN

	var newPin string
	var pinBytes []byte

	if userPIN == nil {
		pinBytes = aesgcm.NewAESGCM(
			ks.logger, ks.debugSecrets, ks.tpm).GenerateKey()
		userPIN = keystore.NewClearPassword(pinBytes)
		newPin = string(pinBytes)
	} else {
		newPin, err = userPIN.String()
		if err != nil {
			logger.Error(err)
			return err
		}
		if newPin == keystore.DEFAULT_PASSWORD {
			pinBytes = aesgcm.NewAESGCM(
				ks.logger, ks.debugSecrets, ks.tpm).GenerateKey()
			userPIN = keystore.NewClearPassword(pinBytes)
			newPin = string(pinBytes)
		}
	}

	// Generate dedicated key store SRK
	srkAttrs := ks.SRKAttributes()
	srkAttrs.Parent = ekAttrs
	srkAttrs.Password = userPIN
	srkAttrs.TPMAttributes.HierarchyAuth = soPIN
	err = ks.tpm.CreateSRK(srkAttrs)
	if err != nil {
		return err
	}
	// if srkAttrs.PlatformPolicy {
	// 	srkAttrs.Password = NewPlatformSecret(ks.backend, ks.tpm, srkAttrs)
	// }

	// Seal the SRK auth to a keyed hash under the PLATFORM KEY STORE
	ksAttrs := ks.KeyAttributes()
	ksAttrs.Parent = srkAttrs

	if ks.platformKS == nil {
		// This is the platform key store - seal the PIN and store to this backend
		_, err = ks.tpm.Seal(ksAttrs, ks.backend)
	} else {
		// This is the TPM 2.0 key store - seal the PIN and store to PLATFORM backend
		// to keep all key store PINs in the same backend
		_, err = ks.tpm.Seal(ksAttrs, ks.platformKS.Backend())
	}
	if err != nil {
		return err
	}

	if ks.debugSecrets {

		ks.logger.Debugf(
			"keystore/tpm2: hierarchy auth / security officer PIN: %s:%s",
			ksAttrs.CN, soPIN)

		// ks.logger.Debugf("keystore/tpm2: key auth / user PIN: %s:%s",
		// 	ksAttrs.CN, newPin)
	}

	return nil
}

// Returns the key store dedicated SRK attributes using it's persistent
// handle.
func (ks *KeyStore) SRKAttributes() *keystore.KeyAttributes {

	srkHandle := tpm2.TPMHandle(ks.config.SRKHandle)

	var srkAttrs *keystore.KeyAttributes
	var err error

	ekAttrs, err := ks.tpm.EKAttributes()
	if err != nil {
		ks.logger.Fatal(err)
	}

	srkAttrs, err = ks.tpm.TPMAttributes(srkHandle)
	if err != nil {

		if err == tpm2.TPMRC(0x18b) || err == keystore.ErrFileNotFound {
			// TPM_RC_HANDLE (handle 1): the handle is not correct for the use
			srkTemplate := tpm2.RSASRKTemplate
			srkTemplate.ObjectAttributes.NoDA = false

			srkAttrs = &keystore.KeyAttributes{
				CN:             ks.config.CN,
				KeyAlgorithm:   x509.RSA,
				KeyType:        keystore.KEY_TYPE_STORAGE,
				PlatformPolicy: ks.config.PlatformPolicy,
				StoreType:      keystore.STORE_TPM2,
				TPMAttributes: &keystore.TPMAttributes{
					Handle:     srkHandle,
					HandleType: tpm2.TPMHTPersistent,
					Hierarchy:  tpm2.TPMRHOwner,
					Template:   srkTemplate,
				}}

			if ks.config.PlatformPolicy {
				srkTemplate.AuthPolicy = ks.tpm.PolicyDigest()
			}
		} else {
			ks.logger.Fatal(err)
		}
	}
	srkAttrs.Parent = ekAttrs

	if ks.config.PlatformPolicy {
		// srkAttrs.Password = NewPlatformSecret(ks.backend, ks.tpm, srkAttrs)
		srkAttrs.PlatformPolicy = true
	}

	return srkAttrs
}

// Returns the key attributes for the key store secret sealed to the SRK
func (ks *KeyStore) KeyAttributes() *keystore.KeyAttributes {
	srkAttrs := ks.SRKAttributes()
	ksAttrs := &keystore.KeyAttributes{
		CN:             fmt.Sprintf("%s.pin", ks.config.CN),
		KeyAlgorithm:   x509.PublicKeyAlgorithm(tpm2.TPMAlgKeyedHash),
		KeyType:        keystore.KEY_TYPE_HMAC,
		Parent:         srkAttrs,
		Password:       srkAttrs.Password,
		PlatformPolicy: srkAttrs.PlatformPolicy,
		StoreType:      keystore.STORE_TPM2,
		TPMAttributes: &keystore.TPMAttributes{
			HandleType: tpm2.TPMHTTransient,
			Hierarchy:  tpm2.TPMRHOwner,
			Template:   tptpm2.KeyedHashTemplate,
		},
	}
	if ksAttrs.PlatformPolicy {
		if ks.platformKS == nil {
			ksAttrs.Password = tptpm2.NewPlatformPassword(
				ks.logger, ks.tpm, ksAttrs, ks.backend)
		} else {
			ksAttrs.Password = tptpm2.NewPlatformPassword(
				ks.logger, ks.tpm, ksAttrs, ks.platformKS.Backend())
		}
	}
	// } else {
	// 	ksAttrs.Password = password.NewRequiredPassword()
	// }
	return ksAttrs
}

// Deletes a key pair from the key store
func (ks *KeyStore) Delete(attrs *keystore.KeyAttributes) error {
	return ks.backend.Delete(attrs)
}

// Generates a new RSA key pair using the provided key attributes
// and returns an OpaqueKey implementing crypto.Signer using
// the underlying Trusted Platform Module.
func (ks *KeyStore) GenerateKey(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return ks.GenerateRSA(attrs)
	case x509.ECDSA:
		return ks.GenerateECDSA(attrs)
	case x509.Ed25519:
		return ks.GenerateEd25519(attrs)
	}
	return nil, keystore.ErrInvalidKeyAlgorithm
}

// Generates a new RSA key pair using the provided key attributes
// and returns an OpaqueKey implementing crypto.Signer using
// the underlying Trusted Platform Module.
func (ks *KeyStore) GenerateRSA(
	keyAttrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	if keyAttrs.TPMAttributes == nil {
		keyAttrs.Parent = ks.SRKAttributes()
	}
	if keyAttrs.Password != nil {
		if err := ks.CreatePassword(keyAttrs, ks.backend); err != nil {
			return nil, err
		}
	}
	rsaPub, err := ks.tpm.CreateRSA(keyAttrs, ks.backend)
	if err != nil {
		return nil, err
	}
	return keystore.NewOpaqueKey(ks, keyAttrs, rsaPub), nil
}

// Generates a new ECDSA key pair using the provided key attributes
// and returns an OpaqueKey implementing crypto.Signer using
// the underlying Trusted Platform Module.
func (ks *KeyStore) GenerateECDSA(
	keyAttrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	if keyAttrs.TPMAttributes == nil {
		keyAttrs.Parent = ks.SRKAttributes()
	}
	if keyAttrs.Password != nil {
		if err := ks.CreatePassword(keyAttrs, ks.backend); err != nil {
			return nil, err
		}
	}
	eccPub, err := ks.tpm.CreateECDSA(keyAttrs, ks.backend)
	if err != nil {
		return nil, err
	}
	return keystore.NewOpaqueKey(ks, keyAttrs, eccPub), nil
}

// Returns keystore.ErrInvalidKeyAlgorithm
func (ks *KeyStore) GenerateEd25519(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	return nil, keystore.ErrUnsupportedKeyAlgorithm
}

// Generates a new AES-256 secret key
func (ks *KeyStore) GenerateSecretKey(
	attrs *keystore.KeyAttributes) error {

	return ks.tpm.CreateSecretKey(attrs, ks.backend)
}

// Returns a Trusted Platform Module crypto.Decrypter
func (ks *KeyStore) Decrypter(
	attrs *keystore.KeyAttributes) (crypto.Decrypter, error) {

	return nil, keystore.ErrUnsupportedKeyAlgorithm
}

// Panics if called because the underlying Trusted Platform
// Module doesn't provide an API to perform an equal operation.
func (ks *KeyStore) Equal(
	opaque keystore.Opaque, x crypto.PrivateKey) bool {

	panic(keystore.ErrUnsupportedKeyAlgorithm)
}

// Returns a TPM 2.0 OpaqueKey for the requested key.
// Implements keystore.KeyStorer
func (ks *KeyStore) Key(
	keyAttrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	if keyAttrs.Parent == nil {
		keyAttrs.Parent = ks.SRKAttributes()
	}

	session, closer, err := ks.tpm.CreateSession(keyAttrs)
	if err != nil {
		return nil, err
	}
	defer closer()

	var handle tpm2.TPMHandle
	if keyAttrs.TPMAttributes == nil ||
		keyAttrs.TPMAttributes.HandleType != tpm2.TPMHTPersistent {

		// This is an ordinary key, load it from the backend
		key, err := ks.tpm.LoadKeyPair(keyAttrs, &session, ks.backend)
		if err != nil {
			return nil, err
		}
		handle = key.ObjectHandle
		if keyAttrs.TPMAttributes == nil {
			attrs, err := ks.tpm.TPMAttributes(handle)
			if err != nil {
				return nil, err
			}
			keyAttrs.TPMAttributes = attrs.TPMAttributes
		}
		defer ks.tpm.Flush(handle)

	} else {
		// This is a persisted key handle that's already loaded
		handle = keyAttrs.TPMAttributes.Handle
	}

	pub, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(ks.tpm.Transport())
	if err != nil {
		ks.logger.Error(err)
		return nil, err
	}

	outPub, err := pub.OutPublic.Contents()
	if err != nil {
		ks.logger.Error(err)
		return nil, err
	}

	if outPub.Type == tpm2.TPMAlgRSA {

		rsaDetail, err := outPub.Parameters.RSADetail()
		if err != nil {
			ks.logger.Error(err)
			return nil, err
		}
		rsaUnique, err := outPub.Unique.RSA()
		if err != nil {
			ks.logger.Error(err)
			return nil, err
		}
		rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			ks.logger.Error(err)
			return nil, err
		}
		return keystore.NewOpaqueKey(ks, keyAttrs, rsaPub), nil

	} else if outPub.Type == tpm2.TPMAlgECC {

		ecDetail, err := outPub.Parameters.ECCDetail()
		if err != nil {
			ks.logger.Error(err)
			return nil, err
		}
		curve, err := ecDetail.CurveID.Curve()
		if err != nil {
			ks.logger.Error(err)
			return nil, err
		}
		eccUnique, err := outPub.Unique.ECC()
		if err != nil {
			ks.logger.Error(err)
			return nil, err
		}
		eccPub := &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}
		return keystore.NewOpaqueKey(ks, keyAttrs, eccPub), nil
	}

	return nil, keystore.ErrUnsupportedKeyAlgorithm
}

// Returns a secret sealed to a TPM keyed hash object using
// a just-in-time retrieval strategy, If the key is configured
// with the platform PCR policy, a PlatformPassword is returned
// otherwise the password is returned in clear text.
func (ks *KeyStore) Password(
	attrs *keystore.KeyAttributes) (keystore.Password, error) {

	if attrs.PlatformPolicy {
		return tptpm2.NewPlatformPassword(
			ks.logger, ks.tpm, attrs, ks.backend), nil
	} else {
		// return password.NewRequiredPassword(), nil
		return keystore.NewClearPassword(nil), nil
	}
}

// Returns a TPM 2.0 crypto.Signer
func (ks *KeyStore) Signer(
	attrs *keystore.KeyAttributes) (crypto.Signer, error) {

	key, err := ks.Key(attrs)
	if err != nil {
		return nil, err
	}

	if attrs.KeyAlgorithm == x509.RSA {
		return NewSignerRSA(
			ks,
			ks.signerStore,
			attrs,
			key.Public(),
			ks.tpm), nil

	} else if attrs.KeyAlgorithm == x509.ECDSA {
		return NewSignerECDSA(
			ks,
			ks.signerStore,
			attrs,
			key.Public(),
			ks.tpm), nil
	}

	return nil, keystore.ErrUnsupportedKeyAlgorithm
}

// Returns the key store type
func (ks *KeyStore) Type() keystore.StoreType {
	return keystore.STORE_TPM2
}

// Returns a software runtime verifier to perform
// signature verifications. The verifier supports
// RSA PKCS1v15, RSA-PSS, ECDSA, and Ed25519.
func (ks *KeyStore) Verifier(
	attrs *keystore.KeyAttributes,
	opts *keystore.VerifyOpts) keystore.Verifier {

	return keystore.NewVerifier(ks.signerStore)
}

// Saves the password in the provided key attributes to the TPM password
// store, optionally using the provided backend. If nil, the default
// backend provider will be used.
func (ks *KeyStore) CreatePassword(
	keyAttrs *keystore.KeyAttributes, backend keystore.KeyBackend) error {

	if keyAttrs.Password == nil {
		return nil
	}

	if backend == nil {
		backend = ks.backend
	}

	passwd, err := keyAttrs.Password.Bytes()
	if err != nil {
		ks.logger.Error(err)
		return err
	}

	// Copy the password to the Secret field - the TPM seal operation
	// seals the Secret field, not the password field.

	if string(passwd) == keystore.DEFAULT_PASSWORD {
		passwd = aesgcm.NewAESGCM(
			ks.logger, ks.debugSecrets, ks.tpm).GenerateKey()
		keyAttrs.Secret = keystore.NewClearPassword(passwd)
	} else {
		keyAttrs.Secret = keyAttrs.Password
	}

	// Copy the key attributes to new secret attributes object & seal
	secretAttrs := *keyAttrs

	// Add SRK attributes if not defined
	if secretAttrs.Parent == nil {
		secretAttrs.Parent = ks.SRKAttributes()
	}

	// Passwords are stored as HMAC secrets
	secretAttrs.KeyType = keystore.KEY_TYPE_HMAC

	// Seal the secret to the TPM
	if _, err := ks.tpm.Seal(&secretAttrs, nil); err != nil {
		return err
	}

	// Replace the clear text password with the platform password
	keyAttrs.Password = tptpm2.NewPlatformPassword(
		ks.logger,
		ks.tpm,
		&secretAttrs,
		nil)

	// Clear the plain text secret from the key attributes, it's
	// no longer needed. The password is gotten from the Password
	// field now using the PlatformPassword object above.
	keyAttrs.Secret = nil

	return nil
}

// Delete a password from the TPM password store, optionally using
// the provided backend. If nil, the default backend provider will
// be used.
func (ks *KeyStore) DeletePassword(
	keyAttrs *keystore.KeyAttributes,
	backend keystore.KeyBackend) error {

	return ks.tpm.DeleteKey(keyAttrs, backend)
}
