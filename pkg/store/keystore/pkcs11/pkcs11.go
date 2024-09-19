package pkcs11

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/ThalesIgnite/crypto11"
	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/miekg/pkcs11"
	"github.com/spf13/afero"

	libtpm2 "github.com/google/go-tpm/tpm2"
	tpm2ks "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/tpm2"
	tptpm2 "github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

var (
	contextMap = make(map[string]*crypto11.Context, 0)
)

type Params struct {
	Backend      keystore.KeyBackend
	Config       *Config
	DebugSecrets bool
	Fs           afero.Fs
	Logger       *logging.Logger
	Random       io.Reader
	SignerStore  keystore.SignerStorer
	TPMKS        tpm2ks.PlatformKeyStorer
}

type KeyStore struct {
	ctx    *crypto11.Context
	params *Params
	keystore.KeyStorer
}

// Generates a new connection to the underlying PKCS #11 module. Returns
// ErrNotInitialized if the token needs to be initialized.
func NewKeyStore(params *Params) (keystore.KeyStorer, error) {

	ks := &KeyStore{params: params}

	if strings.Contains(params.Config.Library, "libsofthsm2.so") {
		os.Setenv("SOFTHSM2_CONF", params.Config.LibraryConfig)
	}

	pinSecret, err := ks.pin()
	if err != nil {
		return nil, err
	}
	pin, err := pinSecret.String()
	if err != nil {
		if err == keystore.ErrFileNotFound {
			return ks, keystore.ErrNotInitalized
		}
		return nil, err
	} else {
		params.Config.Pin = pin
	}

	// Open an "admin connection" using the low level PKCS #11 lib
	// to get the vendor hardware / firmware info and test the connection.
	lib, err := NewPKCS11(params.Logger, params.Config)
	if err != nil {
		if strings.Contains(err.Error(), "CKR_GENERAL_ERROR") {
			return ks, keystore.ErrNotInitalized
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "CKR_CRYPTOKI_ALREADY_INITIALIZED") {
			params.Logger.Warn(err.Error())
			ctx, ok := contextMap[params.Config.Library]
			if !ok {
				return nil, err
			}
			ks.ctx = ctx
			return ks, keystore.ErrAlreadyInitialized
		}
	}

	// Attempt to log into the token
	err = lib.Login()
	if err != nil {
		if strings.Contains(err.Error(), "CKR_PIN_INCORRECT") {
			return ks, ErrInvalidUserPIN
		}
		if strings.Contains(err.Error(), "CKR_TOKEN_NOT_RECOGNIZED") {
			if err := lib.Destroy(); err != nil {
				ks.params.Logger.FatalError(err)
			}
			return ks, keystore.ErrNotInitalized
		} else if strings.Contains(err.Error(), "CKR_USER_ALREADY_LOGGED_IN") {
			ks.params.Logger.Warn(err.Error())
			ctx, ok := contextMap[params.Config.Library]
			if !ok {
				return nil, err
			}
			ks.ctx = ctx
			return ks, nil
		} else {
			return nil, err
		}
	}
	if err := lib.Destroy(); err != nil {
		ks.params.Logger.FatalError(err)
	}

	// Login was successful, return Thales PKCS #11
	// "operator connection"
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       params.Config.Library,
		Pin:        pin,
		TokenLabel: params.Config.TokenLabel,
	})
	ks.ctx = ctx
	if err != nil {
		if !strings.Contains(err.Error(), "CKR_CRYPTOKI_ALREADY_INITIALIZED") {
			ks.params.Logger.Warn(err.Error())
			ctx, ok := contextMap[params.Config.Library]
			if !ok {
				return nil, err
			}
			ks.ctx = ctx
			return ks, keystore.ErrAlreadyInitialized
		}
	}

	contextMap[params.Config.Library] = ctx

	return ks, nil
}

// Generates a new connection to the underlying PKCS #11 module
func (ks *KeyStore) Initialize(soPIN, userPIN keystore.Password) error {

	ks.params.Logger.Info("Initializing PKCS #11 Key Store")

	var pin string
	var err error

	if ks.params.Backend == nil {
		ks.params.Logger.Fatal("pkcs11: backend required")
	}

	if soPIN != nil {
		sopin, err := soPIN.String()
		if err != nil {
			return err
		}
		if len(sopin) < 4 {
			return ErrInvalidSOPINLength
		}
		if sopin == keystore.DEFAULT_PASSWORD {
			pinBytes := aesgcm.NewAESGCM(ks.params.Random).GenerateKey()
			soPIN = keystore.NewClearPassword(pinBytes)
			sopin = string(pinBytes)
		}
		ks.params.Config.SOPin = sopin
	}
	if userPIN != nil {
		pin, err = userPIN.String()
		if err != nil {
			return err
		}
		if len(pin) < 4 {
			return ErrInvalidSOPINLength
		}
		if pin == keystore.DEFAULT_PASSWORD {
			pinBytes := aesgcm.NewAESGCM(ks.params.Random).GenerateKey()
			userPIN = keystore.NewClearPassword(pinBytes)
			pin = string(pinBytes)
		}
		ks.params.Config.Pin = pin
	}

	if ks.params.DebugSecrets {
		ks.params.Logger.Debug("PKCS #11 key store PINs",
			slog.String("soPIN", ks.params.Config.SOPin),
			slog.String("userPIN", ks.params.Config.Pin),
		)
	}

	// Token label check
	if ks.params.Config.TokenLabel == "" {
		ks.params.Logger.Error(ErrInvalidTokenLabel)
		return ErrInvalidTokenLabel
	}

	ks.params.Logger.Info("Initializing PKCS #11 Token",
		slog.String("token-label", ks.params.Config.TokenLabel))

	// If this is OpenHSM, it requires initialization.
	if strings.Contains(ks.params.Config.Library, "libsofthsm2.so") {
		InitSoftHSM(ks.params.Logger, ks.params.Config)
	}

	// Generate PKCS #11 connection to the initialized HSM
	// using miekg's lower-level lib to perform admin operations.
	hsm, err := NewPKCS11(ks.params.Logger, ks.params.Config)
	if err != nil {
		if err == pkcs11.Error(0x191) {
			ks.params.Logger.Warn("CKR_CRYPTOKI_ALREADY_INITIALIZED")
		} else {
			ks.params.Logger.Error(err)
			return err
		}
	} else {

		// Generate new PKCS #11 session, set pin
		session, err := hsm.Session()
		if err != nil {
			ks.params.Logger.Error(err)
			return err
		}
		err = hsm.ctx.SetPIN(session, ks.params.Config.Pin, pin)
		if err != nil {
			ks.params.Logger.Error(err)
			return err
		}
		hsm.Close()
		hsm.Destroy()
	}

	// Get the TPM key store SRK attributes
	srkAttrs := ks.params.TPMKS.SRKAttributes()

	// Generate child key under the key store SRK
	keyAttrs := ks.keyAttrsTemplate()

	keyAttrs.Password = userPIN
	keyAttrs.Parent = srkAttrs
	keyAttrs.TPMAttributes.Hierarchy = srkAttrs.TPMAttributes.Hierarchy
	if err := ks.params.TPMKS.CreatePassword(keyAttrs, nil); err != nil {
		return err
	}

	// Return Thales PKCS #11 "operator connection"
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       ks.params.Config.Library,
		Pin:        pin,
		TokenLabel: ks.params.Config.TokenLabel,
	})
	if err != nil {
		ks.params.Logger.Error(err)
		return err
	}
	ks.ctx = ctx

	contextMap[ks.params.Config.Library] = ctx

	return nil
}

// Returns the key store backend
func (ks *KeyStore) Backend() keystore.KeyBackend {
	return ks.params.Backend
}

// Deletes a key pair from the key store - this is a no-op for PKCS #11
func (ks *KeyStore) Delete(attrs *keystore.KeyAttributes) error {
	return nil
}

// Returns the PKCS #11 password wrapped in a TPM Platform Secret
// that retrieves the password just-in-time.
func (ks *KeyStore) pin() (keystore.Password, error) {
	keyAttrs := ks.keyAttrsTemplate()
	// keyAttrs.CN = fmt.Sprintf("%s.pin", ks.params.Config.CN)
	return ks.params.TPMKS.Password(keyAttrs)
}

// Returns key attriibutes for the PKCS #11 key store pin
func (ks *KeyStore) keyAttrsTemplate() *keystore.KeyAttributes {
	tpmkskAttrs := ks.params.TPMKS.SRKAttributes()
	ksAttrs := &keystore.KeyAttributes{
		CN:             fmt.Sprintf("%s.pin", ks.params.Config.CN),
		Debug:          ks.params.DebugSecrets,
		KeyAlgorithm:   x509.PublicKeyAlgorithm(tpm2.TPMAlgKeyedHash),
		KeyType:        keystore.KEY_TYPE_HMAC,
		Parent:         tpmkskAttrs,
		PlatformPolicy: ks.params.Config.PlatformPolicy,
		Hash:           tpmkskAttrs.Hash,
		StoreType:      keystore.STORE_PKCS11,
		TPMAttributes: &keystore.TPMAttributes{
			HandleType: libtpm2.TPMHTTransient,
			Hierarchy:  tpm2.TPMRHOwner,
			Template:   tptpm2.KeyedHashTemplate,
		},
	}
	if ksAttrs.PlatformPolicy {
		ksAttrs.Password = tptpm2.NewPlatformPassword(
			ks.params.Logger, ks.params.TPMKS.TPM2(), ksAttrs, nil)
	}
	return ksAttrs
}

// Generates a new key pair using the provided key attributes
// and returns an OpaqueKey implementing crypto.Signer using
// the underlying PKCS #11 HSM module.
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
// the underlying PKCS #11 HSM module.
func (ks *KeyStore) GenerateRSA(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	ks.params.Logger.Debug("keystore/pkcs11: generating RSA key")

	if attrs.Parent == nil {
		attrs.Parent = ks.params.TPMKS.SRKAttributes()
	}

	if attrs.RSAAttributes == nil {
		attrs.RSAAttributes = &keystore.RSAAttributes{
			KeySize: 2048,
		}
	}

	id := createID(attrs)
	signerDecrypter, err := ks.ctx.GenerateRSAKeyPair(
		id,
		attrs.RSAAttributes.KeySize)

	if err != nil {
		ks.params.Logger.Error(err)
		return nil, err
	}

	keystore.DebugKeyAttributes(ks.params.Logger, attrs)

	return keystore.NewOpaqueKey(ks, attrs, signerDecrypter.Public()), nil
}

// Generates a new ECDSA key pair using the provided key attributes
// and returns an OpaqueKey implementing crypto.Signer using
// the underlying PKCS #11 HSM module.
func (ks *KeyStore) GenerateECDSA(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	ks.params.Logger.Debug("keystore/pkcs11: generating ECDSA key")

	if attrs.Parent == nil {
		attrs.Parent = ks.params.TPMKS.SRKAttributes()
	}

	if attrs.ECCAttributes == nil {
		attrs.ECCAttributes = &keystore.ECCAttributes{
			Curve: elliptic.P256(),
		}
	}

	id := createID(attrs)
	signerDecrypter, err := ks.ctx.GenerateECDSAKeyPair(
		id,
		attrs.ECCAttributes.Curve)

	if err != nil {
		ks.params.Logger.Error(err)
		return nil, err
	}

	keystore.DebugKeyAttributes(ks.params.Logger, attrs)

	return keystore.NewOpaqueKey(ks, attrs, signerDecrypter.Public()), nil
}

// Returns ErrUnsupportedKeyAlgorithm
func (ks *KeyStore) GenerateEd25519(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	return nil, ErrUnsupportedOperation
}

// Returns a PKCS #11 crypto.Decrypter
func (ks *KeyStore) Decrypter(
	attrs *keystore.KeyAttributes) (crypto.Decrypter, error) {

	id := createID(attrs)
	decrypter, err := ks.ctx.FindKeyPair(id, nil)
	if err != nil {
		return nil, err
	}
	return decrypter.(crypto.Decrypter), nil
}

// Panics if called because the underlying PKCS #11 library
// doesn't provide an API to perform an equal operation.
func (store *KeyStore) Equal(
	opaque keystore.Opaque, x crypto.PrivateKey) bool {

	panic(ErrUnsupportedOperation)
}

// Returns a PKCS #11 crypto.Signer for the requested key
func (ks *KeyStore) Key(
	attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	id := createID(attrs)
	signer, err := ks.ctx.FindKeyPair(id, nil)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, keystore.ErrFileNotFound
	}
	return keystore.NewOpaqueKey(ks, attrs, signer.Public()), nil
}

// Generates a new AES-256 secret key
func (ks *KeyStore) GenerateSecretKey(
	keyAttrs *keystore.KeyAttributes) error {

	_, err := ks.ctx.GenerateSecretKey(
		[]byte(keyAttrs.CN), 256, crypto11.CipherAES)
	if err != nil {
		return err
	}
	return nil
}

// Returns a PKCS #11 crypto.Signer
func (ks *KeyStore) Signer(
	attrs *keystore.KeyAttributes) (crypto.Signer, error) {

	id := createID(attrs)
	signer, err := ks.ctx.FindKeyPair(id, nil)
	if err != nil {
		return nil, err
	}

	if attrs.KeyAlgorithm == x509.RSA {
		return NewSignerRSA(
			ks.params.SignerStore,
			attrs,
			signer.Public(),
			ks.ctx,
			ks), nil

	} else if attrs.KeyAlgorithm == x509.ECDSA {
		return NewSignerECDSA(
			ks,
			ks.params.SignerStore,
			attrs,
			ks.ctx,
			signer.Public()), nil
	}

	return nil, keystore.ErrUnsupportedKeyAlgorithm
}

// Returns the key store type
func (ks *KeyStore) Type() keystore.StoreType {
	return keystore.STORE_PKCS11
}

// Returns a software runtime verifier to perform
// signature verifications. The verifier supports
// RSA PKCS1v15, RSA-PSS, ECDSA, and Ed25519.
func (ks *KeyStore) Verifier(
	attrs *keystore.KeyAttributes,
	opts *keystore.VerifyOpts) keystore.Verifier {

	return keystore.NewVerifier(ks.params.SignerStore)
}

// Closes the key store connection to the PKCS #11 token
func (ks *KeyStore) Close() error {
	if ks.ctx != nil {
		if err := ks.ctx.Close(); err != nil {
			return err
		}
	}
	ks.ctx = nil
	return nil
}

// Generate PKCS #11 key store id. Format as commonName.algorithm
func createID(keyAttrs *keystore.KeyAttributes) []byte {
	return []byte(fmt.Sprintf("%s.%s", keyAttrs.CN, keyAttrs.KeyAlgorithm))
}
