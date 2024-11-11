package pkcs8

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"

	"github.com/google/go-tpm/tpm2"
	libtpm2 "github.com/google/go-tpm/tpm2"
	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	tpmks "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/tpm2"
	tptpm2 "github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	libpkcs8 "github.com/youmark/pkcs8"
)

type Params struct {
	Config       *Config
	DebugSecrets bool
	Logger       *logging.Logger
	Random       io.Reader
	Backend      keystore.KeyBackend
	SignerStore  keystore.SignerStorer
	BlobStore    blobstore.BlobStorer
	TPMKS        tpmks.PlatformKeyStorer
}

type KeyStore struct {
	params *Params
	keystore.KeyStorer
}

// PKCS #8 Key Store Module. This module saves keys to the the provided
// backend in PKCS #8 form.
func NewKeyStore(params *Params) (keystore.KeyStorer, error) {

	ks := &KeyStore{params: params}

	// secret, err := ks.password(ks.keyAttrsTemplate())
	// if err != nil {
	// 	return nil, err
	// }
	// _, err = secret.String()
	// if err != nil {
	// 	if err == keystore.ErrFileNotFound {
	// 		return ks, keystore.ErrNotInitalized
	// 	}
	// 	return nil, err
	// }

	return ks, nil
}

// No-op method that implements keystore.KeyStorer
func (ks *KeyStore) Initialize(soPIN, userPIN keystore.Password) error {

	if ks.params.TPMKS == nil {
		return keystore.ErrNotInitalized
	}

	// // Generate new PIN if not provided via Secret parameter
	// var newPin string
	// var err error

	// // if userPIN == nil || userPIN == keystore.NewClearPassword([]byte(keystore.DEFAULT_PASSWORD)) {
	// if userPIN == nil {
	// 	pinBytes := aesgcm.NewAESGCM(
	// 		ks.params.Logger, ks.params.DebugSecrets, ks.params.Random).GenerateKey()
	// 	userPIN = keystore.NewClearPassword(pinBytes)
	// 	newPin = string(pinBytes)
	// } else {
	// 	newPin, err = userPIN.String()
	// 	if err != nil {
	// 		ks.params.Logger.Error(err)
	// 		return err
	// 	}
	// 	if newPin == keystore.DEFAULT_PASSWORD {
	// 		pinBytes := aesgcm.NewAESGCM(
	// 			ks.params.Logger, ks.params.DebugSecrets, ks.params.Random).GenerateKey()
	// 		userPIN = keystore.NewClearPassword(pinBytes)
	// 		newPin = string(pinBytes)
	// 	}
	// }

	// // Get the platform key store SRK attributes
	// srkAttrs := ks.params.TPMKS.SRKAttributes()

	// // Generate child key under the platform key store SRK
	// keyAttrs := ks.keyAttrsTemplate()

	// if ks.params.DebugSecrets {
	// 	ks.params.Logger.Debug("keystore/pkcs8: security officer PIN: N/A")
	// 	ks.params.Logger.Debugf(
	// 		"keystore/pkcs8: user PIN: %s:%s", keyAttrs.CN, newPin)
	// }

	// keyAttrs.Secret = userPIN
	// keyAttrs.Parent = srkAttrs
	// keyAttrs.TPMAttributes.Hierarchy = srkAttrs.TPMAttributes.Hierarchy
	// err = ks.params.TPMKS.TPM2().GenerateKeyedHash(keyAttrs)
	// if err != nil {
	// 	ks.params.Logger.Error(err)
	// 	return err
	// }

	return nil
}

// Returns key attriibutes for the PKCS #8 key store pin
func (ks *KeyStore) keyAttrsTemplate() *keystore.KeyAttributes {
	tpmkskAttrs := ks.params.TPMKS.SRKAttributes()
	return &keystore.KeyAttributes{
		CN:             fmt.Sprintf("%s.pin", ks.params.Config.CN),
		Debug:          ks.params.DebugSecrets,
		KeyAlgorithm:   x509.PublicKeyAlgorithm(tpm2.TPMAlgKeyedHash),
		KeyType:        keystore.KEY_TYPE_HMAC,
		Parent:         tpmkskAttrs,
		PlatformPolicy: ks.params.Config.PlatformPolicy,
		Hash:           tpmkskAttrs.Hash,
		StoreType:      keystore.STORE_PKCS8,
		TPMAttributes: &keystore.TPMAttributes{
			HandleType: libtpm2.TPMHTTransient,
			Hierarchy:  tpm2.TPMRHOwner,
			Template:   tptpm2.KeyedHashTemplate,
		},
	}
}

// Returns the key store backend
func (ks *KeyStore) Backend() keystore.KeyBackend {
	return ks.params.Backend
}

// No-op method that implements keystore.KeyStorer
func (ks *KeyStore) Close() error {
	return nil
}

// Returns the key store type as a string
func (ks *KeyStore) Type() keystore.StoreType {
	return keystore.STORE_PKCS8
}

// Deletes a key pair from the key store
func (ks *KeyStore) Delete(attrs *keystore.KeyAttributes) error {
	return ks.params.Backend.Delete(attrs)
}

// Generate new private key using the provided key attributes
// and return an OpaqueKey implementing crypto.Signer
func (ks *KeyStore) GenerateKey(attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {
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

// Generate new RSA private key and return an OpaqueKey implementing crypto.Signer
func (ks *KeyStore) GenerateRSA(attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {
	return ks.generateRSA(attrs, false)
}

func (ks *KeyStore) generateRSA(
	attrs *keystore.KeyAttributes, overwrite bool) (keystore.OpaqueKey, error) {

	ks.params.Logger.Debug("keystore/pkcs8: generating RSA key")
	// Provide default key size if not specified or less than 512 bits
	if attrs.RSAAttributes == nil {
		attrs.RSAAttributes = &keystore.RSAAttributes{
			KeySize: 2048,
		}
	}
	if attrs.RSAAttributes.KeySize == 0 || attrs.RSAAttributes.KeySize < 512 {
		attrs.RSAAttributes.KeySize = 2048
	}
	// Generate the key
	privateKey, err := rsa.GenerateKey(ks.params.Random, attrs.RSAAttributes.KeySize)
	if err != nil {
		return nil, err
	}
	// Save the key to the key store.
	err = ks.save(attrs, privateKey, overwrite)
	if err != nil {
		return nil, err
	}
	keystore.DebugKeyAttributes(ks.params.Logger, attrs)
	// Return the new key as an opaque private key implementing
	// crypto.Signer and crypto.Decrypter
	return keystore.NewOpaqueKey(ks, attrs, &privateKey.PublicKey), nil
}

// Generates a new ECDSA private key and return and OpaqueKey
// implementing crypto.Signer
func (ks *KeyStore) GenerateECDSA(attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {
	return ks.generateECDSA(attrs, false)
}

func (ks *KeyStore) generateECDSA(
	attrs *keystore.KeyAttributes, overwrite bool) (keystore.OpaqueKey, error) {

	ks.params.Logger.Debug("keystore/pkcs8: generating ECDSA key")
	if attrs.ECCAttributes == nil {
		attrs.ECCAttributes = &keystore.ECCAttributes{
			Curve: elliptic.P256(),
		}
	}
	if attrs.ECCAttributes.Curve.Params() == nil {
		attrs.ECCAttributes.Curve = elliptic.P256()
	}
	privateKey, err := ecdsa.GenerateKey(attrs.ECCAttributes.Curve, ks.params.Random)
	if err != nil {
		return nil, err
	}
	err = ks.save(attrs, privateKey, overwrite)
	if err != nil {
		return nil, err
	}
	keystore.DebugKeyAttributes(ks.params.Logger, attrs)
	return keystore.NewOpaqueKey(ks, attrs, &privateKey.PublicKey), nil
}

// Generates a new Ed25519 private key and return and OpaqueKey
// implementing crypto.Signer
func (ks *KeyStore) GenerateEd25519(attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {
	return ks.generateEd25519(attrs, false)
}

func (ks *KeyStore) generateEd25519(
	attrs *keystore.KeyAttributes,
	overwrite bool) (keystore.OpaqueKey, error) {

	ks.params.Logger.Debug("keystore/pkcs8: generating Ed25519 key")
	publicKey, privateKey, err := ed25519.GenerateKey(ks.params.Random)
	if err != nil {
		return nil, err
	}
	err = ks.save(attrs, privateKey, overwrite)
	if err != nil {
		return nil, err
	}
	keystore.DebugKeyAttributes(ks.params.Logger, attrs)
	return keystore.NewOpaqueKey(ks, attrs, publicKey), nil
}

// Generates a new AES-256 32 byte secret key
func (ks *KeyStore) GenerateSecretKey(
	attrs *keystore.KeyAttributes) error {

	// bytes := aesgcm.NewAESGCM(
	// 	ks.params.Logger,
	// 	ks.params.DebugSecrets,
	// 	ks.params.Random).GenerateKey()

	// err := ks.Backend().Save(attrs, bytes, keystore.FSEXT_PRIVATE_BLOB)
	// if err != nil {
	// 	return err
	// }
	// return nil

	return ks.params.TPMKS.GenerateSecretKey(attrs)
}

// Rotates an existing key by generating a new key pair and overwriting
// the existing key. This is a destructive operation that will cause the
// existing key pair to be irrecoverable.
func (ks *KeyStore) RotateKey(attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return ks.generateRSA(attrs, true)
	case x509.ECDSA:
		return ks.generateECDSA(attrs, true)
	case x509.Ed25519:
		return ks.generateEd25519(attrs, true)
	}
	return nil, keystore.ErrInvalidKeyAlgorithm
}

// Returns a PKCS #8 crypto.Signer based on the provided key attributes
func (ks *KeyStore) Signer(attrs *keystore.KeyAttributes) (crypto.Signer, error) {

	// Retrieve the requested key
	key, err := ks.privKey(attrs)
	if err != nil {
		return nil, err
	}

	if attrs.KeyAlgorithm == x509.RSA {
		rsaPriv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, keystore.ErrInvalidPrivateKeyRSA
		}
		return NewSignerRSA(
			ks,
			ks.params.SignerStore,
			attrs,
			&rsaPriv.PublicKey), nil

	} else if attrs.KeyAlgorithm == x509.ECDSA {
		ecdsaPriv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, keystore.ErrInvalidPrivateKeyECDSA
		}
		return NewSignerECDSA(
			ks,
			ks.params.SignerStore,
			attrs,
			&ecdsaPriv.PublicKey), nil
	} else if attrs.KeyAlgorithm == x509.Ed25519 {
		ed25519Priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, keystore.ErrInvalidPrivateKeyECDSA
		}
		return NewSignerEd25519(
			ks,
			ks.params.SignerStore,
			attrs,
			ed25519Priv.Public()), nil
	}

	return nil, fmt.Errorf("%s: %s",
		keystore.ErrInvalidSignatureAlgorithm, attrs.KeyAlgorithm)
}

// Returns a custom PKCS #8 verifier
func (ks *KeyStore) Verifier(
	attrs *keystore.KeyAttributes,
	opts *keystore.VerifyOpts) keystore.Verifier {

	return keystore.NewVerifier(ks.params.SignerStore)
}

// Returns a PKCS #8 crypto.Decrypter from the dedicated encryption keys partition.
func (ks *KeyStore) Decrypter(attrs *keystore.KeyAttributes) (crypto.Decrypter, error) {
	ks.privKey(attrs)
	return nil, nil
}

// Returns a private key RSA key backed by this PKCS #8 key store.
// for signing and decryption operations
func (ks *KeyStore) Key(attrs *keystore.KeyAttributes) (keystore.OpaqueKey, error) {
	privKey, err := ks.privKey(attrs)
	if err != nil {
		return nil, err
	}
	if attrs.KeyAlgorithm == x509.RSA {
		rsaPriv, ok := privKey.(*rsa.PrivateKey)
		if ok {
			return keystore.NewOpaqueKey(ks, attrs, rsaPriv.Public()), nil
		}
	} else if attrs.KeyAlgorithm == x509.ECDSA {
		ecdsaPriv, ok := privKey.(*ecdsa.PrivateKey)
		if ok {
			return keystore.NewOpaqueKey(ks, attrs, ecdsaPriv.Public()), nil
		}
	} else if attrs.KeyAlgorithm == x509.Ed25519 {
		ed25519Priv, ok := privKey.(ed25519.PrivateKey)
		if ok {
			return keystore.NewOpaqueKey(ks, attrs, ed25519Priv.Public()), nil
		}
	}
	return nil, fmt.Errorf("%s: %s",
		keystore.ErrInvalidSignatureAlgorithm, attrs.KeyAlgorithm)
}

// Returns a private key RSA key backed by this PKCS #8 key store.
// for signing and decryption operations
func (ks *KeyStore) PrivateKey(attrs *keystore.KeyAttributes) (crypto.Signer, error) {
	privKey, err := ks.privKey(attrs)
	if err != nil {
		return nil, err
	}
	if attrs.KeyAlgorithm == x509.RSA {
		rsaPriv, ok := privKey.(*rsa.PrivateKey)
		if ok {
			return rsaPriv, err
		}
	} else if attrs.KeyAlgorithm == x509.ECDSA {
		ecdsaPriv, ok := privKey.(*ecdsa.PrivateKey)
		if ok {
			return ecdsaPriv, err
		}
	} else if attrs.KeyAlgorithm == x509.Ed25519 {
		ed25519Priv, ok := privKey.(ed25519.PrivateKey)
		if ok {
			return ed25519Priv, err
		}
	}
	return nil, fmt.Errorf("%s: %s",
		keystore.ErrInvalidSignatureAlgorithm, attrs.KeyAlgorithm)
}

// Compares an opaque key with the provided key
// This is the PKCA #8 key store. implementation for
// the opaque key's  crypto.PrivateKey implementation
// https://pkg.go.dev/crypto#PrivateKey
func (ks *KeyStore) Equal(opaque keystore.OpaqueKey, x crypto.PrivateKey) bool {

	var xPub crypto.PublicKey
	switch x.(type) {

	case *rsa.PrivateKey:
		xPub = x.(*rsa.PrivateKey).Public()
		return opaque.Public().(*rsa.PublicKey).Equal(xPub)

	case *ecdsa.PrivateKey:
		xPub = x.(*ecdsa.PrivateKey).Public()
		return opaque.Public().(*ecdsa.PublicKey).Equal(xPub)

	case ed25519.PrivateKey:
		xPub = x.(ed25519.PrivateKey).Public()
		return opaque.Public().(ed25519.PublicKey).Equal(xPub)

	case crypto.PrivateKey:
		if _, ok := x.(*rsa.PublicKey); ok {
			xPub = x.(crypto.PublicKey)
			return opaque.Public().(*rsa.PublicKey).Equal(xPub)
		}
		if _, ok := x.(*ecdsa.PublicKey); ok {
			xPub = x.(crypto.PublicKey)
			return opaque.Public().(*ecdsa.PublicKey).Equal(xPub)
		}
		if _, ok := x.(ed25519.PublicKey); ok {
			xPub = x.(crypto.PublicKey)
			return opaque.Public().(ed25519.PublicKey).Equal(xPub)
		}
		if _, ok := x.(keystore.OpaqueKey); ok {
			xPub := x.(keystore.OpaqueKey).Public()
			switch xPub.(type) {
			case *rsa.PublicKey:
				return opaque.Public().(*rsa.PublicKey).Equal(xPub)
			case *ecdsa.PublicKey:
				return opaque.Public().(*ecdsa.PublicKey).Equal(xPub)
			case ed25519.PublicKey:
				return opaque.Public().(ed25519.PublicKey).Equal(xPub)
			}
		}
	}

	return false
}

// Extracts the public key from the private key, encodes both to supported
// formats (DER, PEM, PKCS1, PKCS8), and saves them to the key store .
func (ks *KeyStore) save(
	attrs *keystore.KeyAttributes,
	privateKey crypto.PrivateKey,
	overwrite bool) error {

	var err error
	var pubKeyDER, password []byte

	// If the key is configured with a platform policy, save the password
	// to the platform key store with the platform PCR authorization policy
	if attrs.Password != nil {
		if err := ks.params.TPMKS.CreatePassword(attrs, ks.params.Backend, overwrite); err != nil {
			return err
		}
		password, err = attrs.Password.Bytes()
		if err != nil {
			return err
		}
	}

	if attrs.KeyAlgorithm == x509.RSA {
		rsaPriv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return keystore.ErrInvalidPrivateKeyRSA
		}
		pubKeyDER, err = keystore.EncodePubKey(&rsaPriv.PublicKey)
		if err != nil {
			return err
		}

	} else if attrs.KeyAlgorithm == x509.ECDSA {
		ecdsaPriv, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return keystore.ErrInvalidPrivateKeyECDSA
		}
		pubKeyDER, err = keystore.EncodePubKey(&ecdsaPriv.PublicKey)
		if err != nil {
			return err
		}
	} else if attrs.KeyAlgorithm == x509.Ed25519 {
		ed25519Priv, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return keystore.ErrInvalidPrivateKeyEd25519
		}
		pubKeyDER, err = keystore.EncodePubKey(ed25519Priv.Public())
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("%s: %s", keystore.ErrInvalidKeyAlgorithm, attrs.KeyAlgorithm)
	}

	// Private Key: Marshal to DER ASN.1 PKCS #8
	pkcs8, err := keystore.EncodePrivKey(privateKey, password)
	err = ks.params.Backend.Save(attrs, pkcs8, keystore.FSEXT_PRIVATE_PKCS8, overwrite)
	if err != nil {
		return err
	}

	// Public Key: Save the ASN.1 DER PKCS1 form
	err = ks.params.Backend.Save(attrs, pubKeyDER, keystore.FSEXT_PUBLIC_PKCS1, overwrite)
	if err != nil {
		return err
	}
	return nil
}

// Returns a PKCS #8 private key from the backend
func (ks *KeyStore) privKey(attrs *keystore.KeyAttributes) (crypto.PrivateKey, error) {
	bytes, err := ks.params.Backend.Get(attrs, keystore.FSEXT_PRIVATE_PKCS8)
	if err != nil {
		return nil, err
	}
	var password []byte
	if attrs.Password != nil {
		if attrs.Parent == nil {
			attrs.Parent = ks.params.TPMKS.SRKAttributes()
		}
		password, err = attrs.Password.Bytes()
		if err != nil {
			// This code could is intended to save a caller who doesnt set the
			// PlatformPassword properly, but im undecided on implementing it
			// as it complicates the logic here and is possibly black-box magic
			// that makes debugging difficult.
			// if attrs.PlatformPolicy {
			// 	password, err = tptpm2.NewPlatformPassword(
			// 		ks.params.Logger, ks.params.TPMKS.TPM2(), attrs, ks.params.Backend).Bytes()
			// 	if err == keystore.ErrFileNotFound {
			// 		password, err = attrs.Password.Bytes()
			// 	}
			// } else {
			// 	return nil, err
			// }
			return nil, err
		}
	}
	key, err := libpkcs8.ParsePKCS8PrivateKey(bytes, password)
	if err != nil {
		keystore.DebugKeyAttributes(ks.params.Logger, attrs)
		if strings.Contains(err.Error(), "asn1: structure error: tags don't match") {
			return nil, keystore.ErrInvalidPassword
		}
		if strings.Contains(err.Error(), "pkcs8: incorrect password") {
			if ks.params.DebugSecrets || attrs.Debug {
				ks.params.Logger.Debugf("%s: %s:%s", err, attrs.CN, password)
			}
			return nil, keystore.ErrInvalidPassword
		}
		return nil, err
	}
	return key.(crypto.PrivateKey), nil
}
