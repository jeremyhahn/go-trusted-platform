package pkcs8

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"strings"

	"github.com/op/go-logging"
	libpkcs8 "github.com/youmark/pkcs8"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store"
	blobstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type Params struct {
	Logger         *logging.Logger
	KeyDir         string
	DefaultKeySize int
	Random         io.Reader
	Backend        store.Backend
	SignerStore    store.SignerStorer
	BlobStore      blobstore.BlobStorer
}

type KeyStorePKCS8 struct {
	params Params
	keystore.KeyStorer
}

// Creates a new PKCS #8 key store
func NewKeyStorePKCS8(params Params) keystore.KeyStorer {
	return KeyStorePKCS8{
		params: params,
	}
}

// Returns the key store type as a string
func (pkcs8 KeyStorePKCS8) Type() keystore.StoreType {
	return keystore.STORE_PKCS8
}

// Create new private key using the provided key attributes
// and return an OpaqueKey implementing crypto.Signer
func (ks KeyStorePKCS8) CreateKey(attrs keystore.KeyAttributes) (keystore.OpaqueKey, error) {
	if attrs.RSAAttributes != nil && attrs.KeyAlgorithm == x509.RSA {
		return ks.CreateRSA(attrs)

	} else if attrs.ECCAttributes != nil {
		if attrs.KeyAlgorithm == x509.ECDSA {
			return ks.CreateECDSA(attrs)
		}
		if attrs.KeyAlgorithm == x509.Ed25519 {
			return ks.CreateEd25519(attrs)
		}
	}
	return nil, keystore.ErrInvalidKeyAlgorithm
}

// Create new RSA private key and return an OpaqueKey implementing crypto.Signer
func (ks KeyStorePKCS8) CreateRSA(attrs keystore.KeyAttributes) (keystore.OpaqueKey, error) {

	// Provide default key size if not specified or less than 512 bits
	if attrs.RSAAttributes.KeySize == 0 || attrs.RSAAttributes.KeySize < 512 {
		attrs.RSAAttributes.KeySize = ks.params.DefaultKeySize
	}

	// Generate the key
	privateKey, err := rsa.GenerateKey(ks.params.Random, attrs.RSAAttributes.KeySize)
	if err != nil {
		return nil, err
	}

	// Save the key to the key store
	err = ks.save(attrs, privateKey)
	if err != nil {
		return nil, err
	}

	keystore.DebugKeyAttributes(ks.params.Logger, attrs)

	// Return the new key as an opaque private key implementing
	// crypto.Signer and crypto.Decrypter
	return keystore.NewOpaqueKey(ks, attrs, &privateKey.PublicKey), nil
}

// Creates a new ECDSA private key and return and OpaqueKey
// implementing crypto.Signer
func (ks KeyStorePKCS8) CreateECDSA(attrs keystore.KeyAttributes) (keystore.OpaqueKey, error) {
	privateKey, err := ecdsa.GenerateKey(attrs.ECCAttributes.Curve, ks.params.Random)
	if err != nil {
		return nil, err
	}
	err = ks.save(attrs, privateKey)
	if err != nil {
		return nil, err
	}

	keystore.DebugKeyAttributes(ks.params.Logger, attrs)

	return keystore.NewOpaqueKey(ks, attrs, &privateKey.PublicKey), nil
}

// Creates a new Ed25519 private key and return and OpaqueKey
// implementing crypto.Signer
func (ks KeyStorePKCS8) CreateEd25519(attrs keystore.KeyAttributes) (keystore.OpaqueKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(ks.params.Random)
	if err != nil {
		return nil, err
	}
	err = ks.save(attrs, privateKey)
	if err != nil {
		return nil, err
	}

	keystore.DebugKeyAttributes(ks.params.Logger, attrs)

	return keystore.NewOpaqueKey(ks, attrs, publicKey), nil
}

// Returns a PKCS #8 crypto.Signer based on the provided key attributes
func (ks KeyStorePKCS8) Signer(attrs keystore.KeyAttributes) (crypto.Signer, error) {

	// Retrieve the requested key
	key, err := ks.privKey(attrs)
	if err != nil {
		return nil, err
	}

	if attrs.RSAAttributes != nil {
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
		}
	} else if attrs.ECCAttributes != nil {
		if attrs.KeyAlgorithm == x509.ECDSA {
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
	}

	return nil, fmt.Errorf("%s: %s",
		keystore.ErrInvalidSignatureAlgorithm, attrs.KeyAlgorithm)
}

// Returns a custom PKCS #8 verifier
func (ks KeyStorePKCS8) Verifier(
	attrs keystore.KeyAttributes,
	opts *keystore.VerifyOpts) keystore.Verifier {

	return NewVerifier(ks.params.SignerStore)
}

// Returns a PKCS #8 crypto.Decrypter from the dedicated encryption keys partition.
func (ks KeyStorePKCS8) Decrypter(attrs keystore.KeyAttributes) (crypto.Decrypter, error) {
	ks.privKey(attrs)
	return nil, nil
}

// Returns a private key RSA key backed by this PKCS #8 key store
// for signing and decryption operations
func (ks KeyStorePKCS8) Key(attrs keystore.KeyAttributes) (crypto.Signer, error) {
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
// This is the PKCA #8 key store implementation for
// the opaque key's  crypto.PrivateKey implementation
// https://pkg.go.dev/crypto#PrivateKey
func (ks KeyStorePKCS8) Equal(opaque keystore.Opaque, x crypto.PrivateKey) bool {
	rsaPriv, ok := x.(*rsa.PrivateKey)
	if !ok {
		return false
	}
	return rsaPriv.Equal(x)
}

// Extracts the public key from the private key, encodes both to supported
// formats (DER, PEM, PKCS1, PKCS8), and saves them to the key store.
func (ks KeyStorePKCS8) save(
	attrs keystore.KeyAttributes,
	privateKey crypto.PrivateKey) error {

	var err error
	var pubKeyDER []byte

	if attrs.KeyAlgorithm == x509.RSA {
		rsaPriv, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return keystore.ErrInvalidPrivateKeyRSA
		}
		pubKeyDER, err = store.EncodePubKey(&rsaPriv.PublicKey)
		if err != nil {
			return err
		}

	} else if attrs.KeyAlgorithm == x509.ECDSA {
		ecdsaPriv, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return keystore.ErrInvalidPrivateKeyECDSA
		}
		pubKeyDER, err = store.EncodePubKey(&ecdsaPriv.PublicKey)
		if err != nil {
			return err
		}
	} else if attrs.KeyAlgorithm == x509.Ed25519 {
		ed25519Priv, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return keystore.ErrInvalidPrivateKeyEd25519
		}
		pubKeyDER, err = store.EncodePubKey(ed25519Priv.Public())
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("%s: %s", keystore.ErrInvalidKeyAlgorithm, attrs.KeyAlgorithm)
	}

	// Private Key: Marshal to DER ASN.1 PKCS #8 (w/ optional password)
	pkcs8, err := store.EncodePrivKey(privateKey, attrs.Password)
	err = ks.params.Backend.Save(attrs, pkcs8, store.FSEXT_PRIVATE_PKCS8, nil)
	if err != nil {
		return err
	}

	// Private Key: Encode to PEM
	pkcs8PEM, err := store.EncodePrivKeyPEM(attrs, privateKey)
	if err != nil {
		return err
	}

	// Private Key: Save PKCS8 PEM encoded key
	err = ks.params.Backend.Save(attrs, pkcs8PEM, store.FSEXT_PRIVATE_PKCS8_PEM, nil)
	if err != nil {
		return err
	}

	// Public Key: Save the ASN.1 DER PKCS1 form
	err = ks.params.Backend.Save(attrs, pubKeyDER, store.FSEXT_PUBLIC_PKCS1, nil)
	if err != nil {
		return err
	}
	// Public Key: Encdode to PEM form
	pubPEM, err := store.EncodePubKeyPEM(attrs.CN, pubKeyDER)
	if err != nil {
		return err
	}
	// Public Key: Save PEM form
	err = ks.params.Backend.Save(attrs, pubPEM, store.FSEXT_PUBLIC_PEM, nil)
	if err != nil {
		return err
	}
	return nil
}

// Returns a PKCS #8 private key from the backend
func (ks KeyStorePKCS8) privKey(attrs keystore.KeyAttributes) (crypto.PrivateKey, error) {
	// keyExt := ks.params.Backend.KeyFileExtension(attrs.KeyAlgorithm, store.FSEXT_PRIVATE_PKCS8)
	// bytes, err := ks.params.Backend.Get(attrs, keyExt, nil)
	var bytes []byte
	var err error
	var key interface{}
	if attrs.X509Attributes != nil {

		switch attrs.X509Attributes.Type {

		case keystore.X509_TYPE_LOCAL_ATTESTATION:
			// Attestation's are signed using the CA key. Look for the CA key in the
			// CA keys partition.
			partition := store.PARTITION_CA
			bytes, err = ks.params.Backend.Get(attrs, store.FSEXT_PRIVATE_PKCS8, &partition)
			if err != nil {
				return nil, err
			}
			key, err = libpkcs8.ParsePKCS8PrivateKey(bytes, attrs.Password)
		case keystore.X509_TYPE_REMOTE_ATTESTATION:
			// 	bytes, err = ks.params.Backend.Get(attrs, store.FSEXT_PRIVATE_PKCS8, nil)
			// Attestation's are signed using the CA key. Look for the CA key in the
			// CA keys partition.
			partition := store.PARTITION_CA
			bytes, err = ks.params.Backend.Get(attrs, store.FSEXT_PRIVATE_PKCS8, &partition)
			if err != nil {
				return nil, err
			}
			key, err = libpkcs8.ParsePKCS8PrivateKey(bytes, attrs.Password)
			bytes, err = ks.params.Backend.Get(attrs, store.FSEXT_PRIVATE_PKCS8, &partition)
			if err != nil {
				return nil, err
			}
			key, err = libpkcs8.ParsePKCS8PrivateKey(bytes, attrs.AuthPassword)

		case keystore.X509_TYPE_TLS:
			bytes, err = ks.params.Backend.Get(attrs, store.FSEXT_PRIVATE_PKCS8, nil)
			key, err = libpkcs8.ParsePKCS8PrivateKey(bytes, attrs.Password)
		}

	} else {
		keyExt := ks.params.Backend.KeyFileExtension(attrs.KeyAlgorithm, store.FSEXT_PRIVATE_PKCS8)
		bytes, err = ks.params.Backend.Get(attrs, keyExt, nil)
		if err != nil {
			return nil, err
		}
		key, err = libpkcs8.ParsePKCS8PrivateKey(bytes, attrs.Password)
	}
	if err != nil {
		if strings.Contains(err.Error(), "asn1: structure error: tags don't match") {
			return nil, store.ErrInvalidPassword
		}
		return nil, err
	}

	return key.(crypto.PrivateKey), nil
}
