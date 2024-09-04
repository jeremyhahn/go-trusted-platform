package keystore

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/youmark/pkcs8"
)

// Encodes a private key to ASN.1 DER PKCS #8 form
func EncodePrivKey(privateKey crypto.PrivateKey, password []byte) ([]byte, error) {
	pkcs8, err := pkcs8.MarshalPrivateKey(privateKey, password, nil)
	if err != nil {
		return nil, err
	}
	return pkcs8, nil
}

// Encodes a DER ASN.1 private key to PEM form
// https://github.com/openssl/openssl/blob/master/include/openssl/pem.h
func EncodePrivKeyPEM(attrs *KeyAttributes, priv crypto.PrivateKey) ([]byte, error) {
	var password []byte
	var err error
	if attrs.Password != nil {
		password, err = attrs.Password.Bytes()
		if err != nil {
			return nil, err
		}
	}
	der, err := EncodePrivKey(priv, password)
	if err != nil {
		return nil, err
	}
	caPrivKeyPEM := new(bytes.Buffer)
	var keyType string
	if attrs.Password != nil {
		keyType = "ENCRYPTED PRIVATE KEY"
	} else if attrs.KeyAlgorithm == x509.RSA {
		keyType = "RSA PRIVATE KEY"
	} else if attrs.KeyAlgorithm == x509.ECDSA || attrs.KeyAlgorithm == x509.Ed25519 {
		keyType = "EC PRIVATE KEY"
	} else {
		return nil, fmt.Errorf("%s: %s",
			ErrInvalidKeyAlgorithm, attrs.KeyAlgorithm)
	}
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  keyType,
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}
	return caPrivKeyPEM.Bytes(), nil
}

// Decodes PEM encoded bytes to crypto.PrivateKey
func DecodePrivKeyPEM(bytes []byte, password Password) (crypto.PrivateKey, error) {
	var block *pem.Block
	passwd, err := password.Bytes()
	if err != nil {
		return nil, err
	}
	if block, _ = pem.Decode(bytes); block == nil {
		return nil, ErrInvalidEncodingPEM
	}
	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, passwd)
	if err != nil {
		if strings.Contains(err.Error(), "pkcs8: incorrect password") {
			return nil, ErrInvalidPassword
		}
		// The PKCS8 package doesn't always return "invalid password",
		// sometimes this ASN.1 error is given when it fails to parse the
		// private key because it's encrypted and the password is incorrect.
		// It's impossible for the private key to have been generated with
		// an invalid structure (if generated by this platform) so this
		// means the password provided was incorrect.
		if strings.Contains(err.Error(), "asn1: structure error: tags don't match") {
			return nil, ErrInvalidPassword
		}
		return nil, err
	}
	return key.(crypto.PrivateKey), nil
}

// Encodes a public key ASN.1 DER form public key to PEM form
func EncodePubKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pubPEM := new(bytes.Buffer)
	err = pem.Encode(pubPEM, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}
	return pubPEM.Bytes(), err
}

// Decodes and returns an ASN.1 DER - PEM encoded - RSA Public Key
func DecodePubKeyPEM(bytes []byte) (crypto.PublicKey, error) {
	var block *pem.Block
	if block, _ = pem.Decode(bytes); block == nil {
		return nil, ErrInvalidEncodingPEM
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pubKey.(crypto.PublicKey), nil
}

// Encodes any public key (RSA/ECC) to ASN.1 DER form
func EncodePubKey(pub any) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}