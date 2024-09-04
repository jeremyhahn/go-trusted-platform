package keystore

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"strings"
)

var (
	TemplateRSA = &KeyAttributes{
		CN:           "www.example.com",
		Hash:         crypto.SHA256,
		KeyAlgorithm: x509.RSA,
		KeyType:      KEY_TYPE_TLS,
		Password:     nil,
		RSAAttributes: &RSAAttributes{
			KeySize: 2048,
		},
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		StoreType:          STORE_PKCS8,
	}

	TemplateECDSA = &KeyAttributes{
		CN: "www.example.com",
		ECCAttributes: &ECCAttributes{
			Curve: elliptic.P256(),
		},
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            KEY_TYPE_TLS,
		Password:           nil,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		StoreType:          STORE_PKCS8,
	}

	TemplateEd25519 = &KeyAttributes{
		CN: "www.example.com",
		ECCAttributes: &ECCAttributes{
			Curve: elliptic.P256(),
		},
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.Ed25519,
		KeyType:            KEY_TYPE_TLS,
		Password:           nil,
		SignatureAlgorithm: x509.PureEd25519,
		StoreType:          STORE_PKCS8,
	}

	Templates = map[x509.PublicKeyAlgorithm]*KeyAttributes{
		x509.RSA:     TemplateRSA,
		x509.ECDSA:   TemplateECDSA,
		x509.Ed25519: TemplateEd25519,
	}
)

// Returns a new key attributes template defaulted to RSA 2048
func NewTemplate() (*KeyAttributes, error) {
	attrs, ok := Templates[x509.RSA]
	if !ok {
		return nil, ErrInvalidKeyAlgorithm
	}
	return attrs, nil
}

// Return a template for the given key algorithm
//
// Supported Algorithms:
// - RSA
// - ECDSA
// - Ed25519
//
// Returns ErrInvalidKeyAlgorithm or ErrInvalidKeyType for respective errors
func Template(algorithm x509.PublicKeyAlgorithm) (*KeyAttributes, error) {
	attrs, ok := Templates[algorithm]
	if !ok {
		return nil, ErrInvalidKeyAlgorithm
	}
	return attrs, nil
}

// Parses the provided algorithm and returns the requested template
// or ErrInvalidKeyAlgorithm if the algorithm is not RSA, ECDSA, or
// Ed25519.
func TemplateFromString(algorithm string) (*KeyAttributes, error) {
	switch strings.ToLower(algorithm) {
	case "rsa":
		return Templates[x509.RSA], nil
	case "ecdsa":
		return Templates[x509.ECDSA], nil
	case "ed25519":
		return Templates[x509.Ed25519], nil
	default:
		return nil, ErrInvalidKeyAlgorithm
	}
}
