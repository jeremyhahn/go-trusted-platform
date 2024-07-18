package keystore

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"strings"
)

var (
	TemplateRSA = KeyAttributes{
		Domain:       "example.com",
		CN:           "www.example.com",
		Hash:         crypto.SHA256,
		KeyAlgorithm: x509.RSA,
		KeyType:      KEY_TYPE_TLS,
		Password:     nil,
		RSAAttributes: &RSAAttributes{
			KeySize: 2048,
		},
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}

	TemplateECDSA = KeyAttributes{
		Domain: "example.com",
		CN:     "www.example.com",
		ECCAttributes: &ECCAttributes{
			Curve: elliptic.P256(),
		},
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.ECDSA,
		KeyType:            KEY_TYPE_TLS,
		Password:           nil,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	TemplateEd25519 = KeyAttributes{
		Domain: "example.com",
		CN:     "www.example.com",
		ECCAttributes: &ECCAttributes{
			Curve: elliptic.P256(),
		},
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.Ed25519,
		KeyType:            KEY_TYPE_TLS,
		Password:           nil,
		SignatureAlgorithm: x509.PureEd25519,
	}

	Templates = map[x509.PublicKeyAlgorithm]KeyAttributes{
		x509.RSA:     TemplateRSA,
		x509.ECDSA:   TemplateECDSA,
		x509.Ed25519: TemplateEd25519,
	}
)

// Return a template for the given key algorithm and key type.
//
// Supported Algorithms:
// - RSA
// - ECDSA
// - Ed25519
//
// Supported Key Types:
// - KEY_TYPE_CA
// - KEY_TYPE_TLS
// - KEY_TYPE_SIGNING
// - KEY_TYPE_ENCRYPT
//
// Returns ErrInvalidKeyAlgorithm or ErrInvalidKeyType for respective errors
func Template(algorithm x509.PublicKeyAlgorithm) (KeyAttributes, error) {
	attrs, ok := Templates[algorithm]
	if !ok {
		return KeyAttributes{}, ErrInvalidKeyAlgorithm
	}
	return attrs, nil
}

// Parses the provided algorithm and returns the requested template
// or ErrInvalidKeyAlgorithm if the algorithm is not RSA, ECDSA, or
// Ed25519.
func TemplateFromString(algorithm string) (KeyAttributes, error) {
	switch strings.ToLower(algorithm) {
	case "rsa":
		return Templates[x509.RSA], nil
	case "ecdsa":
		return Templates[x509.ECDSA], nil
	case "ed25519":
		return Templates[x509.Ed25519], nil
	default:
		return KeyAttributes{}, ErrInvalidKeyAlgorithm
	}
}

// Returns X509 attributes defaulted to TLS type
// with an empty common name (CN) and file name
func X509Template() *X509Attributes {
	return &X509Attributes{
		Type: X509_TYPE_TLS,
	}
}

// Returns X509 attributes defaulted to TLS type
// and the provided common name
func NewX509Template(cn string) *X509Attributes {
	return &X509Attributes{
		CN:   cn,
		Type: X509_TYPE_TLS,
	}
}
