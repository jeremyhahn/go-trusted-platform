package issuance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// keyParams is the key a requested key algorithm issues: its x509 family and,
// for RSA and ECDSA, the modulus size or curve the key store must generate.
type keyParams struct {
	algorithm x509.PublicKeyAlgorithm
	rsaBits   int
	curve     elliptic.Curve
}

// keyAlgorithms maps each key algorithm the CA can issue to its key.
// UNSPECIFIED selects the documented ECDSA P-256 default, named here so the
// key store never falls back to a size or curve of its own.
var keyAlgorithms = map[platformv1.KeyAlgorithm]keyParams{
	platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED: {algorithm: x509.ECDSA, curve: elliptic.P256()},
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048:    {algorithm: x509.RSA, rsaBits: 2048},
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072:    {algorithm: x509.RSA, rsaBits: 3072},
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:    {algorithm: x509.RSA, rsaBits: 4096},
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256:  {algorithm: x509.ECDSA, curve: elliptic.P256()},
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:  {algorithm: x509.ECDSA, curve: elliptic.P384()},
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521:  {algorithm: x509.ECDSA, curve: elliptic.P521()},
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519:     {algorithm: x509.Ed25519},
}

// KeyAttributes builds the attributes of the TLS key the CA generates for an
// issued certificate. The RSA size and ECDSA curve travel with the algorithm,
// so a request for RSA_4096 or ECDSA_P384 is never issued as RSA-2048 or
// P-256. An algorithm the CA cannot issue is an UnsupportedKeyAlgorithmError.
func KeyAttributes(alg platformv1.KeyAlgorithm, cn string, store xkmssdk.StoreType) (*xkmssdk.KeyAttributes, error) {
	params, ok := keyAlgorithms[alg]
	if !ok {
		return nil, &UnsupportedKeyAlgorithmError{Algorithm: alg.String()}
	}
	attrs := &xkmssdk.KeyAttributes{
		CN:           cn,
		KeyAlgorithm: params.algorithm,
		StoreType:    store,
		KeyType:      xkmssdk.KeyTypeTLS,
	}
	if params.rsaBits != 0 {
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: params.rsaBits}
	}
	if params.curve != nil {
		attrs.ECCAttributes = &xkmssdk.ECCAttributes{Curve: params.curve}
	}
	return attrs, nil
}

// keyShape identifies a public key by its algorithm and its size: the RSA
// modulus length in bits or the elliptic curve name. Ed25519 has neither.
type keyShape struct {
	algorithm x509.PublicKeyAlgorithm
	rsaBits   int
	curve     string
}

// shape is the keyShape the parameters generate.
func (p keyParams) shape() keyShape {
	s := keyShape{algorithm: p.algorithm, rsaBits: p.rsaBits}
	if p.curve != nil {
		s.curve = p.curve.Params().Name
	}
	return s
}

// keyAlgorithmsByShape inverts keyAlgorithms, so the algorithm reported for
// an issued key is always the one that would have generated it. The
// UNSPECIFIED entry is a request default, not a key, and is left out.
var keyAlgorithmsByShape = invertKeyAlgorithms()

func invertKeyAlgorithms() map[keyShape]platformv1.KeyAlgorithm {
	byShape := make(map[keyShape]platformv1.KeyAlgorithm, len(keyAlgorithms))
	for alg, params := range keyAlgorithms {
		if alg == platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
			continue
		}
		byShape[params.shape()] = alg
	}
	return byShape
}

// PublicKeyAlgorithm reports the protobuf key algorithm of a certificate's
// public key, read from the key itself: the RSA modulus size, the ECDSA
// curve, or Ed25519. A key type, size or curve the CA does not issue is
// KEY_ALGORITHM_UNSPECIFIED.
func PublicKeyAlgorithm(pub crypto.PublicKey) platformv1.KeyAlgorithm {
	var s keyShape
	switch key := pub.(type) {
	case *rsa.PublicKey:
		s = keyShape{algorithm: x509.RSA, rsaBits: key.N.BitLen()}
	case *ecdsa.PublicKey:
		s = keyShape{algorithm: x509.ECDSA, curve: key.Curve.Params().Name}
	case ed25519.PublicKey:
		s = keyShape{algorithm: x509.Ed25519}
	default:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	}
	return keyAlgorithmsByShape[s]
}
