package keystore

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"strings"
)

func ParseKeyAlgorithm(algorithm string) (x509.PublicKeyAlgorithm, error) {
	switch strings.ToLower(algorithm) {
	case strings.ToLower(x509.RSA.String()):
		return x509.RSA, nil
	case strings.ToLower(x509.ECDSA.String()):
		return x509.ECDSA, nil
	case strings.ToLower(x509.Ed25519.String()):
		return x509.Ed25519, nil
	default:
		return x509.UnknownPublicKeyAlgorithm, ErrInvalidKeyAlgorithm
	}
}

func ParseKeyAlgorithmFromSignatureAlgorithm(
	sigAlgo x509.SignatureAlgorithm) (x509.PublicKeyAlgorithm, error) {
	switch sigAlgo {
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS,
		x509.SHA384WithRSA, x509.SHA384WithRSAPSS,
		x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		return x509.RSA, nil
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return x509.ECDSA, nil
	case x509.PureEd25519:
		return x509.Ed25519, nil
	}
	return x509.UnknownPublicKeyAlgorithm, ErrInvalidKeyAlgorithm
}

// func ParseRSAScheme(scheme string) (RSAScheme, error) {
// 		switch scheme {
// 	case string(RSA_SCHEME_RSAPSS):
// 		return RSA_SCHEME_RSAPSS, nil
// 	case string(RSA_SCHEME_PKCS1v15):
// 		return RSA_SCHEME_PKCS1v15, nil
// 	default:
// 		return RSA_SCHEME_RSAPSS, ErrInvalidSignatureScheme
// 	}
// }

func ParseSignatureAlgorithm(algorithm string) (x509.SignatureAlgorithm, error) {
	supportedAlgos := AvailableSignatureAlgorithms()
	algo, ok := supportedAlgos[algorithm]
	if !ok {
		return x509.SHA256WithRSA, ErrInvalidSignatureAlgorithm
	}
	return algo, nil
}

func ParseCurve(curve string) (elliptic.Curve, error) {
	c := Curve(strings.ToUpper(curve))
	switch c {
	case CURVE_P224:
		return elliptic.P224(), nil
	case CURVE_P256:
		return elliptic.P256(), nil
	case CURVE_P384:
		return elliptic.P384(), nil
	case CURVE_P521:
		return elliptic.P521(), nil
	}
	return nil, ErrInvalidCurve
}

func ParseHash(hash string) (crypto.Hash, error) {
	hashes := AvailableHashes()
	h, ok := hashes[hash]
	if !ok {
		return 0, ErrInvalidHashFunction
	}
	return h, nil
}

func ParseHashFromSignatureAlgorithm(algo *x509.SignatureAlgorithm) (crypto.Hash, error) {
	hash, ok := SignatureAlgorithmHashes()[*algo]
	if !ok {
		return 0, ErrInvalidSignatureAlgorithm
	}
	return hash, nil
}

func ParseStoreType(storeType string) (StoreType, error) {
	st := StoreType(strings.ToLower(storeType))
	switch st {
	case STORE_PKCS8:
		return STORE_PKCS8, nil
	case STORE_PKCS11:
		return STORE_PKCS11, nil
	case STORE_TPM2:
		return STORE_TPM2, nil
	}
	return "", ErrInvalidKeyStore
}
