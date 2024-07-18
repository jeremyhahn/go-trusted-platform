package keystore

import "crypto/x509"

func ParseKeyAlgorithm(algorithm string) (x509.PublicKeyAlgorithm, error) {
	switch algorithm {
	case x509.RSA.String():
		return x509.RSA, nil
	case x509.ECDSA.String():
		return x509.ECDSA, nil
	case x509.Ed25519.String():
		return x509.Ed25519, nil
	default:
		return x509.RSA, ErrInvalidKeyAlgorithm
	}
}

func ParseRSAScheme(scheme string) (RSAScheme, error) {
	switch scheme {
	case string(RSA_SCHEME_RSAPSS):
		return RSA_SCHEME_RSAPSS, nil
	case string(RSA_SCHEME_PKCS1v15):
		return RSA_SCHEME_PKCS1v15, nil
	default:
		return RSA_SCHEME_RSAPSS, ErrInvalidSignatureScheme
	}
}

func ParseSignatureAlgorithm(algorithm string) (x509.SignatureAlgorithm, error) {
	supportedAlgos := AvailableSignatureAlgorithms()
	algo, ok := supportedAlgos[algorithm]
	if !ok {
		return x509.SHA256WithRSA, ErrInvalidSignatureAlgorithm
	}
	return algo, nil
}
