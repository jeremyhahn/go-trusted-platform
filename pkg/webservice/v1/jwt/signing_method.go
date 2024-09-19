package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var (
	ErrInvalidSignatureAlgorithm = errors.New("jwt: invalid signature algorithm")
)

type SigningMethod struct {
	algorithm     string
	hash          crypto.Hash
	keyAttributes *keystore.KeyAttributes
	isPSS         bool
	jwt.SigningMethod
}

func NewSigningMethod(keyAttrs *keystore.KeyAttributes) (*SigningMethod, error) {
	isPSS := false
	algorithm, err := ParseAlgorithm(keyAttrs)
	if err != nil {
		return nil, err
	}
	if algorithm[0] == 'P' {
		isPSS = true
	}
	return &SigningMethod{
		algorithm:     algorithm,
		hash:          keyAttrs.Hash,
		keyAttributes: keyAttrs,
		isPSS:         isPSS,
	}, nil
}

func (sm *SigningMethod) Alg() string {
	return sm.algorithm
}

func (sm *SigningMethod) Digest(signingString string) ([]byte, error) {
	hash := sm.hash.New()
	hash.Reset()
	_, err := hash.Write([]byte(signingString))
	if err != nil {
		return nil, err
	}
	digest := hash.Sum(nil)
	return digest, nil
}

func (sm *SigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	hash := sm.hash.New()
	_, err := hash.Write([]byte(signingString))
	if err != nil {
		return nil, err
	}
	digest := hash.Sum(nil)

	var opts crypto.SignerOpts
	if sm.isPSS {
		opts = &rsa.PSSOptions{
			Hash:       sm.hash,
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
	} else {
		opts = sm.hash
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, jwt.ErrInvalidKey
	}
	return signer.Sign(rand.Reader, digest, opts)
}

func (sm *SigningMethod) Verify(signingString string, signature []byte, key interface{}) error {

	verifier := keystore.NewVerifier(nil)

	if sm.isPSS {
		opts := &keystore.VerifyOpts{
			KeyAttributes: sm.keyAttributes,
			PSSOptions: &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       sm.hash,
			},
		}
		return verifier.Verify(
			key.(crypto.PublicKey), sm.hash, []byte(signingString), signature, opts)
	}

	return verifier.Verify(
		key.(crypto.PublicKey), sm.hash, []byte(signingString), signature, nil)
}

func ParseAlgorithm(keyAttrs *keystore.KeyAttributes) (string, error) {

	switch keyAttrs.SignatureAlgorithm {
	case x509.PureEd25519:
		return "EdDSA", nil
	case x509.SHA256WithRSAPSS:
		return "PS256", nil
	case x509.SHA384WithRSAPSS:
		return "PS384", nil
	case x509.SHA512WithRSAPSS:
		return "PS512", nil
	case x509.ECDSAWithSHA256:
		return "ES256", nil
	case x509.ECDSAWithSHA384:
		return "ES384", nil
	case x509.ECDSAWithSHA512:
		return "ES512", nil
	case x509.SHA256WithRSA:
		return "RS256", nil
	case x509.SHA384WithRSA:
		return "RS384", nil
	case x509.SHA512WithRSA:
		return "RS512", nil
	default:
		return "", ErrInvalidSignatureAlgorithm
	}
}
