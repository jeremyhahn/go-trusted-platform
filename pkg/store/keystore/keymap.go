package keystore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/go-jose/go-jose/v4"
)

type KeyMap map[string]interface{}

func (keyMap KeyMap) Equals(key KeyMap) bool {
	if keyMap["kty"] != key["kty"] {
		return false
	}
	if keyMap["n"] != key["n"] {
		return false
	}
	if keyMap["e"] != key["e"] {
		return false
	}
	if keyMap["crv"] != key["crv"] {
		return false
	}
	if keyMap["x"] != key["x"] {
		return false
	}
	if keyMap["y"] != key["y"] {
		return false
	}
	return true
}

func (keyMap KeyMap) Type() string {
	return keyMap["kty"].(string)
}

func (keyMap KeyMap) Public() (crypto.PublicKey, error) {
	kty, ok := keyMap["kty"].(string)
	if !ok {
		return nil, errors.New("missing or invalid 'kty' field in JSON")
	}
	switch kty {
	case "RSA":
		return DeserializeRSA(keyMap)
	case "EC":
		return DeserializeECDSA(keyMap)
	case "OKP":
		return DeserializeEd25519(keyMap)
	}
	return nil, ErrInvalidKeyType
}

func (keyMap KeyMap) JOSESignatureAlgorithm() (jose.SignatureAlgorithm, error) {
	pubKey, err := keyMap.Public()
	if err != nil {
		return "", err
	}
	switch keyMap.Type() {
	case "RSA":
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return "", ErrInvalidPublicKeyRSA
		}
		switch {
		case rsaKey.Size() <= 256:
			return jose.RS256, nil
		case rsaKey.Size() <= 384:
			return jose.RS384, nil
		default:
			return jose.RS512, nil
		}
	case "EC":
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return "", ErrInvalidPublicKeyECDSA
		}
		switch ecdsaKey.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", ErrInvalidPublicKeyECDSA
		}
	case "OKP":
		return jose.EdDSA, nil
	default:
		return "", ErrInvalidJOSESignatureAlgorithm
	}
}

func (keyMap KeyMap) String() ([]byte, error) {
	bytes, err := json.Marshal(keyMap)
	if err != nil {
		slog.Error(err.Error())
		return nil, err
	}
	return bytes, nil
}

func (keyMap KeyMap) Equal(other KeyMap) bool {
	keyBytes, err := json.Marshal(keyMap)
	if err != nil {
		return false
	}
	otherBytes, err := json.Marshal(other)
	if err != nil {
		return false
	}
	return bytes.Compare(keyBytes, otherBytes) == 0
}
