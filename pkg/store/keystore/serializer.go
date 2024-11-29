package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
)

type KeySerializer struct {
	serializer serializer.Serializer[map[string]interface{}]
}

func NewSerializer(serializerType serializer.SerializerType) (KeySerializer, error) {
	s, err := serializer.NewSerializer[map[string]interface{}](serializerType)
	if err != nil {
		return KeySerializer{}, err
	}
	return KeySerializer{
		serializer: s,
	}, nil
}

func (ks KeySerializer) Type() serializer.SerializerType {
	return ks.serializer.Type()
}

func (ks KeySerializer) Serialize(pubKey crypto.PublicKey) ([]byte, error) {
	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		return ks.SerializeRSA(pubKey)
	case *ecdsa.PublicKey:
		return ks.SerializeECDSA(pubKey)
	case ed25519.PublicKey:
		return ks.SerializeEd25519(pubKey)
	default:
		return nil, serializer.ErrInvalidSerializer
	}
}

func (ks KeySerializer) SerializeRSA(pubKey *rsa.PublicKey) ([]byte, error) {
	nBytes := pubKey.N.Bytes()
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()
	nBase64 := base64.RawURLEncoding.EncodeToString(nBytes)
	eBase64 := base64.RawURLEncoding.EncodeToString(eBytes)
	key := KeyMap{
		"kty": "RSA",
		"n":   nBase64,
		"e":   eBase64,
	}
	return ks.serializer.Serialize(key)
}

func (ks KeySerializer) SerializeECDSA(pubKey *ecdsa.PublicKey) ([]byte, error) {
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	xBase64 := base64.RawURLEncoding.EncodeToString(xBytes)
	yBase64 := base64.RawURLEncoding.EncodeToString(yBytes)
	key := KeyMap{
		"kty": "EC",
		"crv": pubKey.Curve.Params().Name,
		"x":   xBase64,
		"y":   yBase64,
	}
	return ks.serializer.Serialize(key)
}

func (ks KeySerializer) SerializeEd25519(pubKey ed25519.PublicKey) ([]byte, error) {
	xBase64 := base64.RawURLEncoding.EncodeToString(pubKey)
	key := KeyMap{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   xBase64,
	}
	return ks.serializer.Serialize(key)
}

func (ks KeySerializer) KeyAuthorization(token string, pubKey crypto.PublicKey) (string, error) {
	thumbprint, err := ks.Thumbprint(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute JWK thumbprint: %v", err)
	}
	keyAuthorization := fmt.Sprintf("%s.%s", token, thumbprint)
	return keyAuthorization, nil
}

func (ks KeySerializer) Thumbprint(pubKey crypto.PublicKey) (string, error) {

	var jwk map[string]string

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		nBytes := key.N.Bytes()
		eBytes := big.NewInt(int64(key.E)).Bytes()
		n := base64.RawURLEncoding.EncodeToString(nBytes)
		e := base64.RawURLEncoding.EncodeToString(eBytes)
		jwk = map[string]string{
			"e":   e,
			"kty": "RSA",
			"n":   n,
		}

	case *ecdsa.PublicKey:
		xBytes := key.X.Bytes()
		yBytes := key.Y.Bytes()
		x := base64.RawURLEncoding.EncodeToString(xBytes)
		y := base64.RawURLEncoding.EncodeToString(yBytes)
		jwk = map[string]string{
			"crv": key.Curve.Params().Name,
			"kty": "EC",
			"x":   x,
			"y":   y,
		}
	case ed25519.PublicKey:
		x := base64.RawURLEncoding.EncodeToString(key)
		jwk = map[string]string{
			"crv": "Ed25519",
			"kty": "OKP",
			"x":   x,
		}

	default:
		return "", fmt.Errorf("unsupported key type")
	}

	// Create a JSON object with lexicographically sorted keys
	orderedKeys := make([]string, 0, len(jwk))
	for k := range jwk {
		orderedKeys = append(orderedKeys, k)
	}
	sort.Strings(orderedKeys)

	var builder strings.Builder
	builder.WriteString("{")
	for i, k := range orderedKeys {
		value, _ := json.Marshal(jwk[k])
		builder.WriteString(fmt.Sprintf(`"%s":%s`, k, string(value)))
		if i < len(orderedKeys)-1 {
			builder.WriteString(",")
		}
	}
	builder.WriteString("}")

	jsonString := builder.String()

	// Compute the SHA-256 hash
	hash := sha256.Sum256([]byte(jsonString))

	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
