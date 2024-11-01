package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

func ParseKeyMap(key string) (KeyMap, error) {
	var keyMap KeyMap
	if err := json.Unmarshal([]byte(key), &keyMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}
	return keyMap, nil
}

func PublicKeyAlgorithm(key string) (x509.PublicKeyAlgorithm, error) {
	var keyMap map[string]interface{}
	if err := json.Unmarshal([]byte(key), &keyMap); err != nil {
		return 0, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}
	kty, ok := keyMap["kty"].(string)
	if !ok {
		return 0, errors.New("missing or invalid 'kty' field in JSON")
	}
	switch kty {
	case "RSA":
		return x509.RSA, nil
	case "EC":
		return x509.ECDSA, nil
	case "OKP":
		return x509.Ed25519, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %s", kty)
	}
}

func Deserialize(key string) (crypto.PublicKey, error) {

	var keyMap map[string]interface{}

	if err := json.Unmarshal([]byte(key), &keyMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

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
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}

func DeserializeRSA(keyMap KeyMap) (*rsa.PublicKey, error) {

	nStr, ok := keyMap["n"].(string)
	if !ok {
		return nil, errors.New("missing or invalid 'n' field in RSA key JSON")
	}

	eStr, ok := keyMap["e"].(string)
	if !ok {
		return nil, errors.New("missing or invalid 'e' field in RSA key JSON")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'n': %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'e': %v", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	eInt := int(e.Int64())
	if eInt == 0 {
		return nil, errors.New("invalid exponent in RSA key")
	}

	pub := &rsa.PublicKey{
		N: n,
		E: eInt,
	}

	return pub, nil
}

func DeserializeECDSA(keyMap KeyMap) (*ecdsa.PublicKey, error) {

	crvName, ok := keyMap["crv"].(string)
	if !ok {
		return nil, errors.New("missing or invalid 'crv' field in EC key JSON")
	}
	xStr, ok := keyMap["x"].(string)
	if !ok {
		return nil, errors.New("missing or invalid 'x' field in EC key JSON")
	}
	yStr, ok := keyMap["y"].(string)
	if !ok {
		return nil, errors.New("missing or invalid 'y' field in EC key JSON")
	}

	var curve elliptic.Curve
	switch crvName {
	case elliptic.P256().Params().Name:
		curve = elliptic.P256()
	case elliptic.P384().Params().Name:
		curve = elliptic.P384()
	case elliptic.P521().Params().Name:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crvName)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'x': %v", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'y': %v", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("invalid EC public key point")
	}

	return pub, nil
}

func DeserializeEd25519(keyMap KeyMap) (ed25519.PublicKey, error) {

	crvName, ok := keyMap["crv"].(string)
	if !ok || crvName != "Ed25519" {
		return nil, errors.New("missing or invalid 'crv' field in OKP key JSON")
	}

	xStr, ok := keyMap["x"].(string)
	if !ok {
		return nil, errors.New("missing or invalid 'x' field in OKP key JSON")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'x': %v", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(xBytes))
	}

	pub := ed25519.PublicKey(xBytes)

	return pub, nil
}
