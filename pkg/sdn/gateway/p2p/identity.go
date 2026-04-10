//go:build platform_p2p

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package p2p

import (
	"bytes"
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"io"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
)

// GenerateIdentity generates a new Ed25519 identity for testing or non-TPM use.
func GenerateIdentity() (libp2pcrypto.PrivKey, error) {
	privKey, _, err := libp2pcrypto.GenerateEd25519Key(nil)
	if err != nil {
		return nil, &ErrIdentityCreationFailed{Cause: err}
	}
	return privKey, nil
}

// IdentityFromECDSA creates a libp2p private key from an ECDSA private key.
func IdentityFromECDSA(key *ecdsa.PrivateKey) (libp2pcrypto.PrivKey, error) {
	if key == nil {
		return nil, ErrPrivateKeyNil
	}

	privKey, _, err := libp2pcrypto.ECDSAKeyPairFromKey(key)
	if err != nil {
		return nil, &ErrIdentityCreationFailed{Cause: err}
	}
	return privKey, nil
}

// IdentityFromTPM creates a libp2p private key from a TPM IDevID certificate
// and a crypto.Signer that uses the TPM for signing operations.
// This allows the node identity to be backed by hardware security.
func IdentityFromTPM(idevid *x509.Certificate, signer gocrypto.Signer) (libp2pcrypto.PrivKey, error) {
	if idevid == nil {
		return nil, &ErrIdentityCreationFailed{Cause: ErrPrivateKeyNil}
	}
	if signer == nil {
		return nil, &ErrIdentityCreationFailed{Cause: ErrPrivateKeyNil}
	}

	// Extract the public key from the certificate
	pubKey, ok := idevid.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, &ErrIdentityCreationFailed{
			Cause: &ErrInvalidConfigField{
				Field:  "IDevID",
				Reason: "certificate must have an ECDSA public key",
			},
		}
	}

	// Create a TPM-backed private key wrapper
	tpmKey := &tpmPrivKey{
		pubKey: pubKey,
		signer: signer,
	}

	return tpmKey, nil
}

// tpmPrivKey wraps a TPM-backed ECDSA key to implement libp2p's PrivKey interface.
type tpmPrivKey struct {
	pubKey *ecdsa.PublicKey
	signer gocrypto.Signer
}

// Equals checks if two keys are equal by comparing their public keys.
func (k *tpmPrivKey) Equals(other libp2pcrypto.Key) bool {
	// Compare public key representations
	thisPub, err := k.GetPublic().Raw()
	if err != nil {
		return false
	}

	// Get the other key's public key
	var otherPub []byte
	switch otherKey := other.(type) {
	case libp2pcrypto.PrivKey:
		otherPub, err = otherKey.GetPublic().Raw()
		if err != nil {
			return false
		}
	case libp2pcrypto.PubKey:
		otherPub, err = otherKey.Raw()
		if err != nil {
			return false
		}
	default:
		return false
	}

	return bytes.Equal(thisPub, otherPub)
}

// Raw returns the raw bytes of the key.
func (k *tpmPrivKey) Raw() ([]byte, error) {
	// TPM keys cannot be extracted, return a hash of the public key instead.
	pubBytes, err := x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(pubBytes)
	return hash[:], nil
}

// Type returns the key type.
func (k *tpmPrivKey) Type() pb.KeyType {
	return pb.KeyType_ECDSA
}

// Sign signs the given data using the TPM.
func (k *tpmPrivKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return k.signer.Sign(rand.Reader, hash[:], gocrypto.SHA256)
}

// GetPublic returns the public key.
func (k *tpmPrivKey) GetPublic() libp2pcrypto.PubKey {
	return &tpmPubKey{pubKey: k.pubKey}
}

// tpmPubKey wraps an ECDSA public key for the TPM-backed identity.
type tpmPubKey struct {
	pubKey *ecdsa.PublicKey
}

// Equals checks if two keys are equal.
func (k *tpmPubKey) Equals(other libp2pcrypto.Key) bool {
	thisPub, err := k.Raw()
	if err != nil {
		return false
	}

	// Get the other key's bytes
	var otherPub []byte
	switch otherKey := other.(type) {
	case libp2pcrypto.PrivKey:
		otherPub, err = otherKey.GetPublic().Raw()
		if err != nil {
			return false
		}
	case libp2pcrypto.PubKey:
		otherPub, err = otherKey.Raw()
		if err != nil {
			return false
		}
	default:
		return false
	}

	return bytes.Equal(thisPub, otherPub)
}

// Raw returns the raw bytes of the public key.
func (k *tpmPubKey) Raw() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.pubKey)
}

// Type returns the key type.
func (k *tpmPubKey) Type() pb.KeyType {
	return pb.KeyType_ECDSA
}

// Verify verifies a signature against the given data.
func (k *tpmPubKey) Verify(data []byte, sig []byte) (bool, error) {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(k.pubKey, hash[:], sig), nil
}

// IdentityFromReader generates an Ed25519 identity using the provided random reader.
// This is useful for deterministic key generation from a seed.
func IdentityFromReader(reader io.Reader) (libp2pcrypto.PrivKey, error) {
	if reader == nil {
		return nil, &ErrIdentityCreationFailed{
			Cause: &ErrInvalidConfigField{
				Field:  "reader",
				Reason: "reader is nil",
			},
		}
	}

	privKey, _, err := libp2pcrypto.GenerateEd25519Key(reader)
	if err != nil {
		return nil, &ErrIdentityCreationFailed{Cause: err}
	}
	return privKey, nil
}

// MarshalIdentity serializes a private key to bytes.
func MarshalIdentity(key libp2pcrypto.PrivKey) ([]byte, error) {
	if key == nil {
		return nil, ErrPrivateKeyNil
	}
	return libp2pcrypto.MarshalPrivateKey(key)
}

// UnmarshalIdentity deserializes a private key from bytes.
func UnmarshalIdentity(data []byte) (libp2pcrypto.PrivKey, error) {
	if len(data) == 0 {
		return nil, &ErrIdentityCreationFailed{
			Cause: &ErrInvalidConfigField{
				Field:  "data",
				Reason: "data is empty",
			},
		}
	}

	key, err := libp2pcrypto.UnmarshalPrivateKey(data)
	if err != nil {
		return nil, &ErrIdentityCreationFailed{Cause: err}
	}
	return key, nil
}
