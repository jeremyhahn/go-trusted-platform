// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vm

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// AKPublicArea is the parsed TPMT_PUBLIC of an attestation key as the
// control plane recorded it at enrollment (Device.AttestPub). It carries the
// public key the certificate must certify and the object attributes that say
// what kind of key the TPM created.
type AKPublicArea struct {
	// PublicKey is the key in Go form: *rsa.PublicKey or *ecdsa.PublicKey.
	PublicKey crypto.PublicKey
	// FixedTPM: the key cannot leave the TPM that created it.
	FixedTPM bool
	// FixedParent: the key cannot be re-parented.
	FixedParent bool
	// SensitiveDataOrigin: the TPM generated the private part.
	SensitiveDataOrigin bool
	// Restricted: the key only signs TPM-internal data (quotes, certify).
	Restricted bool
	// SignEncrypt: the key is a signing key.
	SignEncrypt bool
	// Decrypt: the key is a decryption key.
	Decrypt bool
}

// ParseAKPublicArea parses TPMT_PUBLIC bytes into an AKPublicArea. Only RSA
// and ECC keys are attestation keys; any other type is refused.
func ParseAKPublicArea(tpmtPublic []byte) (*AKPublicArea, error) {
	if len(tpmtPublic) == 0 {
		return nil, ErrAKPublicAreaInvalid{Reason: "empty public area"}
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](tpmtPublic)
	if err != nil {
		return nil, ErrAKPublicAreaInvalid{Reason: "TPMT_PUBLIC unmarshal failed", Cause: err}
	}

	key, err := publicKeyFromTPMTPublic(pub)
	if err != nil {
		return nil, err
	}

	attrs := pub.ObjectAttributes
	return &AKPublicArea{
		PublicKey:           key,
		FixedTPM:            attrs.FixedTPM,
		FixedParent:         attrs.FixedParent,
		SensitiveDataOrigin: attrs.SensitiveDataOrigin,
		Restricted:          attrs.Restricted,
		SignEncrypt:         attrs.SignEncrypt,
		Decrypt:             attrs.Decrypt,
	}, nil
}

// VerifyRestrictedSigningKey reports whether the public area describes a
// key the CA may certify as an attestation key: TPM-resident
// (fixedTPM, fixedParent, sensitiveDataOrigin), Restricted, a signing key
// and not a decryption key. These are the properties the CA asserted when it
// verified the TCG-CSR-IDEVID at enrollment; a relying party re-issuing the
// certificate from the recorded public area must establish the same ones
// before asking the CA to stamp tcg-cap-verifiedTPMRestricted over them.
func (a *AKPublicArea) VerifyRestrictedSigningKey() error {
	if a == nil {
		return ErrAKPublicAreaNotRestricted{Reason: "no public area"}
	}
	switch {
	case !a.Restricted:
		return ErrAKPublicAreaNotRestricted{Reason: "restricted attribute is clear"}
	case !a.SignEncrypt:
		return ErrAKPublicAreaNotRestricted{Reason: "sign attribute is clear"}
	case a.Decrypt:
		return ErrAKPublicAreaNotRestricted{Reason: "decrypt attribute is set"}
	case !a.FixedTPM:
		return ErrAKPublicAreaNotRestricted{Reason: "fixedTPM attribute is clear"}
	case !a.FixedParent:
		return ErrAKPublicAreaNotRestricted{Reason: "fixedParent attribute is clear"}
	case !a.SensitiveDataOrigin:
		return ErrAKPublicAreaNotRestricted{Reason: "sensitiveDataOrigin attribute is clear"}
	}
	return nil
}

// publicKeyFromTPMTPublic converts the unique field of an RSA or ECC public
// area into the Go public key type.
func publicKeyFromTPMTPublic(pub *tpm2.TPMTPublic) (crypto.PublicKey, error) {
	switch pub.Type {
	case tpm2.TPMAlgRSA:
		parms, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, ErrAKPublicAreaInvalid{Reason: "RSA parameters", Cause: err}
		}
		unique, err := pub.Unique.RSA()
		if err != nil {
			return nil, ErrAKPublicAreaInvalid{Reason: "RSA unique", Cause: err}
		}
		key, err := tpm2.RSAPub(parms, unique)
		if err != nil {
			return nil, ErrAKPublicAreaInvalid{Reason: "RSA public key", Cause: err}
		}
		return key, nil
	case tpm2.TPMAlgECC:
		parms, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, ErrAKPublicAreaInvalid{Reason: "ECC parameters", Cause: err}
		}
		curve, err := parms.CurveID.Curve()
		if err != nil {
			return nil, ErrAKPublicAreaInvalid{Reason: "ECC curve", Cause: err}
		}
		unique, err := pub.Unique.ECC()
		if err != nil {
			return nil, ErrAKPublicAreaInvalid{Reason: "ECC unique", Cause: err}
		}
		// The TPM carries the coordinates as separate, possibly unpadded
		// buffers; the uncompressed SEC 1 point is 0x04 || X || Y at the
		// curve's field size, and parsing it performs the on-curve check.
		size := (curve.Params().BitSize + 7) / 8
		if len(unique.X.Buffer) > size || len(unique.Y.Buffer) > size {
			return nil, ErrAKPublicAreaInvalid{Reason: "ECC coordinate longer than the curve field"}
		}
		point := make([]byte, 1+2*size)
		point[0] = 0x04
		copy(point[1+size-len(unique.X.Buffer):], unique.X.Buffer)
		copy(point[1+2*size-len(unique.Y.Buffer):], unique.Y.Buffer)
		key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, ErrAKPublicAreaInvalid{Reason: "ECC point is not on the curve", Cause: err}
		}
		return key, nil
	default:
		return nil, ErrAKPublicAreaInvalid{Reason: fmt.Sprintf("unsupported key type 0x%04x", uint16(pub.Type))}
	}
}
