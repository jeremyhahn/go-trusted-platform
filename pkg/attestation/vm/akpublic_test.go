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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// restrictedSigningAttrs are the object attributes of an IAK as the TPM
// creates it from the TCG IAK template.
var restrictedSigningAttrs = tpm2.TPMAObject{
	FixedTPM:            true,
	FixedParent:         true,
	SensitiveDataOrigin: true,
	UserWithAuth:        true,
	Restricted:          true,
	SignEncrypt:         true,
}

// eccCoordinates splits an uncompressed P-256 point into its X and Y
// coordinates, the form the TPM carries in TPMS_ECC_POINT.
func eccCoordinates(t *testing.T, pub *ecdsa.PublicKey) (x, y []byte) {
	t.Helper()
	point, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return point[1:33], point[33:65]
}

func marshalECCPublicArea(t *testing.T, pub *ecdsa.PublicKey, attrs tpm2.TPMAObject) []byte {
	t.Helper()
	x, y := eccCoordinates(t, pub)
	return marshalECCPublicAreaXY(x, y, attrs)
}

func marshalECCPublicAreaXY(x, y []byte, attrs tpm2.TPMAObject) []byte {
	area := tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: attrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x},
			Y: tpm2.TPM2BECCParameter{Buffer: y},
		}),
	}
	return tpm2.Marshal(area)
}

func marshalRSAPublicArea(t *testing.T, pub *rsa.PublicKey, attrs tpm2.TPMAObject) []byte {
	t.Helper()
	area := tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgRSA,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: attrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			KeyBits: 2048,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: pub.N.Bytes()}),
	}
	return tpm2.Marshal(area)
}

func TestParseAKPublicArea_ECCRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	area, err := ParseAKPublicArea(marshalECCPublicArea(t, &key.PublicKey, restrictedSigningAttrs))
	if err != nil {
		t.Fatalf("ParseAKPublicArea: %v", err)
	}
	got, ok := area.PublicKey.(*ecdsa.PublicKey)
	if !ok || !got.Equal(&key.PublicKey) {
		t.Fatalf("public key did not round-trip: %T", area.PublicKey)
	}
	if !area.Restricted || !area.SignEncrypt || !area.FixedTPM || !area.FixedParent || !area.SensitiveDataOrigin || area.Decrypt {
		t.Fatalf("attributes did not round-trip: %+v", area)
	}
	if err := area.VerifyRestrictedSigningKey(); err != nil {
		t.Fatalf("restricted signing key refused: %v", err)
	}
}

func TestParseAKPublicArea_RSARoundTrip(t *testing.T) {
	key, err := testRSAKey()
	if err != nil {
		t.Fatal(err)
	}
	area, err := ParseAKPublicArea(marshalRSAPublicArea(t, &key.PublicKey, restrictedSigningAttrs))
	if err != nil {
		t.Fatalf("ParseAKPublicArea: %v", err)
	}
	got, ok := area.PublicKey.(*rsa.PublicKey)
	if !ok || !got.Equal(&key.PublicKey) {
		t.Fatalf("public key did not round-trip: %T", area.PublicKey)
	}
}

func TestParseAKPublicArea_GarbageIsRefused(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":     nil,
		"truncated": {0x00, 0x23, 0x00},
		"random":    {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAKPublicArea(in)
			var invalid ErrAKPublicAreaInvalid
			if !errors.As(err, &invalid) {
				t.Fatalf("want ErrAKPublicAreaInvalid, got %v", err)
			}
		})
	}
}

func TestParseAKPublicArea_UnsupportedTypeIsRefused(t *testing.T) {
	area := tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgKeyedHash,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: restrictedSigningAttrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: make([]byte, 32)}),
	}
	_, err := ParseAKPublicArea(tpm2.Marshal(area))
	var invalid ErrAKPublicAreaInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("want ErrAKPublicAreaInvalid for keyed-hash public area, got %v", err)
	}
}

func TestParseAKPublicArea_OffCurvePointIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := eccCoordinates(t, &key.PublicKey)
	y[31] ^= 0x01 // any Y other than the real one is off the curve
	_, err = ParseAKPublicArea(marshalECCPublicAreaXY(x, y, restrictedSigningAttrs))
	var invalid ErrAKPublicAreaInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("want ErrAKPublicAreaInvalid for off-curve point, got %v", err)
	}
}

func TestParseAKPublicArea_OversizedCoordinateIsRefused(t *testing.T) {
	// A P-256 coordinate is at most 32 bytes; a 33-byte buffer cannot be
	// left-padded into the SEC 1 point and must be refused, not truncated.
	oversized := make([]byte, 33)
	oversized[0] = 0x01
	_, err := ParseAKPublicArea(marshalECCPublicAreaXY(oversized, make([]byte, 32), restrictedSigningAttrs))
	var invalid ErrAKPublicAreaInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("want ErrAKPublicAreaInvalid for a 33-byte P-256 coordinate, got %v", err)
	}
	if invalid.Reason != "ECC coordinate longer than the curve field" {
		t.Errorf("Reason = %q, want the oversized-coordinate refusal", invalid.Reason)
	}
}

func TestParseAKPublicArea_UnsupportedCurveIsRefused(t *testing.T) {
	area := tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: restrictedSigningAttrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			CurveID: tpm2.TPMECCBNP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
	_, err := ParseAKPublicArea(tpm2.Marshal(area))
	var invalid ErrAKPublicAreaInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("want ErrAKPublicAreaInvalid for a BN P-256 public area, got %v", err)
	}
	if invalid.Reason != "ECC curve" || invalid.Cause == nil {
		t.Errorf("want Reason %q with the curve lookup cause, got %+v", "ECC curve", invalid)
	}
}

func TestVerifyRestrictedSigningKey_EachClearedAttributeIsRefused(t *testing.T) {
	cases := map[string]func(*tpm2.TPMAObject){
		"restricted clear":          func(a *tpm2.TPMAObject) { a.Restricted = false },
		"sign clear":                func(a *tpm2.TPMAObject) { a.SignEncrypt = false },
		"decrypt set":               func(a *tpm2.TPMAObject) { a.Decrypt = true },
		"fixedTPM clear":            func(a *tpm2.TPMAObject) { a.FixedTPM = false },
		"fixedParent clear":         func(a *tpm2.TPMAObject) { a.FixedParent = false },
		"sensitiveDataOrigin clear": func(a *tpm2.TPMAObject) { a.SensitiveDataOrigin = false },
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			attrs := restrictedSigningAttrs
			mutate(&attrs)
			area, err := ParseAKPublicArea(marshalECCPublicArea(t, &key.PublicKey, attrs))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = area.VerifyRestrictedSigningKey()
			var notRestricted ErrAKPublicAreaNotRestricted
			if !errors.As(err, &notRestricted) {
				t.Fatalf("want ErrAKPublicAreaNotRestricted, got %v", err)
			}
		})
	}
}

func TestVerifyRestrictedSigningKey_NilIsRefused(t *testing.T) {
	var area *AKPublicArea
	var notRestricted ErrAKPublicAreaNotRestricted
	if err := area.VerifyRestrictedSigningKey(); !errors.As(err, &notRestricted) {
		t.Fatalf("want ErrAKPublicAreaNotRestricted, got %v", err)
	}
}
