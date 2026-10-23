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

// Package rpibootsig is the Raspberry Pi bootloader's signed-boot signature:
// the boot.sig that accompanies a boot.img, in the format rpi-eeprom-digest
// writes and the EEPROM verifies when SIGNED_BOOT=1, and the hash of the
// public key that is burned into OTP.
//
// A boot.sig is what rpi-eeprom-digest -k key -i boot.img writes, byte for byte:
//
//	<lowercase hex SHA-256 of boot.img>
//	ts: <decimal unix seconds>
//	target-soc: <2711|2712>            (optional)
//	rsa2048: <lowercase hex RSA-2048 PKCS#1 v1.5 SHA-256 signature>
//
// The signature is over boot.img itself (openssl dgst -sign -sha256 image),
// not over the other lines: the ts and target-soc lines are not signed, the
// way the upstream tool leaves them.
//
// Signing takes a crypto.Signer: with the fleet key held in the platform KMS
// the signer sends only a digest out and the private key never leaves the KMS.
// Verification takes the public key and the OTP hash and checks them in the
// order the bootloader does: the key against OTP, then the image digest, then
// the signature.
//
// What this package cannot prove is that a given EEPROM accepts the result:
// programming the OTP key hash and the EEPROM's acceptance of the signature
// are validated on hardware (docs/provisioning, Phase 6).
package rpibootsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
)

const (
	// KeyBits is the only modulus size the bootloader verifies.
	KeyBits = 2048

	// KeyHashSize is the size of the OTP key hash (SHA-256).
	KeyHashSize = sha256.Size

	// KeyBlobSize is the bootloader's public key encoding: the modulus in
	// KeyBits/8 little-endian bytes, then the exponent in 8 little-endian
	// bytes.
	KeyBlobSize = KeyBits/8 + 8

	timestampPrefix = "ts: "
	targetSoCPrefix = "target-soc: "
	signaturePrefix = "rsa2048: "
)

// SoCs are the target-soc values rpi-eeprom-digest accepts: the BCM2711
// (Pi 4, CM4) and the BCM2712 (Pi 5, CM5).
var SoCs = map[string]struct{}{"2711": {}, "2712": {}}

// SignOptions are the unsigned parts of a boot.sig.
type SignOptions struct {
	// Timestamp is written as the ts line. A reproducible build passes its
	// SOURCE_DATE_EPOCH.
	Timestamp time.Time
	// TargetSoC is the optional target-soc line ("2711" or "2712"); empty
	// writes none.
	TargetSoC string
}

// Signature is a parsed boot.sig.
type Signature struct {
	// Digest is the SHA-256 of the signed boot.img.
	Digest [sha256.Size]byte
	// Timestamp is when the signature was made.
	Timestamp time.Time
	// TargetSoC is the target-soc line, empty when there is none.
	TargetSoC string
	// RSA is the raw signature.
	RSA []byte
}

// KeyBlob returns pub in the bootloader's encoding (rpi-eeprom-config's
// public key binary): the 256-byte little-endian modulus followed by the
// 8-byte little-endian exponent. This is what the EEPROM carries and what
// KeyHash hashes.
func KeyBlob(pub *rsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.N == nil {
		return nil, &UnsupportedKeyError{Reason: "no RSA public key"}
	}
	if bits := pub.N.BitLen(); bits != KeyBits {
		return nil, &KeyBitsError{Bits: bits}
	}
	if pub.E <= 0 {
		return nil, &UnsupportedKeyError{Reason: "the public exponent is not positive"}
	}
	blob := make([]byte, KeyBlobSize)
	modulus := pub.N.Bytes() // big-endian
	for i, b := range modulus {
		blob[len(modulus)-1-i] = b
	}
	binary.LittleEndian.PutUint64(blob[KeyBits/8:], uint64(pub.E))
	return blob, nil
}

// ParseKeyBlob is the inverse of KeyBlob: the public key held in an EEPROM
// image's pubkey.bin.
func ParseKeyBlob(blob []byte) (*rsa.PublicKey, error) {
	if len(blob) != KeyBlobSize {
		return nil, &UnsupportedKeyError{Reason: "the key blob is " + strconv.Itoa(len(blob)) + " bytes, not " + strconv.Itoa(KeyBlobSize)}
	}
	modulus := make([]byte, KeyBits/8)
	for i := range modulus {
		modulus[len(modulus)-1-i] = blob[i]
	}
	exponent := binary.LittleEndian.Uint64(blob[KeyBits/8:])
	if exponent == 0 || exponent > math.MaxInt32 {
		return nil, &UnsupportedKeyError{Reason: "the public exponent is not a positive 31-bit number"}
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(exponent)}
	if _, err := KeyBlob(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// KeyHash is the SHA-256 of KeyBlob(pub): the digest the bootloader compares
// with the one burned into OTP, and the value an operator fuses.
func KeyHash(pub *rsa.PublicKey) ([KeyHashSize]byte, error) {
	blob, err := KeyBlob(pub)
	if err != nil {
		return [KeyHashSize]byte{}, err
	}
	return sha256.Sum256(blob), nil
}

// PublicKeyOf returns the RSA public key signer signs with, which is what
// KeyBlob and KeyHash take.
func PublicKeyOf(signer crypto.Signer) (*rsa.PublicKey, error) {
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, &UnsupportedKeyError{Reason: "the signing key is not RSA"}
	}
	return pub, nil
}

// header is the unsigned boot.sig header before the rsa2048 signature line.
func header(digest [sha256.Size]byte, opts SignOptions) string {
	text := hex.EncodeToString(digest[:]) + "\n" +
		timestampPrefix + strconv.FormatInt(opts.Timestamp.Unix(), 10) + "\n"
	if opts.TargetSoC != "" {
		text += targetSoCPrefix + opts.TargetSoC + "\n"
	}
	return text
}

// SignDigest signs a SHA-256 digest with signer the way the bootloader
// verifies it: RSA-2048 PKCS#1 v1.5. The signer's key must be RSA-2048 (the
// size KeyBlob encodes). The signature is checked against the signer's public
// key before it is returned, so a KMS that signs with the wrong key, or
// returns a malformed signature, is an error and not a signature the fleet
// refuses. It is the one signing path for boot.sig and for the EEPROM
// HSM-wrapper.
func SignDigest(signer crypto.Signer, digest [sha256.Size]byte) ([]byte, error) {
	pub, err := PublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	if _, err := KeyBlob(pub); err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, &SignError{Step: "the signer refused the digest", Err: err}
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, &SignError{Step: "the signature does not verify under the signing key's public key", Err: err}
	}
	return sig, nil
}

// Sign makes the boot.sig for image, signed by signer at ts, through
// SignDigest.
func Sign(signer crypto.Signer, image []byte, opts SignOptions) ([]byte, error) {
	if _, ok := SoCs[opts.TargetSoC]; !ok && opts.TargetSoC != "" {
		return nil, &TargetSoCError{SoC: opts.TargetSoC}
	}

	digest := sha256.Sum256(image)
	sig, err := SignDigest(signer, digest)
	if err != nil {
		return nil, err
	}
	return []byte(header(digest, opts) + signaturePrefix + hex.EncodeToString(sig) + "\n"), nil
}

// Parse reads a boot.sig.
func Parse(sig []byte) (*Signature, error) {
	lines := strings.Split(strings.TrimSuffix(string(sig), "\n"), "\n")
	if len(lines) != 3 && len(lines) != 4 {
		return nil, &MalformedError{Reason: "expected 3 or 4 lines (digest, ts, optional target-soc, rsa2048), found " + strconv.Itoa(len(lines))}
	}

	var out Signature
	digest, err := hex.DecodeString(lines[0])
	if err != nil || len(digest) != sha256.Size {
		return nil, &MalformedError{Reason: "the first line is not a SHA-256 hex digest"}
	}
	copy(out.Digest[:], digest)

	tsText, ok := strings.CutPrefix(lines[1], timestampPrefix)
	if !ok {
		return nil, &MalformedError{Reason: "the second line is not " + strings.TrimSpace(timestampPrefix) + " <seconds>"}
	}
	secs, err := strconv.ParseInt(tsText, 10, 64)
	if err != nil {
		return nil, &MalformedError{Reason: "the timestamp is not a number of seconds"}
	}
	out.Timestamp = time.Unix(secs, 0).UTC()

	rest := lines[2:]
	if len(rest) == 2 {
		soc, ok := strings.CutPrefix(rest[0], targetSoCPrefix)
		if !ok {
			return nil, &MalformedError{Reason: "the third line is not " + strings.TrimSpace(targetSoCPrefix) + " <soc>"}
		}
		if _, ok := SoCs[soc]; !ok {
			return nil, &TargetSoCError{SoC: soc}
		}
		out.TargetSoC = soc
		rest = rest[1:]
	}

	sigText, ok := strings.CutPrefix(rest[0], signaturePrefix)
	if !ok {
		return nil, &MalformedError{Reason: "the last line is not " + strings.TrimSpace(signaturePrefix) + " <hex>"}
	}
	out.RSA, err = hex.DecodeString(sigText)
	if err != nil || len(out.RSA) != KeyBits/8 {
		return nil, &MalformedError{Reason: "the signature is not " + strconv.Itoa(KeyBits/8) + " bytes of hex"}
	}
	return &out, nil
}

// Verify checks boot.sig against image the way the bootloader does with
// SIGNED_BOOT=1: pub must hash to otpKeyHash, the image must be the one whose
// digest was signed, and the signature must verify under pub. It returns the
// parsed signature on success.
func Verify(sig, image []byte, pub *rsa.PublicKey, otpKeyHash [KeyHashSize]byte) (*Signature, error) {
	got, err := KeyHash(pub)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(got[:], otpKeyHash[:]) {
		return nil, &KeyHashMismatchError{Want: otpKeyHash, Got: got}
	}

	parsed, err := Parse(sig)
	if err != nil {
		return nil, err
	}
	if digest := sha256.Sum256(image); digest != parsed.Digest {
		return nil, &DigestMismatchError{Want: parsed.Digest, Got: digest}
	}

	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, parsed.Digest[:], parsed.RSA); err != nil {
		return nil, &SignatureError{Err: err}
	}
	return parsed, nil
}
