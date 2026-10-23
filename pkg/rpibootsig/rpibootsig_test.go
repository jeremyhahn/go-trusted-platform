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

package rpibootsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	image = []byte("a FAT ramdisk standing in for boot.img")
	stamp = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
)

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return key
}

// signer is a crypto.Signer whose Sign is replaceable, to model a KMS that
// misbehaves.
type signer struct {
	crypto.Signer
	sign func(digest []byte) ([]byte, error)
}

func (s signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.sign(digest)
}

func TestKeyBlob_IsTheBootloadersEncoding(t *testing.T) {
	key := rsaKey(t, KeyBits)
	blob, err := KeyBlob(&key.PublicKey)
	require.NoError(t, err)
	require.Len(t, blob, KeyBlobSize)

	// Little-endian modulus: the first byte is the modulus's last.
	modulus := key.N.Bytes()
	for i := range modulus {
		require.Equal(t, modulus[len(modulus)-1-i], blob[i], "modulus byte %d", i)
	}
	assert.Equal(t, uint64(key.E), binary.LittleEndian.Uint64(blob[KeyBits/8:]))

	hash, err := KeyHash(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(blob), hash)
}

func TestKeyBlob_RefusesKeysTheBootloaderCannotUse(t *testing.T) {
	_, err := KeyBlob(nil)
	var unsupported *UnsupportedKeyError
	assert.ErrorAs(t, err, &unsupported)

	_, err = KeyHash(&rsa.PublicKey{})
	assert.ErrorAs(t, err, &unsupported)

	_, err = KeyBlob(&rsaKey(t, 3072).PublicKey)
	var bits *KeyBitsError
	require.ErrorAs(t, err, &bits)
	assert.Equal(t, 3072, bits.Bits)
}

func TestParseKeyBlob_RoundTrips(t *testing.T) {
	key := rsaKey(t, KeyBits)
	blob, err := KeyBlob(&key.PublicKey)
	require.NoError(t, err)

	pub, err := ParseKeyBlob(blob)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(pub))
}

func TestParseKeyBlob_RefusesAMalformedBlob(t *testing.T) {
	key := rsaKey(t, KeyBits)
	blob, err := KeyBlob(&key.PublicKey)
	require.NoError(t, err)

	zeroExponent := append([]byte(nil), blob...)
	clear(zeroExponent[KeyBits/8:])
	shortModulus := append([]byte(nil), blob...)
	clear(shortModulus[KeyBits/8-128 : KeyBits/8])
	for name, bad := range map[string][]byte{
		"empty":         nil,
		"too short":     blob[:KeyBlobSize-1],
		"zero exponent": zeroExponent,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseKeyBlob(bad)
			var unsupported *UnsupportedKeyError
			assert.ErrorAs(t, err, &unsupported)
		})
	}
	t.Run("a modulus shorter than 2048 bits", func(t *testing.T) {
		_, err := ParseKeyBlob(shortModulus)
		var bits *KeyBitsError
		assert.ErrorAs(t, err, &bits)
	})
}

func TestSignVerify_RoundTrip(t *testing.T) {
	key := rsaKey(t, KeyBits)
	sig, err := Sign(key, image, SignOptions{Timestamp: stamp})
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSuffix(string(sig), "\n"), "\n")
	require.Len(t, lines, 3)
	digest := sha256.Sum256(image)
	assert.Equal(t, hex.EncodeToString(digest[:]), lines[0])
	assert.Equal(t, "ts: 1790856000", lines[1])
	assert.True(t, strings.HasPrefix(lines[2], "rsa2048: "))
	assert.Len(t, lines[2], len("rsa2048: ")+2*KeyBits/8)

	otp, err := KeyHash(&key.PublicKey)
	require.NoError(t, err)
	parsed, err := Verify(sig, image, &key.PublicKey, otp)
	require.NoError(t, err)
	assert.Equal(t, digest, parsed.Digest)
	assert.True(t, stamp.Equal(parsed.Timestamp))
}

func TestVerify_RefusesATamperedImage(t *testing.T) {
	key := rsaKey(t, KeyBits)
	sig, err := Sign(key, image, SignOptions{Timestamp: stamp})
	require.NoError(t, err)
	otp, err := KeyHash(&key.PublicKey)
	require.NoError(t, err)

	tampered := append([]byte(nil), image...)
	tampered[0] ^= 0xff
	_, err = Verify(sig, tampered, &key.PublicKey, otp)
	var mismatch *DigestMismatchError
	assert.ErrorAs(t, err, &mismatch)
}

func TestVerify_RefusesTheWrongKey(t *testing.T) {
	fleet := rsaKey(t, KeyBits)
	other := rsaKey(t, KeyBits)
	fleetHash, err := KeyHash(&fleet.PublicKey)
	require.NoError(t, err)
	otherHash, err := KeyHash(&other.PublicKey)
	require.NoError(t, err)

	t.Run("signed by another key, verified under the key OTP holds", func(t *testing.T) {
		sig, err := Sign(other, image, SignOptions{Timestamp: stamp})
		require.NoError(t, err)
		_, err = Verify(sig, image, &fleet.PublicKey, fleetHash)
		var bad *SignatureError
		assert.ErrorAs(t, err, &bad)
	})
	t.Run("a public key OTP was not fused with", func(t *testing.T) {
		sig, err := Sign(other, image, SignOptions{Timestamp: stamp})
		require.NoError(t, err)
		_, err = Verify(sig, image, &other.PublicKey, fleetHash)
		var mismatch *KeyHashMismatchError
		require.ErrorAs(t, err, &mismatch)
		assert.Equal(t, fleetHash, mismatch.Want)
		assert.Equal(t, otherHash, mismatch.Got)
	})
}

func TestVerify_TimestampIsNotSigned(t *testing.T) {
	key := rsaKey(t, KeyBits)
	sig, err := Sign(key, image, SignOptions{Timestamp: stamp})
	require.NoError(t, err)
	otp, err := KeyHash(&key.PublicKey)
	require.NoError(t, err)

	// rpi-eeprom-digest signs the image alone: the ts line is not covered, so
	// an edit to it still verifies. A boot.sig is therefore only as trustworthy
	// as its transport; the digest and signature are what SIGNED_BOOT rests on.
	altered := strings.Replace(string(sig), "ts: 1790856000", "ts: 1790856001", 1)
	parsed, err := Verify([]byte(altered), image, &key.PublicKey, otp)
	require.NoError(t, err)
	assert.Equal(t, int64(1790856001), parsed.Timestamp.Unix())
}

func TestVerify_RefusesAMalformedSignature(t *testing.T) {
	key := rsaKey(t, KeyBits)
	good, err := Sign(key, image, SignOptions{Timestamp: stamp})
	require.NoError(t, err)
	otp, err := KeyHash(&key.PublicKey)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSuffix(string(good), "\n"), "\n")

	for name, sig := range map[string]string{
		"empty":                  "",
		"only the digest":        lines[0] + "\n",
		"target-soc mislabelled": lines[0] + "\n" + lines[1] + "\nsoc: 2712\n" + lines[2] + "\n",
		"five lines":             lines[0] + "\n" + lines[1] + "\ntarget-soc: 2712\ntarget-soc: 2712\n" + lines[2] + "\n",
		"digest not hex":         "zz\n" + lines[1] + "\n" + lines[2] + "\n",
		"digest too short":       "abcd\n" + lines[1] + "\n" + lines[2] + "\n",
		"no ts label":            lines[0] + "\n1790856000\n" + lines[2] + "\n",
		"ts not a number":        lines[0] + "\nts: soon\n" + lines[2] + "\n",
		"no rsa2048 label":       lines[0] + "\n" + lines[1] + "\nsig: 00\n",
		"signature not hex":      lines[0] + "\n" + lines[1] + "\nrsa2048: zz\n",
		"signature too short":    lines[0] + "\n" + lines[1] + "\nrsa2048: abcd\n",
		"trailing line":          string(good) + "extra\n",
		"signature not at end":   lines[0] + "\n" + lines[2] + "\n" + lines[1] + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify([]byte(sig), image, &key.PublicKey, otp)
			var malformed *MalformedError
			assert.ErrorAs(t, err, &malformed)
		})
	}
}

// TestParse_RefusesAnUnsupportedTargetSoC: target-soc is not covered by the
// signature, so only the parser can keep a value the writer would never emit
// from being accepted.
func TestParse_RefusesAnUnsupportedTargetSoC(t *testing.T) {
	key := rsaKey(t, KeyBits)
	good, err := Sign(key, image, SignOptions{Timestamp: stamp, TargetSoC: "2712"})
	require.NoError(t, err)
	otp, err := KeyHash(&key.PublicKey)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSuffix(string(good), "\n"), "\n")
	require.Len(t, lines, 4)

	for name, soc := range map[string]string{"unknown": "9999", "empty": "", "padded": " 2712"} {
		t.Run(name, func(t *testing.T) {
			sig := []byte(strings.Join([]string{lines[0], lines[1], "target-soc: " + soc, lines[3]}, "\n") + "\n")
			var target *TargetSoCError
			_, err := Parse(sig)
			assert.ErrorAs(t, err, &target)
			_, err = Verify(sig, image, &key.PublicKey, otp)
			assert.ErrorAs(t, err, &target)
		})
	}

	for _, soc := range []string{"2711", "2712"} {
		sig := []byte(strings.Join([]string{lines[0], lines[1], "target-soc: " + soc, lines[3]}, "\n") + "\n")
		parsed, err := Parse(sig)
		require.NoError(t, err)
		assert.Equal(t, soc, parsed.TargetSoC)
	}
}

func TestSign_Errors(t *testing.T) {
	key := rsaKey(t, KeyBits)

	t.Run("not an RSA key", func(t *testing.T) {
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		_, err = Sign(ec, image, SignOptions{Timestamp: stamp})
		var unsupported *UnsupportedKeyError
		assert.ErrorAs(t, err, &unsupported)
	})
	t.Run("RSA of another size", func(t *testing.T) {
		_, err := Sign(rsaKey(t, 3072), image, SignOptions{Timestamp: stamp})
		var bits *KeyBitsError
		assert.ErrorAs(t, err, &bits)
	})
	t.Run("a target-soc the tool does not accept", func(t *testing.T) {
		_, err := Sign(key, image, SignOptions{Timestamp: stamp, TargetSoC: "2835"})
		var soc *TargetSoCError
		assert.ErrorAs(t, err, &soc)
	})
	t.Run("the signer refuses", func(t *testing.T) {
		refuse := errors.New("kms: key disabled")
		_, err := Sign(signer{Signer: key, sign: func([]byte) ([]byte, error) { return nil, refuse }}, image, SignOptions{Timestamp: stamp})
		var signErr *SignError
		require.ErrorAs(t, err, &signErr)
		assert.ErrorIs(t, err, refuse)
	})
	t.Run("the signer signs with another key", func(t *testing.T) {
		other := rsaKey(t, KeyBits)
		wrong := signer{Signer: key, sign: func(digest []byte) ([]byte, error) {
			return rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, digest)
		}}
		_, err := Sign(wrong, image, SignOptions{Timestamp: stamp})
		var signErr *SignError
		assert.ErrorAs(t, err, &signErr)
	})
	t.Run("the signer returns nothing", func(t *testing.T) {
		_, err := Sign(signer{Signer: key, sign: func([]byte) ([]byte, error) { return nil, nil }}, image, SignOptions{Timestamp: stamp})
		var signErr *SignError
		assert.ErrorAs(t, err, &signErr)
	})
}

// A key whose exponent the bootloader cannot carry is refused before it can
// be fused: KeyBlob is what pubkey.bin, and so the OTP hash, are made from.
func TestKeyBlob_RefusesANonPositiveExponent(t *testing.T) {
	key := rsaKey(t, KeyBits)

	_, err := KeyBlob(&rsa.PublicKey{N: key.N, E: 0})
	var unsupported *UnsupportedKeyError
	require.ErrorAs(t, err, &unsupported)
	assert.Contains(t, unsupported.Error(), "exponent")
}

// Verify checks the key before the signature, so a key the bootloader
// cannot use is named as such, not reported as a bad boot.sig.
func TestVerify_RefusesAKeyTheBootloaderCannotUse(t *testing.T) {
	key := rsaKey(t, 3072)
	sig, err := Sign(rsaKey(t, KeyBits), image, SignOptions{Timestamp: stamp})
	require.NoError(t, err)

	_, err = Verify(sig, image, &key.PublicKey, [KeyHashSize]byte{})
	var bits *KeyBitsError
	require.ErrorAs(t, err, &bits)
	assert.Equal(t, 3072, bits.Bits)
}

// The runbook has the operator compare hashes and keys before the
// irreversible OTP burn, so each refusal must print what to compare.
func TestErrors_NameWhatToCheck(t *testing.T) {
	fleet := rsaKey(t, KeyBits)
	other := rsaKey(t, KeyBits)
	fleetHash, err := KeyHash(&fleet.PublicKey)
	require.NoError(t, err)
	otherHash, err := KeyHash(&other.PublicKey)
	require.NoError(t, err)
	sig, err := Sign(fleet, image, SignOptions{Timestamp: stamp})
	require.NoError(t, err)
	byOther, err := Sign(other, image, SignOptions{Timestamp: stamp})
	require.NoError(t, err)
	refuse := errors.New("kms: key disabled")

	_, keyHashErr := Verify(sig, image, &other.PublicKey, fleetHash)
	_, digestErr := Verify(sig, []byte("another image"), &fleet.PublicKey, fleetHash)
	_, signatureErr := Verify(byOther, image, &fleet.PublicKey, fleetHash)
	_, malformedErr := Verify([]byte(""), image, &fleet.PublicKey, fleetHash)
	_, socErr := Sign(fleet, image, SignOptions{Timestamp: stamp, TargetSoC: "2835"})
	_, bitsErr := KeyBlob(&rsaKey(t, 3072).PublicKey)
	_, unsupportedErr := KeyBlob(nil)
	_, signErr := Sign(signer{Signer: fleet, sign: func([]byte) ([]byte, error) { return nil, refuse }}, image, SignOptions{Timestamp: stamp})
	imageDigest := sha256.Sum256(image)

	for name, tc := range map[string]struct {
		err  error
		want []string
	}{
		"key hash":     {keyHashErr, []string{hex.EncodeToString(fleetHash[:]), hex.EncodeToString(otherHash[:])}},
		"digest":       {digestErr, []string{hex.EncodeToString(imageDigest[:])}},
		"signature":    {signatureErr, []string{"does not verify", rsa.ErrVerification.Error()}},
		"malformed":    {malformedErr, []string{"malformed boot.sig"}},
		"target-soc":   {socErr, []string{`"2835"`, "2711", "2712"}},
		"key size":     {bitsErr, []string{"3072", "2048"}},
		"no key":       {unsupportedErr, []string{"no RSA public key"}},
		"signer error": {signErr, []string{refuse.Error()}},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, tc.err)
			for _, want := range tc.want {
				assert.Contains(t, tc.err.Error(), want)
			}
		})
	}
	assert.ErrorIs(t, signatureErr, rsa.ErrVerification)
}

func TestSignDigest_IsTheSignatureInBootSig(t *testing.T) {
	key := rsaKey(t, KeyBits)
	digest := sha256.Sum256(image)

	sig, err := SignDigest(key, digest)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig))

	bootSig, err := Sign(key, image, SignOptions{Timestamp: stamp})
	require.NoError(t, err)
	parsed, err := Parse(bootSig)
	require.NoError(t, err)
	assert.Equal(t, sig, parsed.RSA, "PKCS#1 v1.5 is deterministic: boot.sig carries SignDigest's signature")
}

func TestSignDigest_Errors(t *testing.T) {
	digest := sha256.Sum256(image)

	t.Run("RSA of another size", func(t *testing.T) {
		_, err := SignDigest(rsaKey(t, 3072), digest)
		var bits *KeyBitsError
		assert.ErrorAs(t, err, &bits)
	})
	t.Run("the KMS refuses", func(t *testing.T) {
		refuse := errors.New("kms: permission denied")
		key := rsaKey(t, KeyBits)
		_, err := SignDigest(signer{Signer: key, sign: func([]byte) ([]byte, error) { return nil, refuse }}, digest)
		var signErr *SignError
		require.ErrorAs(t, err, &signErr)
		assert.ErrorIs(t, err, refuse)
	})
}
