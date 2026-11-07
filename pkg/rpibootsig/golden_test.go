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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The testdata is the upstream tools' own output for a fixed image, made
// with a throwaway key whose private half is not kept in the repository:
//
//	SOURCE_DATE_EPOCH=1790856000 rpi-eeprom-digest -k <key> -i boot.img -o boot.sig
//	SOURCE_DATE_EPOCH=1790856000 rpi-eeprom-digest -c 2712 -k <key> -i boot.img -o boot-2712.sig
//	pubkey.bin: pemtobin() from rpi-eeprom-config (N as 256 little-endian bytes, then E as 8)
//
// Verification runs against the upstream files; signing runs with a key made
// at test time and is checked line by line against the upstream layout.
const goldenEpoch = 1790856000

func golden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

// goldenKey is the public half of the key that signed the upstream files,
// read back from pubkey.bin.
func goldenKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	pub, err := ParseKeyBlob(golden(t, "pubkey.bin"))
	require.NoError(t, err)
	return &rsa.PrivateKey{PublicKey: *pub}
}

// assertSameLayout checks sig against the upstream file line by line: every
// line is identical except the signature line, which only has to carry the
// same prefix and length, since sig was made with a different key.
func assertSameLayout(t *testing.T, want, sig []byte) {
	t.Helper()
	wantLines := strings.Split(string(want), "\n")
	gotLines := strings.Split(string(sig), "\n")
	require.Len(t, gotLines, len(wantLines))
	for i, w := range wantLines {
		if prefix, _, ok := strings.Cut(w, " "); ok && strings.HasPrefix(prefix, "rsa") {
			assert.True(t, strings.HasPrefix(gotLines[i], prefix+" "), "line %d", i)
			assert.Len(t, gotLines[i], len(w), "line %d", i)
			continue
		}
		assert.Equal(t, w, gotLines[i], "line %d", i)
	}
}

func TestGolden_SignReproducesTheUpstreamLayout(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	img := golden(t, "boot.img")
	otp, err := KeyHash(&key.PublicKey)
	require.NoError(t, err)

	for name, soc := range map[string]string{"boot.sig": "", "boot-2712.sig": "2712"} {
		t.Run(name, func(t *testing.T) {
			sig, err := Sign(key, img, SignOptions{Timestamp: time.Unix(goldenEpoch, 0), TargetSoC: soc})
			require.NoError(t, err)
			assertSameLayout(t, golden(t, name), sig)
			_, err = Verify(sig, img, &key.PublicKey, otp)
			require.NoError(t, err)
		})
	}
}

func TestGolden_VerifyAcceptsTheUpstreamFile(t *testing.T) {
	key := goldenKey(t)
	img := golden(t, "boot.img")
	otp := sha256.Sum256(golden(t, "pubkey.bin"))

	for name, soc := range map[string]string{"boot.sig": "", "boot-2712.sig": "2712"} {
		t.Run(name, func(t *testing.T) {
			parsed, err := Verify(golden(t, name), img, &key.PublicKey, otp)
			require.NoError(t, err)
			assert.Equal(t, int64(goldenEpoch), parsed.Timestamp.Unix())
			assert.Equal(t, soc, parsed.TargetSoC)
		})
	}
}

func TestGolden_KeyBlobAndHashMatchPemtobin(t *testing.T) {
	key := goldenKey(t)
	blob, err := KeyBlob(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, golden(t, "pubkey.bin"), blob)

	hash, err := KeyHash(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(golden(t, "pubkey.bin")), hash)

	parsed, err := ParseKeyBlob(golden(t, "pubkey.bin"))
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(parsed))
}

func TestGolden_UpstreamFileRefusedWhenTampered(t *testing.T) {
	key := goldenKey(t)
	img := golden(t, "boot.img")
	otp := sha256.Sum256(golden(t, "pubkey.bin"))

	img[0] ^= 0xff
	_, err := Verify(golden(t, "boot.sig"), img, &key.PublicKey, otp)
	var mismatch *DigestMismatchError
	assert.ErrorAs(t, err, &mismatch)
}
