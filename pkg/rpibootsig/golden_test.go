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

// The testdata is the upstream tools' own output for a fixed image, signed
// with a throwaway key that is not kept in the tree:
//
//	SOURCE_DATE_EPOCH=1790856000 rpi-eeprom-digest -k throwaway-key.pem -i boot.img -o boot.sig
//	SOURCE_DATE_EPOCH=1790856000 rpi-eeprom-digest -c 2712 -k throwaway-key.pem -i boot.img -o boot-2712.sig
//	pubkey.bin: pemtobin() from rpi-eeprom-config (N as 256 little-endian bytes, then E as 8)
const goldenEpoch = 1790856000

func golden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

func goldenPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	pub, err := ParseKeyBlob(golden(t, "pubkey.bin"))
	require.NoError(t, err)
	return pub
}

// The upstream signature belongs to the throwaway key, so Sign with a fresh
// key must reproduce every line of the upstream file but the signature, and
// Verify must accept what it wrote.
func TestGolden_SignReproducesTheUpstreamFile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	img := golden(t, "boot.img")
	otp, err := KeyHash(&key.PublicKey)
	require.NoError(t, err)

	for name, tc := range map[string]struct{ file, soc string }{
		"without target-soc": {"boot.sig", ""},
		"with target-soc":    {"boot-2712.sig", "2712"},
	} {
		t.Run(name, func(t *testing.T) {
			sig, err := Sign(key, img, SignOptions{Timestamp: time.Unix(goldenEpoch, 0), TargetSoC: tc.soc})
			require.NoError(t, err)

			want := strings.Split(string(golden(t, tc.file)), "\n")
			got := strings.Split(string(sig), "\n")
			require.Len(t, got, len(want))
			for i := range want {
				if strings.HasPrefix(want[i], signaturePrefix) {
					assert.True(t, strings.HasPrefix(got[i], signaturePrefix), "line %d: %q", i, got[i])
					continue
				}
				assert.Equal(t, want[i], got[i], "line %d", i)
			}

			parsed, err := Verify(sig, img, &key.PublicKey, otp)
			require.NoError(t, err)
			assert.Equal(t, int64(goldenEpoch), parsed.Timestamp.Unix())
			assert.Equal(t, tc.soc, parsed.TargetSoC)
		})
	}
}

func TestGolden_VerifyAcceptsTheUpstreamFile(t *testing.T) {
	pub := goldenPublicKey(t)
	img := golden(t, "boot.img")
	otp := sha256.Sum256(golden(t, "pubkey.bin"))

	for name, soc := range map[string]string{"boot.sig": "", "boot-2712.sig": "2712"} {
		t.Run(name, func(t *testing.T) {
			parsed, err := Verify(golden(t, name), img, pub, otp)
			require.NoError(t, err)
			assert.Equal(t, int64(goldenEpoch), parsed.Timestamp.Unix())
			assert.Equal(t, soc, parsed.TargetSoC)
		})
	}
}

func TestGolden_KeyBlobAndHashMatchPemtobin(t *testing.T) {
	pub := goldenPublicKey(t)
	blob, err := KeyBlob(pub)
	require.NoError(t, err)
	assert.Equal(t, golden(t, "pubkey.bin"), blob)

	hash, err := KeyHash(pub)
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(golden(t, "pubkey.bin")), hash)
}

func TestGolden_UpstreamFileRefusedWhenTampered(t *testing.T) {
	pub := goldenPublicKey(t)
	img := golden(t, "boot.img")
	otp := sha256.Sum256(golden(t, "pubkey.bin"))

	img[0] ^= 0xff
	_, err := Verify(golden(t, "boot.sig"), img, pub, otp)
	var mismatch *DigestMismatchError
	assert.ErrorAs(t, err, &mismatch)
}
