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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The testdata is the upstream tools' own output for a fixed key and image:
//
//	SOURCE_DATE_EPOCH=1790856000 rpi-eeprom-digest -k fleet-test-key.pem -i boot.img -o boot.sig
//	SOURCE_DATE_EPOCH=1790856000 rpi-eeprom-digest -c 2712 -k fleet-test-key.pem -i boot.img -o boot-2712.sig
//	pubkey.bin: pemtobin() from rpi-eeprom-config (N as 256 little-endian bytes, then E as 8)
//
// fleet-test-key.pem is a throwaway key that protects nothing.
const goldenEpoch = 1790856000

func golden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

func goldenKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(golden(t, "fleet-test-key.pem"))
	require.NotNil(t, block)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	rsaKey, ok := key.(*rsa.PrivateKey)
	require.True(t, ok)
	return rsaKey
}

func TestGolden_SignReproducesTheUpstreamFile(t *testing.T) {
	key := goldenKey(t)
	img := golden(t, "boot.img")

	t.Run("without target-soc", func(t *testing.T) {
		sig, err := Sign(key, img, SignOptions{Timestamp: time.Unix(goldenEpoch, 0)})
		require.NoError(t, err)
		assert.Equal(t, string(golden(t, "boot.sig")), string(sig))
	})
	t.Run("with target-soc", func(t *testing.T) {
		sig, err := Sign(key, img, SignOptions{Timestamp: time.Unix(goldenEpoch, 0), TargetSoC: "2712"})
		require.NoError(t, err)
		assert.Equal(t, string(golden(t, "boot-2712.sig")), string(sig))
	})
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
