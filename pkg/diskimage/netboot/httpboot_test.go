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

package netboot

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/diskimagetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/fatimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpibootsig"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
)

var httpBootEpoch = time.Unix(1790856000, 0)

// bootTree writes a small Pi boot partition and returns its directory.
func bootTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.txt"), []byte("arm_64bit=1\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kernel8.img"), []byte("kernel"), 0o644))
	return dir
}

func stagedHTTPBoot(t *testing.T) (*rsa.PrivateKey, string, *HTTPBootFiles) {
	t.Helper()
	key, _ := secureboottest.KeyPair(t, "fleet")
	dest := filepath.Join(t.TempDir(), HTTPBootDir)
	files, err := StageHTTPBoot(HTTPBootInputs{BootTree: bootTree(t), Signer: key, Timestamp: httpBootEpoch}, dest)
	require.NoError(t, err)
	return key, dest, files
}

func TestStageHTTPBoot_WritesAVerifiableSignedImage(t *testing.T) {
	key, dest, files := stagedHTTPBoot(t)

	for _, name := range []string{container.HTTPBootImage, container.HTTPBootSignature, container.HTTPBootPublicKey} {
		assert.FileExists(t, filepath.Join(dest, name))
	}
	want, err := rpibootsig.KeyHash(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, want, files.KeyHash, "the OTP hash is the hash of the fleet public key")
	assert.Len(t, files.KeyHashHex(), 64)

	image, err := os.ReadFile(filepath.Join(dest, container.HTTPBootImage))
	require.NoError(t, err)
	assert.Equal(t, len(image), files.ImageSize)
	fat, err := fatimage.Open(image)
	require.NoError(t, err, "boot.img is the FAT ramdisk the bootloader mounts")
	kernel, err := fat.ReadFile("kernel8.img")
	require.NoError(t, err)
	assert.Equal(t, "kernel", string(kernel))

	parsed, err := VerifyHTTPBoot(dest, files.KeyHash)
	require.NoError(t, err)
	assert.Equal(t, httpBootEpoch.Unix(), parsed.Timestamp.Unix())
	assert.Empty(t, parsed.TargetSoC, "boot.img omits target-soc unless the operator asks for it")
}

func TestStageHTTPBoot_WritesExplicitTargetSoC(t *testing.T) {
	key, _ := secureboottest.KeyPair(t, "fleet")
	dest := filepath.Join(t.TempDir(), HTTPBootDir)
	files, err := StageHTTPBoot(HTTPBootInputs{BootTree: bootTree(t), TargetSoC: "2712", Signer: key, Timestamp: httpBootEpoch}, dest)
	require.NoError(t, err)

	parsed, err := VerifyHTTPBoot(dest, files.KeyHash)
	require.NoError(t, err)
	assert.Equal(t, "2712", parsed.TargetSoC)
}

func TestStageHTTPBoot_ReplacesAStalePair(t *testing.T) {
	key, _ := secureboottest.KeyPair(t, "fleet")
	dest := filepath.Join(t.TempDir(), HTTPBootDir)
	require.NoError(t, os.MkdirAll(dest, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dest, "stale"), []byte("x"), 0o644))

	_, err := StageHTTPBoot(HTTPBootInputs{BootTree: bootTree(t), TargetSoC: "2712", Signer: key, Timestamp: httpBootEpoch}, dest)
	require.NoError(t, err)
	assert.NoFileExists(t, filepath.Join(dest, "stale"))
}

func TestStageHTTPBoot_Errors(t *testing.T) {
	key, _ := secureboottest.KeyPair(t, "fleet")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// A fixed 1024-bit modulus, not rsa.GenerateKey: fips140=only refuses to
	// generate a key that short, and StageHTTPBoot refuses it on its size
	// alone, before any RSA operation.
	shortKey := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537}}
	tree := bootTree(t)
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o644))

	tests := map[string]struct {
		in   HTTPBootInputs
		dest string
		as   any
	}{
		"target-soc":       {in: HTTPBootInputs{BootTree: tree, TargetSoC: "2710", Signer: key}, as: new(*rpibootsig.TargetSoCError)},
		"ecdsa key":        {in: HTTPBootInputs{BootTree: tree, Signer: ecKey}, as: new(*rpibootsig.UnsupportedKeyError)},
		"1024-bit key":     {in: HTTPBootInputs{BootTree: tree, Signer: shortKey}, as: new(*rpibootsig.KeyBitsError)},
		"missing boot dir": {in: HTTPBootInputs{BootTree: filepath.Join(tree, "nope"), Signer: key}, as: new(*HTTPBootError)},
		"unwritable dest":  {in: HTTPBootInputs{BootTree: tree, Signer: key}, dest: filepath.Join(file, "sub"), as: new(*HTTPBootError)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			dest := tc.dest
			if dest == "" {
				dest = filepath.Join(t.TempDir(), HTTPBootDir)
			}
			_, err := StageHTTPBoot(tc.in, dest)
			require.Error(t, err)
			assert.ErrorAs(t, err, tc.as)
			var httpErr *HTTPBootError
			assert.ErrorAs(t, err, &httpErr)
		})
	}
}

func TestVerifyHTTPBoot(t *testing.T) {
	_, dest, files := stagedHTTPBoot(t)
	image := filepath.Join(dest, container.HTTPBootImage)

	t.Run("a tampered image is refused", func(t *testing.T) {
		data, err := os.ReadFile(image)
		require.NoError(t, err)
		data[len(data)-1] ^= 0xff
		tampered := t.TempDir()
		copyDir(t, dest, tampered)
		require.NoError(t, os.WriteFile(filepath.Join(tampered, container.HTTPBootImage), data, 0o644))

		_, err = VerifyHTTPBoot(tampered, files.KeyHash)
		var mismatch *rpibootsig.DigestMismatchError
		assert.ErrorAs(t, err, &mismatch)
	})
	t.Run("a key the OTP is not fused for is refused", func(t *testing.T) {
		other, _ := secureboottest.KeyPair(t, "other")
		otherHash, err := rpibootsig.KeyHash(&other.PublicKey)
		require.NoError(t, err)

		_, err = VerifyHTTPBoot(dest, otherHash)
		var mismatch *rpibootsig.KeyHashMismatchError
		assert.ErrorAs(t, err, &mismatch)
	})
	t.Run("a signature by another key is refused", func(t *testing.T) {
		// boot.sig and pubkey.bin of a different fleet key over the same image:
		// the key hash matches the swapped pubkey.bin, the signature cannot.
		other, _ := secureboottest.KeyPair(t, "other")
		forged := t.TempDir()
		copyDir(t, dest, forged)
		blob, err := rpibootsig.KeyBlob(&other.PublicKey)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(forged, container.HTTPBootPublicKey), blob, 0o644))
		otherHash, err := rpibootsig.KeyHash(&other.PublicKey)
		require.NoError(t, err)

		_, err = VerifyHTTPBoot(forged, otherHash)
		var bad *rpibootsig.SignatureError
		assert.ErrorAs(t, err, &bad)
	})
	t.Run("a missing file is refused", func(t *testing.T) {
		for _, name := range []string{container.HTTPBootImage, container.HTTPBootSignature, container.HTTPBootPublicKey} {
			broken := t.TempDir()
			copyDir(t, dest, broken)
			require.NoError(t, os.Remove(filepath.Join(broken, name)))

			_, err := VerifyHTTPBoot(broken, files.KeyHash)
			var httpErr *HTTPBootError
			assert.ErrorAs(t, err, &httpErr, name)
		}
	})
	t.Run("a malformed key blob is refused", func(t *testing.T) {
		broken := t.TempDir()
		copyDir(t, dest, broken)
		require.NoError(t, os.WriteFile(filepath.Join(broken, container.HTTPBootPublicKey), []byte("short"), 0o644))

		_, err := VerifyHTTPBoot(broken, files.KeyHash)
		var httpErr *HTTPBootError
		assert.ErrorAs(t, err, &httpErr)
	})
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	require.NoError(t, err)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(from, e.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(to, e.Name()), data, 0o644))
	}
}

// httpBootConfig is a Config for httpBootFiles with the fleet key in a fake KMS
// and a Pi TFTP tree already staged.
func httpBootConfig(t *testing.T, kms *secureboottest.KMS, cert *x509.Certificate) *Config {
	t.Helper()
	out := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(out, TFTPTreeDir), 0o755))
	copyDir(t, bootTree(t), filepath.Join(out, TFTPTreeDir))
	return &Config{
		OutputDir: out,
		Model:     "rpi4",
		Sets:      []Set{RaspberryPiSet},
		HTTPBoot:  &HTTPBoot{FleetKey: "kms://sb/fleet", Timestamp: httpBootEpoch},
		Build: &diskimage.BuildConfig{KMSClients: func() (*iso.KMSClients, error) {
			return &iso.KMSClients{KMS: kms, CA: &secureboottest.CA{Certs: map[string]*x509.Certificate{"sb/fleet": cert}}}, nil
		}},
	}
}

func TestHTTPBootFiles_SignsWithTheKMSAndNeverHoldsTheKey(t *testing.T) {
	key, cert := secureboottest.KeyPair(t, "fleet")
	kms := &secureboottest.KMS{Key: key}
	cfg := httpBootConfig(t, kms, cert)

	files, err := cfg.httpBootFiles(context.Background())
	require.NoError(t, err)

	require.NotNil(t, kms.LastReq, "the signature came from the KMS")
	assert.True(t, kms.LastReq.GetPreHashed(), "the KMS is sent a digest, not the image")
	assert.Len(t, kms.LastReq.GetMessage(), 32)
	_, err = VerifyHTTPBoot(filepath.Join(cfg.OutputDir, HTTPBootDir), files.KeyHash)
	require.NoError(t, err)
}

// An unset timestamp signs boot.sig with the build's time, not the zero time
// the EEPROM would read as 1970.
func TestHTTPBootFiles_UnsetTimestampIsTheBuildTime(t *testing.T) {
	key, cert := secureboottest.KeyPair(t, "fleet")
	cfg := httpBootConfig(t, &secureboottest.KMS{Key: key}, cert)
	cfg.HTTPBoot.Timestamp = time.Time{}

	before := time.Now().UTC().Truncate(time.Second)
	files, err := cfg.httpBootFiles(context.Background())
	require.NoError(t, err)
	after := time.Now().UTC().Add(time.Second)

	sig, err := VerifyHTTPBoot(filepath.Join(cfg.OutputDir, HTTPBootDir), files.KeyHash)
	require.NoError(t, err)
	assert.False(t, sig.Timestamp.Before(before), "signed at %s, the build began at %s", sig.Timestamp, before)
	assert.False(t, sig.Timestamp.After(after), "signed at %s, the build ended by %s", sig.Timestamp, after)
}

func TestHTTPBootFiles_Errors(t *testing.T) {
	key, cert := secureboottest.KeyPair(t, "fleet")
	otherKey, _ := secureboottest.KeyPair(t, "other")
	errKMS := errors.New("kms down")

	t.Run("no platform connection", func(t *testing.T) {
		cfg := httpBootConfig(t, &secureboottest.KMS{Key: key}, cert)
		cfg.Build.KMSClients = func() (*iso.KMSClients, error) { return nil, errKMS }
		_, err := cfg.httpBootFiles(context.Background())
		assert.ErrorIs(t, err, errKMS)
	})
	t.Run("the fleet certificate is not in the CA", func(t *testing.T) {
		cfg := httpBootConfig(t, &secureboottest.KMS{Key: key}, cert)
		cfg.HTTPBoot.FleetCert = "kms://sb/unknown"
		_, err := cfg.httpBootFiles(context.Background())
		assert.ErrorIs(t, err, secureboottest.ErrNoCertificate)
	})
	t.Run("the KMS refuses to sign", func(t *testing.T) {
		cfg := httpBootConfig(t, &secureboottest.KMS{Key: key, Err: errKMS}, cert)
		_, err := cfg.httpBootFiles(context.Background())
		var signErr *rpibootsig.SignError
		assert.ErrorAs(t, err, &signErr)
		assert.ErrorIs(t, err, errKMS)
	})
	t.Run("the KMS signs with a key that is not the certificate's", func(t *testing.T) {
		cfg := httpBootConfig(t, &secureboottest.KMS{Key: otherKey}, cert)
		_, err := cfg.httpBootFiles(context.Background())
		var signErr *rpibootsig.SignError
		assert.ErrorAs(t, err, &signErr)
		assert.NoDirExists(t, filepath.Join(cfg.OutputDir, HTTPBootDir), "nothing is served that does not verify")
	})
	t.Run("an unknown model", func(t *testing.T) {
		cfg := httpBootConfig(t, &secureboottest.KMS{Key: key}, cert)
		cfg.Model = "nope"
		_, err := cfg.httpBootFiles(context.Background())
		var httpErr *HTTPBootError
		assert.ErrorAs(t, err, &httpErr)
	})
}

// Build's last step reads the staged files back as the EEPROM does; a staged
// tree that no longer verifies fails the build instead of being served.
func TestReadBackHTTPBoot(t *testing.T) {
	key, cert := secureboottest.KeyPair(t, "fleet")
	staged := func(t *testing.T) (*Config, *HTTPBootFiles) {
		cfg := httpBootConfig(t, &secureboottest.KMS{Key: key}, cert)
		files, err := cfg.httpBootFiles(context.Background())
		require.NoError(t, err)
		return cfg, files
	}

	t.Run("the staged files verify", func(t *testing.T) {
		cfg, files := staged(t)
		require.NoError(t, readBackHTTPBoot(cfg.OutputDir, files))
	})
	t.Run("boot.img changed after it was signed", func(t *testing.T) {
		cfg, files := staged(t)
		image := filepath.Join(cfg.OutputDir, HTTPBootDir, container.HTTPBootImage)
		data, err := os.ReadFile(image)
		require.NoError(t, err)
		data[len(data)-1] ^= 0xff
		require.NoError(t, os.WriteFile(image, data, 0o644))

		err = readBackHTTPBoot(cfg.OutputDir, files)
		var buildErr *BuildError
		require.ErrorAs(t, err, &buildErr)
		assert.Equal(t, "loading the HTTP boot files back", buildErr.Step)
		var httpErr *HTTPBootError
		require.ErrorAs(t, err, &httpErr)
		assert.Equal(t, "verifying boot.sig", httpErr.Step)
	})
	t.Run("pubkey.bin is gone", func(t *testing.T) {
		cfg, files := staged(t)
		require.NoError(t, os.Remove(filepath.Join(cfg.OutputDir, HTTPBootDir, container.HTTPBootPublicKey)))

		var buildErr *BuildError
		require.ErrorAs(t, readBackHTTPBoot(cfg.OutputDir, files), &buildErr)
	})
}

// A pinned fleet certificate signs; any other certificate under the
// reference stops the build before the KMS is asked to sign.
func TestHTTPBootFiles_PinnedFleetCertificate(t *testing.T) {
	key, cert := secureboottest.KeyPair(t, "fleet")
	_, other := secureboottest.KeyPair(t, "fleet")
	sum := sha256.Sum256(cert.Raw)
	pinned := "kms://sb/fleet#sha256=" + hex.EncodeToString(sum[:])

	cfg := httpBootConfig(t, &secureboottest.KMS{Key: key}, cert)
	cfg.HTTPBoot.FleetCert = pinned
	_, err := cfg.httpBootFiles(context.Background())
	require.NoError(t, err)

	kms := &secureboottest.KMS{Key: key}
	cfg = httpBootConfig(t, kms, other)
	cfg.HTTPBoot.FleetCert = pinned
	_, err = cfg.httpBootFiles(context.Background())
	var pinErr *secureboot.CertPinError
	require.ErrorAs(t, err, &pinErr)
	assert.Nil(t, kms.LastReq, "nothing was signed")
	assert.NoDirExists(t, filepath.Join(cfg.OutputDir, HTTPBootDir))
}

func TestResolveHTTPBoot(t *testing.T) {
	key, cert := secureboottest.KeyPair(t, "fleet")
	valid := func() *Config { return httpBootConfig(t, &secureboottest.KMS{Key: key}, cert) }

	require.NoError(t, valid().resolveHTTPBoot())

	tests := map[string]struct {
		edit func(*Config)
		as   any
	}{
		"no Pi set":            {edit: func(c *Config) { c.Sets = []Set{ARM64VirtSet} }, as: new(*NoPiSetError)},
		"board without EEPROM": {edit: func(c *Config) { c.Model = "rpi3b+" }, as: new(*NoEEPROMError)},
		"unknown board":        {edit: func(c *Config) { c.Model = "nope" }, as: new(*HTTPBootError)},
		"fleet key a file":     {edit: func(c *Config) { c.HTTPBoot.FleetKey = "/keys/fleet.pem" }, as: new(*FleetKeyRefError)},
		"empty fleet key":      {edit: func(c *Config) { c.HTTPBoot.FleetKey = "" }, as: new(*FleetKeyRefError)},
		"no platform client":   {edit: func(c *Config) { c.Build.KMSClients = nil }, as: new(*MissingFileError)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := valid()
			tc.edit(cfg)
			err := cfg.resolveHTTPBoot()
			require.Error(t, err)
			assert.ErrorAs(t, err, tc.as)
			var buildErr *BuildError
			assert.ErrorAs(t, err, &buildErr)
		})
	}
}

func TestBuild_RefusesHTTPBootWithoutAPiSet(t *testing.T) {
	cfg := buildConfig(t, diskimagetest.PlatformConfig(t))
	cfg.HTTPBoot = &HTTPBoot{FleetKey: "kms://sb/fleet"}

	_, err := Build(context.Background(), cfg)
	var noPi *NoPiSetError
	assert.ErrorAs(t, err, &noPi, "the HTTP boot configuration is checked before anything is built")
	assert.NoDirExists(t, cfg.OutputDir)
}
