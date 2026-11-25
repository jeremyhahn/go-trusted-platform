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

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/fatimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpibootsig"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpinetboot"
)

// httpBootFixture serves a signed boot.img under /data/http-boot/ and returns
// the flags a Pi holding the fleet key would probe it with.
func httpBootFixture(t *testing.T, tamper bool) (*probeRPiHTTPFlags, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, rpibootsig.KeyBits)
	require.NoError(t, err)
	tree := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tree, "config.txt"), []byte("arm_64bit=1\n"), 0o644))
	image, err := fatimage.Build(os.DirFS(tree), fatimage.Options{})
	require.NoError(t, err)
	sig, err := rpibootsig.Sign(key, image, rpibootsig.SignOptions{Timestamp: time.Unix(1790856000, 0), TargetSoC: "2712"})
	require.NoError(t, err)
	if tamper {
		image[len(image)-1] ^= 0xff
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/data/http-boot/boot.img", func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(image)
		assert.NoError(t, err)
	})
	mux.HandleFunc("/data/http-boot/boot.sig", func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(sig)
		assert.NoError(t, err)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	blob, err := rpibootsig.KeyBlob(&key.PublicKey)
	require.NoError(t, err)
	hash, err := rpibootsig.KeyHash(&key.PublicKey)
	require.NoError(t, err)
	pubkey := filepath.Join(t.TempDir(), "pubkey.bin")
	require.NoError(t, os.WriteFile(pubkey, blob, 0o644))
	return &probeRPiHTTPFlags{
		host:    strings.TrimPrefix(srv.URL, "http://"),
		path:    defaultHTTPBootPath,
		pubkey:  pubkey,
		otpHash: hex.EncodeToString(hash[:]),
	}, key
}

func TestProbeHTTPOptions(t *testing.T) {
	logger := logging.DefaultLogger()
	good, key := httpBootFixture(t, false)

	opts, err := probeHTTPOptions(good, logger)
	require.NoError(t, err)
	hash, err := rpibootsig.KeyHash(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, good.host, opts.Host)
	assert.Equal(t, "data/http-boot", opts.Path, "the container serves its data directory under /data/")
	assert.Equal(t, hash, opts.OTPKeyHash)
	assert.Len(t, opts.PublicKey, rpibootsig.KeyBlobSize)
	assert.Same(t, logger, opts.Logger)

	for name, mutate := range map[string]func(*probeRPiHTTPFlags){
		"no host":           func(f *probeRPiHTTPFlags) { f.host = "" },
		"no pubkey":         func(f *probeRPiHTTPFlags) { f.pubkey = "" },
		"pubkey not a file": func(f *probeRPiHTTPFlags) { f.pubkey = filepath.Join(t.TempDir(), "nope") },
		"hash not hex":      func(f *probeRPiHTTPFlags) { f.otpHash = strings.Repeat("zz", 32) },
		"hash too short":    func(f *probeRPiHTTPFlags) { f.otpHash = "abcd" },
		"no hash":           func(f *probeRPiHTTPFlags) { f.otpHash = "" },
	} {
		t.Run(name, func(t *testing.T) {
			f := *good
			mutate(&f)
			_, err := probeHTTPOptions(&f, logger)
			var invalid *ErrProbeInvalidFlag
			require.ErrorAs(t, err, &invalid, name)
			assert.NotEmpty(t, invalid.Error())
		})
	}
}

func TestPrintHTTPBootReport_ReturnsPrintError(t *testing.T) {
	report := &rpinetboot.HTTPBootReport{
		URL:       "http://10.99.99.1:8080/data/http-boot",
		Image:     rpinetboot.FileReport{Name: rpinetboot.HTTPBootImage, Bytes: 123, SHA256: strings.Repeat("a", 64)},
		Signature: &rpibootsig.Signature{Timestamp: time.Unix(1790856000, 0).UTC()},
		Ramdisk:   []string{"config.txt"},
	}

	err := printHTTPBootReport(report, &cli.CommonFlags{OutputFormat: cli.OutputFormat("bogus")})
	var formatErr cli.ErrInvalidOutputFormat
	require.ErrorAs(t, err, &formatErr)
}

func TestRunProbeRPiHTTP_BootsASignedImage(t *testing.T) {
	flags, _ := httpBootFixture(t, false)

	out := captureStdout(t, func() {
		require.NoError(t, runProbeRPiHTTP(context.Background(), flags, &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}))
	})
	var view probeHTTPView
	require.NoError(t, json.Unmarshal([]byte(out), &view), out)
	assert.Equal(t, "http://"+flags.host+"/data/http-boot", view.URL)
	assert.Equal(t, int64(1790856000), view.Timestamp)
	assert.Equal(t, "2712", view.TargetSoC)
	assert.Equal(t, []string{"config.txt"}, view.Ramdisk)

	table := captureStdout(t, func() {
		require.NoError(t, runProbeRPiHTTP(context.Background(), flags, &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}))
	})
	assert.Contains(t, table, "verified against the OTP key hash")
	assert.Contains(t, table, "target-soc 2712")
	assert.Contains(t, table, "config.txt")
}

func TestRunProbeRPiHTTP_FailsWhatTheBootloaderRefuses(t *testing.T) {
	t.Run("a tampered image", func(t *testing.T) {
		flags, _ := httpBootFixture(t, true)
		err := runProbeRPiHTTP(context.Background(), flags, nil)
		var failed *ErrProbeFailed
		require.ErrorAs(t, err, &failed)
		var digest *rpibootsig.DigestMismatchError
		assert.ErrorAs(t, err, &digest)
	})
	t.Run("an OTP hash of another key", func(t *testing.T) {
		flags, _ := httpBootFixture(t, false)
		flags.otpHash = strings.Repeat("00", 32)
		err := runProbeRPiHTTP(context.Background(), flags, nil)
		var mismatch *rpibootsig.KeyHashMismatchError
		assert.ErrorAs(t, err, &mismatch)
	})
	t.Run("bad flags fail before any request", func(t *testing.T) {
		var invalid *ErrProbeInvalidFlag
		assert.ErrorAs(t, runProbeRPiHTTP(context.Background(), &probeRPiHTTPFlags{}, nil), &invalid)
	})
	t.Run("a server that is not there", func(t *testing.T) {
		flags, _ := httpBootFixture(t, false)
		flags.host = "127.0.0.1:1"
		flags.timeout = 5 * time.Second
		var fetch *rpinetboot.HTTPFetchError
		assert.ErrorAs(t, runProbeRPiHTTP(context.Background(), flags, nil), &fetch)
	})
}

func TestNewProbeCommand_RPiHTTP(t *testing.T) {
	cmd := newProbeCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	httpCmd, _, err := cmd.Find([]string{"rpi-http"})
	require.NoError(t, err)
	assert.Equal(t, "rpi-http", httpCmd.Name())
	for _, flag := range []string{"http-host", "http-path", "pubkey", "otp-key-hash", "timeout"} {
		assert.NotNil(t, httpCmd.Flags().Lookup(flag), flag)
	}
	assert.Equal(t, "data/http-boot", httpCmd.Flags().Lookup("http-path").DefValue)

	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"rpi-http"})
	var invalid *ErrProbeInvalidFlag
	assert.ErrorAs(t, cmd.Execute(), &invalid)
}
