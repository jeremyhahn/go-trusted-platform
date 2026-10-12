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

package rpinetboot

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/fatimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpibootsig"
)

const httpBootPath = "data/http-boot"

var httpBootEpoch = time.Unix(1790856000, 0)

func fleetKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, rpibootsig.KeyBits)
	require.NoError(t, err)
	return key
}

// bootFiles returns a signed boot.img, its boot.sig and the key as the EEPROM
// carries it, for a ramdisk of config.txt and a kernel.
func bootFiles(t *testing.T, key *rsa.PrivateKey) (image, sig, blob []byte) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.txt"), []byte("arm_64bit=1\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kernel8.img"), []byte("kernel"), 0o644))
	image, err := fatimage.Build(os.DirFS(dir), fatimage.Options{})
	require.NoError(t, err)
	sig, err = rpibootsig.Sign(key, image, rpibootsig.SignOptions{Timestamp: httpBootEpoch, TargetSoC: "2711"})
	require.NoError(t, err)
	blob, err = rpibootsig.KeyBlob(&key.PublicKey)
	require.NoError(t, err)
	return image, sig, blob
}

// bootServer serves files under /data/http-boot/ and returns the server's
// HTTP_HOST.
func bootServer(t *testing.T, files map[string][]byte) string {
	t.Helper()
	mux := http.NewServeMux()
	for name, data := range files {
		mux.HandleFunc("/"+httpBootPath+"/"+name, func(w http.ResponseWriter, _ *http.Request) {
			_, err := w.Write(data)
			assert.NoError(t, err)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func options(t *testing.T, host string, key *rsa.PrivateKey) HTTPBootOptions {
	t.Helper()
	hash, err := rpibootsig.KeyHash(&key.PublicKey)
	require.NoError(t, err)
	blob, err := rpibootsig.KeyBlob(&key.PublicKey)
	require.NoError(t, err)
	return HTTPBootOptions{Host: host, Path: httpBootPath, PublicKey: blob, OTPKeyHash: hash}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type closeErrorBody struct {
	*strings.Reader
}

func (b closeErrorBody) Close() error { return assert.AnError }

func TestHTTPBoot_BootsASignedImage(t *testing.T) {
	key := fleetKey(t)
	image, sig, _ := bootFiles(t, key)
	host := bootServer(t, map[string][]byte{HTTPBootImage: image, HTTPBootSignature: sig})

	opts := options(t, host, key)
	opts.Path = "/" + httpBootPath + "/" // the EEPROM's HTTP_PATH, however it is slashed
	report, err := HTTPBoot(context.Background(), opts)
	require.NoError(t, err)

	assert.Equal(t, "http://"+host+"/"+httpBootPath, report.URL)
	digest := sha256.Sum256(image)
	assert.Equal(t, hex.EncodeToString(digest[:]), report.Image.SHA256)
	assert.Equal(t, int64(len(image)), report.Image.Bytes)
	assert.Equal(t, httpBootEpoch.Unix(), report.Signature.Timestamp.Unix())
	assert.Equal(t, "2711", report.Signature.TargetSoC)
	assert.Equal(t, []string{"config.txt", "kernel8.img"}, report.Ramdisk)
}

func TestHTTPBoot_EmptyPathUsesRoot(t *testing.T) {
	key := fleetKey(t)
	image, sig, _ := bootFiles(t, key)
	var paths []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/" + HTTPBootImage:
			_, err := w.Write(image)
			assert.NoError(t, err)
		case "/" + HTTPBootSignature:
			_, err := w.Write(sig)
			assert.NoError(t, err)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	opts := options(t, strings.TrimPrefix(srv.URL, "http://"), key)
	opts.Path = ""

	_, err := HTTPBoot(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, []string{"/" + HTTPBootImage, "/" + HTTPBootSignature}, paths)
}

func TestHTTPBoot_RefusesWhatTheBootloaderWould(t *testing.T) {
	key := fleetKey(t)
	other := fleetKey(t)
	image, sig, _ := bootFiles(t, key)
	otherSig, err := rpibootsig.Sign(other, image, rpibootsig.SignOptions{Timestamp: httpBootEpoch, TargetSoC: "2711"})
	require.NoError(t, err)

	tampered := append([]byte(nil), image...)
	tampered[len(tampered)-1] ^= 0xff

	t.Run("a tampered image", func(t *testing.T) {
		host := bootServer(t, map[string][]byte{HTTPBootImage: tampered, HTTPBootSignature: sig})
		_, err := HTTPBoot(context.Background(), options(t, host, key))
		var refused *HTTPBootRefusedError
		require.ErrorAs(t, err, &refused)
		var mismatch *rpibootsig.DigestMismatchError
		assert.ErrorAs(t, err, &mismatch)
	})
	t.Run("an OTP hash of another key", func(t *testing.T) {
		host := bootServer(t, map[string][]byte{HTTPBootImage: image, HTTPBootSignature: sig})
		opts := options(t, host, key)
		wrong, err := rpibootsig.KeyHash(&other.PublicKey)
		require.NoError(t, err)
		opts.OTPKeyHash = wrong

		_, err = HTTPBoot(context.Background(), opts)
		var mismatch *rpibootsig.KeyHashMismatchError
		assert.ErrorAs(t, err, &mismatch, "the EEPROM key must hash to the OTP value")
	})
	t.Run("a signature by another key", func(t *testing.T) {
		host := bootServer(t, map[string][]byte{HTTPBootImage: image, HTTPBootSignature: otherSig})
		_, err := HTTPBoot(context.Background(), options(t, host, key))
		var bad *rpibootsig.SignatureError
		assert.ErrorAs(t, err, &bad)
	})
	t.Run("a malformed boot.sig", func(t *testing.T) {
		host := bootServer(t, map[string][]byte{HTTPBootImage: image, HTTPBootSignature: []byte("not a signature")})
		_, err := HTTPBoot(context.Background(), options(t, host, key))
		var malformed *rpibootsig.MalformedError
		assert.ErrorAs(t, err, &malformed)
	})
	t.Run("a signed image that is not a FAT ramdisk", func(t *testing.T) {
		junk := []byte("signed, but not a filesystem")
		junkSig, err := rpibootsig.Sign(key, junk, rpibootsig.SignOptions{Timestamp: httpBootEpoch})
		require.NoError(t, err)
		host := bootServer(t, map[string][]byte{HTTPBootImage: junk, HTTPBootSignature: junkSig})

		_, err = HTTPBoot(context.Background(), options(t, host, key))
		var ramdisk *RamdiskError
		assert.ErrorAs(t, err, &ramdisk)
	})
}

func TestHTTPBoot_FetchErrors(t *testing.T) {
	key := fleetKey(t)
	image, sig, _ := bootFiles(t, key)

	t.Run("a missing boot.sig", func(t *testing.T) {
		host := bootServer(t, map[string][]byte{HTTPBootImage: image})
		_, err := HTTPBoot(context.Background(), options(t, host, key))
		var fetch *HTTPFetchError
		require.ErrorAs(t, err, &fetch)
		assert.True(t, strings.HasSuffix(fetch.URL, "/"+HTTPBootSignature))
		var status *HTTPStatusError
		require.ErrorAs(t, err, &status)
		assert.Equal(t, http.StatusNotFound, status.Status)
	})
	t.Run("an image over the limit", func(t *testing.T) {
		host := bootServer(t, map[string][]byte{HTTPBootImage: image, HTTPBootSignature: sig})
		opts := options(t, host, key)
		opts.MaxImageBytes = int64(len(image)) - 1

		_, err := HTTPBoot(context.Background(), opts)
		var size *HTTPSizeError
		assert.ErrorAs(t, err, &size)
	})
	t.Run("an image exactly at the limit", func(t *testing.T) {
		host := bootServer(t, map[string][]byte{HTTPBootImage: image, HTTPBootSignature: sig})
		opts := options(t, host, key)
		opts.MaxImageBytes = int64(len(image))

		_, err := HTTPBoot(context.Background(), opts)
		assert.NoError(t, err)
	})
	t.Run("a server that is not there", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		host := strings.TrimPrefix(srv.URL, "http://")
		srv.Close()

		_, err := HTTPBoot(context.Background(), options(t, host, key))
		var fetch *HTTPFetchError
		assert.ErrorAs(t, err, &fetch)
	})
	t.Run("a cancelled context", func(t *testing.T) {
		host := bootServer(t, map[string][]byte{HTTPBootImage: image, HTTPBootSignature: sig})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := HTTPBoot(ctx, options(t, host, key))
		assert.ErrorIs(t, err, context.Canceled)
	})
	t.Run("a host that is not a URL", func(t *testing.T) {
		_, err := HTTPBoot(context.Background(), options(t, "bad host", key))
		var fetch *HTTPFetchError
		assert.ErrorAs(t, err, &fetch)
	})
}

func TestHTTPBoot_ReturnsBodyCloseError(t *testing.T) {
	key := fleetKey(t)
	image, _, _ := bootFiles(t, key)
	opts := options(t, "example.test", key)
	opts.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       closeErrorBody{Reader: strings.NewReader(string(image))},
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	_, err := HTTPBoot(context.Background(), opts)
	var fetch *HTTPFetchError
	require.ErrorAs(t, err, &fetch)
	assert.ErrorIs(t, err, assert.AnError)
}

func TestHTTPBoot_ConfigErrors(t *testing.T) {
	key := fleetKey(t)

	t.Run("no host", func(t *testing.T) {
		_, err := HTTPBoot(context.Background(), options(t, "", key))
		var cfg *HTTPBootConfigError
		require.ErrorAs(t, err, &cfg)
		assert.Equal(t, "Host", cfg.Field)
	})
	t.Run("no public key", func(t *testing.T) {
		opts := options(t, "127.0.0.1:1", key)
		opts.PublicKey = nil
		_, err := HTTPBoot(context.Background(), opts)
		var cfg *HTTPBootConfigError
		require.ErrorAs(t, err, &cfg)
		assert.Equal(t, "PublicKey", cfg.Field)
		assert.Error(t, cfg.Unwrap())
	})
}
