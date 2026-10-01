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

package iso

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeMirror serves one Alpine branch: an APKINDEX.tar.gz for main and the
// apks named in it. The index lists firmware (depending on common) and
// common.
func fakeMirror(t *testing.T) *httptest.Server {
	t.Helper()
	index := "P:raspberrypi-bootloader\nV:1.0-r0\nA:aarch64\nS:4\nC:Q1aaaa=\nD:raspberrypi-bootloader-common\n\n" +
		"P:raspberrypi-bootloader-common\nV:1.0-r0\nA:aarch64\nS:4\nC:Q1bbbb=\n\n"
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "APKINDEX", Mode: 0o644, Size: int64(len(index)), Typeflag: tar.TypeReg}))
	_, err := tw.Write([]byte(index))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	indexBytes := buf.Bytes()

	mux := http.NewServeMux()
	mux.HandleFunc("/v3.22/main/aarch64/APKINDEX.tar.gz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(indexBytes) })
	mux.HandleFunc("/v3.22/main/aarch64/raspberrypi-bootloader-1.0-r0.apk", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("fw")) })
	mux.HandleFunc("/v3.22/main/aarch64/raspberrypi-bootloader-common-1.0-r0.apk", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("common")) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchPackages_LoadsTheIndexAndDependencies(t *testing.T) {
	// A fresh builder has an empty (not nil) index; FetchPackages must load
	// it rather than report every package missing.
	mirror := fakeMirror(t)
	dest := filepath.Join(t.TempDir(), "apks")
	b := NewPreFetchBuilder(&PreFetchConfig{Mirror: mirror.URL, Version: "3.22", Architecture: "aarch64", WorkDir: t.TempDir()}, logging.DefaultLogger())

	require.NoError(t, b.FetchPackages(context.Background(), []string{"raspberrypi-bootloader"}, dest))

	fw, err := os.ReadFile(filepath.Join(dest, "raspberrypi-bootloader-1.0-r0.apk"))
	require.NoError(t, err)
	assert.Equal(t, "fw", string(fw))
	common, err := os.ReadFile(filepath.Join(dest, "raspberrypi-bootloader-common-1.0-r0.apk"))
	require.NoError(t, err, "the dependency comes along")
	assert.Equal(t, "common", string(common))
}

func TestFetchPackages_Failures(t *testing.T) {
	mirror := fakeMirror(t)
	b := NewPreFetchBuilder(&PreFetchConfig{Mirror: mirror.URL, Version: "3.22", Architecture: "aarch64", WorkDir: t.TempDir()}, logging.DefaultLogger())

	err := b.FetchPackages(context.Background(), []string{"linux-rpi"}, t.TempDir())
	var notFound *ErrPackageNotFound
	require.ErrorAs(t, err, &notFound, "a package the index does not carry")
	assert.Equal(t, "linux-rpi", notFound.Package)

	dead := NewPreFetchBuilder(&PreFetchConfig{Mirror: mirror.URL + "/nowhere", Version: "3.22", Architecture: "aarch64", WorkDir: t.TempDir()}, logging.DefaultLogger())
	err = dead.FetchPackages(context.Background(), []string{"raspberrypi-bootloader"}, t.TempDir())
	var indexErr *ErrAPKINDEXFailed
	require.ErrorAs(t, err, &indexErr, "an unreachable index")
}
