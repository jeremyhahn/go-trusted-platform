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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const platformTestArch = "x86_64"

// gzipTar is a gzip-compressed tar holding the named files. With no files it
// is a valid apk-shaped archive without a .PKGINFO, which the prefetch builder
// identifies by file name.
func gzipTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// platformIndex is the APKINDEX of the strongSwan builder output: the four
// platform-built packages, which depend on Alpine's p11-kit-server.
func platformIndex(skip string) string {
	blocks := map[string]string{
		"trusted-platform-strongswan":        "P:trusted-platform-strongswan\nV:6.0.7-r0\nA:x86_64\nS:4\nC:Q1strongswan=\nD:!strongswan p11-kit-server>=0.26\n\n",
		"trusted-platform-strongswan-openrc": "P:trusted-platform-strongswan-openrc\nV:6.0.7-r0\nA:x86_64\nS:4\nC:Q1strongswanrc=\nD:trusted-platform-strongswan=6.0.7-r0\n\n",
		"trusted-platform-p11-host":          "P:trusted-platform-p11-host\nV:1.0.0-r0\nA:x86_64\nS:4\nC:Q1p11host=\nD:p11-kit-server>=0.26\n\n",
		"trusted-platform-p11-host-openrc":   "P:trusted-platform-p11-host-openrc\nV:1.0.0-r0\nA:x86_64\nS:4\nC:Q1p11hostrc=\nD:trusted-platform-p11-host=1.0.0-r0\n\n",
	}
	var out string
	for _, name := range platformBuiltPackages {
		if name != skip {
			out += blocks[name]
		}
	}
	return out
}

// platformOutput lays out a strongSwan builder output the way the builder
// does: <dir>/<arch>/APKINDEX.tar.gz beside the apks it lists.
func platformOutput(t *testing.T, index string, apks ...string) string {
	t.Helper()
	dir := t.TempDir()
	archDir := filepath.Join(dir, platformTestArch)
	require.NoError(t, os.MkdirAll(archDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(archDir, "APKINDEX.tar.gz"), gzipTar(t, map[string]string{"APKINDEX": index}), 0o644))
	for _, apk := range apks {
		require.NoError(t, os.WriteFile(filepath.Join(archDir, apk), gzipTar(t, nil), 0o644))
	}
	return dir
}

// platformApkFiles are the files platformIndex's four packages are in.
var platformApkFiles = []string{
	"trusted-platform-strongswan-6.0.7-r0.apk",
	"trusted-platform-strongswan-openrc-6.0.7-r0.apk",
	"trusted-platform-p11-host-1.0.0-r0.apk",
	"trusted-platform-p11-host-openrc-1.0.0-r0.apk",
}

// platformMirror is an Alpine mirror holding only p11-kit-server and the
// minirootfs; the community index is absent, as on a mirror without it.
func platformMirror(t *testing.T) *httptest.Server {
	t.Helper()
	index := "P:p11-kit-server\nV:0.26.2-r0\nA:x86_64\nS:4\nC:Q1p11kit=\n\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/v3.22/main/x86_64/APKINDEX.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(gzipTar(t, map[string]string{"APKINDEX": index}))
	})
	mux.HandleFunc("/v3.22/main/x86_64/p11-kit-server-0.26.2-r0.apk", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(gzipTar(t, nil))
	})
	mux.HandleFunc("/v3.22/releases/x86_64/alpine-minirootfs-3.22.2-x86_64.tar.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("rootfs"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newPlatformBuilder(t *testing.T, mirror, platformDir, isoDir string) *PreFetchBuilder {
	t.Helper()
	return NewPreFetchBuilder(&PreFetchConfig{
		Mirror:         mirror,
		Version:        "3.22",
		FullVersion:    "3.22.2",
		Architecture:   platformTestArch,
		WorkDir:        t.TempDir(),
		ISODir:         isoDir,
		PlatformAPKDir: platformDir,
	}, logging.DefaultLogger())
}

// readIndexNames returns the package names a generated APKINDEX.tar.gz lists.
func readIndexNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	_, err = tr.Next()
	require.NoError(t, err)
	body, err := io.ReadAll(tr)
	require.NoError(t, err)

	var names []string
	for _, line := range bytes.Split(body, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("P:")) {
			names = append(names, string(line[2:]))
		}
	}
	return names
}

// The media manifest: a build with PlatformAPKDir leaves the strongSwan apk,
// the module host, their OpenRC services and p11-kit-server in the media's
// offline repository, and in its APKINDEX, where the installer finds them.
func TestBuildLocalRepository_CarriesThePlatformPackages(t *testing.T) {
	isoDir := t.TempDir()
	platformDir := platformOutput(t, platformIndex(""), platformApkFiles...)
	b := newPlatformBuilder(t, platformMirror(t).URL, platformDir, isoDir)

	require.NoError(t, b.BuildLocalRepository(context.Background()))

	repo := filepath.Join(isoDir, "apks-prefetch", platformTestArch)
	for _, file := range append([]string{"p11-kit-server-0.26.2-r0.apk"}, platformApkFiles...) {
		assert.FileExists(t, filepath.Join(repo, file), "the media's offline repository carries %s", file)
	}
	assert.ElementsMatch(t, PlatformPackages(), readIndexNames(t, filepath.Join(repo, "APKINDEX.tar.gz")),
		"the media's APKINDEX lists exactly the platform packages and nothing else of this mirror")
	assert.FileExists(t, filepath.Join(isoDir, ".pre-fetch"))
}

// A medium built without PlatformAPKDir is unchanged: none of the platform
// packages are required.
func TestCollectRequiredPackages_PlatformPackagesAreOptIn(t *testing.T) {
	without := CollectRequiredPackages(&PreFetchConfig{})
	for _, name := range PlatformPackages() {
		assert.NotContains(t, without, name)
	}

	with := CollectRequiredPackages(&PreFetchConfig{PlatformAPKDir: "/builder/output"})
	for _, name := range PlatformPackages() {
		assert.Contains(t, with, name)
	}
}

func TestPlatformPackages_ArePresentOnlyWhenTheMediaCarriesThem(t *testing.T) {
	plain := InstallerOverrides{ExtraPackages: []string{"nginx"}}
	assert.Equal(t, []string{"nginx"}, plain.installPackages())

	carried := InstallerOverrides{ExtraPackages: []string{"nginx"}, PlatformAPKDir: "/builder/output"}
	assert.Equal(t, append([]string{"nginx"}, PlatformPackages()...), carried.installPackages())

	// The result is a copy: changing it leaves the configuration alone.
	packages := plain.installPackages()
	packages[0] = "changed"
	assert.Equal(t, []string{"nginx"}, plain.ExtraPackages)
}

// The media is never built without a platform package: each way the builder
// output can fall short is a typed ErrPlatformAPKMissing naming what is gone.
func TestLoadPlatformIndex_FailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		dir     func(t *testing.T) string
		missing string
	}{
		{
			name:    "no builder output for the architecture",
			dir:     func(t *testing.T) string { return t.TempDir() },
			missing: "APKINDEX.tar.gz",
		},
		{
			name: "index that is not an archive",
			dir: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.MkdirAll(filepath.Join(dir, platformTestArch), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, platformTestArch, "APKINDEX.tar.gz"), []byte("not gzip"), 0o644))
				return dir
			},
			missing: "APKINDEX.tar.gz",
		},
		{
			name: "index without the module host",
			dir: func(t *testing.T) string {
				return platformOutput(t, platformIndex("trusted-platform-p11-host"), platformApkFiles...)
			},
			missing: "trusted-platform-p11-host",
		},
		{
			name:    "indexed apk that is not in the output",
			dir:     func(t *testing.T) string { return platformOutput(t, platformIndex(""), platformApkFiles[:3]...) },
			missing: "trusted-platform-p11-host-openrc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newPlatformBuilder(t, "http://unused.invalid", tt.dir(t), t.TempDir())

			err := b.loadPlatformIndex()

			var missing *ErrPlatformAPKMissing
			require.ErrorAs(t, err, &missing)
			assert.Equal(t, tt.missing, missing.Package)
			assert.Contains(t, missing.Error(), "make strongswan-build")
		})
	}
}

// A platform-built entry replaces a mirror entry of the same name, and the
// download step copies the builder's apk rather than fetching.
func TestLoadPlatformIndex_PlatformEntriesWin(t *testing.T) {
	platformDir := platformOutput(t, platformIndex(""), platformApkFiles...)
	b := newPlatformBuilder(t, "http://unused.invalid", platformDir, t.TempDir())
	b.packageIndex["trusted-platform-strongswan"] = &apkPackageEntry{Name: "trusted-platform-strongswan", Version: "0-mirror"}

	require.NoError(t, b.loadPlatformIndex())

	entry := b.packageIndex["trusted-platform-strongswan"]
	assert.Equal(t, "6.0.7-r0", entry.Version)
	assert.Equal(t, filepath.Join(platformDir, platformTestArch, platformApkFiles[0]), entry.LocalPath)

	dest := t.TempDir()
	require.NoError(t, b.downloadPackage(context.Background(), entry, dest))
	assert.FileExists(t, filepath.Join(dest, platformApkFiles[0]))
}

func TestCopyLocalPackage_Errors(t *testing.T) {
	dir := t.TempDir()
	assert.Error(t, copyLocalPackage(filepath.Join(dir, "absent.apk"), filepath.Join(dir, "out.apk")), "source that does not exist")

	src := filepath.Join(dir, "in.apk")
	require.NoError(t, os.WriteFile(src, []byte("apk"), 0o644))
	assert.Error(t, copyLocalPackage(src, filepath.Join(dir, "no-such-dir", "out.apk")), "destination that cannot be created")
}

// builderApks returns the apks the strongSwan builder's Makefile verifies, the
// ones the media require.
func builderApks(t *testing.T, makefile string) []string {
	t.Helper()
	data, err := os.ReadFile(makefile)
	require.NoError(t, err)
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "PLATFORM_APKS"); ok {
			_, list, found := strings.Cut(rest, "=")
			require.True(t, found, "PLATFORM_APKS has no value")
			return strings.Fields(list)
		}
	}
	return nil
}

// The media require exactly the apks the builder produces and verifies; a name
// changed on one side only would fail the image build late, on a node's media.
func TestPlatformPackages_MatchTheBuilder(t *testing.T) {
	makefile := filepath.Join("..", "..", "build", "docker", "strongswan-builder", "Makefile")

	assert.ElementsMatch(t, platformBuiltPackages, builderApks(t, makefile))
}

func TestBuilderApks_UnnamedWhenTheMakefileHasNone(t *testing.T) {
	makefile := filepath.Join(t.TempDir(), "Makefile")
	require.NoError(t, os.WriteFile(makefile, []byte("all:\n\ttrue\n"), 0o600))

	assert.Empty(t, builderApks(t, makefile))
}
