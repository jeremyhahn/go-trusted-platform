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

//go:build !fips

// The platform apks are verified against their APKINDEX C: checksum, which a
// FIPS build refuses to compute (apk_checksum_fips_test.go).

package iso

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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

// apkSegment is one gzip stream of an apk: a tar of one file without the
// end-of-archive blocks, the way abuild writes the signature and control
// segments.
func apkSegment(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}))
	_, err := tw.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, tw.Flush())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// platformAPK is an apk laid out as abuild writes one, its signature, control
// and data segments each a gzip stream, and its APKINDEX C: checksum.
func platformAPK(t *testing.T, name, version string) (apk []byte, checksum string) {
	t.Helper()
	return platformAPKBuild(t, name, version, "")
}

// platformAPKBuild is platformAPK from a labelled build: builds of one version
// with different labels differ in their data, as two runs of the builder do.
func platformAPKBuild(t *testing.T, name, version, build string) (apk []byte, checksum string) {
	t.Helper()
	control := apkSegment(t, ".PKGINFO", fmt.Sprintf("pkgname = %s\npkgver = %s\narch = %s\n", name, version, platformTestArch))
	apk = slices.Concat(
		apkSegment(t, ".SIGN.RSA.builder.rsa.pub", "signature"),
		control,
		gzipTar(t, map[string]string{"usr/share/doc/" + name + "/README": name + build}),
	)
	hasher, err := newAPKChecksumHasher()
	require.NoError(t, err)
	_, err = hasher.Write(control)
	require.NoError(t, err)
	return apk, "Q1" + base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

// platformBuilds are the strongSwan builder's four packages, which depend on
// Alpine's p11-kit-server.
var platformBuilds = []struct{ name, version, depends string }{
	{"trusted-platform-strongswan", "6.0.7-r0", "!strongswan p11-kit-server>=0.26"},
	{"trusted-platform-strongswan-openrc", "6.0.7-r0", "trusted-platform-strongswan=6.0.7-r0"},
	{"trusted-platform-p11-host", "1.0.0-r0", "p11-kit-server>=0.26"},
	{"trusted-platform-p11-host-openrc", "1.0.0-r0", "trusted-platform-p11-host=1.0.0-r0"},
}

// platformOutput lays out a strongSwan builder output the way the builder
// does: <dir>/<arch>/APKINDEX.tar.gz beside the apks it lists. The index lists
// every package but skip; only the named apk files are written.
func platformOutput(t *testing.T, skip string, apks ...string) string {
	t.Helper()
	return platformOutputBuild(t, "", skip, apks...)
}

// platformOutputBuild is platformOutput holding the apks of a labelled build.
func platformOutputBuild(t *testing.T, build, skip string, apks ...string) string {
	t.Helper()
	dir := t.TempDir()
	archDir := filepath.Join(dir, platformTestArch)
	require.NoError(t, os.MkdirAll(archDir, 0o755))

	var index strings.Builder
	for _, p := range platformBuilds {
		apk, checksum := platformAPKBuild(t, p.name, p.version, build)
		if p.name != skip {
			fmt.Fprintf(&index, "P:%s\nV:%s\nA:%s\nS:%d\nC:%s\nD:%s\n\n", p.name, p.version, platformTestArch, len(apk), checksum, p.depends)
		}
		file := fmt.Sprintf("%s-%s.apk", p.name, p.version)
		if slices.Contains(apks, file) {
			require.NoError(t, os.WriteFile(filepath.Join(archDir, file), apk, 0o644))
		}
	}
	require.NoError(t, os.WriteFile(filepath.Join(archDir, "APKINDEX.tar.gz"), gzipTar(t, map[string]string{"APKINDEX": index.String()}), 0o644))
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
	platformDir := platformOutput(t, "", platformApkFiles...)
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
	plain := &PreFetchConfig{ExtraPackages: []string{"nginx"}}
	assert.Equal(t, []string{"nginx"}, plain.installedPackages())

	carried := &PreFetchConfig{ExtraPackages: []string{"nginx"}, PlatformAPKDir: "/builder/output"}
	assert.Equal(t, append(PlatformPackages(), "nginx"), carried.installedPackages())

	// The result is a copy: changing it leaves the configuration alone.
	packages := plain.installedPackages()
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
				return platformOutput(t, "trusted-platform-p11-host", platformApkFiles...)
			},
			missing: "trusted-platform-p11-host",
		},
		{
			name:    "indexed apk that is not in the output",
			dir:     func(t *testing.T) string { return platformOutput(t, "", platformApkFiles[:3]...) },
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
	platformDir := platformOutput(t, "", platformApkFiles...)
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

// A rebuild keeps its version and pkgrel, so an ISO work directory reused
// across builds already holds a file of each platform apk's name. The media
// must carry the build its index describes, not the earlier one.
func TestBuildLocalRepository_ReplacesTheApksOfAnEarlierBuild(t *testing.T) {
	isoDir := t.TempDir()
	mirror := platformMirror(t).URL
	earlier := platformOutputBuild(t, "earlier build", "", platformApkFiles...)
	require.NoError(t, newPlatformBuilder(t, mirror, earlier, isoDir).BuildLocalRepository(context.Background()))

	rebuilt := platformOutput(t, "", platformApkFiles...)
	require.NoError(t, newPlatformBuilder(t, mirror, rebuilt, isoDir).BuildLocalRepository(context.Background()))

	repo := filepath.Join(isoDir, "apks-prefetch", platformTestArch)
	for _, file := range platformApkFiles {
		before, err := os.ReadFile(filepath.Join(earlier, platformTestArch, file))
		require.NoError(t, err)
		want, err := os.ReadFile(filepath.Join(rebuilt, platformTestArch, file))
		require.NoError(t, err)
		require.NotEqual(t, before, want, "the two builds of %s differ", file)

		got, err := os.ReadFile(filepath.Join(repo, file))
		require.NoError(t, err)
		assert.Equal(t, want, got, "the media carries the rebuilt %s", file)
	}
}

// The copy on the media is checked against the index entry, so an apk that
// changed after its index was read never reaches the media unnoticed.
func TestDownloadPackage_RefusesAnApkThatChangedAfterItsIndexWasRead(t *testing.T) {
	platformDir := platformOutput(t, "", platformApkFiles...)
	b := newPlatformBuilder(t, "http://unused.invalid", platformDir, t.TempDir())
	require.NoError(t, b.loadPlatformIndex())
	entry := b.packageIndex["trusted-platform-strongswan"]
	require.NoError(t, os.Truncate(entry.LocalPath, 64))
	dest := t.TempDir()

	err := b.downloadPackage(context.Background(), entry, dest)

	var invalid *ErrPlatformAPKInvalid
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, filepath.Join(dest, platformApkFiles[0]), invalid.Path)
}

func TestCopyLocalPackage_Errors(t *testing.T) {
	dir := t.TempDir()
	assert.Error(t, copyLocalPackage(filepath.Join(dir, "absent.apk"), filepath.Join(dir, "out.apk")), "source that does not exist")

	src := filepath.Join(dir, "in.apk")
	require.NoError(t, os.WriteFile(src, []byte("apk"), 0o644))
	assert.Error(t, copyLocalPackage(src, filepath.Join(dir, "no-such-dir", "out.apk")), "destination that cannot be created")
}

// An apk that is not the one its index entry describes fails the build as
// ErrPlatformAPKInvalid, rather than being copied onto media whose install
// then cannot find it.
func TestLoadPlatformIndex_RejectsAnApkItsIndexDoesNotDescribe(t *testing.T) {
	platformDir := platformOutput(t, "", platformApkFiles...)
	apk := filepath.Join(platformDir, platformTestArch, platformApkFiles[2])
	require.NoError(t, os.Truncate(apk, 64))
	b := newPlatformBuilder(t, "http://unused.invalid", platformDir, t.TempDir())

	err := b.loadPlatformIndex()

	var invalid *ErrPlatformAPKInvalid
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, apk, invalid.Path)
	assert.Contains(t, invalid.Error(), "make strongswan-build")
}

// writePlatformAPK writes apk and returns the index entry describing it.
func writePlatformAPK(t *testing.T, apk []byte, checksum string) *apkPackageEntry {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trusted-platform-p11-host-1.0.0-r0.apk")
	require.NoError(t, os.WriteFile(path, apk, 0o644))
	return &apkPackageEntry{Name: "trusted-platform-p11-host", Size: int64(len(apk)), Checksum: checksum, LocalPath: path}
}

func TestVerifyPlatformAPK_AcceptsTheApkItsEntryDescribes(t *testing.T) {
	apk, checksum := platformAPK(t, "trusted-platform-p11-host", "1.0.0-r0")

	entry := writePlatformAPK(t, apk, checksum)

	assert.NoError(t, verifyPlatformAPK(entry.LocalPath, entry))
}

// Each way a builder output apk can differ from its index entry is refused,
// naming the apk and what differs.
func TestVerifyPlatformAPK_RefusesWhatItsEntryDoesNotDescribe(t *testing.T) {
	apk, checksum := platformAPK(t, "trusted-platform-p11-host", "1.0.0-r0")
	_, otherChecksum := platformAPK(t, "trusted-platform-p11-host", "1.0.1-r0")

	tests := []struct {
		name   string
		entry  func(t *testing.T) *apkPackageEntry
		reason string
		cause  error
	}{
		{
			name: "file that is not there",
			entry: func(t *testing.T) *apkPackageEntry {
				return &apkPackageEntry{LocalPath: filepath.Join(t.TempDir(), "absent.apk")}
			},
			reason: "cannot be read",
			cause:  os.ErrNotExist,
		},
		{
			name: "truncated",
			entry: func(t *testing.T) *apkPackageEntry {
				entry := writePlatformAPK(t, apk[:len(apk)-8], checksum)
				entry.Size = int64(len(apk))
				return entry
			},
			reason: "bytes, its index entry",
		},
		{
			name: "from another build",
			entry: func(t *testing.T) *apkPackageEntry {
				return writePlatformAPK(t, apk, otherChecksum)
			},
			reason: "control checksum",
		},
		{
			name: "data segment that does not match its CRC",
			entry: func(t *testing.T) *apkPackageEntry {
				corrupt := slices.Clone(apk)
				corrupt[len(corrupt)-6] ^= 0xff // the gzip trailer's CRC-32
				return writePlatformAPK(t, corrupt, checksum)
			},
			reason: "not a well-formed apk",
			cause:  gzip.ErrChecksum,
		},
		{
			name: "no control segment",
			entry: func(t *testing.T) *apkPackageEntry {
				return writePlatformAPK(t, gzipTar(t, map[string]string{"usr/bin/charon": "elf"}), checksum)
			},
			reason: "not a well-formed apk",
			cause:  ErrAPKNoControlSegment{},
		},
		{
			name: "not gzip",
			entry: func(t *testing.T) *apkPackageEntry {
				return writePlatformAPK(t, []byte("not an apk"), checksum)
			},
			reason: "not a well-formed apk",
			cause:  gzip.ErrHeader,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := tt.entry(t)

			err := verifyPlatformAPK(entry.LocalPath, entry)

			var invalid *ErrPlatformAPKInvalid
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, entry.LocalPath, invalid.Path)
			assert.Contains(t, invalid.Error(), tt.reason)
			if tt.cause != nil {
				assert.ErrorIs(t, err, tt.cause)
			}
		})
	}
}

// GenerateAPKINDEX skips a malformed mirror apk, but not a platform-built one:
// the install asks for it by name.
func TestGenerateAPKINDEX_FailsOnAPlatformApkItCannotIndex(t *testing.T) {
	dir := t.TempDir()
	b := newPlatformBuilder(t, "http://unused.invalid", t.TempDir(), t.TempDir())
	b.packageIndex["trusted-platform-p11-host"] = &apkPackageEntry{
		Name:      "trusted-platform-p11-host",
		Version:   "1.0.0-r0",
		LocalPath: filepath.Join(string(filepath.Separator), "builder", platformTestArch, "trusted-platform-p11-host-1.0.0-r0.apk"),
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "unrelated-1.0-r0.apk"), []byte("not an apk"), 0o644))
	require.NoError(t, b.GenerateAPKINDEX(context.Background(), dir), "a malformed mirror apk is skipped")

	platformAPK := filepath.Join(dir, "trusted-platform-p11-host-1.0.0-r0.apk")
	require.NoError(t, os.WriteFile(platformAPK, []byte("not an apk"), 0o644))

	err := b.GenerateAPKINDEX(context.Background(), dir)

	var invalid *ErrPlatformAPKInvalid
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, platformAPK, invalid.Path)
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
