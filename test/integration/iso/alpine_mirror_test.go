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

//go:build integration

package iso

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// mirrorPackageVersion is the version every fixture package carries.
const mirrorPackageVersion = "1.0-r0"

// alpineMirror is a local Alpine mirror in the test process. iso customize
// pre-fetches the offline repository from the build config's alpine-mirror
// (pkg/iso PreFetchBuilder): the main and community APKINDEX.tar.gz, every
// package the install needs, and the alpine-minirootfs tarball. Served from
// here, the result does not depend on dl-cdn.alpinelinux.org. The packages
// are small valid apks (a gzip tar with a .PKGINFO); nothing installs them.
type alpineMirror struct {
	server *httptest.Server
	// arch, fullVersion and majorMinor are the default build config's: the
	// release the mirror carries.
	arch        string
	fullVersion string
	majorMinor  string
	// files maps each URL path the mirror serves to its body and the
	// counter its requests add to.
	files map[string]mirrorFile

	indexGets   atomic.Int64
	packageGets atomic.Int64
	rootfsGets  atomic.Int64
	unknownGets atomic.Int64
}

type mirrorFile struct {
	body []byte
	hits *atomic.Int64
}

// newAlpineMirror starts the mirror for the default build config's Alpine
// version and architecture; the test's cleanup stops it.
func newAlpineMirror(t *testing.T) *alpineMirror {
	t.Helper()
	defaults := pkgiso.DefaultISOBuildConfig()
	arch := defaults.Architecture
	fullVersion := defaults.AlpineVersion
	majorMinor := fullVersion
	if parts := strings.Split(fullVersion, "."); len(parts) >= 2 {
		majorMinor = parts[0] + "." + parts[1]
	}
	repoBase := fmt.Sprintf("/alpine/v%s", majorMinor)

	m := &alpineMirror{
		arch:        arch,
		fullVersion: fullVersion,
		majorMinor:  majorMinor,
		files:       make(map[string]mirrorFile),
	}
	var index strings.Builder
	for _, name := range mirrorPackageNames() {
		apk := gzipTar(t, map[string][]byte{
			".PKGINFO": []byte(fmt.Sprintf("pkgname = %s\npkgver = %s\narch = %s\n", name, mirrorPackageVersion, arch)),
		})
		sum := sha256.Sum256(apk)
		fmt.Fprintf(&index, "C:Q2%s\nP:%s\nV:%s\nA:%s\nS:%d\nI:%d\nT:%s\n\n",
			base64.StdEncoding.EncodeToString(sum[:]), name, mirrorPackageVersion, arch, len(apk), len(apk), name)
		m.files[fmt.Sprintf("%s/main/%s/%s-%s.apk", repoBase, arch, name, mirrorPackageVersion)] =
			mirrorFile{body: apk, hits: &m.packageGets}
	}
	m.files[fmt.Sprintf("%s/main/%s/APKINDEX.tar.gz", repoBase, arch)] =
		mirrorFile{body: gzipTar(t, map[string][]byte{"APKINDEX": []byte(index.String())}), hits: &m.indexGets}
	m.files[fmt.Sprintf("%s/community/%s/APKINDEX.tar.gz", repoBase, arch)] =
		mirrorFile{body: gzipTar(t, map[string][]byte{"APKINDEX": nil}), hits: &m.indexGets}
	m.files[fmt.Sprintf("%s/releases/%s/alpine-minirootfs-%s-%s.tar.gz", repoBase, arch, fullVersion, arch)] =
		mirrorFile{body: gzipTar(t, map[string][]byte{"etc/alpine-release": []byte(fullVersion + "\n")}), hits: &m.rootfsGets}

	m.server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.server.Close)
	return m
}

// mirrorPackageNames is every package the pre-fetch can ask for: the
// required set with each optional feature on. The index may list more than
// one customize run resolves; only the resolved packages are fetched.
func mirrorPackageNames() []string {
	all := pkgiso.CollectRequiredPackages(&pkgiso.PreFetchConfig{
		EnableFIDO2:     true,
		FilesystemLVM:   true,
		IMAEnabled:      true,
		IMAAuditEnabled: true,
		GatewayRole:     true,
		PlatformAPKDir:  "platform-apks",
	})
	seen := make(map[string]bool, len(all))
	names := make([]string, 0, len(all))
	for _, name := range all {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

func (m *alpineMirror) serve(w http.ResponseWriter, r *http.Request) {
	file, ok := m.files[r.URL.Path]
	if !ok || r.Method != http.MethodGet {
		m.unknownGets.Add(1)
		http.NotFound(w, r)
		return
	}
	file.hits.Add(1)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(file.body))
}

// URL is the mirror base iso customize takes as alpine-mirror.
func (m *alpineMirror) URL() string {
	return m.server.URL + "/alpine"
}

// writeBuildConfig writes an ISO build config naming the mirror, for
// iso customize --config, and returns its path.
func (m *alpineMirror) writeBuildConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "iso-build-local-mirror.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("alpine-mirror: %q\n", m.URL())), 0o644); err != nil {
		t.Fatalf("writing the local mirror build config: %v", err)
	}
	return path
}

// requireServedPreFetch fails the test unless the pre-fetch read both
// indexes, packages and the minirootfs from this mirror and asked for
// nothing it does not serve.
func (m *alpineMirror) requireServedPreFetch(t *testing.T) {
	t.Helper()
	if got := m.indexGets.Load(); got != 2 {
		t.Errorf("local mirror served %d APKINDEX requests, want 2 (main and community)", got)
	}
	if m.packageGets.Load() == 0 {
		t.Errorf("local mirror served no packages")
	}
	if got := m.rootfsGets.Load(); got != 1 {
		t.Errorf("local mirror served the minirootfs %d times, want 1", got)
	}
	if got := m.unknownGets.Load(); got != 0 {
		t.Errorf("local mirror answered %d requests for paths it does not serve", got)
	}
}

// gzipTar returns a gzip-compressed tar of files, in name order.
func gzipTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatalf("writing tar header %s: %v", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("writing tar entry %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}
	return buf.Bytes()
}

// preFetchFrom returns a pre-fetch builder for the mirror's architecture,
// reading the given Alpine release from it into a fresh ISO tree.
func (m *alpineMirror) preFetchFrom(t *testing.T, majorMinor, fullVersion string) (*pkgiso.PreFetchBuilder, string) {
	t.Helper()
	isoDir := t.TempDir()
	return pkgiso.NewPreFetchBuilder(&pkgiso.PreFetchConfig{
		Mirror:       m.URL(),
		Version:      majorMinor,
		FullVersion:  fullVersion,
		Architecture: m.arch,
		WorkDir:      t.TempDir(),
		ISODir:       isoDir,
	}, logging.DefaultLogger()), isoDir
}

func TestAlpineMirror_ServesTheOfflineRepositoryPreFetchBuilds(t *testing.T) {
	mirror := newAlpineMirror(t)
	builder, isoDir := mirror.preFetchFrom(t, mirror.majorMinor, mirror.fullVersion)

	require.NoError(t, builder.BuildLocalRepository(context.Background()))
	require.NoError(t, requireOfflineRepository(isoDir))
	assert.True(t, FileExists(filepath.Join(isoDir, fmt.Sprintf("alpine-minirootfs-%s-%s.tar.gz", mirror.fullVersion, mirror.arch))))
	mirror.requireServedPreFetch(t)
}

func TestAlpineMirror_RefusesAReleaseItDoesNotCarry(t *testing.T) {
	mirror := newAlpineMirror(t)
	builder, isoDir := mirror.preFetchFrom(t, "9.99", "9.99.0")

	err := builder.BuildLocalRepository(context.Background())
	var failed *pkgiso.ErrPreFetchFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "load_index", failed.Operation)
	assert.Error(t, requireOfflineRepository(isoDir))
	assert.Positive(t, mirror.unknownGets.Load())
	assert.Zero(t, mirror.packageGets.Load())
}
