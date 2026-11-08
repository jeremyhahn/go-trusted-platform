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

// The pre-fetch indexes the mirror apks by their APKINDEX C: checksum, which a
// FIPS build refuses to compute (apk_checksum_fips_test.go).

package iso

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// releaseMirrorPackageVersion is the version every fixture package carries.
const releaseMirrorPackageVersion = "1.0-r0"

// releaseMirror is an Alpine mirror carrying the default build config's
// release: the main and community APKINDEX.tar.gz, every package the
// pre-fetch can ask for, and the alpine-minirootfs tarball. It counts the
// requests for each, and for every path it does not serve.
type releaseMirror struct {
	server      *httptest.Server
	arch        string
	fullVersion string
	majorMinor  string
	files       map[string]releaseMirrorFile

	indexGets   atomic.Int64
	packageGets atomic.Int64
	rootfsGets  atomic.Int64
	unknownGets atomic.Int64
}

type releaseMirrorFile struct {
	body []byte
	hits *atomic.Int64
}

func newReleaseMirror(t *testing.T) *releaseMirror {
	t.Helper()
	defaults := DefaultISOBuildConfig()
	m := &releaseMirror{
		arch:        defaults.Architecture,
		fullVersion: defaults.AlpineVersion,
		majorMinor:  getMajorVersion(defaults.AlpineVersion),
		files:       make(map[string]releaseMirrorFile),
	}
	repoBase := "/alpine/v" + m.majorMinor

	var index strings.Builder
	for _, name := range releaseMirrorPackageNames() {
		apk := gzipTar(t, map[string]string{
			".PKGINFO": fmt.Sprintf("pkgname = %s\npkgver = %s\narch = %s\n", name, releaseMirrorPackageVersion, m.arch),
		})
		sum := sha256.Sum256(apk)
		fmt.Fprintf(&index, "C:Q2%s\nP:%s\nV:%s\nA:%s\nS:%d\nI:%d\nT:%s\n\n",
			base64.StdEncoding.EncodeToString(sum[:]), name, releaseMirrorPackageVersion, m.arch, len(apk), len(apk), name)
		m.files[fmt.Sprintf("%s/main/%s/%s-%s.apk", repoBase, m.arch, name, releaseMirrorPackageVersion)] =
			releaseMirrorFile{body: apk, hits: &m.packageGets}
	}
	m.files[fmt.Sprintf("%s/main/%s/APKINDEX.tar.gz", repoBase, m.arch)] =
		releaseMirrorFile{body: gzipTar(t, map[string]string{"APKINDEX": index.String()}), hits: &m.indexGets}
	m.files[fmt.Sprintf("%s/community/%s/APKINDEX.tar.gz", repoBase, m.arch)] =
		releaseMirrorFile{body: gzipTar(t, map[string]string{"APKINDEX": ""}), hits: &m.indexGets}
	m.files[fmt.Sprintf("%s/releases/%s/alpine-minirootfs-%s-%s.tar.gz", repoBase, m.arch, m.fullVersion, m.arch)] =
		releaseMirrorFile{body: gzipTar(t, map[string]string{"etc/alpine-release": m.fullVersion + "\n"}), hits: &m.rootfsGets}

	m.server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.server.Close)
	return m
}

// releaseMirrorPackageNames is every package the pre-fetch can ask for: the
// required set with each optional feature on. The index may list more than
// one run resolves; only the resolved packages are fetched.
func releaseMirrorPackageNames() []string {
	all := CollectRequiredPackages(&PreFetchConfig{
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

func (m *releaseMirror) serve(w http.ResponseWriter, r *http.Request) {
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

// preFetchFrom returns a pre-fetch builder for the mirror's architecture,
// reading the given Alpine release from it into a fresh ISO tree.
func (m *releaseMirror) preFetchFrom(t *testing.T, majorMinor, fullVersion string) (*PreFetchBuilder, string) {
	t.Helper()
	isoDir := t.TempDir()
	return NewPreFetchBuilder(&PreFetchConfig{
		Mirror:       m.server.URL + "/alpine",
		Version:      majorMinor,
		FullVersion:  fullVersion,
		Architecture: m.arch,
		WorkDir:      t.TempDir(),
		ISODir:       isoDir,
	}, logging.DefaultLogger()), isoDir
}

// offlineRepositoryIndex is the index the autoinstall installs from.
func (m *releaseMirror) offlineRepositoryIndex(isoDir string) string {
	return filepath.Join(isoDir, "apks-prefetch", m.arch, "APKINDEX.tar.gz")
}

// The pre-fetch builds the offline repository from the mirror alone: both
// indexes, the packages and the minirootfs, asking for nothing it does not
// serve.
func TestBuildLocalRepository_FromAReleaseMirror(t *testing.T) {
	mirror := newReleaseMirror(t)
	builder, isoDir := mirror.preFetchFrom(t, mirror.majorMinor, mirror.fullVersion)

	require.NoError(t, builder.BuildLocalRepository(context.Background()))

	assert.FileExists(t, mirror.offlineRepositoryIndex(isoDir))
	assert.FileExists(t, filepath.Join(isoDir, fmt.Sprintf("alpine-minirootfs-%s-%s.tar.gz", mirror.fullVersion, mirror.arch)))
	assert.Equal(t, int64(2), mirror.indexGets.Load(), "APKINDEX requests: main and community")
	assert.NotZero(t, mirror.packageGets.Load(), "the mirror served no packages")
	assert.Equal(t, int64(1), mirror.rootfsGets.Load(), "minirootfs requests")
	assert.Zero(t, mirror.unknownGets.Load(), "requests for paths the mirror does not serve")
}

// A release the mirror does not carry fails at its index, before any package
// is fetched, and leaves no offline repository.
func TestBuildLocalRepository_RefusesAReleaseTheMirrorDoesNotCarry(t *testing.T) {
	mirror := newReleaseMirror(t)
	builder, isoDir := mirror.preFetchFrom(t, "9.99", "9.99.0")

	err := builder.BuildLocalRepository(context.Background())

	var failed *ErrPreFetchFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "load_index", failed.Operation)
	assert.NoFileExists(t, mirror.offlineRepositoryIndex(isoDir))
	assert.Positive(t, mirror.unknownGets.Load())
	assert.Zero(t, mirror.packageGets.Load())
}
