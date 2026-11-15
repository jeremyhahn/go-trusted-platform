//go:build integration

package iso

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPKCacheDir checks where the runner-local APK cache lives: the
// GTP_ISO_APK_CACHE override when set, else a per-version, per-arch
// directory under the user cache directory.
func TestAPKCacheDir(t *testing.T) {
	override := t.TempDir()
	t.Setenv(EnvISOAPKCache, override)
	assert.Equal(t, override, apkCacheDir(t))

	t.Setenv(EnvISOAPKCache, "")
	got := apkCacheDir(t)
	if got == "" {
		t.Skip("no user cache directory on this host")
	}
	assert.True(t, strings.HasSuffix(got,
		filepath.Join("go-trusted-platform", "iso-apk", DefaultAlpineVersion, DefaultArch)), got)
}

// TestSeedPrefetchCache checks that a cached package is placed in the
// pre-fetch directory iso customize reads, so it is not downloaded again,
// and that neither a partial temp file nor a platform-built package is seeded.
func TestSeedPrefetchCache(t *testing.T) {
	cache := t.TempDir()
	t.Setenv(EnvISOAPKCache, cache)
	writeFile(t, filepath.Join(cache, "musl-1.2.5-r0.apk"), "musl")
	writeFile(t, filepath.Join(cache, ".busybox-1.36.1-r0.apk.1.tmp"), "partial")
	writeFile(t, filepath.Join(cache, "trusted-platform-p11-host-1.0.0-r0.apk"), "stale build")

	isoDir := t.TempDir()
	seedPrefetchCache(t, isoDir)

	prefetch := filepath.Join(isoDir, "apks-prefetch", DefaultArch)
	data, err := os.ReadFile(filepath.Join(prefetch, "musl-1.2.5-r0.apk"))
	require.NoError(t, err)
	assert.Equal(t, "musl", string(data))
	assert.Equal(t, []string{"musl-1.2.5-r0.apk"}, dirNames(t, prefetch))
}

// TestHarvestPrefetchCache checks that the packages a customize run downloaded
// land in the cache whole, that platform-built packages stay out, and that no
// partial temp file ever shows up under a *.apk name.
func TestHarvestPrefetchCache(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "nested", "cache")
	t.Setenv(EnvISOAPKCache, cache)

	isoDir := t.TempDir()
	prefetch := filepath.Join(isoDir, "apks-prefetch", DefaultArch)
	writeFile(t, filepath.Join(prefetch, "openssl-3.3.2-r0.apk"), "openssl")
	writeFile(t, filepath.Join(prefetch, "zlib-1.3.1-r1.apk"), "zlib")
	writeFile(t, filepath.Join(prefetch, "trusted-platform-p11-host-1.0.0-r0.apk"), "platform")
	writeFile(t, filepath.Join(prefetch, "APKINDEX.tar.gz"), "index")

	harvestPrefetchCache(t, isoDir)
	// A second harvest over a populated cache keeps it whole.
	harvestPrefetchCache(t, isoDir)

	assert.Equal(t, []string{"openssl-3.3.2-r0.apk", "zlib-1.3.1-r1.apk"}, dirNames(t, cache))
	data, err := os.ReadFile(filepath.Join(cache, "zlib-1.3.1-r1.apk"))
	require.NoError(t, err)
	assert.Equal(t, "zlib", string(data))
	matches, err := filepath.Glob(filepath.Join(cache, "*.apk"))
	require.NoError(t, err)
	for _, m := range matches {
		assert.NotContains(t, filepath.Base(m), ".tmp")
	}

	// The harvested cache seeds the next run's pre-fetch directory.
	next := t.TempDir()
	seedPrefetchCache(t, next)
	assert.Equal(t, []string{"openssl-3.3.2-r0.apk", "zlib-1.3.1-r1.apk"},
		dirNames(t, filepath.Join(next, "apks-prefetch", DefaultArch)))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
