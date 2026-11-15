//go:build integration

package iso

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// EnvISOAPKCache overrides the runner-local APK cache directory.
const EnvISOAPKCache = "GTP_ISO_APK_CACHE"

// The ISO VM fixture's `iso customize` pre-fetches every APK the offline
// repository needs. On main d416ba86d (run 43689586687) that pre-fetch spent
// the whole 10-minute customize limit: the package index loaded in 39 s, then
// 294 packages came one by one from the public Alpine mirror and only 130 of
// them were on disk when customize was killed at 600 s, before any VM install.
// The fixture now seeds the pre-fetch directory from a cache that survives
// between runs on the same runner; downloadPackage skips a file that already
// exists, so only packages the cache lacks are fetched.

// platformAPKPrefixes name the packages iso customize builds from the
// platform tree. They are copied fresh on every run (pkg.LocalPath), so the
// cache never holds them.
var platformAPKPrefixes = []string{"trusted-platform-", "go-trusted-platform-"}

// apkCacheDir returns the runner-local APK cache,
// <root>/<alpine version>/<arch>, where <root> is $GTP_ISO_APK_CACHE when set
// (CI mounts the external go-trusted-platform-iso-apk-cache volume there, see
// build/docker/devcontainer/compose.yaml, so one volume holds every version
// and the cache outlives the `run --rm` integration container), else
// <user cache dir>/go-trusted-platform/iso-apk. It returns "" when neither is
// available.
func apkCacheDir(t *testing.T) string {
	t.Helper()
	base := os.Getenv(EnvISOAPKCache)
	if base == "" {
		userCache, err := os.UserCacheDir()
		if err != nil || userCache == "" {
			t.Logf("APK cache disabled: no user cache directory: %v", err)
			return ""
		}
		base = filepath.Join(userCache, "go-trusted-platform", "iso-apk")
	}
	return filepath.Join(base, DefaultAlpineVersion, DefaultArch)
}

// prefetchDir is where iso customize keeps its pre-fetched packages.
func prefetchDir(isoDir string) string {
	return filepath.Join(isoDir, "apks-prefetch", DefaultArch)
}

// seedPrefetchCache places every cached package in isoDir's pre-fetch
// directory before customize runs. Failures only cost a download, so they
// are logged, not fatal.
func seedPrefetchCache(t *testing.T, isoDir string) {
	t.Helper()
	cache := apkCacheDir(t)
	if cache == "" {
		return
	}
	n, err := linkAPKs(cache, prefetchDir(isoDir))
	if err != nil {
		t.Logf("APK cache: seeding %s from %s: %v", prefetchDir(isoDir), cache, err)
	}
	t.Logf("APK cache: seeded %d packages from %s", n, cache)
}

// harvestPrefetchCache stores the packages a successful customize downloaded
// in the cache for the next run.
func harvestPrefetchCache(t *testing.T, isoDir string) {
	t.Helper()
	cache := apkCacheDir(t)
	if cache == "" {
		return
	}
	n, err := linkAPKs(prefetchDir(isoDir), cache)
	if err != nil {
		t.Logf("APK cache: harvesting %s into %s: %v", prefetchDir(isoDir), cache, err)
	}
	t.Logf("APK cache: stored %d new packages in %s", n, cache)
}

// cacheableAPK reports whether name is a mirror package the cache may hold.
func cacheableAPK(name string) bool {
	if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".apk") {
		return false
	}
	for _, p := range platformAPKPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

// linkAPKs hard-links (or copies) each cacheable *.apk in src that dst lacks
// into dst. Each file is written under a hidden temp name and renamed into
// place, so a killed run never leaves a partial file under a *.apk name.
// A missing src is not an error. It returns how many files it placed.
func linkAPKs(src, dst string) (int, error) {
	entries, err := os.ReadDir(src)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return 0, err
	}
	placed := 0
	var firstErr error
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !cacheableAPK(name) {
			continue
		}
		target := filepath.Join(dst, name)
		if _, err := os.Stat(target); err == nil {
			continue
		}
		if err := placeAtomically(filepath.Join(src, name), target); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		placed++
	}
	return placed, firstErr
}

func placeAtomically(src, target string) error {
	dir := filepath.Dir(target)
	pattern := "." + filepath.Base(target) + ".*.tmp"

	// The cache volume is shared across containers, whose PIDs collide, so
	// every staging name is created exclusively by os.CreateTemp and this
	// writer only ever removes or renames a path it created itself.
	if staged, err := linkStaged(src, dir, pattern); err == nil {
		if err := os.Rename(staged, target); err != nil {
			_ = os.Remove(staged)
			return err
		}
		return nil
	}

	out, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tmp := out.Name()
	if err := copyFile(src, out); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// linkStaged hard-links src to a fresh staging name in dir: it reserves the
// name with os.CreateTemp, removes its own empty file and links in its place.
// On failure nothing it created is left, and nothing else is touched.
func linkStaged(src, dir, pattern string) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	f.Close()
	if err := os.Remove(name); err != nil {
		return "", err
	}
	if err := linkFile(src, name); err != nil {
		return "", err
	}
	return name, nil
}

// linkFile and copyFile are hooks the tests swap to force the copy path and
// to interrupt a copy.
var (
	linkFile = os.Link
	copyFile = copyInto
)

func copyInto(src string, out *os.File) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	_, err = io.Copy(out, in)
	return err
}
