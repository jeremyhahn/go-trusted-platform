//go:build integration

package iso

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPKCacheDir checks where the runner-local APK cache lives: the
// per-version, per-arch directory under the GTP_ISO_APK_CACHE override when
// set (one CI volume holds every version), else under the user cache directory.
func TestAPKCacheDir(t *testing.T) {
	override := t.TempDir()
	t.Setenv(EnvISOAPKCache, override)
	assert.Equal(t, filepath.Join(override, DefaultAlpineVersion, DefaultArch), apkCacheDir(t))

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
	root := t.TempDir()
	t.Setenv(EnvISOAPKCache, root)
	cache := filepath.Join(root, DefaultAlpineVersion, DefaultArch)
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
	root := filepath.Join(t.TempDir(), "nested", "cache")
	t.Setenv(EnvISOAPKCache, root)
	cache := filepath.Join(root, DefaultAlpineVersion, DefaultArch)

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

// forceCopyPath makes placeAtomically skip the hard link, as it does when the
// cache volume and the prefetch dir sit on different filesystems.
func forceCopyPath(t *testing.T) {
	t.Helper()
	orig := linkFile
	linkFile = func(string, string) error { return errors.New("link refused by test") }
	t.Cleanup(func() { linkFile = orig })
}

func tmpNames(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, n := range dirNames(t, dir) {
		if strings.HasSuffix(n, ".tmp") {
			out = append(out, n)
		}
	}
	return out
}

func TestPlaceAtomicallyConcurrentWritersPublishCompleteFiles(t *testing.T) {
	forceCopyPath(t)
	srcDir, dst := t.TempDir(), t.TempDir()
	payload := make([]byte, 1<<20)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	src := filepath.Join(srcDir, "musl-1.2.5-r0.apk")
	require.NoError(t, os.WriteFile(src, payload, 0o644))
	target := filepath.Join(dst, "musl-1.2.5-r0.apk")

	const writers = 8
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = placeAtomically(src, target)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "writer %d", i)
	}
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(payload, got), "cached APK differs from the source (%d of %d bytes)", len(got), len(payload))
	assert.Empty(t, tmpNames(t, dst), "staging files left behind")
}

func TestPlaceAtomicallyLeavesOtherWritersStagingFiles(t *testing.T) {
	forceCopyPath(t)
	srcDir, dst := t.TempDir(), t.TempDir()
	src := filepath.Join(srcDir, "busybox-1.36.1-r0.apk")
	writeFile(t, src, "complete package")
	target := filepath.Join(dst, "busybox-1.36.1-r0.apk")

	// Another container's writer, whose PID may equal ours, is mid-copy.
	other := filepath.Join(dst, fmt.Sprintf(".%s.%d.tmp", filepath.Base(target), os.Getpid()))
	writeFile(t, other, "half of another writer's copy")

	require.NoError(t, placeAtomically(src, target))

	got, err := os.ReadFile(other)
	require.NoError(t, err, "another writer's staging file was removed or renamed")
	assert.Equal(t, "half of another writer's copy", string(got))
	pub, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "complete package", string(pub))
}

func TestPlaceAtomicallyInterruptedCopyPublishesNothing(t *testing.T) {
	forceCopyPath(t)
	orig := copyFile
	copyFile = func(src string, out *os.File) error {
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		if _, err := io.CopyN(out, in, 4); err != nil {
			return err
		}
		return errors.New("copy interrupted by test")
	}
	t.Cleanup(func() { copyFile = orig })

	srcDir, dst := t.TempDir(), t.TempDir()
	src := filepath.Join(srcDir, "zlib-1.3.1-r0.apk")
	writeFile(t, src, "a package longer than four bytes")
	target := filepath.Join(dst, "zlib-1.3.1-r0.apk")

	require.Error(t, placeAtomically(src, target))
	assert.Empty(t, dirNames(t, dst), "an interrupted copy left files in the cache")
}

// TestPlaceAtomicallyHidesAPausedCopy pauses a copy part way through and
// checks what another container reading the shared cache would see: the
// final name must hold either nothing or the previous complete file, never
// the partial bytes, until the copy finishes (Codex P1, #1915).
func TestPlaceAtomicallyHidesAPausedCopy(t *testing.T) {
	const prefix = 4 << 10
	for _, tc := range []struct {
		name string
		old  []byte
	}{
		{name: "no previous file"},
		{name: "previous complete file", old: bytes.Repeat([]byte("old complete apk "), 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forceCopyPath(t)
			srcDir, dst := t.TempDir(), t.TempDir()
			payload := make([]byte, 1<<20)
			_, err := rand.Read(payload)
			require.NoError(t, err)
			src := filepath.Join(srcDir, "musl-1.2.5-r0.apk")
			require.NoError(t, os.WriteFile(src, payload, 0o644))
			target := filepath.Join(dst, "musl-1.2.5-r0.apk")
			if tc.old != nil {
				require.NoError(t, os.WriteFile(target, tc.old, 0o644))
			}

			paused, release := make(chan struct{}), make(chan struct{})
			orig := copyFile
			copyFile = func(src string, out *os.File) error {
				in, err := os.Open(src)
				if err != nil {
					return err
				}
				defer in.Close()
				if _, err := io.CopyN(out, in, prefix); err != nil {
					return err
				}
				close(paused)
				<-release
				_, err = io.Copy(out, in)
				return err
			}
			t.Cleanup(func() { copyFile = orig })

			done := make(chan error, 1)
			go func() { done <- placeAtomically(src, target) }()
			<-paused

			got, err := os.ReadFile(target)
			if tc.old == nil {
				assert.True(t, errors.Is(err, os.ErrNotExist),
					"a paused copy exposed %d bytes under the final name", len(got))
			} else {
				require.NoError(t, err)
				assert.True(t, bytes.Equal(tc.old, got),
					"a paused copy replaced the complete file with %d partial bytes", len(got))
			}

			close(release)
			require.NoError(t, <-done)
			got, err = os.ReadFile(target)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(payload, got), "the finished copy is not the full source")
			assert.Empty(t, tmpNames(t, dst), "the finished copy left staging files")
		})
	}
}
