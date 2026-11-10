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

package modulesign

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// errCov964Compress is the codec failure the recompress tests inject.
type errCov964Compress struct{}

func (errCov964Compress) Error() string { return "cov964: injected compress failure" }

// cov964FailingCompress replaces the compress half of the codec registered for
// ext with one that always fails, restoring the original codec when t ends.
func cov964FailingCompress(t *testing.T, ext string) {
	t.Helper()
	original, ok := compressionCodecs[ext]
	if !ok {
		t.Fatalf("no codec registered for %q", ext)
	}
	failing := original
	failing.compress = func([]byte) ([]byte, error) { return nil, errCov964Compress{} }
	compressionCodecs[ext] = failing
	t.Cleanup(func() { compressionCodecs[ext] = original })
}

// TestSignCompressedModuleRecompressFailure checks that a codec which cannot
// recompress the signed module surfaces ErrCompress naming the module and
// codec, wraps the codec error, and leaves the original file untouched with
// no temp file behind.
func TestSignCompressedModuleRecompressFailure(t *testing.T) {
	key, cert := ecdsaFixture(t)
	module := []byte("\x7fELF cov964 module body")

	cases := []struct {
		ext      string
		codec    string
		compress func(*testing.T, []byte) []byte
	}{
		{ext: ".gz", codec: "gzip", compress: gzipBytes},
		{ext: ".zst", codec: "zstd", compress: zstdBytes},
	}
	for _, tc := range cases {
		t.Run(tc.codec, func(t *testing.T) {
			cov964FailingCompress(t, tc.ext)

			dir := t.TempDir()
			path := filepath.Join(dir, "module.ko"+tc.ext)
			original := tc.compress(t, module)
			if err := os.WriteFile(path, original, 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			err := signCompressedModule(path, key, cert)

			var ce ErrCompress
			if !errors.As(err, &ce) {
				t.Fatalf("error = %v, want ErrCompress", err)
			}
			if ce.Path != path || ce.Codec != tc.codec {
				t.Errorf("ErrCompress = {Path: %q, Codec: %q}, want {%q, %q}", ce.Path, ce.Codec, path, tc.codec)
			}
			var injected errCov964Compress
			if !errors.As(err, &injected) {
				t.Errorf("error = %v, want it to wrap the codec error", err)
			}

			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("ReadFile: %v", readErr)
			}
			if !bytes.Equal(got, original) {
				t.Error("module file changed although recompression failed")
			}
			entries, dirErr := os.ReadDir(dir)
			if dirErr != nil {
				t.Fatalf("ReadDir: %v", dirErr)
			}
			if len(entries) != 1 {
				t.Errorf("directory holds %d entries, want only the module", len(entries))
			}
		})
	}
}
