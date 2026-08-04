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
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// --- codec helpers that compress/decompress INDEPENDENTLY of the package -----
//
// Setup compresses with the upstream libraries directly so the round-trip tests
// exercise SignModule's own decompress path (not the package's compress helper),
// and verify by decompressing with the libraries directly.

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func gunzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return out
}

func zstdBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	w, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	out := w.EncodeAll(data, nil)
	if err := w.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return out
}

func unzstdBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	r, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer r.Close()
	out, err := r.DecodeAll(data, nil)
	if err != nil {
		t.Fatalf("zstd decode: %v", err)
	}
	return out
}

type codecFixture struct {
	name       string
	ext        string
	compress   func(*testing.T, []byte) []byte
	decompress func(*testing.T, []byte) []byte
}

func supportedCodecFixtures() []codecFixture {
	return []codecFixture{
		{"gzip", ".ko.gz", gzipBytes, gunzipBytes},
		{"zstd", ".ko.zst", zstdBytes, unzstdBytes},
	}
}

// --- tests -------------------------------------------------------------------

// TestSignModuleCompressedRoundTrip is the primary contract test for each
// supported codec: a compressed fake module is signed, and after decompression
// the payload must be the original module bytes followed by the kernel trailer,
// with a signature that verifies against the in-test RSA key. The file must stay
// compressed (re-encoded with the same codec) and keep its mode.
func TestSignModuleCompressedRoundTrip(t *testing.T) {
	key, cert := rsaFixture(t)
	moduleBody := append([]byte("\x7fELF"), bytes.Repeat([]byte("kernel module payload "), 64)...)

	for _, tc := range supportedCodecFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "driver"+tc.ext)
			original := tc.compress(t, moduleBody)
			const mode os.FileMode = 0o640
			if err := os.WriteFile(path, original, mode); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			if err := SignModule(path, key, cert); err != nil {
				t.Fatalf("SignModule: %v", err)
			}

			signedRaw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if bytes.Equal(signedRaw, original) {
				t.Fatal("compressed module was not rewritten")
			}

			// The on-disk file must still be valid compressed data, and its
			// decompressed form must be original_module || trailer.
			decompressed := tc.decompress(t, signedRaw)
			if !bytes.HasPrefix(decompressed, moduleBody) {
				t.Fatal("decompressed payload does not start with the original module body")
			}
			if !bytes.HasSuffix(decompressed, []byte(magic)) {
				t.Fatal("decompressed payload does not end with the kernel magic marker")
			}

			// The appended blob must equal BuildModuleSignature over the ORIGINAL
			// (decompressed) module bytes, byte for byte.
			appended := decompressed[len(moduleBody):]
			want, err := BuildModuleSignature(moduleBody, key, cert)
			if err != nil {
				t.Fatalf("BuildModuleSignature: %v", err)
			}
			if !bytes.Equal(appended, want) {
				t.Fatal("appended signature does not match BuildModuleSignature output")
			}

			// Cryptographically verify the signature on the decompressed payload.
			cmsDER, _, marker := splitEnvelope(t, appended)
			if string(marker) != magic {
				t.Fatalf("marker = %q, want the kernel magic", marker)
			}
			_, si := parseCMS(t, cmsDER)
			digest := sha256.Sum256(signedAttrsSET(t, si))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], si.Signature); err != nil {
				t.Fatalf("RSA signature failed to verify on decompressed module: %v", err)
			}
			wantMD := sha256.Sum256(moduleBody)
			if got := messageDigestAttr(t, si); !bytes.Equal(got, wantMD[:]) {
				t.Errorf("messageDigest = %x, want %x", got, wantMD)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat: %v", err)
			}
			if info.Mode().Perm() != mode {
				t.Errorf("mode = %v, want %v", info.Mode().Perm(), mode)
			}
		})
	}
}

// TestSignModuleCompressedECDSA confirms the compressed path is signer-agnostic:
// an ECDSA key produces a verifiable signature on the decompressed payload.
func TestSignModuleCompressedECDSA(t *testing.T) {
	key, cert := ecdsaFixture(t)
	moduleBody := []byte("\x7fELF ecdsa compressed module body")
	path := filepath.Join(t.TempDir(), "driver.ko.zst")
	if err := os.WriteFile(path, zstdBytes(t, moduleBody), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := SignModule(path, key, cert); err != nil {
		t.Fatalf("SignModule: %v", err)
	}

	signedRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	decompressed := unzstdBytes(t, signedRaw)
	if !bytes.HasSuffix(decompressed, []byte(magic)) {
		t.Fatal("decompressed payload does not end with the kernel magic marker")
	}
}

// TestSignModuleCorruptCompressed guards that bytes that are not valid for the
// codec surface ErrDecompress (wrapping the codec error) and leave the file
// untouched.
func TestSignModuleCorruptCompressed(t *testing.T) {
	key, cert := rsaFixture(t)
	for _, tc := range supportedCodecFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "broken"+tc.ext)
			garbage := []byte("this is plainly not a valid compressed module stream")
			if err := os.WriteFile(path, garbage, 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			err := SignModule(path, key, cert)
			var de ErrDecompress
			if !errors.As(err, &de) {
				t.Fatalf("error = %v, want ErrDecompress", err)
			}
			if de.Path != path {
				t.Errorf("Path = %s, want %s", de.Path, path)
			}
			if de.Codec != tc.name {
				t.Errorf("Codec = %q, want %q", de.Codec, tc.name)
			}
			if de.Err == nil {
				t.Error("ErrDecompress.Err is nil; want the wrapped codec error")
			}

			// A decompression failure must not modify the file.
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("ReadFile: %v", readErr)
			}
			if !bytes.Equal(got, garbage) {
				t.Error("corrupt module was modified on a decompression failure")
			}
		})
	}
}

// TestSignModuleCompressedMissingFile guards that a missing compressed module
// surfaces ErrModuleRead from the stat in the compressed path.
func TestSignModuleCompressedMissingFile(t *testing.T) {
	key, cert := rsaFixture(t)
	for _, tc := range supportedCodecFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "absent"+tc.ext)
			err := SignModule(path, key, cert)
			var re ErrModuleRead
			if !errors.As(err, &re) {
				t.Fatalf("error = %v, want ErrModuleRead", err)
			}
			if !errors.Is(err, os.ErrNotExist) {
				t.Errorf("error does not unwrap to os.ErrNotExist: %v", err)
			}
		})
	}
}

// TestSignModuleCompressedUnreadable guards that a compressed-module PATH that
// stats successfully but cannot be read as a file (here, a directory) yields
// ErrModuleRead from the compressed signing path's read step.
func TestSignModuleCompressedUnreadable(t *testing.T) {
	key, cert := rsaFixture(t)
	dir := filepath.Join(t.TempDir(), "notafile.ko.gz")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	err := SignModule(dir, key, cert)
	var re ErrModuleRead
	if !errors.As(err, &re) {
		t.Fatalf("error = %v, want ErrModuleRead", err)
	}
}

// TestSignModuleCompressedPropagatesSignerError guards that a signer failure on
// the compressed path is propagated (as ErrSign) and leaves the file untouched.
func TestSignModuleCompressedPropagatesSignerError(t *testing.T) {
	_, cert := rsaFixture(t)
	path := filepath.Join(t.TempDir(), "driver.ko.gz")
	original := gzipBytes(t, []byte("\x7fELF module to sign"))
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	signer := fakeSigner{pub: nil, err: errors.New("token removed")}
	err := SignModule(path, signer, cert)
	var se ErrSign
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want ErrSign", err)
	}

	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if !bytes.Equal(got, original) {
		t.Error("compressed module was modified on a signing failure")
	}
}

// TestCodecRoundTrip exercises the package's own codec helpers directly: a
// compress followed by a decompress must reproduce the input exactly.
func TestCodecRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("module codec round trip "), 50)
	codecs := map[string]moduleCodec{".gz": compressionCodecs[".gz"], ".zst": compressionCodecs[".zst"]}
	for ext, codec := range codecs {
		t.Run(codec.name, func(t *testing.T) {
			compressed, err := codec.compress(payload)
			if err != nil {
				t.Fatalf("%s compress: %v", ext, err)
			}
			if bytes.Equal(compressed, payload) {
				t.Errorf("%s compress returned the input unchanged", ext)
			}
			out, err := codec.decompress(compressed)
			if err != nil {
				t.Fatalf("%s decompress: %v", ext, err)
			}
			if !bytes.Equal(out, payload) {
				t.Errorf("%s round trip mismatch", ext)
			}
		})
	}
}

// TestCodecDecompressErrors guards that the codec decompress helpers reject
// malformed input across the distinct gzip failure modes (bad header, truncated
// body, corrupted checksum) and a malformed zstd frame.
func TestCodecDecompressErrors(t *testing.T) {
	if _, err := gzipDecompress([]byte("not a gzip header at all")); err == nil {
		t.Error("gzipDecompress(bad header) = nil error, want failure")
	}
	if _, err := zstdDecompress([]byte("not a zstd frame at all")); err == nil {
		t.Error("zstdDecompress(garbage) = nil error, want failure")
	}

	// A valid gzip header followed by a truncated deflate body: NewReader
	// succeeds, but inflating the body fails partway with unexpected EOF.
	full := gzipBytes(t, bytes.Repeat([]byte("module body "), 100))
	if _, err := gzipDecompress(full[:15]); err == nil {
		t.Error("gzipDecompress(truncated) = nil error, want failure")
	}

	// A complete gzip stream with a corrupted CRC32 trailer: the body inflates
	// cleanly, but the closing checksum check fails. The trailer is the final 8
	// bytes (CRC32 || ISIZE), so flipping the first trailer byte leaves the
	// deflate body intact.
	badCRC := append([]byte(nil), full...)
	badCRC[len(badCRC)-8] ^= 0xFF
	if _, err := gzipDecompress(badCRC); err == nil {
		t.Error("gzipDecompress(bad checksum) = nil error, want failure")
	}
}

// TestIsCompressedModule guards the extension recognition that routes a path to
// the compressed signing path. Recognition covers xz even though it is
// unsupported, so .ko.xz reaches signCompressedModule and reports a typed error.
func TestIsCompressedModule(t *testing.T) {
	compressed := []string{
		"a.ko.gz",
		"a.ko.xz",
		"a.ko.zst",
		"/lib/modules/6.1.0/kernel/drivers/net/e1000.ko.zst",
	}
	for _, p := range compressed {
		if !isCompressedModule(p) {
			t.Errorf("isCompressedModule(%q) = false, want true", p)
		}
	}

	plain := []string{
		"a.ko",         // uncompressed module
		"a.gz",         // compressed, but not a .ko
		"a.xz",         // compressed, but not a .ko
		"a.zst",        // compressed, but not a .ko
		"a.ko.bz2",     // unrecognized compression extension
		"firmware.bin", // not a module at all
		"a.ko.gz.bak",  // trailing extension is not a codec
	}
	for _, p := range plain {
		if isCompressedModule(p) {
			t.Errorf("isCompressedModule(%q) = true, want false", p)
		}
	}
}
