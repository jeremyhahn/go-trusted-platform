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
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// moduleCodec decompresses and recompresses a kernel module payload for one
// compressed-module extension. The kernel verifies the appended CMS signature
// against the DECOMPRESSED module image (it decompresses the module first, then
// checks the trailing signature), so a compressed module is signed by
// decompressing it, appending the signature to the raw .ko bytes, and
// recompressing with the same codec.
type moduleCodec struct {
	name       string
	decompress func([]byte) ([]byte, error)
	compress   func([]byte) ([]byte, error)
}

// compressionCodecs maps a compressed-module extension (as returned by
// filepath.Ext) to its codec. gzip is served by the standard library; zstd by
// the pure-Go github.com/klauspost/compress/zstd already in the module graph.
// xz is intentionally absent — see unsupportedCompressionCodecs.
var compressionCodecs = map[string]moduleCodec{
	".gz":  {name: "gzip", decompress: gzipDecompress, compress: gzipCompress},
	".zst": {name: "zstd", decompress: zstdDecompress, compress: zstdCompress},
}

// unsupportedCompressionCodecs maps a recognized-but-unsupported compressed
// module extension to the module dependency that would be required to support
// it. No pure-Go xz/LZMA codec is in the platform's module graph (klauspost
// /compress ships no xz package, and ulikunitz/xz is not a dependency), and
// shelling out to the xz binary is not an option for a static initramfs signer,
// so .ko.xz signing returns ErrUnsupportedCompressionCodec naming the dependency
// that would unblock it.
var unsupportedCompressionCodecs = map[string]string{
	".xz": "github.com/ulikunitz/xz",
}

// isCompressionExt reports whether ext (a filepath.Ext result such as ".gz") is
// a recognized compressed-module extension, whether or not the platform can sign
// that codec. The recognized set is derived from the codec maps so the two never
// drift apart.
func isCompressionExt(ext string) bool {
	if _, ok := compressionCodecs[ext]; ok {
		return true
	}
	_, ok := unsupportedCompressionCodecs[ext]
	return ok
}

// signCompressedModule decompresses koPath, appends the CMS signature and kernel
// trailer to the raw module bytes, recompresses with the same codec, and writes
// the result back atomically (preserving mode). Modules compressed with a codec
// the platform cannot handle (xz) return ErrUnsupportedCompressionCodec without
// touching the file.
func signCompressedModule(koPath string, signer crypto.Signer, cert *x509.Certificate) error {
	ext := filepath.Ext(koPath)
	codec, ok := compressionCodecs[ext]
	if !ok {
		return ErrUnsupportedCompressionCodec{
			Path:       koPath,
			Codec:      strings.TrimPrefix(ext, "."),
			Dependency: unsupportedCompressionCodecs[ext],
		}
	}

	info, err := os.Stat(koPath)
	if err != nil {
		return ErrModuleRead{Path: koPath, Err: err}
	}

	compressed, err := os.ReadFile(koPath)
	if err != nil {
		return ErrModuleRead{Path: koPath, Err: err}
	}

	moduleContent, err := codec.decompress(compressed)
	if err != nil {
		return ErrDecompress{Path: koPath, Codec: codec.name, Err: err}
	}

	trailer, err := BuildModuleSignature(moduleContent, signer, cert)
	if err != nil {
		return err
	}

	signed := make([]byte, 0, len(moduleContent)+len(trailer))
	signed = append(signed, moduleContent...)
	signed = append(signed, trailer...)

	recompressed, err := codec.compress(signed)
	if err != nil {
		return ErrCompress{Path: koPath, Codec: codec.name, Err: err}
	}

	return atomicWrite(koPath, recompressed, info.Mode().Perm())
}

// gzipDecompress returns the inflated contents of a gzip stream. The reader is
// closed so the gzip CRC and length trailer are validated.
func gzipDecompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(r)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	if err := r.Close(); err != nil {
		return nil, err
	}
	return out, nil
}

// gzipCompress returns data compressed as a gzip stream.
func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// zstdDecompress returns the decoded contents of a zstd frame. Concurrency is
// pinned to 1 so signing a large module tree does not spawn GOMAXPROCS workers
// per call; the decoder is closed to release its resources.
func zstdDecompress(data []byte) ([]byte, error) {
	r, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.DecodeAll(data, nil)
}

// zstdCompress returns data encoded as a single zstd frame. Concurrency is
// pinned to 1 for the same reason as zstdDecompress; the encoder is closed to
// release its resources.
func zstdCompress(data []byte) ([]byte, error) {
	w, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	out := w.EncodeAll(data, nil)
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out, nil
}
