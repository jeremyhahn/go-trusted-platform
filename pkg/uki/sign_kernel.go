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

package uki

import (
	"io"
	"os"
	"path/filepath"
)

// FileSigner signs a PE/COFF file (Authenticode) — what
// authenticode.Authenticode provides.
type FileSigner interface {
	SignFile(inputPath, outputPath string) error
}

// SignKernel writes the kernel at src, db-signed, to dst. A
// gzip-compressed vmlinuz is decompressed first: firmware verifies and runs
// the PE image inside it (U-Boot under Secure Boot verifies every EFI image
// it loads, the kernel an iPXE boots included). The decompressed image is
// written beside dst and removed afterwards.
func SignKernel(src, dst string, signer FileSigner) error {
	raw, err := OpenKernel(src)
	if err != nil {
		return err
	}
	defer raw.Close()
	unsigned := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".unsigned")
	out, err := os.Create(unsigned)
	if err != nil {
		return &WrappedError{Msg: "writing the decompressed kernel", Err: err}
	}
	defer os.Remove(unsigned)
	if _, err := io.Copy(out, raw); err != nil {
		_ = out.Close()
		return &WrappedError{Msg: "decompressing the kernel", Err: err}
	}
	if err := out.Close(); err != nil {
		return &WrappedError{Msg: "writing the decompressed kernel", Err: err}
	}
	if err := signer.SignFile(unsigned, dst); err != nil {
		return &WrappedError{Msg: "signing the kernel", Err: err}
	}
	return nil
}
