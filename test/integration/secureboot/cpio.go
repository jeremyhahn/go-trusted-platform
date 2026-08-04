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

package secureboot

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

// cpioEntry is a single member of a newc-format initramfs archive.
type cpioEntry struct {
	// Name is the archive path (no leading slash).
	Name string
	// Mode is the full mode word including the file type bits
	// (e.g. 0100755 regular executable, 040755 directory, 020644 char dev).
	Mode uint32
	// Data is the file content (nil for directories and device nodes).
	Data []byte
	// Rdev major/minor for device nodes.
	RdevMajor, RdevMinor uint32
}

// writeCPIO serializes entries into a gzip-compressed SVR4 newc cpio archive
// suitable for the kernel initramfs loader. Inode numbers are synthesized
// sequentially; the kernel ignores them.
func writeCPIO(w io.Writer, entries []cpioEntry) error {
	gz := gzip.NewWriter(w)
	var buf bytes.Buffer

	writeHeader := func(ino uint32, e cpioEntry, dataLen int) {
		fmt.Fprintf(&buf, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
			ino,           // c_ino
			e.Mode,        // c_mode
			0,             // c_uid
			0,             // c_gid
			1,             // c_nlink
			0,             // c_mtime
			dataLen,       // c_filesize
			0,             // c_devmajor
			0,             // c_devminor
			e.RdevMajor,   // c_rdevmajor
			e.RdevMinor,   // c_rdevminor
			len(e.Name)+1, // c_namesize (includes NUL)
			0)             // c_check
		buf.WriteString(e.Name)
		buf.WriteByte(0)
		// Header (110) + name + NUL padded to a 4-byte boundary.
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
	}

	for i, e := range entries {
		writeHeader(uint32(i+1), e, len(e.Data))
		buf.Write(e.Data)
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
	}

	// Trailer entry.
	writeHeader(0, cpioEntry{Name: "TRAILER!!!"}, 0)

	if _, err := gz.Write(buf.Bytes()); err != nil {
		return ErrCommandFailed{Command: "cpio write", Err: err}
	}
	if err := gz.Close(); err != nil {
		return ErrCommandFailed{Command: "cpio gzip close", Err: err}
	}
	return nil
}
