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

// Package modulesign signs Linux kernel modules with a detached CMS/PKCS#7
// signature in the exact format the kernel's module-signature verifier accepts.
//
// The signed module file layout is:
//
//	original_module_bytes || cms_der || module_signature(12B) || magic(28B)
//
// where cms_der is a detached CMS SignedData over the raw module bytes (no
// embedded certificates; the signer is matched by issuer + serial against the
// kernel keyring), module_signature is the 12-byte struct module_signature
// trailer, and magic is the 28-byte "~Module signature appended~\n" marker.
//
// Compressed modules (.ko.gz/.ko.zst) are signed by decompressing the module,
// appending the same trailer to the decompressed bytes, and recompressing with
// the matching codec: the kernel decompresses the module before verifying the
// appended signature, so the signature must cover the decompressed image. xz is
// not yet supported because no pure-Go xz codec is in the module graph.
//
// The private key never lives in this package. Signing is delegated to an
// injected crypto.Signer (typically SDK-backed): this package only assembles the
// CMS DER envelope and kernel trailer around an externally produced signature,
// mirroring how pkg/authenticode wraps an Authenticode PKCS#7 envelope around a
// keystore-produced signature.
package modulesign

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// magic is the kernel module signature marker appended last. The trailing
	// newline is part of the 28-byte marker.
	magic = "~Module signature appended~\n"

	// pkeyIDPKCS7 is PKEY_ID_PKCS7, the id_type for a PKCS#7/CMS signature.
	pkeyIDPKCS7 = 2

	// moduleSigTrailerLen is sizeof(struct module_signature).
	moduleSigTrailerLen = 12
)

// SignModule signs the kernel module at koPath in place, appending the detached
// CMS signature and kernel trailer. The private key is provided by signer
// (SDK-backed); cert supplies the issuer and serial for the SignerInfo. The file
// is rewritten atomically and its original mode is preserved.
//
// Compressed modules are detected by extension. .ko.gz and .ko.zst are
// decompressed, signed over their decompressed bytes, and recompressed with the
// same codec. .ko.xz is reported with ErrUnsupportedCompressionCodec because no
// pure-Go xz codec is available; the file is left untouched.
func SignModule(koPath string, signer crypto.Signer, cert *x509.Certificate) error {
	if isCompressedModule(koPath) {
		return signCompressedModule(koPath, signer, cert)
	}

	info, err := os.Stat(koPath)
	if err != nil {
		return ErrModuleRead{Path: koPath, Err: err}
	}

	content, err := os.ReadFile(koPath)
	if err != nil {
		return ErrModuleRead{Path: koPath, Err: err}
	}

	trailer, err := BuildModuleSignature(content, signer, cert)
	if err != nil {
		return err
	}

	signed := make([]byte, 0, len(content)+len(trailer))
	signed = append(signed, content...)
	signed = append(signed, trailer...)

	return atomicWrite(koPath, signed, info.Mode().Perm())
}

// BuildModuleSignature returns cms_der || module_signature || magic for the given
// module content. It is factored out of SignModule so the signature envelope is
// unit-testable without touching the filesystem.
func BuildModuleSignature(moduleContent []byte, signer crypto.Signer, cert *x509.Certificate) ([]byte, error) {
	if signer == nil {
		return nil, ErrNilSigner{}
	}
	if cert == nil {
		return nil, ErrNilCertificate{}
	}

	cmsDER, err := buildDetachedCMS(moduleContent, signer, cert)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(cmsDER)+moduleSigTrailerLen+len(magic))
	out = append(out, cmsDER...)
	out = append(out, moduleSigTrailer(len(cmsDER))...)
	out = append(out, magic...)
	return out, nil
}

// moduleSigTrailer builds the 12-byte struct module_signature trailer. All
// fields other than id_type (PKEY_ID_PKCS7) and the big-endian sig_len are zero.
func moduleSigTrailer(sigLen int) []byte {
	trailer := make([]byte, moduleSigTrailerLen)
	trailer[2] = pkeyIDPKCS7
	binary.BigEndian.PutUint32(trailer[8:12], uint32(sigLen))
	return trailer
}

// EnumerateModules returns the absolute paths of all kernel modules under
// <rootfs>/lib/modules/<kver>, sorted lexically. Compressed modules
// (.ko.gz/.ko.xz/.ko.zst) are included so callers can see the full set; signing
// a .ko.gz/.ko.zst rewrites it in place, while signing a .ko.xz returns
// ErrUnsupportedCompressionCodec rather than silently skipping it.
func EnumerateModules(rootfs, kver string) ([]string, error) {
	moduleDir := filepath.Join(rootfs, "lib", "modules", kver)
	base, err := filepath.Abs(moduleDir)
	if err != nil {
		return nil, ErrEnumerate{Path: moduleDir, Err: err}
	}

	var modules []string
	walkErr := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if isModuleFile(path) {
			modules = append(modules, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, ErrEnumerate{Path: base, Err: walkErr}
	}

	sort.Strings(modules)
	return modules, nil
}

// isModuleFile reports whether path names a kernel module, compressed or not.
func isModuleFile(path string) bool {
	return strings.HasSuffix(path, ".ko") || isCompressedModule(path)
}

// isCompressedModule reports whether path names a compressed kernel module: a
// .ko file carrying a recognized compression extension, whether or not the
// platform can currently sign that codec.
func isCompressedModule(path string) bool {
	ext := filepath.Ext(path)
	if !isCompressionExt(ext) {
		return false
	}
	return strings.HasSuffix(strings.TrimSuffix(path, ext), ".ko")
}

// atomicWrite writes data to a temp file in the same directory and renames it
// over path, preserving mode. The temp file is removed on any failure.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".sign-*")
	if err != nil {
		return ErrModuleWrite{Path: path, Err: err}
	}
	tmpName := tmp.Name()

	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return ErrModuleWrite{Path: path, Err: err}
	}
	if err := tmp.Close(); err != nil {
		return ErrModuleWrite{Path: path, Err: err}
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return ErrModuleWrite{Path: path, Err: err}
	}
	if err := os.Rename(tmpName, path); err != nil {
		return ErrModuleWrite{Path: path, Err: err}
	}
	committed = true
	return nil
}
