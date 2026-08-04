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

import "fmt"

// ErrNilSigner indicates that no crypto.Signer was supplied.
type ErrNilSigner struct{}

// Error returns the error message.
func (ErrNilSigner) Error() string { return "modulesign: signer is nil" }

// ErrNilCertificate indicates that no signing certificate was supplied.
type ErrNilCertificate struct{}

// Error returns the error message.
func (ErrNilCertificate) Error() string { return "modulesign: certificate is nil" }

// ErrUnsupportedCompressionCodec indicates that the module is compressed with a
// codec the platform cannot sign because no pure-Go implementation of it is in
// the module graph. Decompressing via an external binary is not an option for a
// static initramfs signer, so the codec is reported along with the module
// dependency (Dependency) that would unblock support. .ko.gz and .ko.zst are
// signed in place; only .ko.xz currently surfaces this error.
type ErrUnsupportedCompressionCodec struct {
	Path       string
	Codec      string
	Dependency string
}

// Error returns the error message.
func (e ErrUnsupportedCompressionCodec) Error() string {
	if e.Dependency != "" {
		return fmt.Sprintf("modulesign: unsupported compression codec %q for %s (requires %s)",
			e.Codec, e.Path, e.Dependency)
	}
	return fmt.Sprintf("modulesign: unsupported compression codec %q for %s", e.Codec, e.Path)
}

// ErrUnsupportedKeyType indicates the signing key is neither RSA nor ECDSA.
type ErrUnsupportedKeyType struct {
	KeyType string
}

// Error returns the error message.
func (e ErrUnsupportedKeyType) Error() string {
	return fmt.Sprintf("modulesign: unsupported signing key type: %s", e.KeyType)
}

// ErrModuleRead indicates the module file could not be read.
type ErrModuleRead struct {
	Path string
	Err  error
}

// Error returns the error message.
func (e ErrModuleRead) Error() string {
	return fmt.Sprintf("modulesign: read module %s: %v", e.Path, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrModuleRead) Unwrap() error { return e.Err }

// ErrModuleWrite indicates the signed module could not be written.
type ErrModuleWrite struct {
	Path string
	Err  error
}

// Error returns the error message.
func (e ErrModuleWrite) Error() string {
	return fmt.Sprintf("modulesign: write module %s: %v", e.Path, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrModuleWrite) Unwrap() error { return e.Err }

// ErrDecompress indicates a compressed module could not be decompressed before
// signing. Codec names the compression codec involved (gzip/zstd).
type ErrDecompress struct {
	Path  string
	Codec string
	Err   error
}

// Error returns the error message.
func (e ErrDecompress) Error() string {
	return fmt.Sprintf("modulesign: decompress %s (%s): %v", e.Path, e.Codec, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrDecompress) Unwrap() error { return e.Err }

// ErrCompress indicates a signed module could not be recompressed after the
// signature was appended. Codec names the compression codec involved.
type ErrCompress struct {
	Path  string
	Codec string
	Err   error
}

// Error returns the error message.
func (e ErrCompress) Error() string {
	return fmt.Sprintf("modulesign: recompress %s (%s): %v", e.Path, e.Codec, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrCompress) Unwrap() error { return e.Err }

// ErrSign indicates the injected signer failed to produce a signature.
type ErrSign struct {
	Err error
}

// Error returns the error message.
func (e ErrSign) Error() string {
	return fmt.Sprintf("modulesign: signing failed: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e ErrSign) Unwrap() error { return e.Err }

// ErrASN1Marshal indicates a DER encoding step failed.
type ErrASN1Marshal struct {
	Stage string
	Err   error
}

// Error returns the error message.
func (e ErrASN1Marshal) Error() string {
	return fmt.Sprintf("modulesign: asn1 marshal %s: %v", e.Stage, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrASN1Marshal) Unwrap() error { return e.Err }

// ErrEnumerate indicates the module tree could not be walked.
type ErrEnumerate struct {
	Path string
	Err  error
}

// Error returns the error message.
func (e ErrEnumerate) Error() string {
	return fmt.Sprintf("modulesign: enumerate modules %s: %v", e.Path, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrEnumerate) Unwrap() error { return e.Err }
