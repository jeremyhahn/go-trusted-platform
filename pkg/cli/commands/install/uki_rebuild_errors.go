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

package install

import "fmt"

// ErrUKIRebuildConfigNotFound is returned when no platform config can be located
// to resolve the Secure Boot resign-mode for the UKI rebuild.
type ErrUKIRebuildConfigNotFound struct {
	Path string
}

func (e ErrUKIRebuildConfigNotFound) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("uki-rebuild: config not found at %s (and no /etc/platformd/config.yaml or /etc/platformd/install.yaml)", e.Path)
	}
	return "uki-rebuild: no platform config found (looked for /etc/platformd/config.yaml and /etc/platformd/install.yaml)"
}

// ErrRemoteSignerSetup is returned when the platform SDK client needed for
// remote DB hash-signing cannot be constructed.
type ErrRemoteSignerSetup struct {
	Err error
}

func (e ErrRemoteSignerSetup) Error() string {
	return fmt.Sprintf("uki-rebuild: failed to set up remote DB signer over the platform SDK client: %v", e.Err)
}

func (e ErrRemoteSignerSetup) Unwrap() error { return e.Err }

// ErrRemoteCertEmpty is returned when the platform CA returns no certificate for
// the requested DB key identifier during remote hash-signing.
type ErrRemoteCertEmpty struct {
	KeyID string
}

func (e ErrRemoteCertEmpty) Error() string {
	return fmt.Sprintf("uki-rebuild: platform CA returned no certificate for DB key %q", e.KeyID)
}

// ErrCABundleRead is returned when the CA bundle used to verify the control
// plane's TLS certificate cannot be read.
type ErrCABundleRead struct {
	Path string
	Err  error
}

func (e ErrCABundleRead) Error() string {
	return fmt.Sprintf("install: failed to read CA bundle %s: %v", e.Path, e.Err)
}

func (e ErrCABundleRead) Unwrap() error { return e.Err }

// ErrCABundleParse is returned when the CA bundle contains no usable PEM
// certificates.
type ErrCABundleParse struct {
	Path string
}

func (e ErrCABundleParse) Error() string {
	return fmt.Sprintf("install: CA bundle %s contained no PEM certificates", e.Path)
}

// ErrEKCertRead is returned when the TPM EK certificate file cannot be read.
type ErrEKCertRead struct {
	Path string
	Err  error
}

func (e ErrEKCertRead) Error() string {
	return fmt.Sprintf("install: failed to read EK certificate %s: %v", e.Path, e.Err)
}

func (e ErrEKCertRead) Unwrap() error { return e.Err }

// ErrEKCertParse is returned when the TPM EK certificate file does not parse as
// an X.509 certificate.
type ErrEKCertParse struct {
	Path string
	Err  error
}

func (e ErrEKCertParse) Error() string {
	return fmt.Sprintf("install: EK certificate %s did not parse: %v", e.Path, e.Err)
}

func (e ErrEKCertParse) Unwrap() error { return e.Err }

// ErrRemoteSignKeyRef is returned when the Secure Boot DB key URI does not yield
// a usable KMS key identifier for post-install remote re-signing.
type ErrRemoteSignKeyRef struct {
	KeyURI string
}

func (e ErrRemoteSignKeyRef) Error() string {
	return fmt.Sprintf("uki-rebuild: secure-boot db key-uri %q is not a usable kms:// reference", e.KeyURI)
}

// ErrRemoteCertDecode is returned when the DB certificate fetched from the CA
// cannot be PEM-decoded or parsed during post-install remote re-signing.
type ErrRemoteCertDecode struct {
	KeyID string
	Err   error
}

func (e ErrRemoteCertDecode) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("uki-rebuild: DB certificate for key %q did not decode: %v", e.KeyID, e.Err)
	}
	return fmt.Sprintf("uki-rebuild: DB certificate for key %q did not decode", e.KeyID)
}

func (e ErrRemoteCertDecode) Unwrap() error { return e.Err }

// ErrUnsupportedHash is returned when the Authenticode signer requests a hash
// the platform KMS Sign RPC does not map to a HashAlgorithm.
type ErrUnsupportedHash struct {
	Hash string
}

func (e ErrUnsupportedHash) Error() string {
	return fmt.Sprintf("uki-rebuild: unsupported hash %q for remote KMS signing (want SHA-256/384/512)", e.Hash)
}

// ErrRemoteSignFailed is returned when the platform KMS Sign RPC fails during
// post-install remote re-signing.
type ErrRemoteSignFailed struct {
	KeyID string
	Err   error
}

func (e ErrRemoteSignFailed) Error() string {
	return fmt.Sprintf("uki-rebuild: KMS sign with DB key %q failed: %v", e.KeyID, e.Err)
}

func (e ErrRemoteSignFailed) Unwrap() error { return e.Err }

// ErrRemoteSignEmpty is returned when the platform KMS Sign RPC returns an empty
// signature during post-install remote re-signing.
type ErrRemoteSignEmpty struct {
	KeyID string
}

func (e ErrRemoteSignEmpty) Error() string {
	return fmt.Sprintf("uki-rebuild: KMS returned an empty signature for DB key %q", e.KeyID)
}
