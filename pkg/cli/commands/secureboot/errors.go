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

package secureboot

import "fmt"

// ErrCertificateLoad indicates a Secure Boot certificate (PK, KEK, or DB)
// could not be loaded or parsed.
type ErrCertificateLoad struct {
	Role  string
	Path  string
	Cause error
}

func (e ErrCertificateLoad) Error() string {
	return fmt.Sprintf("secure-boot: failed to load %s certificate from %s: %v", e.Role, e.Path, e.Cause)
}

func (e ErrCertificateLoad) Unwrap() error { return e.Cause }

// ErrUKINotFound indicates the signed UKI required for verify-before-enforce
// does not exist at the expected path.
type ErrUKINotFound struct {
	Path string
}

func (e ErrUKINotFound) Error() string {
	return fmt.Sprintf("secure-boot: signed UKI not found at %s (use --uki to point at the signed unified kernel image)", e.Path)
}

// ErrEnforceIncomplete indicates key enrollment was committed but the
// firmware state read back afterwards does not reflect an enrolled Platform
// Key, so Secure Boot enforcement cannot be confirmed.
type ErrEnforceIncomplete struct {
	Reason string
}

func (e ErrEnforceIncomplete) Error() string {
	return "secure-boot: enforcement incomplete: " + e.Reason
}

// ErrNotPEMCertificate indicates a certificate file did not contain a PEM
// CERTIFICATE block.
type ErrNotPEMCertificate struct {
	Path string
}

func (e ErrNotPEMCertificate) Error() string {
	return "secure-boot: no PEM CERTIFICATE block found in " + e.Path
}
