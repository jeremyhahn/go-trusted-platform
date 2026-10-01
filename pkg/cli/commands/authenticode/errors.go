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

package authenticode

import "fmt"

// ErrDaemonConnectionRequired is returned when a command requires daemon connection
// but dual-mode is not yet implemented
type ErrDaemonConnectionRequired struct {
	Operation string
}

func (e ErrDaemonConnectionRequired) Error() string {
	return fmt.Sprintf("%s: daemon connection required (dual-mode not yet implemented)", e.Operation)
}

// ErrReadKeyFailed is returned when reading the signing key fails
type ErrReadKeyFailed struct {
	Path   string
	Reason string
}

func (e ErrReadKeyFailed) Error() string {
	return fmt.Sprintf("failed to read signing key '%s': %s", e.Path, e.Reason)
}

// ErrDecodeKeyFailed is returned when decoding the signing key PEM fails
type ErrDecodeKeyFailed struct {
	Path string
}

func (e ErrDecodeKeyFailed) Error() string {
	return fmt.Sprintf("failed to decode signing key PEM: %s", e.Path)
}

// ErrParseKeyFailed is returned when parsing the signing key fails
type ErrParseKeyFailed struct {
	Reason string
}

func (e ErrParseKeyFailed) Error() string {
	return fmt.Sprintf("failed to parse signing key: %s", e.Reason)
}

// ErrReadCertificateFailed is returned when reading the certificate fails
type ErrReadCertificateFailed struct {
	Path   string
	Reason string
}

func (e ErrReadCertificateFailed) Error() string {
	return fmt.Sprintf("failed to read certificate '%s': %s", e.Path, e.Reason)
}

// ErrParseCertificateFailed is returned when parsing the certificate fails
type ErrParseCertificateFailed struct {
	Reason string
}

func (e ErrParseCertificateFailed) Error() string {
	return fmt.Sprintf("failed to parse certificate: %s", e.Reason)
}

// ErrCreateSignerFailed is returned when creating the authenticode signer fails
type ErrCreateSignerFailed struct {
	Reason string
}

func (e ErrCreateSignerFailed) Error() string {
	return fmt.Sprintf("failed to create authenticode signer: %s", e.Reason)
}

// ErrSignFileFailed is returned when signing a file fails
type ErrSignFileFailed struct {
	Input  string
	Reason string
}

func (e ErrSignFileFailed) Error() string {
	return fmt.Sprintf("failed to sign file '%s': %s", e.Input, e.Reason)
}

// ErrVerifyFileFailed is returned when verifying a file fails
type ErrVerifyFileFailed struct {
	Input  string
	Reason string
}

func (e ErrVerifyFileFailed) Error() string {
	return fmt.Sprintf("failed to verify file '%s': %s", e.Input, e.Reason)
}
