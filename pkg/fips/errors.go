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

package fips

import "errors"

var (
	// ErrUnsupportedOS is returned when the OS is not supported for FIPS installation
	ErrUnsupportedOS = errors.New("unsupported operating system for FIPS installation")

	// ErrNotImplemented is returned when a FIPS installer is not yet implemented
	ErrNotImplemented = errors.New("FIPS installer not implemented for this OS")

	// ErrVerificationFailed is returned when FIPS verification fails
	ErrVerificationFailed = errors.New("FIPS verification failed")

	// ErrKernelNotFound is returned when the FIPS kernel cannot be found
	ErrKernelNotFound = errors.New("FIPS kernel not found")

	// ErrOpenSSLNotConfigured is returned when OpenSSL is not configured for FIPS
	ErrOpenSSLNotConfigured = errors.New("OpenSSL not configured for FIPS mode")
)
