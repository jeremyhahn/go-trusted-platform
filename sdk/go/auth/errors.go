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

package auth

import (
	"errors"
	"fmt"
)

// Sentinel errors for common conditions.
var (
	// ErrNoToken indicates that no token is available.
	ErrNoToken = errors.New("no authentication token available")

	// ErrNoRefreshCallback indicates that token refresh was requested but no callback is configured.
	ErrNoRefreshCallback = errors.New("no token refresh callback configured")

	// ErrNoCertificate indicates that no certificate is configured.
	ErrNoCertificate = errors.New("no certificate configured")

	// ErrNoPrivateKey indicates that no private key is configured.
	ErrNoPrivateKey = errors.New("no private key configured")
)

// ErrTokenExpired is returned when the authentication token has expired.
type ErrTokenExpired struct {
	ExpiredAt int64
}

// Error implements the error interface.
func (e ErrTokenExpired) Error() string {
	return fmt.Sprintf("authentication token expired at %d", e.ExpiredAt)
}

// ErrTokenRefreshFailed is returned when token refresh fails.
type ErrTokenRefreshFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrTokenRefreshFailed) Error() string {
	return fmt.Sprintf("token refresh failed: %v", e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrTokenRefreshFailed) Unwrap() error {
	return e.Err
}

// ErrCertificateLoadFailed is returned when loading a certificate fails.
type ErrCertificateLoadFailed struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e ErrCertificateLoadFailed) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("failed to load certificate from %s: %v", e.Path, e.Err)
	}
	return fmt.Sprintf("failed to load certificate: %v", e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrCertificateLoadFailed) Unwrap() error {
	return e.Err
}

// ErrKeyLoadFailed is returned when loading a private key fails.
type ErrKeyLoadFailed struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e ErrKeyLoadFailed) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("failed to load private key from %s: %v", e.Path, e.Err)
	}
	return fmt.Sprintf("failed to load private key: %v", e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrKeyLoadFailed) Unwrap() error {
	return e.Err
}

// ErrCALoadFailed is returned when loading a CA certificate fails.
type ErrCALoadFailed struct {
	Path string
	Err  error
}

// Error implements the error interface.
func (e ErrCALoadFailed) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("failed to load CA certificate from %s: %v", e.Path, e.Err)
	}
	return fmt.Sprintf("failed to load CA certificate: %v", e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrCALoadFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidToken is returned when a token is malformed or invalid.
type ErrInvalidToken struct {
	Reason string
}

// Error implements the error interface.
func (e ErrInvalidToken) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid token: %s", e.Reason)
	}
	return "invalid token"
}

// ErrInvalidCertificate is returned when a certificate is invalid.
type ErrInvalidCertificate struct {
	Reason string
}

// Error implements the error interface.
func (e ErrInvalidCertificate) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid certificate: %s", e.Reason)
	}
	return "invalid certificate"
}
