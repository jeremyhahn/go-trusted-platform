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

import "strconv"

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

// KMSKeyRefError is a key URI that names no KMS key.
type KMSKeyRefError struct {
	KeyURI string
}

func (e *KMSKeyRefError) Error() string {
	return "secureboot: key-uri " + strconv.Quote(e.KeyURI) + " is not a usable kms:// reference"
}

// KMSPublicKeyError is a KMS-held key signer built without the key's
// public key.
type KMSPublicKeyError struct {
	KeyID string
}

func (e *KMSPublicKeyError) Error() string {
	return "secureboot: no public key for KMS key " + strconv.Quote(e.KeyID)
}

// KMSCertificateError is a KMS-held key's certificate that could not be
// fetched from the platform CA or parsed.
type KMSCertificateError struct {
	Ref string
	Err error
}

func (e *KMSCertificateError) Error() string {
	return "secureboot: certificate " + strconv.Quote(e.Ref) + ": " + e.Err.Error()
}

func (e *KMSCertificateError) Unwrap() error { return e.Err }

// CertPinError is a certificate whose SHA-256 fingerprint is not the one its
// reference was pinned to: the CA holds a different certificate under it.
type CertPinError struct {
	Ref  string
	Want string
	Got  string
}

func (e *CertPinError) Error() string {
	return "secureboot: certificate " + strconv.Quote(e.Ref) + " has SHA-256 fingerprint " + e.Got +
		", but it is pinned to " + e.Want
}

// CertPinFormatError is a cert-uri whose #sha256= pin is not a reference
// followed by a 32-byte hex SHA-256 fingerprint.
type CertPinFormatError struct {
	CertURI string
}

func (e *CertPinFormatError) Error() string {
	return "secureboot: cert-uri " + strconv.Quote(e.CertURI) +
		" must be <kms://ref>#sha256=<SHA-256 fingerprint of the certificate, in hex>"
}

// KMSSignError is a KMS Sign call that failed or returned no signature.
type KMSSignError struct {
	KeyID string
	Err   error
}

func (e *KMSSignError) Error() string {
	return "secureboot: KMS sign with key " + strconv.Quote(e.KeyID) + ": " + e.Err.Error()
}

func (e *KMSSignError) Unwrap() error { return e.Err }

// UnsupportedHashError is a digest hash the KMS Sign call cannot carry.
type UnsupportedHashError struct {
	Hash string
}

func (e *UnsupportedHashError) Error() string {
	return "secureboot: unsupported hash " + strconv.Quote(e.Hash) + " for KMS signing (want SHA-256/384/512)"
}
