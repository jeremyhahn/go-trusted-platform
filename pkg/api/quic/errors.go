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

package quic

import (
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Sentinel errors for QUIC operations
var (
	ErrServerNotRunning = errors.New("server is not running")
	ErrServerRunning    = errors.New("server is already running")
)

// CA sentinel errors
var (
	ErrCANotInitialized       = errors.New("certificate authority not initialized")
	ErrCAMissingCommonName    = errors.New("common name is required")
	ErrCAMissingSerial        = errors.New("serial number is required")
	ErrCAMissingCertificate   = errors.New("certificate (PEM or DER) is required")
	ErrCAInvalidPEM           = errors.New("failed to decode PEM certificate")
	ErrCAInvalidExtendDays    = errors.New("extend_days must be positive")
	ErrCACRLNotSupported      = errors.New("CRL generation not supported")
	ErrCABundleNotFound       = errors.New("CA bundle not found")
	ErrCACertStoreUnavailable = errors.New("certificate store not available")
)

// ErrTLSConfigGeneration represents a TLS configuration generation failure
type ErrTLSConfigGeneration struct {
	Reason string
	Err    error
}

func (e ErrTLSConfigGeneration) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("TLS config generation failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("TLS config generation failed: %s", e.Reason)
}

func (e ErrTLSConfigGeneration) Unwrap() error {
	return e.Err
}

// ErrCAInvalidAlgorithm represents an invalid key algorithm error
type ErrCAInvalidAlgorithm struct {
	Algorithm string
}

func (e ErrCAInvalidAlgorithm) Error() string {
	return fmt.Sprintf("invalid key algorithm: %s", e.Algorithm)
}

// ErrCACertNotFound represents a certificate not found error
type ErrCACertNotFound struct {
	Serial string
}

func (e ErrCACertNotFound) Error() string {
	return fmt.Sprintf("certificate not found: %s", e.Serial)
}

// ErrCAEncodingFailed represents an encoding failure error
type ErrCAEncodingFailed struct {
	Cause error
}

func (e ErrCAEncodingFailed) Error() string {
	return fmt.Sprintf("failed to encode payload: %v", e.Cause)
}

func (e ErrCAEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrCADecodingFailed represents a decoding failure error
type ErrCADecodingFailed struct {
	Cause error
}

func (e ErrCADecodingFailed) Error() string {
	return fmt.Sprintf("failed to decode payload: %v", e.Cause)
}

func (e ErrCADecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrCAIssueFailed represents a certificate issuance failure
type ErrCAIssueFailed struct {
	Cause error
}

func (e ErrCAIssueFailed) Error() string {
	return fmt.Sprintf("failed to issue certificate: %v", e.Cause)
}

func (e ErrCAIssueFailed) Unwrap() error {
	return e.Cause
}

// ErrCARevokeFailed represents a certificate revocation failure
type ErrCARevokeFailed struct {
	Cause error
}

func (e ErrCARevokeFailed) Error() string {
	return fmt.Sprintf("failed to revoke certificate: %v", e.Cause)
}

func (e ErrCARevokeFailed) Unwrap() error {
	return e.Cause
}

// ErrCARenewFailed represents a certificate renewal failure
type ErrCARenewFailed struct {
	Cause error
}

func (e ErrCARenewFailed) Error() string {
	return fmt.Sprintf("failed to renew certificate: %v", e.Cause)
}

func (e ErrCARenewFailed) Unwrap() error {
	return e.Cause
}

// ErrCAParseFailed represents a certificate parsing failure
type ErrCAParseFailed struct {
	Cause error
}

func (e ErrCAParseFailed) Error() string {
	return fmt.Sprintf("failed to parse certificate: %v", e.Cause)
}

func (e ErrCAParseFailed) Unwrap() error {
	return e.Cause
}

// ErrCACRLFailed represents a CRL generation failure
type ErrCACRLFailed struct {
	Cause error
}

func (e ErrCACRLFailed) Error() string {
	return fmt.Sprintf("failed to generate CRL: %v", e.Cause)
}

func (e ErrCACRLFailed) Unwrap() error {
	return e.Cause
}

// ErrCACRLParseFailed represents a CRL parsing failure
type ErrCACRLParseFailed struct {
	Cause error
}

func (e ErrCACRLParseFailed) Error() string {
	return fmt.Sprintf("failed to parse CRL: %v", e.Cause)
}

func (e ErrCACRLParseFailed) Unwrap() error {
	return e.Cause
}

// ErrCABundleFailed represents a CA bundle retrieval failure
type ErrCABundleFailed struct {
	Cause error
}

func (e ErrCABundleFailed) Error() string {
	return fmt.Sprintf("failed to get CA bundle: %v", e.Cause)
}

func (e ErrCABundleFailed) Unwrap() error {
	return e.Cause
}

// ErrorToStatus converts an error to a status code
func ErrorToStatus(err error) byte {
	if err == nil {
		return quicwire.StatusOK
	}

	var protoErr *quicwire.ErrProtocol
	if errors.As(err, &protoErr) {
		return protoErr.Status
	}

	// Map common errors to status codes
	switch {
	case errors.Is(err, quicwire.ErrNilRequest), errors.Is(err, quicwire.ErrNilResponse):
		return quicwire.StatusInvalidRequest
	case errors.Is(err, quicwire.ErrPayloadTooLarge), errors.Is(err, quicwire.ErrTokenTooLarge):
		return quicwire.StatusInvalidArgument
	case errors.Is(err, quicwire.ErrClientClosed), errors.Is(err, ErrServerNotRunning):
		return quicwire.StatusUnavailable
	case errors.Is(err, ErrCANotInitialized), errors.Is(err, ErrCACertStoreUnavailable):
		return quicwire.StatusUnavailable
	case errors.Is(err, ErrCAMissingCommonName), errors.Is(err, ErrCAMissingSerial),
		errors.Is(err, ErrCAMissingCertificate), errors.Is(err, ErrCAInvalidPEM),
		errors.Is(err, ErrCAInvalidExtendDays):
		return quicwire.StatusInvalidArgument
	case errors.Is(err, ErrCACRLNotSupported):
		return quicwire.StatusNotImplemented
	case errors.Is(err, ErrCABundleNotFound):
		return quicwire.StatusNotFound
	default:
		return quicwire.StatusInternalError
	}
}

// IsNotFound checks if the error represents a "not found" condition
func IsNotFound(err error) bool {
	var protoErr *quicwire.ErrProtocol
	if errors.As(err, &protoErr) {
		return protoErr.Status == quicwire.StatusNotFound
	}
	var certNotFound ErrCACertNotFound
	if errors.As(err, &certNotFound) {
		return true
	}
	return errors.Is(err, ErrCABundleNotFound)
}

// IsUnauthorized checks if the error represents an authorization failure
func IsUnauthorized(err error) bool {
	var protoErr *quicwire.ErrProtocol
	if errors.As(err, &protoErr) {
		return protoErr.Status == quicwire.StatusUnauthorized
	}
	return false
}

// IsUnavailable checks if the error represents service unavailability
func IsUnavailable(err error) bool {
	var protoErr *quicwire.ErrProtocol
	if errors.As(err, &protoErr) {
		return protoErr.Status == quicwire.StatusUnavailable
	}
	return errors.Is(err, ErrServerNotRunning) || errors.Is(err, quicwire.ErrClientClosed) ||
		errors.Is(err, ErrCANotInitialized) || errors.Is(err, ErrCACertStoreUnavailable)
}

// IsCAError checks if the error is a CA-related error
func IsCAError(err error) bool {
	switch {
	case errors.Is(err, ErrCANotInitialized),
		errors.Is(err, ErrCAMissingCommonName),
		errors.Is(err, ErrCAMissingSerial),
		errors.Is(err, ErrCAMissingCertificate),
		errors.Is(err, ErrCAInvalidPEM),
		errors.Is(err, ErrCAInvalidExtendDays),
		errors.Is(err, ErrCACRLNotSupported),
		errors.Is(err, ErrCABundleNotFound),
		errors.Is(err, ErrCACertStoreUnavailable):
		return true
	}

	var invalidAlg ErrCAInvalidAlgorithm
	if errors.As(err, &invalidAlg) {
		return true
	}

	var certNotFound ErrCACertNotFound
	if errors.As(err, &certNotFound) {
		return true
	}

	var encodingFailed ErrCAEncodingFailed
	if errors.As(err, &encodingFailed) {
		return true
	}

	var decodingFailed ErrCADecodingFailed
	if errors.As(err, &decodingFailed) {
		return true
	}

	var issueFailed ErrCAIssueFailed
	if errors.As(err, &issueFailed) {
		return true
	}

	var revokeFailed ErrCARevokeFailed
	if errors.As(err, &revokeFailed) {
		return true
	}

	var renewFailed ErrCARenewFailed
	if errors.As(err, &renewFailed) {
		return true
	}

	var parseFailed ErrCAParseFailed
	if errors.As(err, &parseFailed) {
		return true
	}

	var crlFailed ErrCACRLFailed
	if errors.As(err, &crlFailed) {
		return true
	}

	var crlParseFailed ErrCACRLParseFailed
	if errors.As(err, &crlParseFailed) {
		return true
	}

	var bundleFailed ErrCABundleFailed
	return errors.As(err, &bundleFailed)
}
