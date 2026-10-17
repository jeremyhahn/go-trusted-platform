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

// TimestampError reports that the RFC 3161 time-stamp authority at URL could
// not countersign a signature: the request failed, the TSA refused it, or
// the token it returned does not match the signature it was asked to stamp.
type TimestampError struct {
	URL    string
	Reason string
	Err    error
}

// Error returns the error message.
func (e *TimestampError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("authenticode: timestamp from %s: %s: %v", e.URL, e.Reason, e.Err)
	}
	return fmt.Sprintf("authenticode: timestamp from %s: %s", e.URL, e.Reason)
}

// Unwrap returns the underlying error.
func (e *TimestampError) Unwrap() error {
	return e.Err
}

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

// Verification refusals. Each names the part of a signed image the
// verifier found out of profile; the detail travels in a WrappedError
// around the sentinel, so callers match with errors.Is.
var (
	// ErrCertificateHeader: the WIN_CERTIFICATE entry is not revision 2.0
	// PKCS#7 SignedData, or its dwLength does not frame the PKCS#7 inside
	// the certificate table entry (PE Format, "The Attribute Certificate
	// Table").
	ErrCertificateHeader = &MessageError{Msg: "authenticode: WIN_CERTIFICATE header out of profile"}

	// ErrContentType: the SignedData's content type, or the signed
	// content-type attribute, is not SPC_INDIRECT_DATA_OBJID (Authenticode
	// PE signedData; RFC 2315 §9.2 and RFC 5652 §11.1: the attribute is
	// present and equals the content type).
	ErrContentType = &MessageError{Msg: "authenticode: content type is not SpcIndirectDataContent"}

	// ErrDigestAlgorithm: a digest algorithm the signature names is not
	// the SHA-256 the verifier computes, or the SignedData's
	// digestAlgorithms do not list the signer's (RFC 2315 §9.1).
	ErrDigestAlgorithm = &MessageError{Msg: "authenticode: digest algorithm is not SHA-256"}

	// ErrSignerIdentifier: no embedded certificate carries the issuer and
	// serial number the SignerInfo names (RFC 2315 §9.2).
	ErrSignerIdentifier = &MessageError{Msg: "authenticode: no certificate matches the signer identifier"}
)
