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

// Package rest provides the REST transport adapter for the platform SDK.
package rest

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrHTTPStatus represents an HTTP error response.
type ErrHTTPStatus struct {
	StatusCode int
	Status     string
	Body       string
}

// Error implements the error interface.
func (e ErrHTTPStatus) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("HTTP %d %s: %s", e.StatusCode, e.Status, e.Body)
	}
	return fmt.Sprintf("HTTP %d %s", e.StatusCode, e.Status)
}

// ErrRequestFailed represents a request failure.
type ErrRequestFailed struct {
	Method string
	Path   string
	Err    error
}

// Error implements the error interface.
func (e ErrRequestFailed) Error() string {
	return fmt.Sprintf("request %s %s failed: %v", e.Method, e.Path, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrRequestFailed) Unwrap() error {
	return e.Err
}

// ErrMarshalFailed represents a JSON marshaling failure.
type ErrMarshalFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrMarshalFailed) Error() string {
	return fmt.Sprintf("failed to marshal request: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e ErrMarshalFailed) Unwrap() error {
	return e.Err
}

// ErrUnmarshalFailed represents a JSON unmarshaling failure.
type ErrUnmarshalFailed struct {
	Err error
}

// Error implements the error interface.
func (e ErrUnmarshalFailed) Error() string {
	return fmt.Sprintf("failed to unmarshal response: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e ErrUnmarshalFailed) Unwrap() error {
	return e.Err
}

// ErrClientClosed indicates the client has been closed.
type ErrClientClosed struct{}

// Error implements the error interface.
func (e ErrClientClosed) Error() string {
	return "REST client is closed"
}

// ErrNotImplemented indicates a method is not implemented for REST transport.
type ErrNotImplemented struct {
	Method string
}

// Error implements the error interface.
func (e ErrNotImplemented) Error() string {
	return fmt.Sprintf("method not implemented for REST transport: %s", e.Method)
}

// ErrNoRESTRoute is returned, before any request is built, for a gRPC method
// the platform deliberately serves no REST route for. Reason names where the
// operation is served instead. It carries codes.Unimplemented, the code the
// platform's gRPC and QUIC servers answer the same methods with, so
// status.Code(err) matches across transports while errors.As still finds it.
type ErrNoRESTRoute struct {
	Method string
	Reason string
}

// Error implements the error interface.
func (e ErrNoRESTRoute) Error() string {
	return fmt.Sprintf("REST transport has no route for %s: %s", e.Method, e.Reason)
}

// GRPCStatus reports the error as codes.Unimplemented to status.FromError.
func (e ErrNoRESTRoute) GRPCStatus() *status.Status {
	return status.New(codes.Unimplemented, e.Error())
}

// ErrUnexpectedReplyType indicates a custom REST response decoder received
// a reply message of an unexpected concrete type. This is a programming
// error in the adapter's method routing, not a wire failure.
type ErrUnexpectedReplyType struct {
	Method string
}

// Error implements the error interface.
func (e ErrUnexpectedReplyType) Error() string {
	return fmt.Sprintf("unexpected reply message type for gRPC method %s", e.Method)
}

// ErrUnexpectedRequestType indicates a custom REST request encoder received a
// request message of an unexpected concrete type. This is a programming error
// in the adapter's method routing, not a wire failure.
type ErrUnexpectedRequestType struct {
	Method string
}

// Error implements the error interface.
func (e ErrUnexpectedRequestType) Error() string {
	return fmt.Sprintf("unexpected request message type for gRPC method %s", e.Method)
}

// ErrSwitchActionNotAcknowledged indicates a switch port mutator answered
// with a status other than "ok", so the change was not acknowledged.
type ErrSwitchActionNotAcknowledged struct {
	Method string
	Status string
}

// Error implements the error interface.
func (e ErrSwitchActionNotAcknowledged) Error() string {
	return fmt.Sprintf("%s: switch answered status %q, not \"ok\"", e.Method, e.Status)
}

// ErrUnknownPortType indicates an SDN port type outside the pb PortType enum,
// which has no REST name to send.
type ErrUnknownPortType struct {
	Type int32
}

// Error implements the error interface.
func (e ErrUnknownPortType) Error() string {
	return fmt.Sprintf("unknown SDN port type %d", e.Type)
}

// ErrDurationClearNotSupported indicates an UpdateIPAMPool request asked to
// set a pool duration to zero. The REST pool update keeps any duration it
// is not given a positive value for, so the request cannot be carried.
type ErrDurationClearNotSupported struct {
	Field string
}

// Error implements the error interface.
func (e ErrDurationClearNotSupported) Error() string {
	return fmt.Sprintf("REST cannot set %s to zero: the REST pool update keeps a zero duration (send -1 to keep it)", e.Field)
}

// ErrProfileConfigNotJSON indicates a DeviceProfile's config bytes are not a
// JSON document. The REST profile routes carry config as a JSON value, so
// bytes that are not JSON cannot be sent without corrupting them.
type ErrProfileConfigNotJSON struct{}

// Error implements the error interface.
func (e ErrProfileConfigNotJSON) Error() string {
	return "device profile config is not valid JSON; the REST transport sends it as a JSON value"
}

// ErrHashAlgorithmNotSupported indicates a KMS Sign or Verify request names a
// hash the REST routes cannot carry. They accept SHA-256, SHA-384 and SHA-512
// only and read any other name as SHA-256, so sending it would sign with the
// wrong digest.
type ErrHashAlgorithmNotSupported struct {
	Algorithm string
}

// Error implements the error interface.
func (e ErrHashAlgorithmNotSupported) Error() string {
	return fmt.Sprintf("hash algorithm %s is not supported by the KMS REST routes (SHA-256, SHA-384 and SHA-512 only)", e.Algorithm)
}

// ErrKeyAlgorithmNotSupported indicates a KMS key-generation request names a
// key algorithm the REST route cannot carry: one GenerateKey's route does not
// mint, or a value outside the proto enum, which has no name to send.
type ErrKeyAlgorithmNotSupported struct {
	Algorithm string
}

// Error implements the error interface.
func (e ErrKeyAlgorithmNotSupported) Error() string {
	return fmt.Sprintf("key algorithm %s is not supported by the KMS REST routes", e.Algorithm)
}

// ErrKeyUsageNotSupported indicates a KMS GenerateKey request names a key
// usage the REST route does not accept (it takes ENCRYPT, DECRYPT, SIGN,
// VERIFY, WRAP and UNWRAP only).
type ErrKeyUsageNotSupported struct {
	Usage string
}

// Error implements the error interface.
func (e ErrKeyUsageNotSupported) Error() string {
	return fmt.Sprintf("key usage %s is not supported by the KMS REST routes", e.Usage)
}

// ErrWrappingAlgorithmNotSupported indicates a KMS GenerateWrappedDataKey
// request names a wrapping algorithm. The REST route takes none and wraps with
// the KEK's own algorithm, so sending the request would ignore the choice.
type ErrWrappingAlgorithmNotSupported struct {
	Algorithm string
}

// Error implements the error interface.
func (e ErrWrappingAlgorithmNotSupported) Error() string {
	return fmt.Sprintf("wrapping algorithm %s cannot be chosen over the KMS REST routes; the KEK's own algorithm applies", e.Algorithm)
}

// ErrPCRDigestNotHex indicates a profile's PCR baseline carried a digest
// that is not hex, the encoding the device webservice uses for it.
type ErrPCRDigestNotHex struct {
	Index string
	Err   error
}

// Error implements the error interface.
func (e ErrPCRDigestNotHex) Error() string {
	return fmt.Sprintf("PCR %s baseline digest is not hex: %v", e.Index, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrPCRDigestNotHex) Unwrap() error {
	return e.Err
}

// ErrDNSRecordTypeRequired indicates an AddRecord request carried no record
// type. The DNS REST route dispatches on the type, so a record without one
// cannot be added.
type ErrDNSRecordTypeRequired struct{}

// Error implements the error interface.
func (e ErrDNSRecordTypeRequired) Error() string {
	return "DNS record type is required"
}
