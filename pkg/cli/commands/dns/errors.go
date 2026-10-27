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

package dns

import "strconv"

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error { return e.Err }

// ErrUnknownRecordType is returned for a --type the DNS service does not know.
type ErrUnknownRecordType struct {
	Type string
}

// Error implements the error interface.
func (e *ErrUnknownRecordType) Error() string {
	return "unknown DNS record type " + strconv.Quote(e.Type) +
		" (A, AAAA, CNAME, MX, NS, TXT, SRV, SOA, CAA, TLSA, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM)"
}

// ErrRecordTypeNotWritable is returned when a record of a type the service
// does not accept in AddRecord / UpdateRecord is written. SOA is set at zone
// creation; DNSSEC records are produced by signing.
type ErrRecordTypeNotWritable struct {
	Type string
}

// Error implements the error interface.
func (e *ErrRecordTypeNotWritable) Error() string {
	return "record type " + e.Type + " cannot be written directly (A, AAAA, CNAME, MX, NS, TXT, SRV, CAA, TLSA)"
}

// ErrFlagRequired is returned when a required flag is missing.
type ErrFlagRequired struct {
	Flag string
}

// Error implements the error interface.
func (e *ErrFlagRequired) Error() string {
	return "--" + e.Flag + " is required"
}

// ErrRecordNotFound is returned by record get when the zone holds no record
// of that type and name.
type ErrRecordNotFound struct {
	Zone string
	Type string
	Name string
}

// Error implements the error interface.
func (e *ErrRecordNotFound) Error() string {
	return "zone " + e.Zone + " has no " + e.Type + " record named " + strconv.Quote(e.Name)
}

// ErrRenderFailed is returned when a response cannot be converted for JSON or
// YAML output.
type ErrRenderFailed struct {
	Err error
}

// Error implements the error interface.
func (e *ErrRenderFailed) Error() string {
	return "failed to render DNS response: " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *ErrRenderFailed) Unwrap() error { return e.Err }
