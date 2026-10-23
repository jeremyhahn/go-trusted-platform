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

// DetailError appends detail text directly after the underlying cause.
type DetailError struct {
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *DetailError) Error() string {
	return e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *DetailError) Unwrap() error {
	return e.Err
}

// CleanupError reports a failure together with the failure of the cleanup
// that followed it, so the leftover state the cleanup was meant to remove is
// reported instead of hidden. errors.Is and errors.As match either error.
type CleanupError struct {
	Err     error
	Cleanup error
}

// Error implements the error interface.
func (e *CleanupError) Error() string {
	return e.Err.Error() + " (cleanup failed: " + e.Cleanup.Error() + ")"
}

// Unwrap returns both the original failure and the cleanup failure.
func (e *CleanupError) Unwrap() []error {
	return []error{e.Err, e.Cleanup}
}

// ZoneError reports an operation that failed on one zone. Op is the verb
// ("sign", "save"), so the message reads "failed to sign zone example.com.".
type ZoneError struct {
	Op   string
	Zone string
	Err  error
}

// Error renders the operation, the zone and the cause.
func (e *ZoneError) Error() string {
	return "failed to " + e.Op + " zone " + e.Zone + ": " + e.Err.Error()
}

// Unwrap returns the cause.
func (e *ZoneError) Unwrap() error {
	return e.Err
}

// RecordError reports a record operation that failed on one owner name. Op is
// the verb ("add", "find"), so the message reads
// "failed to add SRV record _sip._tcp.example.com.: ...".
type RecordError struct {
	Op   string
	Type string
	Name string
	Err  error
}

// Error renders the operation, the record type, the owner name and the cause.
func (e *RecordError) Error() string {
	return "failed to " + e.Op + " " + e.Type + " record " + e.Name + ": " + e.Err.Error()
}

// Unwrap returns the cause.
func (e *RecordError) Unwrap() error {
	return e.Err
}
