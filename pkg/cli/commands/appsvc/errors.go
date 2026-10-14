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

package appsvc

// WrappedError wraps an underlying error with a message naming the command
// that failed.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *WrappedError) Unwrap() error { return e.Err }

// ErrInvalidFlag reports a flag value the command cannot turn into a request
// field.
type ErrInvalidFlag struct {
	Flag  string
	Value string
	Want  string
}

// Error implements the error interface.
func (e ErrInvalidFlag) Error() string {
	return "invalid --" + e.Flag + " " + quote(e.Value) + ": want " + e.Want
}

// quote wraps a flag value in double quotes for an error message.
func quote(value string) string {
	return "\"" + value + "\""
}
