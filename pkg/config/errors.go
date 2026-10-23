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

package config

import "strconv"

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

// ErrInvalidConfigKey reports a key that is missing or invalid when the
// configuration is loaded, naming the file it was read from and the dotted
// key path, so the operator can fix the file without reading the source.
type ErrInvalidConfigKey struct {
	// File is the configuration file the key was read from.
	File string
	// Key is the dotted key path, e.g. "quicbaas.spiffe-trust-domain".
	Key string
	// Err is the validation failure.
	Err error
}

// Error implements the error interface.
func (e *ErrInvalidConfigKey) Error() string {
	msg := "config file " + strconv.Quote(e.File) + ": key " + e.Key
	if e.Err == nil {
		return msg + ": invalid"
	}
	return msg + ": " + e.Err.Error()
}

// Unwrap returns the validation failure.
func (e *ErrInvalidConfigKey) Unwrap() error {
	return e.Err
}
