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

package main

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

// FlagError reports a flag value pxeboot refuses at startup.
type FlagError struct {
	// Flag is the flag name without its dashes, e.g. "dhcp-dns".
	Flag string
	Err  error
}

// Error implements the error interface.
func (e *FlagError) Error() string {
	return "--" + e.Flag + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *FlagError) Unwrap() error {
	return e.Err
}
