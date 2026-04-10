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

package events

// ErrNilBuilder is returned when a method is called on a nil builder.
type ErrNilBuilder struct{}

func (e ErrNilBuilder) Error() string {
	return "enrollment event builder is nil"
}

// ErrNilLogger is returned when a nil logger is provided.
type ErrNilLogger struct{}

func (e ErrNilLogger) Error() string {
	return "audit logger cannot be nil"
}

// ErrEmptyDeviceID is returned when an empty device ID is provided.
type ErrEmptyDeviceID struct{}

func (e ErrEmptyDeviceID) Error() string {
	return "device ID cannot be empty"
}

// ErrNilVerificationResult is returned when a nil verification result is provided.
type ErrNilVerificationResult struct{}

func (e ErrNilVerificationResult) Error() string {
	return "verification result cannot be nil"
}
