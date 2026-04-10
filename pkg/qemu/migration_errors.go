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

package qemu

import "fmt"

// ErrMigrationFailed is returned when a migration operation fails.
type ErrMigrationFailed struct {
	URI   string
	Cause error
}

func (e ErrMigrationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("migration to %s failed: %v", e.URI, e.Cause)
	}
	return fmt.Sprintf("migration to %s failed", e.URI)
}

func (e ErrMigrationFailed) Unwrap() error {
	return e.Cause
}

// ErrMigrationCancelled is returned when a migration is cancelled.
type ErrMigrationCancelled struct {
	URI string
}

func (e ErrMigrationCancelled) Error() string {
	if e.URI != "" {
		return fmt.Sprintf("migration to %s was cancelled", e.URI)
	}
	return "migration was cancelled"
}

// ErrMigrationInProgress is returned when attempting to start a migration
// while another migration is already in progress.
type ErrMigrationInProgress struct{}

func (e ErrMigrationInProgress) Error() string {
	return "migration is already in progress"
}

// ErrMigrationNotActive is returned when attempting to cancel or query
// a migration when no migration is active.
type ErrMigrationNotActive struct{}

func (e ErrMigrationNotActive) Error() string {
	return "no migration is currently active"
}

// ErrMigrationInvalidURI is returned when the migration URI is invalid.
type ErrMigrationInvalidURI struct {
	URI   string
	Cause error
}

func (e ErrMigrationInvalidURI) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("invalid migration URI %q: %v", e.URI, e.Cause)
	}
	return fmt.Sprintf("invalid migration URI %q", e.URI)
}

func (e ErrMigrationInvalidURI) Unwrap() error {
	return e.Cause
}

// ErrMigrationTimeout is returned when a migration operation times out.
type ErrMigrationTimeout struct {
	URI     string
	Elapsed string
}

func (e ErrMigrationTimeout) Error() string {
	if e.Elapsed != "" {
		return fmt.Sprintf("migration to %s timed out after %s", e.URI, e.Elapsed)
	}
	return fmt.Sprintf("migration to %s timed out", e.URI)
}

// ErrMigrationSetupFailed is returned when migration setup fails.
type ErrMigrationSetupFailed struct {
	Operation string
	Cause     error
}

func (e ErrMigrationSetupFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("migration setup failed during %s: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("migration setup failed during %s", e.Operation)
}

func (e ErrMigrationSetupFailed) Unwrap() error {
	return e.Cause
}

// ErrMigrationCapabilityNotSupported is returned when a migration capability
// is not supported by the QEMU instance.
type ErrMigrationCapabilityNotSupported struct {
	Capability string
}

func (e ErrMigrationCapabilityNotSupported) Error() string {
	return fmt.Sprintf("migration capability %q is not supported", e.Capability)
}

// ErrMigrationParameterInvalid is returned when a migration parameter
// has an invalid value.
type ErrMigrationParameterInvalid struct {
	Parameter string
	Value     interface{}
	Cause     error
}

func (e ErrMigrationParameterInvalid) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("invalid migration parameter %s=%v: %v", e.Parameter, e.Value, e.Cause)
	}
	return fmt.Sprintf("invalid migration parameter %s=%v", e.Parameter, e.Value)
}

func (e ErrMigrationParameterInvalid) Unwrap() error {
	return e.Cause
}
