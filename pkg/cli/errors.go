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

package cli

import "fmt"

// ErrConfigFileNotFound is returned when the config file cannot be found
type ErrConfigFileNotFound struct {
	Path string
}

func (e ErrConfigFileNotFound) Error() string {
	return fmt.Sprintf("config file not found: %s", e.Path)
}

// ErrConfigReadFailed is returned when reading the config file fails
type ErrConfigReadFailed struct {
	Path string
	Err  error
}

func (e ErrConfigReadFailed) Error() string {
	return fmt.Sprintf("failed to read config file: %s: %v", e.Path, e.Err)
}

func (e ErrConfigReadFailed) Unwrap() error {
	return e.Err
}

// ErrConfigParseFailed is returned when parsing the config file fails
type ErrConfigParseFailed struct {
	Path string
	Err  error
}

func (e ErrConfigParseFailed) Error() string {
	return fmt.Sprintf("failed to parse config file: %s: %v", e.Path, e.Err)
}

func (e ErrConfigParseFailed) Unwrap() error {
	return e.Err
}

// ErrConfigMarshalFailed is returned when marshaling the config fails
type ErrConfigMarshalFailed struct {
	Err error
}

func (e ErrConfigMarshalFailed) Error() string {
	return fmt.Sprintf("failed to marshal config: %v", e.Err)
}

func (e ErrConfigMarshalFailed) Unwrap() error {
	return e.Err
}

// ErrConfigWriteFailed is returned when writing the config file fails
type ErrConfigWriteFailed struct {
	Path string
	Err  error
}

func (e ErrConfigWriteFailed) Error() string {
	return fmt.Sprintf("failed to write config file: %s: %v", e.Path, e.Err)
}

func (e ErrConfigWriteFailed) Unwrap() error {
	return e.Err
}

// ErrConfigDirCreateFailed is returned when creating the config directory fails
type ErrConfigDirCreateFailed struct {
	Path string
	Err  error
}

func (e ErrConfigDirCreateFailed) Error() string {
	return fmt.Sprintf("failed to create config directory: %s: %v", e.Path, e.Err)
}

func (e ErrConfigDirCreateFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidContext is returned when an invalid context is specified
type ErrInvalidContext struct {
	Context string
}

func (e ErrInvalidContext) Error() string {
	return fmt.Sprintf("invalid context: %s", e.Context)
}

// ErrContextNotFound is returned when the specified context does not exist
type ErrContextNotFound struct {
	Context string
}

func (e ErrContextNotFound) Error() string {
	return fmt.Sprintf("context not found: %s", e.Context)
}

// ErrNoContextSet is returned when no context is currently set
type ErrNoContextSet struct{}

func (e ErrNoContextSet) Error() string {
	return "no context currently set"
}

// ErrInvalidOutputFormat is returned when an invalid output format is specified
type ErrInvalidOutputFormat struct {
	Format string
}

func (e ErrInvalidOutputFormat) Error() string {
	return fmt.Sprintf("invalid output format: %s (valid: table, json, yaml)", e.Format)
}

// ErrConnectionFailed is returned when connection to the platform fails
type ErrConnectionFailed struct {
	Target string
	Err    error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("failed to connect to %s: %v", e.Target, e.Err)
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrEmbeddedHostUnavailable is returned when a context uses the embedded
// transport and the command has no way to host platformd in-process.
type ErrEmbeddedHostUnavailable struct{}

func (e ErrEmbeddedHostUnavailable) Error() string {
	return "the embedded transport needs platformd hosted in this process, and this command cannot host it"
}

// ErrInvalidServiceType is returned when an invalid service type is specified
type ErrInvalidServiceType struct {
	Type string
}

func (e ErrInvalidServiceType) Error() string {
	return fmt.Sprintf("invalid service type: %s", e.Type)
}

// ErrOperationFailed is returned when an operation fails
type ErrOperationFailed struct {
	Operation string
	Err       error
}

func (e ErrOperationFailed) Error() string {
	return fmt.Sprintf("%s operation failed: %v", e.Operation, e.Err)
}

// ErrInsufficientPermissions is returned when the user lacks necessary permissions
type ErrInsufficientPermissions struct {
	Operation string
}

func (e ErrInsufficientPermissions) Error() string {
	return fmt.Sprintf("insufficient permissions for operation: %s", e.Operation)
}

// ErrAutoDetectionFailed is returned when context auto-detection fails
type ErrAutoDetectionFailed struct {
	Reason string
}

func (e ErrAutoDetectionFailed) Error() string {
	return fmt.Sprintf("failed to auto-detect context: %s", e.Reason)
}

// ErrInvalidShellType is returned when an invalid shell type is specified for completion
type ErrInvalidShellType struct {
	Shell string
}

func (e ErrInvalidShellType) Error() string {
	return fmt.Sprintf("invalid shell type: %s (valid: bash, zsh, fish, powershell)", e.Shell)
}

// ErrCompletionGenerationFailed is returned when completion script generation fails
type ErrCompletionGenerationFailed struct {
	Shell string
	Err   error
}

func (e ErrCompletionGenerationFailed) Error() string {
	return fmt.Sprintf("failed to generate %s completion script: %v", e.Shell, e.Err)
}

// ErrTLSCACertLoadFailed is returned when a CA certificate file cannot be read.
type ErrTLSCACertLoadFailed struct {
	Path string
	Err  error
}

func (e ErrTLSCACertLoadFailed) Error() string {
	return fmt.Sprintf("failed to load CA certificate %s: %v", e.Path, e.Err)
}

func (e ErrTLSCACertLoadFailed) Unwrap() error {
	return e.Err
}

// ErrTLSCACertInvalid is returned when a CA certificate file contains no valid PEM data.
type ErrTLSCACertInvalid struct {
	Path string
}

func (e ErrTLSCACertInvalid) Error() string {
	return fmt.Sprintf("CA certificate file contains no valid PEM data: %s", e.Path)
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
