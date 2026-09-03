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

package bootstrap

import (
	"fmt"
	"time"
)

// ErrConfigPathRequired is returned when no configuration path is provided
type ErrConfigPathRequired struct{}

func (e ErrConfigPathRequired) Error() string {
	return "configuration file path is required (use --config flag)"
}

// ErrConfigFileReadFailed is returned when the configuration file cannot be read
type ErrConfigFileReadFailed struct {
	Path string
	Err  error
}

func (e ErrConfigFileReadFailed) Error() string {
	return fmt.Sprintf("failed to read configuration file %s: %v", e.Path, e.Err)
}

func (e ErrConfigFileReadFailed) Unwrap() error {
	return e.Err
}

// ErrConfigParseFailed is returned when the configuration file cannot be parsed
type ErrConfigParseFailed struct {
	Path string
	Err  error
}

func (e ErrConfigParseFailed) Error() string {
	return fmt.Sprintf("failed to parse configuration file %s: %v", e.Path, e.Err)
}

func (e ErrConfigParseFailed) Unwrap() error {
	return e.Err
}

// ErrSecretURIRequired is returned when no secret URI is provided
type ErrSecretURIRequired struct{}

func (e ErrSecretURIRequired) Error() string {
	return "secret URI is required"
}

// ErrInvalidSecretURI is returned when a secret URI format is invalid
type ErrInvalidSecretURI struct {
	URI    string
	Reason string
}

func (e ErrInvalidSecretURI) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid secret URI %q: %s", e.URI, e.Reason)
	}
	return fmt.Sprintf("invalid secret URI: %q", e.URI)
}

// ErrSecretResolutionFailed is returned when a secret cannot be resolved
type ErrSecretResolutionFailed struct {
	URI string
	Err error
}

func (e ErrSecretResolutionFailed) Error() string {
	return fmt.Sprintf("failed to resolve secret %s: %v", e.URI, e.Err)
}

func (e ErrSecretResolutionFailed) Unwrap() error {
	return e.Err
}

// ErrMigrationFailed is returned when secret migration fails
type ErrMigrationFailed struct {
	Err error
}

func (e ErrMigrationFailed) Error() string {
	return fmt.Sprintf("secret migration failed: %v", e.Err)
}

func (e ErrMigrationFailed) Unwrap() error {
	return e.Err
}

// ErrNoSecretsFound is returned when no secrets are found in the configuration
type ErrNoSecretsFound struct {
	Path string
}

func (e ErrNoSecretsFound) Error() string {
	return fmt.Sprintf("no secret URIs found in configuration: %s", e.Path)
}

// ErrSecretVerificationFailed is returned when secret verification fails
type ErrSecretVerificationFailed struct {
	FailedCount int
	TotalCount  int
}

func (e ErrSecretVerificationFailed) Error() string {
	return fmt.Sprintf("secret verification failed: %d of %d secrets could not be resolved", e.FailedCount, e.TotalCount)
}

// ErrBackupCreationFailed is returned when backup creation fails
type ErrBackupCreationFailed struct {
	Path string
	Err  error
}

func (e ErrBackupCreationFailed) Error() string {
	return fmt.Sprintf("failed to create backup of %s: %v", e.Path, e.Err)
}

func (e ErrBackupCreationFailed) Unwrap() error {
	return e.Err
}

// ErrConfigUpdateFailed is returned when configuration update fails
type ErrConfigUpdateFailed struct {
	Path string
	Err  error
}

func (e ErrConfigUpdateFailed) Error() string {
	return fmt.Sprintf("failed to update configuration %s: %v", e.Path, e.Err)
}

func (e ErrConfigUpdateFailed) Unwrap() error {
	return e.Err
}

// ErrResolverNotAvailable is returned when a required resolver is not available
type ErrResolverNotAvailable struct {
	Scheme string
}

func (e ErrResolverNotAvailable) Error() string {
	return fmt.Sprintf("resolver not available for scheme: %s", e.Scheme)
}

// ErrKMSClientRequired is returned when the KMS client is not initialized
type ErrKMSClientRequired struct{}

func (e ErrKMSClientRequired) Error() string {
	return "KMS client is required for this operation"
}

// ErrSecretsNotImplemented is returned when the secrets service is not yet implemented
type ErrSecretsNotImplemented struct{}

func (e ErrSecretsNotImplemented) Error() string {
	return "secrets service is not yet implemented in the platform KMS; use env:// for environment variables or kms://...?ensure=true for persistent auto-generation"
}

// ErrEnvVarNotSet is returned when an environment variable is not set
type ErrEnvVarNotSet struct {
	Name string
}

func (e ErrEnvVarNotSet) Error() string {
	return fmt.Sprintf("environment variable not set: %s", e.Name)
}

// ErrFileReadFailed is returned when reading a file fails
type ErrFileReadFailed struct {
	Path string
	Err  error
}

func (e ErrFileReadFailed) Error() string {
	return fmt.Sprintf("failed to read file %s: %v", e.Path, e.Err)
}

func (e ErrFileReadFailed) Unwrap() error {
	return e.Err
}

// ErrAlreadyKMSManaged is returned when a secret is already KMS-managed
type ErrAlreadyKMSManaged struct {
	Path string
}

func (e ErrAlreadyKMSManaged) Error() string {
	return fmt.Sprintf("secret is already KMS-managed: %s", e.Path)
}

// ErrKMSStoreFailed is returned when storing a secret in KMS fails
type ErrKMSStoreFailed struct {
	Path string
	Err  error
}

func (e ErrKMSStoreFailed) Error() string {
	return fmt.Sprintf("failed to store secret in KMS at path %s: %v", e.Path, e.Err)
}

func (e ErrKMSStoreFailed) Unwrap() error {
	return e.Err
}

// ErrKMSEncryptFailed is returned when encrypting with KMS fails
type ErrKMSEncryptFailed struct {
	KeyID string
	Err   error
}

func (e ErrKMSEncryptFailed) Error() string {
	return fmt.Sprintf("failed to encrypt with KMS key %s: %v", e.KeyID, e.Err)
}

func (e ErrKMSEncryptFailed) Unwrap() error {
	return e.Err
}

// Trust bootstrap errors

// ErrTrustServerURLRequired is returned when the server URL is not provided to the trust command.
type ErrTrustServerURLRequired struct{}

func (e ErrTrustServerURLRequired) Error() string {
	return "bootstrap trust: --server-url is required"
}

// ErrTrustBootstrapFailed is returned when the trust bootstrap operation fails.
type ErrTrustBootstrapFailed struct {
	Cause error
}

func (e ErrTrustBootstrapFailed) Error() string {
	return fmt.Sprintf("bootstrap trust: failed: %v", e.Cause)
}

func (e ErrTrustBootstrapFailed) Unwrap() error {
	return e.Cause
}

// ErrTrustInstallFailed is returned when installing the CA bundle to the system trust store fails.
type ErrTrustInstallFailed struct {
	Path  string
	Cause error
}

func (e ErrTrustInstallFailed) Error() string {
	return fmt.Sprintf("bootstrap trust: failed to install CA bundle to %s: %v", e.Path, e.Cause)
}

func (e ErrTrustInstallFailed) Unwrap() error {
	return e.Cause
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

// ErrBootstrapShutdownStuck reports that the orchestrator did not return after
// its context was cancelled and the shutdown grace period elapsed. A goroutine
// dump precedes it on stderr (#135). This is a distinct, named failure rather
// than a generic timeout so the operator is told which condition they hit and
// where the diagnosis went.
type ErrBootstrapShutdownStuck struct {
	Grace time.Duration
}

func (e ErrBootstrapShutdownStuck) Error() string {
	return fmt.Sprintf(
		"bootstrap: orchestrator did not shut down within %s of cancellation; goroutine dump written to stderr (#135)",
		e.Grace)
}
