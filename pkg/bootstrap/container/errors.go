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

package container

import "fmt"

// ErrManifestNotFound is returned when the manifest file does not exist.
type ErrManifestNotFound struct {
	Path string
}

func (e ErrManifestNotFound) Error() string {
	return fmt.Sprintf("container: manifest not found: %s", e.Path)
}

// ErrMACNotInManifest is returned when a MAC address is not found in the manifest.
type ErrMACNotInManifest struct {
	MAC string
}

func (e ErrMACNotInManifest) Error() string {
	return fmt.Sprintf("container: MAC %s not in manifest", e.MAC)
}

// ErrServerStartFailed is returned when the bootstrap server fails to start.
type ErrServerStartFailed struct {
	Cause error
}

func (e ErrServerStartFailed) Error() string {
	return fmt.Sprintf("container: server start failed: %v", e.Cause)
}

func (e ErrServerStartFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidServerConfig is returned when the server configuration is invalid.
type ErrInvalidServerConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidServerConfig) Error() string {
	return fmt.Sprintf("container: invalid config: field %s: %s", e.Field, e.Reason)
}

// ErrManifestWrite is returned when writing the manifest to disk fails.
type ErrManifestWrite struct {
	Path  string
	Cause error
}

func (e ErrManifestWrite) Error() string {
	return fmt.Sprintf("container: failed to write manifest to %s: %v", e.Path, e.Cause)
}

func (e ErrManifestWrite) Unwrap() error {
	return e.Cause
}

// ErrManifestRead is returned when reading the manifest from disk fails.
type ErrManifestRead struct {
	Path  string
	Cause error
}

func (e ErrManifestRead) Error() string {
	return fmt.Sprintf("container: failed to read manifest from %s: %v", e.Path, e.Cause)
}

func (e ErrManifestRead) Unwrap() error {
	return e.Cause
}

// ErrManifestParse is returned when parsing the manifest YAML fails.
type ErrManifestParse struct {
	Path  string
	Cause error
}

func (e ErrManifestParse) Error() string {
	return fmt.Sprintf("container: failed to parse manifest from %s: %v", e.Path, e.Cause)
}

func (e ErrManifestParse) Unwrap() error {
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
