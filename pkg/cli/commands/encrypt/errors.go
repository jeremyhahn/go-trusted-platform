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

package encrypt

import "fmt"

// ErrValueOrFileRequired is returned when neither --value nor --file is provided.
type ErrValueOrFileRequired struct{}

func (e ErrValueOrFileRequired) Error() string {
	return "encrypt: either --value or --file is required"
}

// ErrValueAndFileMutuallyExclusive is returned when both --value and --file
// are provided.
type ErrValueAndFileMutuallyExclusive struct{}

func (e ErrValueAndFileMutuallyExclusive) Error() string {
	return "encrypt: --value and --file are mutually exclusive"
}

// ErrReadSecretFile is returned when the secret file cannot be read.
type ErrReadSecretFile struct {
	Path  string
	Cause error
}

func (e ErrReadSecretFile) Error() string {
	return fmt.Sprintf("encrypt: failed to read secret file %s: %s", e.Path, e.Cause.Error())
}

func (e ErrReadSecretFile) Unwrap() error {
	return e.Cause
}

// ErrEncryptionFailed is returned when the KMS encryption operation fails.
type ErrEncryptionFailed struct {
	Cause error
}

func (e ErrEncryptionFailed) Error() string {
	return fmt.Sprintf("encrypt: encryption failed: %s", e.Cause.Error())
}

func (e ErrEncryptionFailed) Unwrap() error {
	return e.Cause
}

// ErrConnectionFailed is returned when connecting to the platform daemon fails.
type ErrConnectionFailed struct {
	Cause error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("encrypt: failed to connect to platform daemon: %s", e.Cause.Error())
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Cause
}
