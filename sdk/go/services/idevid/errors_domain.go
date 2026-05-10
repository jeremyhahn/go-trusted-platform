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

package idevid

import "fmt"

// ErrStatusMessage wraps a status error message from the server.
type ErrStatusMessage struct {
	Message string
}

func (e *ErrStatusMessage) Error() string {
	return e.Message
}

// ErrInvalidAlgorithm is returned when an algorithm string is not recognized.
type ErrInvalidAlgorithm struct {
	Algorithm string
}

func (e *ErrInvalidAlgorithm) Error() string {
	return fmt.Sprintf("invalid algorithm: %s", e.Algorithm)
}

// ErrIDevIDNotFound is returned when the IDevID key is not found.
type ErrIDevIDNotFound struct{}

func (e *ErrIDevIDNotFound) Error() string {
	return "IDevID key not found"
}

// ErrIDevIDCertificateNotFound is returned when the IDevID certificate is not found.
type ErrIDevIDCertificateNotFound struct{}

func (e *ErrIDevIDCertificateNotFound) Error() string {
	return "IDevID certificate not found"
}

// ErrIAKNotFound is returned when the IAK key is not found.
type ErrIAKNotFound struct{}

func (e *ErrIAKNotFound) Error() string {
	return "IAK key not found"
}

// ErrIAKCertificateNotFound is returned when the IAK certificate is not found.
type ErrIAKCertificateNotFound struct{}

func (e *ErrIAKCertificateNotFound) Error() string {
	return "IAK certificate not found"
}
