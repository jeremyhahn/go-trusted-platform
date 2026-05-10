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

package kms

import "fmt"

// ErrServiceUnavailable indicates a backing SDK client was not provided.
type ErrServiceUnavailable struct {
	Service string
}

func (e *ErrServiceUnavailable) Error() string {
	return fmt.Sprintf("kms %s service is not available", e.Service)
}

// ErrInvalidRequest is returned when a request fails validation before
// it can be sent to the SDK.
type ErrInvalidRequest struct {
	Field  string
	Reason string
}

func (e *ErrInvalidRequest) Error() string {
	if e.Field == "" {
		return "invalid kms request: " + e.Reason
	}
	return fmt.Sprintf("invalid kms request: %s: %s", e.Field, e.Reason)
}

// ErrUnknownAlgorithm is returned when a string algorithm name cannot
// be mapped to an SDK constant.
type ErrUnknownAlgorithm struct {
	Algorithm string
}

func (e *ErrUnknownAlgorithm) Error() string {
	return fmt.Sprintf("unknown kms algorithm: %q", e.Algorithm)
}
