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

package ntp

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error { return e.Err }

// ntpClient is the subset of the SDK time-synchronization client the CLI
// commands use. It is satisfied by *ntpsvc.Client and by test fakes.
type ntpClient interface {
	// Status returns the node's synchronization state.
	Status(ctx context.Context) (*platformv1.NTPStatus, error)

	// Sources returns the configured time sources.
	Sources(ctx context.Context) ([]*platformv1.NTPSource, error)

	// Step forces an immediate clock correction.
	Step(ctx context.Context) (*platformv1.NTPStatus, error)
}
