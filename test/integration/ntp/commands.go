// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration

package ntp

import (
	"context"
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// NTPCommands is the transport-agnostic surface every adapter (CLI plus the
// five SDK transports) implements, so the multi-protocol test body runs
// unchanged against each protocol.
type NTPCommands interface {
	// Name identifies the transport under test.
	Name() string

	// Setup connects the adapter to the running platformd.
	Setup(ctx context.Context) error

	// Teardown releases the adapter's resources.
	Teardown() error

	// Status returns the node's synchronization state.
	Status(ctx context.Context) (*platformv1.NTPStatus, error)

	// Sources returns the configured time sources.
	Sources(ctx context.Context) ([]*platformv1.NTPSource, error)

	// Step forces an immediate clock correction.
	Step(ctx context.Context) (*platformv1.NTPStatus, error)
}

// ErrConnectionFailed indicates the adapter could not connect to platformd.
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

// Error implements the error interface.
func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection to %s failed: %v", e.Protocol, e.Endpoint, e.Err)
}

// Unwrap returns the underlying dial failure.
func (e ErrConnectionFailed) Unwrap() error { return e.Err }

// ErrCLICommandFailed indicates a platformctl invocation failed.
type ErrCLICommandFailed struct {
	Args   []string
	Output string
	Err    error
}

// Error implements the error interface.
func (e ErrCLICommandFailed) Error() string {
	return fmt.Sprintf("platformctl %v failed: %v (output: %s)", e.Args, e.Err, e.Output)
}

// Unwrap returns the underlying exec failure.
func (e ErrCLICommandFailed) Unwrap() error { return e.Err }

// ErrCLIDecodeFailed indicates platformctl JSON output could not be parsed.
type ErrCLIDecodeFailed struct {
	Args   []string
	Output string
	Err    error
}

// Error implements the error interface.
func (e ErrCLIDecodeFailed) Error() string {
	return fmt.Sprintf("decoding platformctl %v output failed: %v (output: %s)", e.Args, e.Err, e.Output)
}

// Unwrap returns the underlying decode failure.
func (e ErrCLIDecodeFailed) Unwrap() error { return e.Err }
