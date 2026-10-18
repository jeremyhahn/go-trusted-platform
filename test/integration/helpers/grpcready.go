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

//go:build integration

package helpers

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// GRPCNotReadyError reports that a gRPC client connection did not reach the
// Ready state before its context ended.
type GRPCNotReadyError struct {
	// Target is the address the connection dials.
	Target string
	// State is the last connectivity state the connection reported.
	State connectivity.State
	// Err is the context error that ended the wait, or nil when the
	// connection was shut down.
	Err error
}

func (e *GRPCNotReadyError) Error() string {
	return fmt.Sprintf("gRPC connection to %s not ready (last state %s): %v", e.Target, e.State, e.Err)
}

// Unwrap exposes the context error to errors.Is/errors.As.
func (e *GRPCNotReadyError) Unwrap() error { return e.Err }

// WaitGRPCReady starts conn connecting and blocks until it is Ready or ctx
// ends. grpc.NewClient never dials on construction, so an adapter that must
// fail fast on an unreachable daemon calls this with a bounded context; it
// replaces the deprecated grpc.DialContext with grpc.WithBlock.
func WaitGRPCReady(ctx context.Context, conn *grpc.ClientConn) error {
	conn.Connect()
	for {
		state := conn.GetState()
		switch state {
		case connectivity.Ready:
			return nil
		case connectivity.Shutdown:
			return &GRPCNotReadyError{Target: conn.Target(), State: state}
		}
		if !conn.WaitForStateChange(ctx, state) {
			return &GRPCNotReadyError{Target: conn.Target(), State: state, Err: ctx.Err()}
		}
	}
}
