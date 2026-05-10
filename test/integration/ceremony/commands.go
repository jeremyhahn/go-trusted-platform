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

package ceremony

import (
	"context"
	"fmt"

	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

// CeremonyCommands is the transport-agnostic surface every adapter implements.
//
// All six adapters (CLI, REST, gRPC, QUIC, MCP, Unix) share the same method
// set so the multi-protocol test body can run against each transport without
// re-writing assertions.
type CeremonyCommands interface {
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	Init(ctx context.Context, req *ceremonysdk.InitRequest) (*ceremonysdk.InitResponse, error)
	Status(ctx context.Context) (*ceremonysdk.StatusResponse, error)
	ClaimCertBegin(ctx context.Context, req *ceremonysdk.ClaimCertBeginRequest) (*ceremonysdk.ClaimCertBeginResponse, error)
	ClaimCertComplete(ctx context.Context, req *ceremonysdk.ClaimCertCompleteRequest) (*ceremonysdk.ClaimCertCompleteResponse, error)
	ClaimShare(ctx context.Context, req *ceremonysdk.ClaimShareRequest) (*ceremonysdk.ClaimShareResponse, error)
	SignCSR(ctx context.Context, req *ceremonysdk.SignCSRRequest) (*ceremonysdk.SignCSRResponse, error)
}

// ErrConnectionFailed indicates the adapter could not connect to platformd.
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection to %s failed: %v", e.Protocol, e.Endpoint, e.Err)
}

func (e ErrConnectionFailed) Unwrap() error { return e.Err }

// ErrCallFailed indicates a protocol call failed.
type ErrCallFailed struct {
	Protocol string
	Method   string
	Err      error
}

func (e ErrCallFailed) Error() string {
	return fmt.Sprintf("%s call %s failed: %v", e.Protocol, e.Method, e.Err)
}

func (e ErrCallFailed) Unwrap() error { return e.Err }

// ErrNotImplemented indicates the transport has not wired a given operation.
type ErrNotImplemented struct {
	Protocol string
	Method   string
}

func (e ErrNotImplemented) Error() string {
	return fmt.Sprintf("%s: %s not implemented", e.Protocol, e.Method)
}

// ErrTransportNotAvailable indicates the transport endpoint is disabled for
// this integration run (for example REST Phase 3.5 routes are not yet wired).
type ErrTransportNotAvailable struct {
	Protocol string
	Reason   string
}

func (e ErrTransportNotAvailable) Error() string {
	return fmt.Sprintf("%s transport not available: %s", e.Protocol, e.Reason)
}
