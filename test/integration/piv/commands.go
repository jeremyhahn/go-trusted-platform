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

package piv

import (
	"context"
	"fmt"

	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
)

// PIVCommands is the transport-agnostic contract every adapter implements.
type PIVCommands interface {
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	ListDevices(ctx context.Context, req *pivsdk.ListDevicesRequest) (*pivsdk.ListDevicesResponse, error)
	ListSlots(ctx context.Context, req *pivsdk.ListSlotsRequest) (*pivsdk.ListSlotsResponse, error)
	SlotInfo(ctx context.Context, req *pivsdk.SlotInfoRequest) (*pivsdk.SlotInfoResponse, error)
	Generate(ctx context.Context, req *pivsdk.GenerateRequest) (*pivsdk.GenerateResponse, error)
	Import(ctx context.Context, req *pivsdk.ImportRequest) (*pivsdk.ImportResponse, error)
	Sign(ctx context.Context, req *pivsdk.SignRequest) (*pivsdk.SignResponse, error)
	Attest(ctx context.Context, req *pivsdk.AttestRequest) (*pivsdk.AttestResponse, error)
	Reset(ctx context.Context, req *pivsdk.ResetRequest) (*pivsdk.ResetResponse, error)
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
