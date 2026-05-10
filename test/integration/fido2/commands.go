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

package fido2

import (
	"context"
	"fmt"

	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
)

// FIDO2Commands is the transport-agnostic contract every adapter implements.
type FIDO2Commands interface {
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	ListDevices(ctx context.Context, req *fido2sdk.ListDevicesRequest) (*fido2sdk.ListDevicesResponse, error)
	WaitDevice(ctx context.Context, req *fido2sdk.WaitDeviceRequest) (*fido2sdk.WaitDeviceResponse, error)
	Info(ctx context.Context, req *fido2sdk.InfoRequest) (*fido2sdk.InfoResponse, error)
	Register(ctx context.Context, req *fido2sdk.RegisterRequest) (*fido2sdk.RegisterResponse, error)
	Authenticate(ctx context.Context, req *fido2sdk.AuthenticateRequest) (*fido2sdk.AuthenticateResponse, error)
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
