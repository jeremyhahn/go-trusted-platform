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

package fido2

import "context"

// Service defines the operations exposed by the platform FIDO2 service.
//
// Implementations dispatch over whichever SDK transport the caller selected
// via the platform.Client; GRPCClient is the gRPC-backed implementation.
type Service interface {
	// ListDevices enumerates FIDO2 authenticators attached to the host.
	ListDevices(ctx context.Context, req *ListDevicesRequest) (*ListDevicesResponse, error)
	// WaitDevice blocks until a FIDO2 authenticator is detected.
	WaitDevice(ctx context.Context, req *WaitDeviceRequest) (*WaitDeviceResponse, error)
	// Info returns detailed info about a specific authenticator.
	Info(ctx context.Context, req *InfoRequest) (*InfoResponse, error)
	// Register performs a WebAuthn credential registration.
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)
	// Authenticate tests a WebAuthn authentication ceremony against a credential.
	Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthenticateResponse, error)
}
