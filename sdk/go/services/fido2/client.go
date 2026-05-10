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
// via the platform.Client. The Phase 3 default client (returned by NewClient)
// is a stub that returns ErrNotYetWired for every method until the server-side
// FIDO2 handlers land in Phase 3.5.
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

// Client is the default Service implementation.
//
// TODO: wire to platformd server-side FIDO2 handlers (Phase 3.5).
// Today every method returns ErrNotYetWired.
type Client struct{}

// NewClient constructs a Phase 3 stub FIDO2 client.
func NewClient() *Client {
	return &Client{}
}

// ListDevices is the stubbed ListDevices entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) ListDevices(_ context.Context, _ *ListDevicesRequest) (*ListDevicesResponse, error) {
	return nil, &ErrListDevicesFailed{Cause: ErrNotYetWired}
}

// WaitDevice is the stubbed WaitDevice entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) WaitDevice(_ context.Context, _ *WaitDeviceRequest) (*WaitDeviceResponse, error) {
	return nil, &ErrWaitDeviceFailed{Cause: ErrNotYetWired}
}

// Info is the stubbed Info entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Info(_ context.Context, _ *InfoRequest) (*InfoResponse, error) {
	return nil, &ErrDeviceInfoFailed{Cause: ErrNotYetWired}
}

// Register is the stubbed Register entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Register(_ context.Context, _ *RegisterRequest) (*RegisterResponse, error) {
	return nil, &ErrRegisterFailed{Cause: ErrNotYetWired}
}

// Authenticate is the stubbed Authenticate entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Authenticate(_ context.Context, _ *AuthenticateRequest) (*AuthenticateResponse, error) {
	return nil, &ErrAuthenticateFailed{Cause: ErrNotYetWired}
}

// Compile-time interface check.
var _ Service = (*Client)(nil)
