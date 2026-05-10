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

package piv

import "context"

// Service defines the operations exposed by the platform PIV service.
//
// Implementations dispatch over whichever SDK transport the caller selected
// via the platform.Client. The Phase 3 default client (returned by NewClient)
// is a stub that returns ErrNotYetWired for every method until the server-side
// PIV handlers land in Phase 3.5.
type Service interface {
	// ListDevices enumerates PIV devices attached to the host.
	ListDevices(ctx context.Context, req *ListDevicesRequest) (*ListDevicesResponse, error)
	// ListSlots lists the slots available on a device.
	ListSlots(ctx context.Context, req *ListSlotsRequest) (*ListSlotsResponse, error)
	// SlotInfo returns detailed information about a single slot.
	SlotInfo(ctx context.Context, req *SlotInfoRequest) (*SlotInfoResponse, error)
	// Generate asks the device to generate a fresh key in a slot.
	Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error)
	// Import imports an existing private key into a slot.
	Import(ctx context.Context, req *ImportRequest) (*ImportResponse, error)
	// Sign signs a payload with the key in the specified slot.
	Sign(ctx context.Context, req *SignRequest) (*SignResponse, error)
	// Attest returns the attestation certificate(s) for a slot.
	Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error)
	// Reset factory-resets a PIV device.
	Reset(ctx context.Context, req *ResetRequest) (*ResetResponse, error)
}

// Client is the default Service implementation.
//
// TODO: wire to platformd server-side PIV handlers (Phase 3.5).
// Today every method returns ErrNotYetWired.
type Client struct{}

// NewClient constructs a Phase 3 stub PIV client.
func NewClient() *Client {
	return &Client{}
}

// ListDevices is the stubbed ListDevices entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) ListDevices(_ context.Context, _ *ListDevicesRequest) (*ListDevicesResponse, error) {
	return nil, &ErrListDevicesFailed{Cause: ErrNotYetWired}
}

// ListSlots is the stubbed ListSlots entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) ListSlots(_ context.Context, _ *ListSlotsRequest) (*ListSlotsResponse, error) {
	return nil, &ErrListSlotsFailed{Cause: ErrNotYetWired}
}

// SlotInfo is the stubbed SlotInfo entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) SlotInfo(_ context.Context, _ *SlotInfoRequest) (*SlotInfoResponse, error) {
	return nil, &ErrSlotInfoFailed{Cause: ErrNotYetWired}
}

// Generate is the stubbed Generate entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Generate(_ context.Context, _ *GenerateRequest) (*GenerateResponse, error) {
	return nil, &ErrGenerateFailed{Cause: ErrNotYetWired}
}

// Import is the stubbed Import entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Import(_ context.Context, _ *ImportRequest) (*ImportResponse, error) {
	return nil, &ErrImportFailed{Cause: ErrNotYetWired}
}

// Sign is the stubbed Sign entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Sign(_ context.Context, _ *SignRequest) (*SignResponse, error) {
	return nil, &ErrSignFailed{Cause: ErrNotYetWired}
}

// Attest is the stubbed Attest entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Attest(_ context.Context, _ *AttestRequest) (*AttestResponse, error) {
	return nil, &ErrAttestFailed{Cause: ErrNotYetWired}
}

// Reset is the stubbed Reset entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Reset(_ context.Context, _ *ResetRequest) (*ResetResponse, error) {
	return nil, &ErrResetFailed{Cause: ErrNotYetWired}
}

// Compile-time interface check.
var _ Service = (*Client)(nil)
