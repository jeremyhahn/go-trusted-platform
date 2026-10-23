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
// via the platform.Client; GRPCClient is the gRPC-backed implementation.
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
