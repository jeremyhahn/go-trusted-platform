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

package luks

import "context"

// Service defines the operations exposed by the platform LUKS2 volume service.
//
// GRPCClient implements it over a platform.v1.LUKSServiceClient, which
// platform.Client.LUKS() returns for whichever SDK transport the caller
// selected.
type Service interface {
	// Status returns the high-level state of a LUKS device.
	Status(ctx context.Context, req *StatusRequest) (*StatusResponse, error)
	// ListSlots lists the active keyslots on a device.
	ListSlots(ctx context.Context, req *ListSlotsRequest) (*ListSlotsResponse, error)
	// Info returns a detailed header dump for a device.
	Info(ctx context.Context, req *InfoRequest) (*InfoResponse, error)
	// EnrollPassphrase adds a passphrase keyslot to a device.
	EnrollPassphrase(ctx context.Context, req *EnrollPassphraseRequest) (*EnrollPassphraseResponse, error)
	// EnrollFIDO2 adds a FIDO2 keyslot to a device.
	EnrollFIDO2(ctx context.Context, req *EnrollFIDO2Request) (*EnrollFIDO2Response, error)
	// EnrollTPM adds a TPM2-sealed keyslot to a device.
	EnrollTPM(ctx context.Context, req *EnrollTPMRequest) (*EnrollTPMResponse, error)
	// EnrollRecovery adds a recovery-key keyslot to a device.
	EnrollRecovery(ctx context.Context, req *EnrollRecoveryRequest) (*EnrollRecoveryResponse, error)
	// RemoveKey removes an existing keyslot.
	RemoveKey(ctx context.Context, req *RemoveKeyRequest) (*RemoveKeyResponse, error)
	// TestUnlock verifies a keyslot can unlock a device without mounting it.
	TestUnlock(ctx context.Context, req *TestUnlockRequest) (*TestUnlockResponse, error)
	// ChangePassphrase replaces an existing passphrase slot with a new value.
	ChangePassphrase(ctx context.Context, req *ChangePassphraseRequest) (*ChangePassphraseResponse, error)
}
