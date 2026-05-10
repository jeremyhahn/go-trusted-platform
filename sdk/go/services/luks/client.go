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
// Implementations dispatch over whichever SDK transport the caller selected
// via the platform.Client. The Phase 3 default client (returned by NewClient)
// is a stub that returns ErrNotYetWired for every method until the server-side
// LUKS handlers land in Phase 3.5.
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

// Client is the default Service implementation.
//
// TODO: wire to platformd server-side LUKS handlers (Phase 3.5).
// Today every method returns ErrNotYetWired.
type Client struct{}

// NewClient constructs a Phase 3 stub LUKS client.
func NewClient() *Client {
	return &Client{}
}

// Status is the stubbed Status entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Status(_ context.Context, _ *StatusRequest) (*StatusResponse, error) {
	return nil, &ErrStatusFailed{Cause: ErrNotYetWired}
}

// ListSlots is the stubbed ListSlots entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) ListSlots(_ context.Context, _ *ListSlotsRequest) (*ListSlotsResponse, error) {
	return nil, &ErrListSlotsFailed{Cause: ErrNotYetWired}
}

// Info is the stubbed Info entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) Info(_ context.Context, _ *InfoRequest) (*InfoResponse, error) {
	return nil, &ErrInfoFailed{Cause: ErrNotYetWired}
}

// EnrollPassphrase is the stubbed EnrollPassphrase entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) EnrollPassphrase(_ context.Context, _ *EnrollPassphraseRequest) (*EnrollPassphraseResponse, error) {
	return nil, &ErrEnrollPassphraseFailed{Cause: ErrNotYetWired}
}

// EnrollFIDO2 is the stubbed EnrollFIDO2 entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) EnrollFIDO2(_ context.Context, _ *EnrollFIDO2Request) (*EnrollFIDO2Response, error) {
	return nil, &ErrEnrollFIDO2Failed{Cause: ErrNotYetWired}
}

// EnrollTPM is the stubbed EnrollTPM entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) EnrollTPM(_ context.Context, _ *EnrollTPMRequest) (*EnrollTPMResponse, error) {
	return nil, &ErrEnrollTPMFailed{Cause: ErrNotYetWired}
}

// EnrollRecovery is the stubbed EnrollRecovery entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) EnrollRecovery(_ context.Context, _ *EnrollRecoveryRequest) (*EnrollRecoveryResponse, error) {
	return nil, &ErrEnrollRecoveryFailed{Cause: ErrNotYetWired}
}

// RemoveKey is the stubbed RemoveKey entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) RemoveKey(_ context.Context, _ *RemoveKeyRequest) (*RemoveKeyResponse, error) {
	return nil, &ErrRemoveKeyFailed{Cause: ErrNotYetWired}
}

// TestUnlock is the stubbed TestUnlock entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) TestUnlock(_ context.Context, _ *TestUnlockRequest) (*TestUnlockResponse, error) {
	return nil, &ErrTestUnlockFailed{Cause: ErrNotYetWired}
}

// ChangePassphrase is the stubbed ChangePassphrase entrypoint.
// TODO: wire to platformd server-side handler (Phase 3.5).
func (c *Client) ChangePassphrase(_ context.Context, _ *ChangePassphraseRequest) (*ChangePassphraseResponse, error) {
	return nil, &ErrChangePassphraseFailed{Cause: ErrNotYetWired}
}

// Compile-time interface check.
var _ Service = (*Client)(nil)
