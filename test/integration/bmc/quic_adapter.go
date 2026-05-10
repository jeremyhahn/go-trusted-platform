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

// This file implements the BMCCommands interface using the QUIC protocol.
// The BMC service is not yet wired to the QUIC transport layer. Setup returns
// ErrQUICNotImplemented so the test runner can skip this adapter gracefully.

//go:build integration

package bmc_integration

import (
	"context"

	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// =============================================================================
// QUIC Protocol Adapter
// =============================================================================

// QUICAdapter implements BMCCommands using the QUIC protocol.
// The BMC service is not yet wired to the QUIC transport layer; all methods
// return ErrQUICNotImplemented until the server-side opcodes are defined.
type QUICAdapter struct{}

// NewQUICAdapter creates a new QUIC adapter for BMC integration testing.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{}
}

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup returns ErrQUICNotImplemented because the BMC service is not yet
// exposed over the QUIC transport.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	return ErrQUICNotImplemented{}
}

// Teardown is a no-op.
func (q *QUICAdapter) Teardown() error {
	return nil
}

// PowerOn is not implemented for QUIC.
func (q *QUICAdapter) PowerOn(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	return nil, ErrQUICNotImplemented{}
}

// PowerOff is not implemented for QUIC.
func (q *QUICAdapter) PowerOff(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	return nil, ErrQUICNotImplemented{}
}

// PowerStatus is not implemented for QUIC.
func (q *QUICAdapter) PowerStatus(ctx context.Context, profileID uint64) (bmcsvc.PowerState, error) {
	return bmcsvc.PowerStateUnspecified, ErrQUICNotImplemented{}
}

// SetBootDevice is not implemented for QUIC.
func (q *QUICAdapter) SetBootDevice(ctx context.Context, profileID uint64, device bmcsvc.BootDevice, persistent bool) error {
	return ErrQUICNotImplemented{}
}

// GetBootDevice is not implemented for QUIC.
func (q *QUICAdapter) GetBootDevice(ctx context.Context, profileID uint64) (bmcsvc.BootDevice, error) {
	return bmcsvc.BootDeviceUnspecified, ErrQUICNotImplemented{}
}

// MountISO is not implemented for QUIC.
func (q *QUICAdapter) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	return ErrQUICNotImplemented{}
}

// UnmountISO is not implemented for QUIC.
func (q *QUICAdapter) UnmountISO(ctx context.Context, profileID uint64) error {
	return ErrQUICNotImplemented{}
}

// VirtualMediaStatus is not implemented for QUIC.
func (q *QUICAdapter) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcsvc.VirtualMediaInfo, error) {
	return nil, ErrQUICNotImplemented{}
}

// GetSensors is not implemented for QUIC.
func (q *QUICAdapter) GetSensors(ctx context.Context, profileID uint64) ([]bmcsvc.SensorReading, error) {
	return nil, ErrQUICNotImplemented{}
}

// GetSystemInfo is not implemented for QUIC.
func (q *QUICAdapter) GetSystemInfo(ctx context.Context, profileID uint64) (*bmcsvc.SystemInfo, error) {
	return nil, ErrQUICNotImplemented{}
}

// GetWebCertificate is not implemented for QUIC.
func (q *QUICAdapter) GetWebCertificate(ctx context.Context, profileID uint64) (*bmcsvc.CertificateInfo, error) {
	return nil, ErrQUICNotImplemented{}
}

// ListUsers is not implemented for QUIC.
func (q *QUICAdapter) ListUsers(ctx context.Context, profileID uint64) ([]bmcsvc.User, error) {
	return nil, ErrQUICNotImplemented{}
}

// Ensure QUICAdapter implements BMCCommands interface.
var _ BMCCommands = (*QUICAdapter)(nil)
