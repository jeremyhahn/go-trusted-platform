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

// This file implements the BMCCommands interface using the MCP (Model Context Protocol).
// The BMC service is not yet wired to the MCP transport layer. Setup returns
// ErrMCPNotImplemented so the test runner can skip this adapter gracefully.

//go:build integration

package bmc_integration

import (
	"context"

	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// =============================================================================
// MCP Protocol Adapter
// =============================================================================

// MCPAdapter implements BMCCommands using the MCP (Model Context Protocol).
// The BMC service is not yet wired to the MCP transport layer; all methods
// return ErrMCPNotImplemented until the MCP tools are registered.
type MCPAdapter struct{}

// NewMCPAdapter creates a new MCP adapter for BMC integration testing.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup returns ErrMCPNotImplemented because the BMC service is not yet
// exposed over the MCP transport.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	return ErrMCPNotImplemented{}
}

// Teardown is a no-op.
func (m *MCPAdapter) Teardown() error {
	return nil
}

// PowerOn is not implemented for MCP.
func (m *MCPAdapter) PowerOn(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	return nil, ErrMCPNotImplemented{}
}

// PowerOff is not implemented for MCP.
func (m *MCPAdapter) PowerOff(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	return nil, ErrMCPNotImplemented{}
}

// PowerStatus is not implemented for MCP.
func (m *MCPAdapter) PowerStatus(ctx context.Context, profileID uint64) (bmcsvc.PowerState, error) {
	return bmcsvc.PowerStateUnspecified, ErrMCPNotImplemented{}
}

// SetBootDevice is not implemented for MCP.
func (m *MCPAdapter) SetBootDevice(ctx context.Context, profileID uint64, device bmcsvc.BootDevice, persistent bool) error {
	return ErrMCPNotImplemented{}
}

// GetBootDevice is not implemented for MCP.
func (m *MCPAdapter) GetBootDevice(ctx context.Context, profileID uint64) (bmcsvc.BootDevice, error) {
	return bmcsvc.BootDeviceUnspecified, ErrMCPNotImplemented{}
}

// MountISO is not implemented for MCP.
func (m *MCPAdapter) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	return ErrMCPNotImplemented{}
}

// UnmountISO is not implemented for MCP.
func (m *MCPAdapter) UnmountISO(ctx context.Context, profileID uint64) error {
	return ErrMCPNotImplemented{}
}

// VirtualMediaStatus is not implemented for MCP.
func (m *MCPAdapter) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcsvc.VirtualMediaInfo, error) {
	return nil, ErrMCPNotImplemented{}
}

// GetSensors is not implemented for MCP.
func (m *MCPAdapter) GetSensors(ctx context.Context, profileID uint64) ([]bmcsvc.SensorReading, error) {
	return nil, ErrMCPNotImplemented{}
}

// GetSystemInfo is not implemented for MCP.
func (m *MCPAdapter) GetSystemInfo(ctx context.Context, profileID uint64) (*bmcsvc.SystemInfo, error) {
	return nil, ErrMCPNotImplemented{}
}

// GetWebCertificate is not implemented for MCP.
func (m *MCPAdapter) GetWebCertificate(ctx context.Context, profileID uint64) (*bmcsvc.CertificateInfo, error) {
	return nil, ErrMCPNotImplemented{}
}

// ListUsers is not implemented for MCP.
func (m *MCPAdapter) ListUsers(ctx context.Context, profileID uint64) ([]bmcsvc.User, error) {
	return nil, ErrMCPNotImplemented{}
}

// Ensure MCPAdapter implements BMCCommands interface.
var _ BMCCommands = (*MCPAdapter)(nil)
