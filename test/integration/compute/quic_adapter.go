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

package compute_test

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// Error Types
// =============================================================================

// =============================================================================
// QUIC Adapter
// =============================================================================

// QUICAdapter implements ComputeCommands using the QUIC protocol.
// The QUIC compute wire protocol is not yet defined, so all methods return
// surface.ErrNoSurface, the typed declaration the suite skips on.
type QUICAdapter struct {
	endpoint string
}

// NewQUICAdapter creates a new QUIC adapter.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint: GetQUICEndpoint(),
	}
}

// Setup prepares the QUIC adapter for testing.
func (a *QUICAdapter) Setup(ctx context.Context) error {
	return nil
}

// Teardown cleans up after testing.
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name.
func (a *QUICAdapter) Name() string {
	return "QUIC"
}

// CreateVM is not implemented for the QUIC protocol.
func (a *QUICAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "CreateVM"}
}

// StartVM is not implemented for the QUIC protocol.
func (a *QUICAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "StartVM"}
}

// StopVM is not implemented for the QUIC protocol.
func (a *QUICAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "StopVM"}
}

// DeleteVM is not implemented for the QUIC protocol.
func (a *QUICAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "DeleteVM"}
}

// GetVM is not implemented for the QUIC protocol.
func (a *QUICAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "GetVM"}
}

// ListVMs is not implemented for the QUIC protocol.
func (a *QUICAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	return nil, surface.ErrNoSurface{Transport: "QUIC", Operation: "ListVMs"}
}
