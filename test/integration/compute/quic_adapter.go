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
	"fmt"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrQUICNotImplemented indicates a compute method is not yet implemented
// for the QUIC wire protocol.
type ErrQUICNotImplemented struct {
	Method string
}

func (e ErrQUICNotImplemented) Error() string {
	return fmt.Sprintf("compute: QUIC method %s not implemented", e.Method)
}

// =============================================================================
// QUIC Adapter
// =============================================================================

// QUICAdapter implements ComputeCommands using the QUIC protocol.
// The QUIC compute wire protocol is not yet defined, so all methods return
// ErrQUICNotImplemented to allow the test runner to skip cleanly.
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
	return nil, ErrQUICNotImplemented{Method: "CreateVM"}
}

// StartVM is not implemented for the QUIC protocol.
func (a *QUICAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	return nil, ErrQUICNotImplemented{Method: "StartVM"}
}

// StopVM is not implemented for the QUIC protocol.
func (a *QUICAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	return nil, ErrQUICNotImplemented{Method: "StopVM"}
}

// DeleteVM is not implemented for the QUIC protocol.
func (a *QUICAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	return nil, ErrQUICNotImplemented{Method: "DeleteVM"}
}

// GetVM is not implemented for the QUIC protocol.
func (a *QUICAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	return nil, ErrQUICNotImplemented{Method: "GetVM"}
}

// ListVMs is not implemented for the QUIC protocol.
func (a *QUICAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	return nil, ErrQUICNotImplemented{Method: "ListVMs"}
}
