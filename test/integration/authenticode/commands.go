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

package authenticode

import (
	"context"
	"time"
)

// AuthenticodeCommands defines the central command set for Authenticode integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements this interface.
// Tests are written once against this interface and run against all protocols.
type AuthenticodeCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Sign Commands (platformctl authenticode sign)
	Sign(ctx context.Context, opts SignOptions) (*SignResult, error)

	// Verify Commands (platformctl authenticode verify)
	Verify(ctx context.Context, opts VerifyOptions) (*VerifyResult, error)
}

// =============================================================================
// Sign Types
// =============================================================================

// SignOptions contains options for signing a PE/COFF file.
type SignOptions struct {
	// KeyPath is the path to the signing private key (PEM format)
	KeyPath string
	// CertPath is the path to the signing certificate (PEM format)
	CertPath string
	// Input is the path to the input PE/COFF file to sign
	Input string
	// Output is the path to the output signed file
	Output string
}

// SignResult contains the result of a sign operation.
type SignResult struct {
	Success   bool
	Message   string
	Input     string
	Output    string
	SignedAt  time.Time
	Algorithm string
}

// =============================================================================
// Verify Types
// =============================================================================

// VerifyOptions contains options for verifying a PE/COFF file signature.
type VerifyOptions struct {
	// Input is the path to the signed PE/COFF file to verify
	Input string
	// CertPath is the optional path to a certificate for trust verification
	CertPath string
}

// VerifyResult contains the result of a verify operation.
type VerifyResult struct {
	Verified      bool
	Message       string
	Input         string
	Certificate   string
	SignerSubject string
	SignedAt      time.Time
}
