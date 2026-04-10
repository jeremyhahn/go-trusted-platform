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

package fido2

import (
	"context"
)

// FIDO2Commands defines the central command set for FIDO2 integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements this interface.
// Tests are written once against this interface and run against all protocols.
type FIDO2Commands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// List Commands (platformctl fido2 list)
	List(ctx context.Context, opts ListOptions) (*ListResult, error)

	// Info Commands (platformctl fido2 info)
	Info(ctx context.Context, opts InfoOptions) (*InfoResult, error)

	// Enroll Commands (platformctl fido2 enroll)
	Enroll(ctx context.Context, opts EnrollOptions) (*EnrollResult, error)

	// Remove Commands (platformctl fido2 remove)
	Remove(ctx context.Context, opts RemoveOptions) (*RemoveResult, error)

	// Test Commands (platformctl fido2 test)
	Test(ctx context.Context, opts TestOptions) (*TestResult, error)
}

// =============================================================================
// List Types
// =============================================================================

// ListOptions contains options for listing FIDO2 tokens.
type ListOptions struct {
	Device string
	Debug  bool
}

// ListResult contains the result of a FIDO2 list operation.
type ListResult struct {
	Tokens []FIDO2TokenInfo
	Device string
}

// FIDO2TokenInfo contains parsed FIDO2 token information.
type FIDO2TokenInfo struct {
	TokenID         string
	Type            string
	Keyslots        []string
	FIDO2Credential string
	FIDO2Salt       string
	FIDO2RP         string
	FIDO2UPRequired bool
}

// =============================================================================
// Info Types
// =============================================================================

// InfoOptions contains options for getting device information.
type InfoOptions struct {
	Device string
	Debug  bool
}

// InfoResult contains the result of a FIDO2 info operation.
type InfoResult struct {
	Device         string
	UUID           string
	Label          string
	Version        int
	Cipher         string
	KeySize        int
	SectorSize     int
	ActiveKeyslots []KeyslotInfo
	FIDO2Tokens    []FIDO2TokenInfo
	Segments       []SegmentInfo
}

// KeyslotInfo contains keyslot information.
type KeyslotInfo struct {
	SlotNumber int
	Type       string
	KeySize    int
	Priority   *int
	KDFType    string
	KDFHash    string
	Encryption string
}

// SegmentInfo contains data segment information.
type SegmentInfo struct {
	SegmentID  string
	Type       string
	Offset     string
	Size       string
	Encryption string
	SectorSize int
}

// =============================================================================
// Enroll Types
// =============================================================================

// EnrollOptions contains options for enrolling a FIDO2 credential.
type EnrollOptions struct {
	Device     string
	Passphrase string
	Slot       int
	RP         string
	User       string
	FIPS       bool
	Debug      bool
}

// EnrollResult contains the result of a FIDO2 enroll operation.
type EnrollResult struct {
	Success      bool
	Message      string
	Device       string
	Slot         int
	RelyingParty string
}

// =============================================================================
// Remove Types
// =============================================================================

// RemoveOptions contains options for removing a FIDO2 token.
type RemoveOptions struct {
	Device  string
	TokenID string
	Slot    int
	Force   bool
	Debug   bool
}

// RemoveResult contains the result of a FIDO2 remove operation.
type RemoveResult struct {
	Success        bool
	Message        string
	TokenIDRemoved string
	SlotRemoved    int
}

// =============================================================================
// Test Types
// =============================================================================

// TestOptions contains options for testing FIDO2 unlock.
type TestOptions struct {
	Device string
	Debug  bool
}

// TestResult contains the result of a FIDO2 test operation.
type TestResult struct {
	Success      bool
	Message      string
	TokenInfo    *FIDO2TokenInfo
	RelyingParty string
	Keyslots     []string
}
