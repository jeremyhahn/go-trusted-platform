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

package tpm

import (
	"context"
	"time"
)

// TPMCommands defines the central command set for TPM integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements this interface.
// Tests are written once against this interface and run against all protocols.
type TPMCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// TPM Info Commands (platformctl tpm info)
	Info(ctx context.Context) (*InfoResult, error)

	// TPM Provision Commands (platformctl tpm provision)
	Provision(ctx context.Context, opts ProvisionOptions) (*ProvisionResult, error)

	// TPM Clear Commands (platformctl tpm clear)
	Clear(ctx context.Context, opts ClearOptions) (*ClearResult, error)

	// EK Commands (platformctl tpm ek ...)
	EKCreate(ctx context.Context, opts EKCreateOptions) (*EKCreateResult, error)
	EKInfo(ctx context.Context, handle uint32) (*EKInfoResult, error)
	EKCertificate(ctx context.Context) (*EKCertificateResult, error)
	EKDelete(ctx context.Context, handle uint32, password string) (*EKDeleteResult, error)

	// SRK Commands (platformctl tpm srk ...)
	SRKCreate(ctx context.Context, opts SRKCreateOptions) (*SRKCreateResult, error)
	SRKInfo(ctx context.Context, handle uint32) (*SRKInfoResult, error)
	SRKDelete(ctx context.Context, handle uint32, password string) (*SRKDeleteResult, error)

	// Seal/Unseal Commands (platformctl tpm seal/unseal)
	Seal(ctx context.Context, opts SealOptions) (*SealResult, error)
	Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error)

	// Event Log Commands (platformctl tpm eventlog)
	EventLog(ctx context.Context, path string) (*EventLogResult, error)
}

// =============================================================================
// TPM Info Types
// =============================================================================

// InfoResult contains the result of a TPM info operation.
type InfoResult struct {
	Version      string
	Manufacturer *ManufacturerInfo
	IsSimulator  bool
	FIPSMode     bool
	PCRBanks     []string
	MaxNVRAMSize uint32
}

// ManufacturerInfo contains TPM manufacturer details.
type ManufacturerInfo struct {
	Name            string
	ID              uint32
	Model           string
	FirmwareVersion string
}

// =============================================================================
// TPM Provision Types
// =============================================================================

// ProvisionOptions contains options for TPM provisioning.
type ProvisionOptions struct {
	CreateEK            bool
	CreateSRK           bool
	CreateAK            bool
	OwnerPassword       string
	EndorsementPassword string
}

// ProvisionResult contains the result of a TPM provision operation.
type ProvisionResult struct {
	Success    bool
	Message    string
	EKCreated  bool
	SRKCreated bool
	AKCreated  bool
}

// =============================================================================
// TPM Clear Types
// =============================================================================

// ClearOptions contains options for TPM clear operation.
type ClearOptions struct {
	OwnerPassword string
	Confirm       bool
}

// ClearResult contains the result of a TPM clear operation.
type ClearResult struct {
	Success bool
	Message string
}

// =============================================================================
// EK (Endorsement Key) Types
// =============================================================================

// EKCreateOptions contains options for creating an EK.
type EKCreateOptions struct {
	Algorithm  string
	Persistent bool
}

// EKCreateResult contains the result of an EK creation.
type EKCreateResult struct {
	Success   bool
	Handle    uint32
	Algorithm string
	PublicKey []byte
	CreatedAt time.Time
}

// EKInfoResult contains EK information.
type EKInfoResult struct {
	Handle    uint32
	Algorithm string
	PublicKey []byte
}

// EKCertificateResult contains the EK certificate.
type EKCertificateResult struct {
	Format      string
	Certificate []byte
}

// EKDeleteResult contains the result of an EK deletion.
type EKDeleteResult struct {
	Success bool
	Message string
}

// =============================================================================
// SRK (Storage Root Key) Types
// =============================================================================

// SRKCreateOptions contains options for creating an SRK.
type SRKCreateOptions struct {
	Algorithm  string
	Handle     uint32
	Password   string
	Persistent bool
	Policy     bool
}

// SRKCreateResult contains the result of an SRK creation.
type SRKCreateResult struct {
	Success   bool
	Handle    uint32
	Algorithm string
	PublicKey []byte
	CreatedAt time.Time
}

// SRKInfoResult contains SRK information.
type SRKInfoResult struct {
	Handle    uint32
	Algorithm string
	PublicKey []byte
}

// SRKDeleteResult contains the result of an SRK deletion.
type SRKDeleteResult struct {
	Success bool
	Message string
}

// =============================================================================
// Seal/Unseal Types
// =============================================================================

// SealOptions contains options for sealing data.
// PCR binding is not an option here because no transport request carries a
// policy field: `platformctl tpm seal --pcrs` is the only way to bind, and
// the suite exercises password auth on the SSRK-parented object instead.
type SealOptions struct {
	CN             string
	Data           []byte
	Password       string
	ParentPassword string
}

// SealResult contains the result of a seal operation.
type SealResult struct {
	Success bool
	Message string
}

// UnsealOptions contains options for unsealing data.
type UnsealOptions struct {
	CN             string
	Password       string
	ParentPassword string
}

// UnsealResult contains the result of an unseal operation.
type UnsealResult struct {
	Success bool
	Data    []byte
}

// =============================================================================
// Event Log Types
// =============================================================================

// EventLogResult contains the result of an event log read.
type EventLogResult struct {
	Events []EventLogEntry
}

// EventLogEntry contains a single event log entry.
type EventLogEntry struct {
	PCRIndex  uint32
	EventType uint32
	Digest    []byte
	EventData []byte
}
