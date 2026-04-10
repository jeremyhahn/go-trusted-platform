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

// Package compute_test provides multi-protocol integration tests for the
// Compute (VM lifecycle) service.
package compute_test

import "context"

// ComputeCommands defines the interface for VM operations across all protocols.
type ComputeCommands interface {
	// Setup prepares the adapter for testing.
	Setup(ctx context.Context) error

	// Teardown cleans up after testing.
	Teardown(ctx context.Context) error

	// Name returns the adapter name.
	Name() string

	// CreateVM creates a new virtual machine.
	CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error)

	// StartVM starts a stopped virtual machine.
	StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error)

	// StopVM stops a running virtual machine.
	StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error)

	// DeleteVM deletes a virtual machine.
	DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error)

	// GetVM retrieves a virtual machine by ID.
	GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error)

	// ListVMs lists virtual machines with optional filtering.
	ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error)
}

// =============================================================================
// Option Types
// =============================================================================

// CreateVMOptions contains parameters for creating a virtual machine.
type CreateVMOptions struct {
	Name       string
	CPUs       uint32
	MemoryMB   uint64
	DiskSizeGB uint64
	Firmware   string // "bios", "uefi", "uefi-secure-boot"
	SecureBoot bool
	TPM        bool
	Start      bool
	Labels     map[string]string
}

// StartVMOptions contains parameters for starting a virtual machine.
type StartVMOptions struct {
	VMID string
}

// StopVMOptions contains parameters for stopping a virtual machine.
type StopVMOptions struct {
	VMID           string
	Force          bool
	TimeoutSeconds uint32
}

// DeleteVMOptions contains parameters for deleting a virtual machine.
type DeleteVMOptions struct {
	VMID        string
	Force       bool
	DeleteDisks bool
}

// GetVMOptions contains parameters for retrieving a virtual machine.
type GetVMOptions struct {
	VMID string
}

// ListVMsOptions contains parameters for listing virtual machines.
type ListVMsOptions struct {
	Labels      map[string]string
	StateFilter string
	PageSize    uint32
}

// =============================================================================
// Result Types
// =============================================================================

// CreateVMResult contains the result of creating a virtual machine.
type CreateVMResult struct {
	VMID    string
	Name    string
	State   string
	Success bool
	Labels  map[string]string
}

// StartVMResult contains the result of starting a virtual machine.
type StartVMResult struct {
	Success bool
	Message string
}

// StopVMResult contains the result of stopping a virtual machine.
type StopVMResult struct {
	Success bool
	Message string
}

// DeleteVMResult contains the result of deleting a virtual machine.
type DeleteVMResult struct {
	Success bool
	Message string
}

// GetVMResult contains the result of retrieving a virtual machine.
type GetVMResult struct {
	VMID     string
	Name     string
	State    string
	CPUs     uint32
	MemoryMB uint64
	Labels   map[string]string
}

// ListVMsResult contains the result of listing virtual machines.
type ListVMsResult struct {
	VMs        []VMSummary
	TotalItems uint64
}

// VMSummary contains summary information about a virtual machine.
type VMSummary struct {
	VMID   string
	Name   string
	State  string
	Labels map[string]string
}
