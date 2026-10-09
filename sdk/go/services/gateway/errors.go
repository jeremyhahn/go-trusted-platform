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

package gateway

import "fmt"

// Gateway Errors

type ErrGetStatusFailed struct {
	Cause error
}

func (e *ErrGetStatusFailed) Error() string {
	return fmt.Sprintf("failed to get gateway status: %v", e.Cause)
}

func (e *ErrGetStatusFailed) Unwrap() error { return e.Cause }

// ErrGetSnapshotFailed reports a telemetry snapshot read that failed.
type ErrGetSnapshotFailed struct {
	GatewayID string
	Cause     error
}

func (e *ErrGetSnapshotFailed) Error() string {
	if e.GatewayID == "" {
		return fmt.Sprintf("failed to get the gateway snapshot: %v", e.Cause)
	}
	return fmt.Sprintf("failed to get the snapshot for gateway %s: %v", e.GatewayID, e.Cause)
}

func (e *ErrGetSnapshotFailed) Unwrap() error { return e.Cause }

// ErrListSnapshotsFailed reports a telemetry snapshot listing that failed.
type ErrListSnapshotsFailed struct {
	Cause error
}

func (e *ErrListSnapshotsFailed) Error() string {
	return fmt.Sprintf("failed to list gateway snapshots: %v", e.Cause)
}

func (e *ErrListSnapshotsFailed) Unwrap() error { return e.Cause }

type ErrGetAdmittedVTEPFailed struct {
	GatewayID string
	VTEP      string
	Cause     error
}

func (e *ErrGetAdmittedVTEPFailed) Error() string {
	return fmt.Sprintf("failed to get gateway %q admitted VTEP %q: %v", e.GatewayID, e.VTEP, e.Cause)
}

func (e *ErrGetAdmittedVTEPFailed) Unwrap() error { return e.Cause }

type ErrListAdmittedVTEPsFailed struct {
	GatewayID string
	Cause     error
}

func (e *ErrListAdmittedVTEPsFailed) Error() string {
	return fmt.Sprintf("failed to list gateway %q admitted VTEPs: %v", e.GatewayID, e.Cause)
}

func (e *ErrListAdmittedVTEPsFailed) Unwrap() error { return e.Cause }

type ErrSetModeFailed struct {
	Cause error
}

func (e *ErrSetModeFailed) Error() string {
	return fmt.Sprintf("failed to set gateway mode: %v", e.Cause)
}

func (e *ErrSetModeFailed) Unwrap() error { return e.Cause }

// BGP Errors

type ErrGetBGPStatusFailed struct {
	Cause error
}

func (e *ErrGetBGPStatusFailed) Error() string {
	return fmt.Sprintf("failed to get BGP status: %v", e.Cause)
}

func (e *ErrGetBGPStatusFailed) Unwrap() error { return e.Cause }

type ErrListBGPPeersFailed struct {
	Cause error
}

func (e *ErrListBGPPeersFailed) Error() string {
	return fmt.Sprintf("failed to list BGP peers: %v", e.Cause)
}

func (e *ErrListBGPPeersFailed) Unwrap() error { return e.Cause }

type ErrAnnouncePrefixFailed struct {
	Prefix string
	Cause  error
}

func (e *ErrAnnouncePrefixFailed) Error() string {
	return fmt.Sprintf("failed to announce prefix %s: %v", e.Prefix, e.Cause)
}

func (e *ErrAnnouncePrefixFailed) Unwrap() error { return e.Cause }

type ErrWithdrawPrefixFailed struct {
	Prefix string
	Cause  error
}

func (e *ErrWithdrawPrefixFailed) Error() string {
	return fmt.Sprintf("failed to withdraw prefix %s: %v", e.Prefix, e.Cause)
}

func (e *ErrWithdrawPrefixFailed) Unwrap() error { return e.Cause }

type ErrListAnnouncedPrefixesFailed struct {
	Cause error
}

func (e *ErrListAnnouncedPrefixesFailed) Error() string {
	return fmt.Sprintf("failed to list announced prefixes: %v", e.Cause)
}

func (e *ErrListAnnouncedPrefixesFailed) Unwrap() error { return e.Cause }

// IPAM Errors

type ErrListIPAMPoolsFailed struct {
	Cause error
}

func (e *ErrListIPAMPoolsFailed) Error() string {
	return fmt.Sprintf("failed to list IPAM pools: %v", e.Cause)
}

func (e *ErrListIPAMPoolsFailed) Unwrap() error { return e.Cause }

type ErrAllocateIPFailed struct {
	PoolID string
	Cause  error
}

func (e *ErrAllocateIPFailed) Error() string {
	return fmt.Sprintf("failed to allocate IP from pool %s: %v", e.PoolID, e.Cause)
}

func (e *ErrAllocateIPFailed) Unwrap() error { return e.Cause }

type ErrReleaseIPFailed struct {
	IP    string
	Cause error
}

func (e *ErrReleaseIPFailed) Error() string {
	return fmt.Sprintf("failed to release IP %s: %v", e.IP, e.Cause)
}

func (e *ErrReleaseIPFailed) Unwrap() error { return e.Cause }

type ErrListAllocationsFailed struct {
	Cause error
}

func (e *ErrListAllocationsFailed) Error() string {
	return fmt.Sprintf("failed to list IP allocations: %v", e.Cause)
}

func (e *ErrListAllocationsFailed) Unwrap() error { return e.Cause }

type ErrCreateIPAMPoolFailed struct {
	Name  string
	Cause error
}

func (e *ErrCreateIPAMPoolFailed) Error() string {
	return fmt.Sprintf("failed to create IPAM pool %s: %v", e.Name, e.Cause)
}

func (e *ErrCreateIPAMPoolFailed) Unwrap() error { return e.Cause }

type ErrGetIPAMPoolFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetIPAMPoolFailed) Error() string {
	return fmt.Sprintf("failed to get IPAM pool %s: %v", e.ID, e.Cause)
}

func (e *ErrGetIPAMPoolFailed) Unwrap() error { return e.Cause }

type ErrUpdateIPAMPoolFailed struct {
	ID    string
	Cause error
}

func (e *ErrUpdateIPAMPoolFailed) Error() string {
	return fmt.Sprintf("failed to update IPAM pool %s: %v", e.ID, e.Cause)
}

func (e *ErrUpdateIPAMPoolFailed) Unwrap() error { return e.Cause }

type ErrDeleteIPAMPoolFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteIPAMPoolFailed) Error() string {
	return fmt.Sprintf("failed to delete IPAM pool %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteIPAMPoolFailed) Unwrap() error { return e.Cause }
