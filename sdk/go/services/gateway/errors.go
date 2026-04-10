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
