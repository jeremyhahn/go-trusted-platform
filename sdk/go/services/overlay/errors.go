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

package overlay

import "fmt"

// VTEP Errors

type ErrListVTEPsFailed struct {
	Cause error
}

func (e *ErrListVTEPsFailed) Error() string {
	return fmt.Sprintf("failed to list VTEPs: %v", e.Cause)
}

func (e *ErrListVTEPsFailed) Unwrap() error { return e.Cause }

type ErrGetVTEPFailed struct {
	NodeID string
	Cause  error
}

func (e *ErrGetVTEPFailed) Error() string {
	return fmt.Sprintf("failed to get VTEP %s: %v", e.NodeID, e.Cause)
}

func (e *ErrGetVTEPFailed) Unwrap() error { return e.Cause }

// VNI Errors

type ErrCreateVNIFailed struct {
	VNI   uint32
	Cause error
}

func (e *ErrCreateVNIFailed) Error() string {
	return fmt.Sprintf("failed to create VNI %d: %v", e.VNI, e.Cause)
}

func (e *ErrCreateVNIFailed) Unwrap() error { return e.Cause }

type ErrDeleteVNIFailed struct {
	VNI   uint32
	Cause error
}

func (e *ErrDeleteVNIFailed) Error() string {
	return fmt.Sprintf("failed to delete VNI %d: %v", e.VNI, e.Cause)
}

func (e *ErrDeleteVNIFailed) Unwrap() error { return e.Cause }

type ErrListVNIsFailed struct {
	Cause error
}

func (e *ErrListVNIsFailed) Error() string {
	return fmt.Sprintf("failed to list VNIs: %v", e.Cause)
}

func (e *ErrListVNIsFailed) Unwrap() error { return e.Cause }

// Tunnel Errors

type ErrListTunnelsFailed struct {
	Cause error
}

func (e *ErrListTunnelsFailed) Error() string {
	return fmt.Sprintf("failed to list tunnels: %v", e.Cause)
}

func (e *ErrListTunnelsFailed) Unwrap() error { return e.Cause }

type ErrGetTunnelStatsFailed struct {
	RemoteVTEP string
	VNI        uint32
	Cause      error
}

func (e *ErrGetTunnelStatsFailed) Error() string {
	return fmt.Sprintf("failed to get tunnel stats for %s VNI %d: %v", e.RemoteVTEP, e.VNI, e.Cause)
}

func (e *ErrGetTunnelStatsFailed) Unwrap() error { return e.Cause }

// MAC Errors

type ErrListRemoteMACsFailed struct {
	Cause error
}

func (e *ErrListRemoteMACsFailed) Error() string {
	return fmt.Sprintf("failed to list remote MACs: %v", e.Cause)
}

func (e *ErrListRemoteMACsFailed) Unwrap() error { return e.Cause }

type ErrForgetMACFailed struct {
	MAC   string
	VNI   uint32
	Cause error
}

func (e *ErrForgetMACFailed) Error() string {
	return fmt.Sprintf("failed to forget MAC %s on VNI %d: %v", e.MAC, e.VNI, e.Cause)
}

func (e *ErrForgetMACFailed) Unwrap() error { return e.Cause }

// Status Errors

type ErrGetStatusFailed struct {
	Cause error
}

func (e *ErrGetStatusFailed) Error() string {
	return fmt.Sprintf("failed to get overlay status: %v", e.Cause)
}

func (e *ErrGetStatusFailed) Unwrap() error { return e.Cause }
