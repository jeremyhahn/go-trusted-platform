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

package tpmnv

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrIndexRequired is returned when an NV operation names index 0.
// It is InvalidArgument on every transport.
type ErrIndexRequired struct{}

// Error returns the message.
func (ErrIndexRequired) Error() string { return "index is required" }

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrIndexRequired) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrDataRequired is returned when an NV write carries no data.
// It is InvalidArgument on every transport.
type ErrDataRequired struct{}

// Error returns the message.
func (ErrDataRequired) Error() string { return "data is required" }

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrDataRequired) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrTransportUnavailable is returned when the TPM exposes no raw
// go-tpm transport. It is Unavailable on every transport.
type ErrTransportUnavailable struct{}

// Error returns the message.
func (ErrTransportUnavailable) Error() string { return "TPM transport not available" }

// GRPCStatus classifies the error as Unavailable.
func (e ErrTransportUnavailable) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}
