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

// Package tpmpcr holds the PCR-extend argument validation shared by every
// daemon transport (QUIC, MCP), so each one rejects the same requests
// with the same typed errors before the TPM sees them.
package tpmpcr

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MaxIndex is the highest PCR index a TPM 2.0 PC-client platform exposes.
const MaxIndex = 23

// DefaultHashAlg is the PCR bank extended when the caller names none.
const DefaultHashAlg = "sha256"

// Extender is the part of the TPM a PCR extend needs.
type Extender interface {
	ExtendPCR(pcrIndex int, hashAlg string, data []byte) error
}

// ErrInvalidIndex is returned for a PCR index outside 0..MaxIndex.
// It is InvalidArgument on every transport.
type ErrInvalidIndex struct {
	Index int
}

// Error returns the message.
func (e ErrInvalidIndex) Error() string {
	return fmt.Sprintf("invalid PCR index %d (must be 0-%d)", e.Index, MaxIndex)
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrInvalidIndex) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrDataRequired is returned when an extend carries no data.
// It is InvalidArgument on every transport.
type ErrDataRequired struct{}

// Error returns the message.
func (ErrDataRequired) Error() string { return "data is required" }

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrDataRequired) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// Extend validates the request and extends the PCR at index in the
// hashAlg bank (DefaultHashAlg when empty) with data.
func Extend(tpm Extender, index int, hashAlg string, data []byte) error {
	if index < 0 || index > MaxIndex {
		return ErrInvalidIndex{Index: index}
	}
	if len(data) == 0 {
		return ErrDataRequired{}
	}
	if hashAlg == "" {
		hashAlg = DefaultHashAlg
	}
	return tpm.ExtendPCR(index, hashAlg, data)
}
