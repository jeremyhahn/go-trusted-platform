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

package daemon

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The MCP VM and container tools answer every error with the gRPC status
// class ComputeService answers the same failure with, so an MCP caller and a
// gRPC caller decode the same error class for the same input (#304). The MCP
// server reads the class through GRPCStatus (pkg/api/mcp toolErrorCode).

// ErrComputeToolFailed carries a compute orchestrator error out of an MCP VM
// or container tool, classified by the ComputeService mapper of the twin RPC.
// The message and the error chain are the cause's own.
type ErrComputeToolFailed struct {
	Class codes.Code
	Cause error
}

// Error implements the error interface.
func (e ErrComputeToolFailed) Error() string {
	return e.Cause.Error()
}

// Unwrap exposes the orchestrator error to errors.Is and errors.As.
func (e ErrComputeToolFailed) Unwrap() error {
	return e.Cause
}

// GRPCStatus reports the class the twin RPC answers the cause with.
func (e ErrComputeToolFailed) GRPCStatus() *status.Status {
	return status.New(e.Class, e.Error())
}

// classifyComputeErr wraps err with the class toStatus, a ComputeService
// error mapper, gives it. A nil err stays nil.
func classifyComputeErr(err error, toStatus func(error) error) error {
	if err == nil {
		return nil
	}
	return ErrComputeToolFailed{Class: status.Code(toStatus(err)), Cause: err}
}

// validateVMPCRIndex refuses a PCR index outside the 24 PCRs of a TPM 2.0
// bank, as AttestVM does on every transport.
func validateVMPCRIndex(idx int) error {
	if idx < 0 || idx > 23 {
		return status.Error(codes.InvalidArgument, "PCR index must be between 0 and 23")
	}
	return nil
}

// GRPCStatus classifies a missing compute orchestrator as ComputeService
// does: FailedPrecondition.
func (e ErrVMComputeNotAvailable) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// GRPCStatus classifies a missing snapshot capability as ComputeService does.
func (e ErrVMSnapshotsNotSupported) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// GRPCStatus classifies a missing attestation capability as ComputeService
// does.
func (e ErrVMAttestationNotSupported) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// GRPCStatus classifies a missing metrics capability as ComputeService does.
func (e ErrVMMetricsNotSupported) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// GRPCStatus classifies a missing disk capability as ComputeService does.
func (e ErrVMDiskOpsNotSupported) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// GRPCStatus classifies a missing log capability as ComputeService does.
func (e ErrVMLogsNotSupported) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// GRPCStatus classifies a missing migration capability as ComputeService
// does.
func (e ErrVMMigrateNotSupported) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// GRPCStatus classifies missing evidence as invalid input.
func (e ErrVMEvidenceRequired) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// GRPCStatus classifies an unknown snapshot as NotFound.
func (e ErrVMSnapshotNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// GRPCStatus classifies a missing compute orchestrator as ComputeService
// does: FailedPrecondition.
func (e ErrContainerServiceNotAvailable) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// GRPCStatus classifies an unknown container as GetContainer does: NotFound.
func (e ErrContainerNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// GRPCStatus classifies a missing or empty argument as InvalidArgument.
func (e ErrContainerInvalidParameter) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// GRPCStatus classifies a missing log capability as ComputeService does:
// Unimplemented.
func (e ErrContainerLogsNotSupported) GRPCStatus() *status.Status {
	return status.New(codes.Unimplemented, e.Error())
}

// GRPCStatus classifies a missing attestation capability as ComputeService
// does: Unimplemented.
func (e ErrContainerAttestNotSupported) GRPCStatus() *status.Status {
	return status.New(codes.Unimplemented, e.Error())
}

// GRPCStatus classifies a missing exec capability as ComputeService does:
// Unimplemented.
func (e ErrContainerExecNotSupported) GRPCStatus() *status.Status {
	return status.New(codes.Unimplemented, e.Error())
}

// GRPCStatus classifies a missing metrics capability as ComputeService does:
// Unimplemented.
func (e ErrContainerMetricsNotSupported) GRPCStatus() *status.Status {
	return status.New(codes.Unimplemented, e.Error())
}
