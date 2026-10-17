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

// Package tpmek contains the single CreateEK entry point shared by every
// daemon transport (gRPC, REST, Unix, QUIC, MCP).
//
// The SDK's TrustedPlatformModule.EKAttributes caches the attributes it
// reads back from the persistent EK handle, and those carry no creation
// template. Handing them to CreateEK makes go-tpm marshal a zero
// TPMT_PUBLIC (TPM 2.0 Library Part 2 §12.2.4), which panics with "no
// union member for tag 0". Create refuses that input with a typed error
// instead, so no transport can crash the daemon through it.
package tpmek

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// ErrTPMUnavailable is returned when no TPM service is wired.
// It is Unavailable on every transport.
type ErrTPMUnavailable struct{}

// Error returns the message.
func (ErrTPMUnavailable) Error() string { return "TPM service not available" }

// GRPCStatus classifies the error as Unavailable.
func (e ErrTPMUnavailable) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// ErrEKExists is returned when the EK handle already holds a persistent
// object. TPM2_EvictControl (TPM 2.0 Library Part 3 §28.5) cannot persist
// a second object at an occupied handle. It is AlreadyExists on every
// transport.
type ErrEKExists struct {
	Handle uint32
}

// Error returns the message.
func (e ErrEKExists) Error() string {
	return fmt.Sprintf("endorsement key already exists at handle 0x%08X", e.Handle)
}

// GRPCStatus classifies the error as AlreadyExists.
func (e ErrEKExists) GRPCStatus() *status.Status {
	return status.New(codes.AlreadyExists, e.Error())
}

// ErrEKTemplateUnavailable is returned when the EK attributes the TPM
// reports carry no creation template, so there is nothing to give
// TPM2_CreatePrimary. It is FailedPrecondition on every transport.
type ErrEKTemplateUnavailable struct {
	Handle uint32
}

// Error returns the message.
func (e ErrEKTemplateUnavailable) Error() string {
	return fmt.Sprintf("endorsement key attributes for handle 0x%08X carry no creation template", e.Handle)
}

// GRPCStatus classifies the error as FailedPrecondition.
func (e ErrEKTemplateUnavailable) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// Create creates and persists the EK the TPM configuration names and
// returns its attributes. It refuses an occupied EK handle with
// ErrEKExists and template-less attributes with ErrEKTemplateUnavailable.
func Create(tpm xkmssdk.TrustedPlatformModule) (*xkmssdk.KeyAttributes, error) {
	if tpm == nil {
		return nil, ErrTPMUnavailable{}
	}
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, err
	}
	if ekAttrs.TPMAttributes == nil {
		return nil, ErrEKTemplateUnavailable{}
	}
	handle := ekAttrs.TPMAttributes.Handle

	// A readable public area means an object is persisted at the handle.
	// Any read error leaves the decision to TPM2_CreatePrimary, which
	// reports its own failure.
	if _, _, err := tpm.ReadHandle(handle); err == nil {
		return nil, ErrEKExists{Handle: uint32(handle)}
	}
	if ekAttrs.TPMAttributes.Template.Type == 0 {
		return nil, ErrEKTemplateUnavailable{Handle: uint32(handle)}
	}
	if err := tpm.CreateEK(ekAttrs); err != nil {
		return nil, err
	}
	return ekAttrs, nil
}
