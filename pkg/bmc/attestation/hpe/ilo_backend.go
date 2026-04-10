// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package hpe

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// ILOBackend is a stub for the future HPE iLO5/iLO6 attestation
// backend.
//
// TODO(phase-3): implement using the documented Redfish endpoints:
//
//	GET /redfish/v1/Managers/1/SecurityService
//	GET /redfish/v1/Managers/1/SecurityService/SecurityDashboard
//	POST .../Actions/HpeSecurityService.GetSiliconRootOfTrustEvidence
//
// iLO5 and iLO6 expose slightly different endpoints; the concrete
// implementation must discover the sub-variant at runtime.
type ILOBackend struct{}

// compile-time interface check
var _ attestation.AttestationProvider = (*ILOBackend)(nil)

// NewILOBackend constructs the stub backend.
func NewILOBackend() *ILOBackend { return &ILOBackend{} }

func (b *ILOBackend) Dump(ctx context.Context, nonce []byte) (*attestation.Evidence, error) {
	return nil, attestation.ErrNotImplemented{Vendor: attestation.VendorHPE, Action: attestation.ActionDump}
}

func (b *ILOBackend) List(ctx context.Context) ([]attestation.EvidenceMetadata, error) {
	return nil, attestation.ErrNotImplemented{Vendor: attestation.VendorHPE, Action: attestation.ActionList}
}

func (b *ILOBackend) Download(ctx context.Context, id string) (*attestation.Evidence, error) {
	return nil, attestation.ErrNotImplemented{Vendor: attestation.VendorHPE, Action: attestation.ActionDownload}
}

func (b *ILOBackend) Delete(ctx context.Context, id string) error {
	return attestation.ErrNotImplemented{Vendor: attestation.VendorHPE, Action: attestation.ActionDelete}
}

func (b *ILOBackend) GetInfo(ctx context.Context, ev *attestation.Evidence) (*attestation.Measurement, error) {
	return nil, attestation.ErrNotImplemented{Vendor: attestation.VendorHPE, Action: attestation.ActionGetInfo}
}

func (b *ILOBackend) Compare(ctx context.Context, live, ref *attestation.Evidence) (*attestation.CompareResult, error) {
	return nil, attestation.ErrNotImplemented{Vendor: attestation.VendorHPE, Action: attestation.ActionCompare}
}

func init() {
	attestation.Register(attestation.VendorHPE, func(_ context.Context, _ attestation.Target) (attestation.AttestationProvider, error) {
		return NewILOBackend(), nil
	})
}
