// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package dell

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// RedfishBackend is a stub for the future Dell iDRAC9 attestation
// backend.
//
// TODO(phase-2): implement using the documented iDRAC9 Redfish
// endpoints:
//
//	GET /redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttestation
//	POST .../Actions/DellAttestation.GetAttestation
//	GET /redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttestation/DICEChain
//
// These endpoints require iDRAC9 firmware 4.40.40.00 or newer.
type RedfishBackend struct{}

// compile-time interface check
var _ attestation.AttestationProvider = (*RedfishBackend)(nil)

// NewRedfishBackend constructs the stub backend. It never returns an
// error; per-method calls return [attestation.ErrNotImplemented].
func NewRedfishBackend() *RedfishBackend { return &RedfishBackend{} }

func (b *RedfishBackend) Dump(ctx context.Context, nonce []byte) (*attestation.Evidence, error) {
	return nil, attestation.ErrNotImplemented{Vendor: attestation.VendorDell, Action: attestation.ActionDump}
}

func (b *RedfishBackend) List(ctx context.Context) ([]attestation.EvidenceMetadata, error) {
	return nil, attestation.ErrNotImplemented{Vendor: attestation.VendorDell, Action: attestation.ActionList}
}

func (b *RedfishBackend) Download(ctx context.Context, id string) (*attestation.Evidence, error) {
	return nil, attestation.ErrNotImplemented{Vendor: attestation.VendorDell, Action: attestation.ActionDownload}
}

func (b *RedfishBackend) Delete(ctx context.Context, id string) error {
	return attestation.ErrNotImplemented{Vendor: attestation.VendorDell, Action: attestation.ActionDelete}
}

func (b *RedfishBackend) GetInfo(ctx context.Context, ev *attestation.Evidence) (*attestation.Measurement, error) {
	return nil, attestation.ErrNotImplemented{Vendor: attestation.VendorDell, Action: attestation.ActionGetInfo}
}

func (b *RedfishBackend) Compare(ctx context.Context, live, ref *attestation.Evidence) (*attestation.CompareResult, error) {
	return nil, attestation.ErrNotImplemented{Vendor: attestation.VendorDell, Action: attestation.ActionCompare}
}

func init() {
	attestation.Register(attestation.VendorDell, func(_ context.Context, _ attestation.Target) (attestation.AttestationProvider, error) {
		return NewRedfishBackend(), nil
	})
}
