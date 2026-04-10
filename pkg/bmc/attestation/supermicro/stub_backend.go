// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package supermicro

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

// unsupportedPlatformReason is the operator-facing explanation of why
// every method on this backend returns [attestation.ErrAttestationUnsupported].
//
// Evidence from the 2026-04-08 survey against real hardware: SUM 2.14.0
// against an X10SDV-TP8F BMC with SFT-DCMS-SINGLE + SFT-SDDC-SINGLE
// activated returned "Remote Attestation is not supported on this
// platform" (error 609.100). Strings extracted from the sum binary
// contain the gating message "Support only on RoT system of X12 and
// later platforms."
const unsupportedPlatformReason = "X10 pre-dates the Silicon Root of Trust silicon; " +
	"SUM requires an X12+ RoT platform. See docs/architecture/bmc-attestation.md " +
	"for the revival plan when RoT-capable hardware is available."

// StubBackend is the placeholder Supermicro attestation backend. It
// intentionally returns [attestation.ErrAttestationUnsupported] from
// every method rather than ErrNotImplemented: the failure is a
// hardware capability gap (X10 has no RoT), not a missing-code gap,
// and callers that retry or fall back based on ErrNotImplemented
// would burn cycles on a case that cannot be unblocked by software.
//
// When the project has access to X12+ Supermicro RoT hardware, this
// package will be replaced with a pure-Go native backend that speaks
// the SUM Attestation wire protocol directly; no shell-out wrapper.
type StubBackend struct {
	platform string // optional, populated from target for better error messages
}

// compile-time interface check
var _ attestation.AttestationProvider = (*StubBackend)(nil)

// NewStubBackend constructs the stub. It never returns an error; the
// hardware gating is enforced lazily on each provider method call.
func NewStubBackend(platform string) *StubBackend {
	return &StubBackend{platform: platform}
}

func (b *StubBackend) unsupported(action attestation.Action) error {
	return attestation.ErrAttestationUnsupported{
		Vendor:   attestation.VendorSupermicro,
		Platform: b.platform,
		Reason:   unsupportedPlatformReason,
	}
}

func (b *StubBackend) Dump(ctx context.Context, nonce []byte) (*attestation.Evidence, error) {
	return nil, b.unsupported(attestation.ActionDump)
}

func (b *StubBackend) List(ctx context.Context) ([]attestation.EvidenceMetadata, error) {
	return nil, b.unsupported(attestation.ActionList)
}

func (b *StubBackend) Download(ctx context.Context, id string) (*attestation.Evidence, error) {
	return nil, b.unsupported(attestation.ActionDownload)
}

func (b *StubBackend) Delete(ctx context.Context, id string) error {
	return b.unsupported(attestation.ActionDelete)
}

func (b *StubBackend) GetInfo(ctx context.Context, ev *attestation.Evidence) (*attestation.Measurement, error) {
	return nil, b.unsupported(attestation.ActionGetInfo)
}

func (b *StubBackend) Compare(ctx context.Context, live, ref *attestation.Evidence) (*attestation.CompareResult, error) {
	return nil, b.unsupported(attestation.ActionCompare)
}

func init() {
	attestation.Register(attestation.VendorSupermicro, func(_ context.Context, t attestation.Target) (attestation.AttestationProvider, error) {
		return NewStubBackend(t.Platform), nil
	})
}
