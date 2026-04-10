// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import "context"

// AttestationProvider is the vendor-neutral interface implemented by each
// BMC attestation backend. Methods mirror the verbs exposed by
// Supermicro's SUM Attestation command because that verb set is a superset
// of Dell and HPE capabilities and provides a stable contract.
type AttestationProvider interface {
	// Dump triggers the BMC to produce a fresh attestation measurement
	// bound to the supplied nonce and returns the resulting Evidence.
	Dump(ctx context.Context, nonce []byte) (*Evidence, error)

	// List enumerates attestation evidence already present on the BMC.
	List(ctx context.Context) ([]EvidenceMetadata, error)

	// Download retrieves a previously generated evidence blob by ID.
	Download(ctx context.Context, id string) (*Evidence, error)

	// Delete removes a stored evidence blob from the BMC.
	Delete(ctx context.Context, id string) error

	// GetInfo parses an opaque Evidence blob into a structured
	// [Measurement]. This is the only place backend-specific parsing
	// of Raw is allowed.
	GetInfo(ctx context.Context, ev *Evidence) (*Measurement, error)

	// Compare performs a vendor-specific comparison between a live
	// evidence blob and a known-good reference.
	Compare(ctx context.Context, live, ref *Evidence) (*CompareResult, error)
}
