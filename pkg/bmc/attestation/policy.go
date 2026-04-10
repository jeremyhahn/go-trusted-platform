// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import "context"

// Policy is a declarative set of rules that an [Evidence] blob must
// satisfy to be considered trustworthy. A zero Policy rejects nothing
// and accepts nothing on its own; callers must populate at least one
// rule before handing it to a [Verifier].
type Policy struct {
	// AllowedVendors restricts which vendors are acceptable. Empty
	// means "any known vendor".
	AllowedVendors []Vendor

	// RequireNonceEcho rejects evidence whose parsed NonceEcho does
	// not match the nonce the verifier was supplied with.
	RequireNonceEcho bool

	// TrustedIssuers is the set of x509 issuer subjects accepted for
	// the attestation certificate chain leaf signer.
	TrustedIssuers []string

	// Reference, when non-nil, instructs the verifier to run a
	// vendor Compare between the live evidence and this reference.
	Reference *Evidence

	// MaxAgeSeconds rejects evidence whose CreatedAt is older than
	// this many seconds. Zero disables the check.
	MaxAgeSeconds int64
}

// VerifyResult is returned by a [Verifier] and carries a pass/fail
// outcome plus human-readable reasons for audit trails.
type VerifyResult struct {
	Passed  bool
	Reasons []string
}

// Verifier appraises an [Evidence] blob against a [Policy]. It is a
// separate interface from [AttestationProvider] so that verification
// can run offline in a dedicated appraisal service that never talks to
// a live BMC.
type Verifier interface {
	Verify(ctx context.Context, ev *Evidence, pol *Policy) (*VerifyResult, error)
}
