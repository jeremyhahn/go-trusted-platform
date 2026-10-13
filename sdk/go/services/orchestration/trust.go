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

package orchestration

import (
	quicbaasorch "github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
)

// TrustLevel selects the integrity tier required of an agent execution on a
// per-request basis.
type TrustLevel = quicbaasorch.TrustLevel

// TrustPolicy is the server-side policy governing how TrustLevelDefault
// resolves and which explicit levels are permitted.
type TrustPolicy = quicbaasorch.TrustPolicy

// TrustCapabilities describes what the target host can actually prove. The
// zero value advertises no capability, so a required tier fails closed.
type TrustCapabilities = quicbaasorch.TrustCapabilities

// TrustLevelViolationError signals that a requested TrustLevel cannot be
// satisfied under the active TrustPolicy or on the target host.
type TrustLevelViolationError = quicbaasorch.TrustLevelViolationError

// InputValidationError indicates invalid input, such as an unknown trust
// level or policy name. It wraps ErrInvalidInput.
type InputValidationError = quicbaasorch.InputValidationError

// Trust levels, lowest tier first. TrustLevelDefault is the zero value and
// defers to the server's TrustPolicy.
const (
	// TrustLevelDefault lets the server resolve the effective level from its
	// configured TrustPolicy and any tenant override.
	TrustLevelDefault = quicbaasorch.TrustLevelDefault

	// TrustLevelNone requires no integrity guarantee.
	TrustLevelNone = quicbaasorch.TrustLevelNone

	// TrustLevelPinned is Tier 0: launch and verify by immutable content
	// digest. Requires no hardware.
	TrustLevelPinned = quicbaasorch.TrustLevelPinned

	// TrustLevelAttested is Tier 1: Tier 0 plus a host TPM quote verified
	// against the expected PCR set.
	TrustLevelAttested = quicbaasorch.TrustLevelAttested

	// TrustLevelMeasured is Tier 2: Tier 1 plus measured launch.
	TrustLevelMeasured = quicbaasorch.TrustLevelMeasured
)

// Trust policies. TrustPolicyOptIn is the zero value.
const (
	// TrustPolicyOptIn resolves DEFAULT to TrustLevelNone and rejects nothing.
	TrustPolicyOptIn = quicbaasorch.TrustPolicyOptIn

	// TrustPolicyPinned resolves DEFAULT to TrustLevelPinned and forbids
	// TrustLevelNone.
	TrustPolicyPinned = quicbaasorch.TrustPolicyPinned

	// TrustPolicyAttested resolves DEFAULT to TrustLevelAttested and forbids
	// anything below it.
	TrustPolicyAttested = quicbaasorch.TrustPolicyAttested

	// TrustPolicyMeasured resolves DEFAULT to TrustLevelMeasured and forbids
	// anything below it.
	TrustPolicyMeasured = quicbaasorch.TrustPolicyMeasured
)

// ErrInvalidInput is the sentinel wrapped by InputValidationError.
var ErrInvalidInput = quicbaasorch.ErrInvalidInput

// ResolveTrustLevel resolves the effective trust level for a request given the
// server policy, an optional tenant override (which may only tighten the
// server policy) and the host's capabilities. Resolution is deny-by-default:
// a level below the policy floor, or one the host cannot prove, returns a
// *TrustLevelViolationError rather than a downgrade.
//
// It is a function, not a variable bound to the upstream one, so no package
// linked into the binary can replace the resolver.
func ResolveTrustLevel(
	requested TrustLevel,
	serverPolicy TrustPolicy,
	tenantOverride *TrustPolicy,
	caps TrustCapabilities,
) (TrustLevel, error) {
	return quicbaasorch.ResolveTrustLevel(requested, serverPolicy, tenantOverride, caps)
}

// ParseTrustLevel decodes a string (as produced by TrustLevel.String) back
// into a TrustLevel. The empty string maps to TrustLevelDefault; an unknown
// name returns a *InputValidationError.
func ParseTrustLevel(s string) (TrustLevel, error) {
	return quicbaasorch.ParseTrustLevel(s)
}

// ParseTrustPolicy decodes a string (as produced by TrustPolicy.String) back
// into a TrustPolicy. The empty string maps to TrustPolicyOptIn; an unknown
// name returns a *InputValidationError.
func ParseTrustPolicy(s string) (TrustPolicy, error) {
	return quicbaasorch.ParseTrustPolicy(s)
}
