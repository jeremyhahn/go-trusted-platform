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

// Package orchestration re-exports the container-trust axis of the go-quicbaas
// agentic surface, so a platform SDK consumer can name and resolve trust
// levels without importing go-quicbaas:
//
//	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/orchestration"
//
// replaces
//
//	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
//
// without any type conversion.
//
// It adds NO behavior: every identifier is a type alias, a constant copy, a
// variable bound to the upstream value or a function that forwards to the
// upstream one unchanged. A value produced anywhere in the stack
// is the same value here, so errors.Is, errors.As and type assertions work
// across the boundary unchanged.
//
// # Coverage
//
// The trust axis and the closure of what it needs:
//
//   - TrustLevel and its levels, lowest tier first: TrustLevelDefault,
//     TrustLevelNone, TrustLevelPinned (Tier 0), TrustLevelAttested (Tier 1),
//     TrustLevelMeasured (Tier 2).
//   - TrustPolicy and its policies: TrustPolicyOptIn, TrustPolicyPinned,
//     TrustPolicyAttested, TrustPolicyMeasured.
//   - TrustCapabilities, what a host can prove.
//   - ResolveTrustLevel, ParseTrustLevel and ParseTrustPolicy.
//   - The errors they return: TrustLevelViolationError, InputValidationError
//     and its sentinel ErrInvalidInput.
//
// The agentic clients themselves (Orchestrator, Project, Account) are routed by
// the sibling package sdk/go/services/quicbaas.
package orchestration
