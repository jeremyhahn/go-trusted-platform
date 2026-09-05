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

package calleradmission

// ErrUnknownStrategy reports a strategy name the package does not implement.
type ErrUnknownStrategy struct {
	Strategy string
}

func (e ErrUnknownStrategy) Error() string {
	return "attestation caller admission: unknown strategy " + e.Strategy
}

// ErrChainVerification reports a presented certificate that does not chain
// to the configured anchors for client authentication.
type ErrChainVerification struct {
	Cause error
}

func (e ErrChainVerification) Error() string {
	return "attestation caller admission: client certificate does not chain to a configured anchor: " + e.Cause.Error()
}

func (e ErrChainVerification) Unwrap() error { return e.Cause }
