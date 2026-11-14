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

//go:build !opa

package container

import "context"

// OPAEngine is the stand-in for the OPA Rego engine in a build without the
// opa tag: every operation returns ErrOPANotBuilt.
type OPAEngine struct{}

// NewOPAEngine returns ErrOPANotBuilt.
func NewOPAEngine() (*OPAEngine, error) {
	return nil, ErrOPANotBuilt
}

// LoadBundle returns ErrOPANotBuilt.
func (e *OPAEngine) LoadBundle(ctx context.Context, bundle *PolicyBundle) error {
	return ErrOPANotBuilt
}

// Evaluate returns ErrOPANotBuilt.
func (e *OPAEngine) Evaluate(ctx context.Context, input OPAPolicyInput) (*OPAPolicyDecision, error) {
	return nil, ErrOPANotBuilt
}

// Close does nothing and returns nil.
func (e *OPAEngine) Close() error {
	return nil
}
