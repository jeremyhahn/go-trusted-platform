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

package opa

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// regoFileExtension is the file extension for Rego policies (the watcher
// uses it in both builds).
const regoFileExtension = ".rego"

// OPAEngine is the stand-in for the OPA policy engine in a build without
// the opa tag: every operation returns ErrOPANotBuilt.
type OPAEngine struct{}

// NewOPAEngine returns an engine that refuses every operation with
// ErrOPANotBuilt.
func NewOPAEngine() *OPAEngine {
	return &OPAEngine{}
}

// Initialize returns ErrOPANotBuilt.
func (e *OPAEngine) Initialize(ctx context.Context, cfg *config.PolicyConfig) error {
	return ErrOPANotBuilt{}
}

// LoadPolicy returns ErrOPANotBuilt.
func (e *OPAEngine) LoadPolicy(ctx context.Context, name string, content []byte) error {
	return ErrOPANotBuilt{}
}

// UnloadPolicy returns ErrOPANotBuilt.
func (e *OPAEngine) UnloadPolicy(ctx context.Context, name string) error {
	return ErrOPANotBuilt{}
}

// Evaluate returns ErrOPANotBuilt.
func (e *OPAEngine) Evaluate(ctx context.Context, policyName string, input map[string]interface{}) (*EvaluationResult, error) {
	return nil, ErrOPANotBuilt{}
}

// EvaluateWithData returns ErrOPANotBuilt.
func (e *OPAEngine) EvaluateWithData(ctx context.Context, policyName string, input map[string]interface{}, data map[string]interface{}) (*EvaluationResult, error) {
	return nil, ErrOPANotBuilt{}
}

// ListPolicies returns no policies.
func (e *OPAEngine) ListPolicies() []*PolicyBundle {
	return nil
}

// GetPolicy returns ErrOPANotBuilt.
func (e *OPAEngine) GetPolicy(name string) (*PolicyBundle, error) {
	return nil, ErrOPANotBuilt{}
}

// Reload returns ErrOPANotBuilt.
func (e *OPAEngine) Reload(ctx context.Context) error {
	return ErrOPANotBuilt{}
}

// Close does nothing and returns nil.
func (e *OPAEngine) Close() error {
	return nil
}

// IsInitialized reports false: the engine never initializes.
func (e *OPAEngine) IsInitialized() bool {
	return false
}

// Stats returns zero statistics.
func (e *OPAEngine) Stats() EngineStats {
	return EngineStats{}
}
