// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxysvc

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// OPAConfig is the proxy `opa:` section enabling per-route OPA policy
// evaluation for routes that set auth.opa-policy.
type OPAConfig struct {
	// Enabled activates the policy evaluator.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// PolicyDir optionally overlays operator policies over the embedded
	// defaults (a directory policy with the same name wins). Policies are
	// loaded once at startup.
	PolicyDir string `yaml:"policy-dir,omitempty" json:"policy_dir,omitempty" mapstructure:"policy-dir"`
}

// OPAEvaluator is the production proxy.PolicyEvaluator over the platform OPA
// engine (pkg/policy/opa) with its embedded policies — including
// proxy_authz, the default proxy authorization policy — plus any operator
// policy directory. The engine's default action is deny, so an undefined
// policy result never allows.
type OPAEvaluator struct {
	engine *opa.OPAEngine
}

// NewOPAEvaluator builds and initializes the evaluator. Initialization
// failures (missing policy directory, unparsable policy) are returned so the
// proxy fails closed at assembly time rather than denying every request at
// runtime.
func NewOPAEvaluator(ctx context.Context, cfg *OPAConfig) (*OPAEvaluator, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, &ErrOPADisabled{}
	}
	engine := opa.NewOPAEngine()
	if err := engine.Initialize(ctx, &config.PolicyConfig{
		PolicyDir:     cfg.PolicyDir,
		DefaultAction: "deny",
	}); err != nil {
		return nil, err
	}
	return &OPAEvaluator{engine: engine}, nil
}

// Evaluate implements proxy.PolicyEvaluator, projecting the engine result
// onto the chain's (allowed, violations, error) contract.
func (e *OPAEvaluator) Evaluate(ctx context.Context, policy string, input map[string]any) (bool, []string, error) {
	result, err := e.engine.Evaluate(ctx, policy, input)
	if err != nil {
		return false, nil, err
	}
	violations := make([]string, 0, len(result.Violations))
	for _, v := range result.Violations {
		violations = append(violations, v.Message)
	}
	return result.Allowed, violations, nil
}

var _ proxy.PolicyEvaluator = (*OPAEvaluator)(nil)
