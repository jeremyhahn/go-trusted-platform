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

package vpn

import (
	"context"
	"errors"
	"slices"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
)

// PosturePackage is the Rego package every posture policy declares. A tenant
// policy replaces the embedded default inside an engine of its own, so it
// must use the same package and cannot merge with another tenant's rules.
const PosturePackage = "data.vpn.posture"

// PosturePolicy is a tenant's posture policy as the control plane delivers
// it. The service evaluates the tenant's policy whose Name equals the
// configured posture-policy; a tenant without one gets the gateway default.
type PosturePolicy struct {
	TenantID string `json:"tenant_id" yaml:"tenant-id"`
	Name     string `json:"name" yaml:"name"`
	Module   string `json:"module" yaml:"module"`
}

// tenantPosture is one tenant's compiled policy, or the reason it could not
// be compiled. A broken policy refuses the tenant's admissions.
type tenantPosture struct {
	engine *opa.OPAEngine
	err    error
}

// CompilePosturePolicy compiles a tenant posture policy in an isolated
// engine: the embedded policies are loaded, then the module replaces the
// embedded posture default under DefaultPosturePolicy. The returned engine
// evaluates the module under that name. The control plane calls this to
// validate a policy before storing it; the service calls it on delivery.
func CompilePosturePolicy(ctx context.Context, p PosturePolicy) (*opa.OPAEngine, error) {
	if p.Module == "" {
		return nil, &ErrPosturePolicyInvalid{TenantID: p.TenantID, Name: p.Name, Reason: "module is empty"}
	}
	engine := opa.NewOPAEngine()
	if err := engine.Initialize(ctx, &config.PolicyConfig{}); err != nil {
		return nil, &ErrPostureUnavailable{Cause: err}
	}
	if err := engine.LoadPolicy(ctx, DefaultPosturePolicy, []byte(p.Module)); err != nil {
		return nil, &ErrPosturePolicyInvalid{TenantID: p.TenantID, Name: p.Name, Reason: err.Error()}
	}
	bundle, err := engine.GetPolicy(DefaultPosturePolicy)
	if err != nil {
		return nil, &ErrPostureUnavailable{Cause: err}
	}
	if bundle.Package != PosturePackage {
		return nil, &ErrPosturePolicyInvalid{TenantID: p.TenantID, Name: p.Name,
			Reason: "the module declares " + bundle.Package + "; a posture policy declares package vpn.posture"}
	}
	return engine, nil
}

// SetPosturePolicies replaces the tenant posture policies. Only policies
// named after the configured posture-policy are compiled; the others belong
// to gateways configured with a different name. A policy that fails to
// compile is kept as broken, so its tenant is refused rather than falling
// back to the default, and the failures are returned joined.
func (s *Service) SetPosturePolicies(ctx context.Context, policies []PosturePolicy) error {
	set := make(map[string]tenantPosture)
	var errs []error
	for _, p := range policies {
		if p.TenantID == "" {
			errs = append(errs, &ErrPosturePolicyInvalid{Name: p.Name, Reason: "tenant_id is required"})
			continue
		}
		if p.Name != s.cfg.PosturePolicy {
			continue
		}
		if _, dup := set[p.TenantID]; dup {
			err := &ErrPosturePolicyInvalid{TenantID: p.TenantID, Name: p.Name, Reason: "delivered more than once"}
			set[p.TenantID] = tenantPosture{err: err}
			errs = append(errs, err)
			continue
		}
		engine, err := CompilePosturePolicy(ctx, p)
		if err != nil {
			errs = append(errs, err)
		}
		set[p.TenantID] = tenantPosture{engine: engine, err: err}
	}
	s.tenantPosture.Store(&set)
	return errors.Join(errs...)
}

// postureFor returns the evaluator and policy name that judge the tenant: its
// own policy when one was delivered, else the gateway default.
func (s *Service) postureFor(tenantID string) (PostureEvaluator, string, error) {
	if p := s.tenantPosture.Load(); p != nil {
		if tp, ok := (*p)[tenantID]; ok {
			if tp.err != nil {
				return nil, "", tp.err
			}
			return tp.engine, DefaultPosturePolicy, nil
		}
	}
	return s.deps.Posture, s.cfg.PosturePolicy, nil
}

// PosturePolicyErrors returns, sorted, why each tenant's delivered policy is
// refused. A tenant listed here is refused admission until a policy that
// compiles is delivered.
func (s *Service) PosturePolicyErrors() []string {
	p := s.tenantPosture.Load()
	if p == nil {
		return nil
	}
	var out []string
	for _, tp := range *p {
		if tp.err != nil {
			out = append(out, tp.err.Error())
		}
	}
	slices.Sort(out)
	return out
}
