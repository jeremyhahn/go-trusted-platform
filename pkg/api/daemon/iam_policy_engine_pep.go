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

package daemon

import (
	"context"
	"errors"
	"time"

	quiciam "github.com/jeremyhahn/go-quicbaas/pkg/iam"
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
)

var (
	// errPolicyEngineUnavailable denies a check made with no policy engine.
	errPolicyEngineUnavailable = errors.New("iam policy engine: not available")
	// errPolicyEngineNilRequest denies a check made with no request.
	errPolicyEngineNilRequest = errors.New("iam policy engine: nil check request")
)

// policyEnginePEP is an SDK PEPClient answered by the app's own IAM policy
// engine. The pinned embedded transport answers every IAM.PEP check with
// "not configured", so a certificate principal resolved through the SDK PEP
// would never be admitted (#646, Codex finding 2 on #1906).
type policyEnginePEP struct {
	engine *quicbaassdk.IAMDomainPolicyEngine
}

var _ sdkiam.PEPClient = policyEnginePEP{}

// Check evaluates req with the policy engine. A nil engine or request is
// denied with an error, never allowed.
func (p policyEnginePEP) Check(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
	if p.engine == nil {
		return nil, errPolicyEngineUnavailable
	}
	if req == nil {
		return nil, errPolicyEngineNilRequest
	}
	tenantID := req.Subject.TenantID
	if tenantID == "" {
		tenantID = req.TenantID
	}
	resp, err := p.engine.Evaluate(ctx, &quiciam.CheckRequest{
		Subject: quiciam.Subject{
			ID:            req.Subject.ID,
			TenantID:      tenantID,
			Roles:         req.Subject.Roles,
			Groups:        req.Subject.Groups,
			Attributes:    req.Subject.Attributes,
			Authenticated: true,
		},
		Action:   req.Action,
		Resource: req.Resource,
		Context:  req.Context,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errPolicyEngineUnavailable
	}
	effect := sdkiam.EffectDeny
	if resp.Allowed {
		effect = sdkiam.EffectAllow
	}
	return &sdkiam.CheckResponse{
		Allowed:          resp.Allowed,
		Effect:           effect,
		MatchedPolicy:    resp.MatchedPolicy,
		MatchedRule:      resp.MatchedRule,
		EvaluationTimeNs: resp.EvaluationTimeNs,
		Reason:           resp.Reason,
		Timestamp:        time.Now(),
	}, nil
}

// CheckBatch evaluates each request in order with Check. Any error denies
// the whole batch.
func (p policyEnginePEP) CheckBatch(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error) {
	if p.engine == nil {
		return nil, errPolicyEngineUnavailable
	}
	if req == nil {
		return nil, errPolicyEngineNilRequest
	}
	out := &sdkiam.CheckBatchResponse{Results: make([]sdkiam.CheckResponse, 0, len(req.Requests))}
	for i := range req.Requests {
		resp, err := p.Check(ctx, &req.Requests[i])
		if err != nil {
			return nil, err
		}
		out.Results = append(out.Results, *resp)
		out.TotalEvaluationTimeNs += resp.EvaluationTimeNs
		if resp.Allowed {
			out.AllowedCount++
			continue
		}
		out.DeniedCount++
		if req.StopOnDeny {
			break
		}
	}
	out.AllAllowed = out.DeniedCount == 0 && len(out.Results) == len(req.Requests)
	return out, nil
}

// certificatePrincipalPEP picks the policy decision point the mTLS
// certificate resolver asks: the app's policy engine when svc is an
// app.IAMProvider that returns one, else fallback (the SDK PEP). It reports
// whether the engine was chosen.
func certificatePrincipalPEP(ctx context.Context, svc any, fallback sdkiam.PEPClient) (sdkiam.PEPClient, bool) {
	provider, ok := svc.(app.IAMProvider)
	if !ok || provider == nil {
		return fallback, false
	}
	engine, err := provider.GetPolicyEngine(ctx)
	if err != nil || engine == nil {
		return fallback, false
	}
	return policyEnginePEP{engine: engine}, true
}
