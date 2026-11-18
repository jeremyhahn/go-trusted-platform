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
	"testing"

	quiciam "github.com/jeremyhahn/go-quicbaas/pkg/iam"
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
)

// stubRBACAuthorizer allows exactly the permissions it lists, keyed by
// "subject|tenant|resource:action".
type stubRBACAuthorizer struct {
	allowed map[string]bool
}

func (a stubRBACAuthorizer) Authorize(_ context.Context, subject *quiciam.Subject, resource, action string) error {
	if subject != nil && a.allowed[subject.ID+"|"+subject.TenantID+"|"+resource+":"+action] {
		return nil
	}
	return errors.New("not permitted")
}

func newTestPolicyEngine() *quicbaassdk.IAMDomainPolicyEngine {
	return quiciam.NewPolicyEngine(quiciam.PolicyEngineOptions{
		RBACAuthorizer: stubRBACAuthorizer{allowed: map[string]bool{
			"alice|acme|device:read": true,
		}},
	})
}

func pepCheck(subject, tenant, resource, action string) *sdkiam.CheckRequest {
	return &sdkiam.CheckRequest{
		Subject:  sdkiam.CheckSubject{ID: subject, TenantID: tenant, Roles: []string{"operator"}},
		Resource: resource,
		Action:   action,
	}
}

func TestPolicyEnginePEP_AllowsThroughEngine(t *testing.T) {
	pep := policyEnginePEP{engine: newTestPolicyEngine()}
	resp, err := pep.Check(context.Background(), pepCheck("alice", "acme", "device", "read"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !resp.Allowed || resp.Effect != sdkiam.EffectAllow {
		t.Fatalf("got allowed=%v effect=%v reason=%q, want allow", resp.Allowed, resp.Effect, resp.Reason)
	}
}

func TestPolicyEnginePEP_DeniesThroughEngine(t *testing.T) {
	pep := policyEnginePEP{engine: newTestPolicyEngine()}
	for _, req := range []*sdkiam.CheckRequest{
		pepCheck("alice", "acme", "device", "write"),
		pepCheck("alice", "other", "device", "read"),
		pepCheck("bob", "acme", "device", "read"),
	} {
		resp, err := pep.Check(context.Background(), req)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if resp.Allowed || resp.Effect != sdkiam.EffectDeny {
			t.Fatalf("%+v: got allowed=%v effect=%v, want deny", req, resp.Allowed, resp.Effect)
		}
	}
}

func TestPolicyEnginePEP_RequestTenantFillsSubject(t *testing.T) {
	pep := policyEnginePEP{engine: newTestPolicyEngine()}
	req := pepCheck("alice", "", "device", "read")
	req.TenantID = "acme"
	resp, err := pep.Check(context.Background(), req)
	if err != nil || !resp.Allowed {
		t.Fatalf("got resp=%+v err=%v, want allow from the request tenant", resp, err)
	}
}

func TestPolicyEnginePEP_CheckBatch(t *testing.T) {
	pep := policyEnginePEP{engine: newTestPolicyEngine()}
	resp, err := pep.CheckBatch(context.Background(), &sdkiam.CheckBatchRequest{Requests: []sdkiam.CheckRequest{
		*pepCheck("alice", "acme", "device", "read"),
		*pepCheck("alice", "acme", "device", "write"),
	}})
	if err != nil {
		t.Fatalf("CheckBatch: %v", err)
	}
	if len(resp.Results) != 2 || !resp.Results[0].Allowed || resp.Results[1].Allowed {
		t.Fatalf("results = %+v, want [allow deny]", resp.Results)
	}
	if resp.AllAllowed || resp.AllowedCount != 1 || resp.DeniedCount != 1 {
		t.Fatalf("got all=%v allowed=%d denied=%d", resp.AllAllowed, resp.AllowedCount, resp.DeniedCount)
	}
}

func TestPolicyEnginePEP_NilEngineOrRequestDenies(t *testing.T) {
	var nilEngine policyEnginePEP
	if resp, err := nilEngine.Check(context.Background(), pepCheck("alice", "acme", "device", "read")); err == nil || (resp != nil && resp.Allowed) {
		t.Fatalf("nil engine: got resp=%+v err=%v, want a denial error", resp, err)
	}
	if resp, err := nilEngine.CheckBatch(context.Background(), &sdkiam.CheckBatchRequest{}); err == nil || (resp != nil && resp.AllAllowed) {
		t.Fatalf("nil engine batch: got resp=%+v err=%v, want a denial error", resp, err)
	}
	pep := policyEnginePEP{engine: newTestPolicyEngine()}
	if resp, err := pep.Check(context.Background(), nil); err == nil || (resp != nil && resp.Allowed) {
		t.Fatalf("nil request: got resp=%+v err=%v, want a denial error", resp, err)
	}
	if resp, err := pep.CheckBatch(context.Background(), nil); err == nil || (resp != nil && resp.AllAllowed) {
		t.Fatalf("nil batch: got resp=%+v err=%v, want a denial error", resp, err)
	}
}

// Codex finding 2 on #1906: the certificate resolver admits a principal
// through a real policy engine, not only through a mocked PEP.
func TestIAMCertificatePrincipals_ResolveThroughThePolicyEngine(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	engine := quiciam.NewPolicyEngine(quiciam.PolicyEngineOptions{
		RBACAuthorizer: stubRBACAuthorizer{allowed: map[string]bool{
			"u-device|tenant-a|device:read": true,
			"u-device|tenant-a|tenant:read": true,
		}},
	})
	resolver := newTestIAMCertificatePrincipals(t, users, roles, policyEnginePEP{engine: engine})

	principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "device-01", TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("ResolveCertificatePrincipal: %v", err)
	}
	if got := principal.Scopes; len(got) != 2 || got[0] != "device:read" || got[1] != "tenant:read" {
		t.Fatalf("scopes = %v, want [device:read tenant:read]", got)
	}
}

type stubIAMProviderService struct {
	engine *quicbaassdk.IAMDomainPolicyEngine
	err    error
}

func (s stubIAMProviderService) GetPolicyEngine(context.Context) (*quicbaassdk.IAMDomainPolicyEngine, error) {
	return s.engine, s.err
}

type stubPlainService struct{}

func TestCertificatePrincipalPEP_ChoosesEngineAdapter(t *testing.T) {
	engine := newTestPolicyEngine()
	fallback := &mockSDKPEPClient{}
	pep, usesEngine := certificatePrincipalPEP(context.Background(), stubIAMProviderService{engine: engine}, fallback)
	adapter, ok := pep.(policyEnginePEP)
	if !usesEngine || !ok || adapter.engine != engine {
		t.Fatalf("got %T usesEngine=%v, want the policy engine adapter", pep, usesEngine)
	}
}

func TestCertificatePrincipalPEP_FallsBack(t *testing.T) {
	fallback := &mockSDKPEPClient{}
	for name, svc := range map[string]any{
		"no IAMProvider": stubPlainService{},
		"nil service":    nil,
		"nil engine":     stubIAMProviderService{},
		"engine error":   stubIAMProviderService{engine: newTestPolicyEngine(), err: errors.New("down")},
	} {
		pep, usesEngine := certificatePrincipalPEP(context.Background(), svc, fallback)
		if usesEngine || pep != sdkiam.PEPClient(fallback) {
			t.Fatalf("%s: got %T usesEngine=%v, want the fallback", name, pep, usesEngine)
		}
	}
}
