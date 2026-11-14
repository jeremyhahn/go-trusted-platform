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

// The tenant posture policies compile in a real OPA engine; the !opa build's
// behaviour is tenant_posture_noopa_test.go (#1691).

//go:build opa

package vpn

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pinnedAgentPolicy admits only agent 9.9.9; the harness reports 0.1.0.
const pinnedAgentPolicy = `package vpn.posture

import rego.v1

default allow := false

allow if count(violations) == 0

violations contains {"rule": "agent-pinned", "message": "agent version is not pinned"} if {
	input.posture.agent_version != "9.9.9"
}
`

func TestCompilePosturePolicy_CompilesInAnIsolatedEngine(t *testing.T) {
	engine, err := CompilePosturePolicy(context.Background(), PosturePolicy{TenantID: "t", Name: DefaultPosturePolicy, Module: pinnedAgentPolicy})
	require.NoError(t, err)
	result, err := engine.Evaluate(context.Background(), DefaultPosturePolicy, map[string]interface{}{
		"posture": map[string]interface{}{"agent_version": "9.9.9"},
	})
	require.NoError(t, err)
	assert.True(t, result.Allowed, "the tenant module replaces the embedded default rather than merging with it")
}

func TestCompilePosturePolicy_RefusesBadModules(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"syntax":        "package vpn.posture\nallow if {",
		"wrong package": "package tenant.rules\n\nimport rego.v1\n\ndefault allow := true\n",
	}
	for name, module := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := CompilePosturePolicy(context.Background(), PosturePolicy{TenantID: "t", Name: "p", Module: module})
			var invalid *ErrPosturePolicyInvalid
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Equal(t, "t", invalid.TenantID)
		})
	}
}

func TestAdmit_EvaluatesTheTenantsOwnPosturePolicy(t *testing.T) {
	h := newHarness(t, testConfig())
	require.NoError(t, h.svc.SetPosturePolicies(context.Background(), []PosturePolicy{
		{TenantID: "tenant-a", Name: DefaultPosturePolicy, Module: pinnedAgentPolicy},
	}))

	_, err := h.svc.Admit(context.Background(), h.request(t))
	var violation *ErrPostureViolation
	require.True(t, errors.As(err, &violation), "got %v", err)
	assert.Equal(t, []string{"agent-pinned"}, violation.Violations)
	assert.Equal(t, 0, h.posture.inputCount(), "the gateway default is not consulted for a tenant with its own policy")
}

func TestAdmit_OtherTenantsKeepTheDefault(t *testing.T) {
	h := newHarness(t, testConfig())
	require.NoError(t, h.svc.SetPosturePolicies(context.Background(), []PosturePolicy{
		{TenantID: "tenant-b", Name: DefaultPosturePolicy, Module: pinnedAgentPolicy},
		{TenantID: "tenant-a", Name: "other-gateway-policy", Module: pinnedAgentPolicy},
	}))

	_, err := h.svc.Admit(context.Background(), h.request(t))
	require.NoError(t, err)
	assert.Equal(t, 1, h.posture.inputCount())
}

// TestAdmit_ABrokenTenantPolicyRefuses: a delivered policy that does not
// compile refuses its tenant; it never falls back to the default.
func TestAdmit_ABrokenTenantPolicyRefuses(t *testing.T) {
	h := newHarness(t, testConfig())
	err := h.svc.SetPosturePolicies(context.Background(), []PosturePolicy{
		{TenantID: "tenant-a", Name: DefaultPosturePolicy, Module: "package vpn.posture\nallow if {"},
	})
	var invalid *ErrPosturePolicyInvalid
	require.True(t, errors.As(err, &invalid), "got %v", err)

	_, err = h.svc.Admit(context.Background(), h.request(t))
	var unavailable *ErrPostureUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, 0, h.posture.inputCount())
	require.Len(t, h.svc.PosturePolicyErrors(), 1)
	assert.Contains(t, h.svc.PosturePolicyErrors()[0], "tenant-a")
}

func TestPosturePolicyErrors_EmptyWhenEveryPolicyCompiles(t *testing.T) {
	h := newHarness(t, testConfig())
	assert.Empty(t, h.svc.PosturePolicyErrors(), "nothing delivered, nothing refused")
	require.NoError(t, h.svc.SetPosturePolicies(context.Background(), []PosturePolicy{
		{TenantID: "tenant-a", Name: DefaultPosturePolicy, Module: pinnedAgentPolicy},
	}))
	assert.Empty(t, h.svc.PosturePolicyErrors())
}

func TestSetPosturePolicies_RefusesDuplicatesAndMissingTenant(t *testing.T) {
	h := newHarness(t, testConfig())
	err := h.svc.SetPosturePolicies(context.Background(), []PosturePolicy{
		{Name: DefaultPosturePolicy, Module: pinnedAgentPolicy},
		{TenantID: "tenant-a", Name: DefaultPosturePolicy, Module: pinnedAgentPolicy},
		{TenantID: "tenant-a", Name: DefaultPosturePolicy, Module: pinnedAgentPolicy},
	})
	var invalid *ErrPosturePolicyInvalid
	require.True(t, errors.As(err, &invalid), "got %v", err)

	_, err = h.svc.Admit(context.Background(), h.request(t))
	var unavailable *ErrPostureUnavailable
	assert.True(t, errors.As(err, &unavailable), "an ambiguous delivery refuses the tenant, got %v", err)
}
