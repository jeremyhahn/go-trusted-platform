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

// A build without the opa tag has no engine to compile a tenant posture
// policy in: every delivered policy is refused as unavailable, and the
// tenant's admissions fail closed (#1691). make test-noopa runs these.

//go:build !opa

package vpn

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
)

const noopaPostureModule = "package vpn.posture\nallow := true\n"

func TestCompilePosturePolicy_NoOPA_TheEngineIsUnavailable(t *testing.T) {
	engine, err := CompilePosturePolicy(context.Background(),
		PosturePolicy{TenantID: "t", Name: DefaultPosturePolicy, Module: noopaPostureModule})
	assert.Nil(t, engine)
	var unavailable *ErrPostureUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, "t", unavailable.TenantID)
	assert.Equal(t, DefaultPosturePolicy, unavailable.Name)
	var notBuilt opa.ErrOPANotBuilt
	assert.True(t, errors.As(err, &notBuilt), "the cause is the missing opa tag: %v", err)
}

func TestCompilePosturePolicy_NoOPA_AnEmptyModuleIsStillInvalid(t *testing.T) {
	_, err := CompilePosturePolicy(context.Background(),
		PosturePolicy{TenantID: "t", Name: DefaultPosturePolicy})
	var invalid *ErrPosturePolicyInvalid
	require.True(t, errors.As(err, &invalid), "got %v", err)
}

func TestAdmit_NoOPA_ATenantPolicyRefusesAsUnavailable(t *testing.T) {
	h := newHarness(t, testConfig())
	err := h.svc.SetPosturePolicies(context.Background(), []PosturePolicy{
		{TenantID: "tenant-a", Name: DefaultPosturePolicy, Module: noopaPostureModule},
	})
	var unavailable *ErrPostureUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)

	_, err = h.svc.Admit(context.Background(), h.request(t))
	require.True(t, errors.As(err, &unavailable), "the tenant fails closed: %v", err)
	assert.Equal(t, 0, h.posture.inputCount())
	require.Len(t, h.svc.PosturePolicyErrors(), 1)
	assert.Contains(t, h.svc.PosturePolicyErrors()[0], "opa build tag", "the operator is told why")
}

// TestSetPosturePolicies_NoOPA_EachRefusalNamesItsTenant pins that, with no
// engine built in, each tenant's refusal says which tenant it belongs to.
func TestSetPosturePolicies_NoOPA_EachRefusalNamesItsTenant(t *testing.T) {
	h := newHarness(t, testConfig())
	err := h.svc.SetPosturePolicies(context.Background(), []PosturePolicy{
		{TenantID: "tenant-a", Name: DefaultPosturePolicy, Module: noopaPostureModule},
		{TenantID: "tenant-b", Name: DefaultPosturePolicy, Module: noopaPostureModule},
	})
	joined, ok := err.(interface{ Unwrap() []error })
	require.True(t, ok, "a joined error: %v", err)
	var tenants []string
	for _, e := range joined.Unwrap() {
		var unavailable *ErrPostureUnavailable
		require.True(t, errors.As(e, &unavailable), "got %v", e)
		assert.Equal(t, DefaultPosturePolicy, unavailable.Name)
		tenants = append(tenants, unavailable.TenantID)
	}
	assert.ElementsMatch(t, []string{"tenant-a", "tenant-b"}, tenants)

	lines := h.svc.PosturePolicyErrors()
	require.Len(t, lines, 2)
	for i, tenant := range []string{"tenant-a", "tenant-b"} {
		assert.Contains(t, lines[i], tenant)
		assert.Contains(t, lines[i], "opa build tag", "the operator is told why")
	}
}
