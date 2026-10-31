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

package iam

import (
	"context"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingPolicyClient stores every policy the adapter creates, so a test
// can show what the SDK was asked to persist.
type recordingPolicyClient struct {
	iamsdk.PolicyClient
	created []*iamsdk.CreatePolicyRequest
}

func (c *recordingPolicyClient) Create(_ context.Context, tenantID string, req *iamsdk.CreatePolicyRequest) (*iamsdk.Policy, error) {
	c.created = append(c.created, req)
	return &iamsdk.Policy{Name: req.Name, TenantID: tenantID}, nil
}

type policySDKClient struct {
	iamsdk.Client
	policies *recordingPolicyClient
}

func (c policySDKClient) Policy() iamsdk.PolicyClient { return c.policies }

func createPolicyFromYAML(t *testing.T, specYAML string) (*recordingPolicyClient, error) {
	t.Helper()
	policies := &recordingPolicyClient{}
	_, err := NewQuicBaaSIAMAdapter(policySDKClient{policies: policies}).CreatePolicy(context.Background(), "tenant-a", &CreatePolicyRequest{
		Name:     "conditional",
		SpecYAML: specYAML,
	})
	return policies, err
}

// A conditional allow must never be stored as an unconditional one: the
// SDK's create keeps no condition, so the adapter refuses the policy.
func TestQuicBaaSIAMAdapter_CreatePolicy_RefusesConditions(t *testing.T) {
	cases := []struct {
		name      string
		specYAML  string
		condition string
	}{
		{"when on a flat rule", "rules:\n- name: office-hours\n  effect: allow\n  actions: [read]\n  resources: ['*']\n  when:\n  - time: business-hours\n", "when"},
		{"unless on a spec rule", "spec:\n  rules:\n  - name: not-quarantined\n    effect: allow\n    actions: [read]\n    resources: ['*']\n    unless:\n    - attribute: quarantined\n", "unless"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policies, err := createPolicyFromYAML(t, tc.specYAML)

			var unsupported ErrPolicyConditionUnsupported
			require.ErrorAs(t, err, &unsupported)
			assert.Equal(t, tc.condition, unsupported.Condition)
			assert.Contains(t, err.Error(), tc.condition)
			assert.Contains(t, err.Error(), "invalid policy spec")
			assert.Empty(t, policies.created, "a refused policy must not be stored")
		})
	}
}

func TestQuicBaaSIAMAdapter_CreatePolicy_KeepsUnconditionalRules(t *testing.T) {
	policies, err := createPolicyFromYAML(t, "rules:\n- name: readers\n  effect: allow\n  actions: [read]\n  resources: [users/*]\n")

	require.NoError(t, err)
	require.Len(t, policies.created, 1)
	require.Len(t, policies.created[0].Rules, 1)
	rule := policies.created[0].Rules[0]
	assert.Equal(t, "readers", rule.Name)
	assert.Equal(t, iamsdk.EffectAllow, rule.Effect)
	assert.Equal(t, []iamsdk.ActionMatcher{{Pattern: "read"}}, rule.Actions)
	assert.Equal(t, []iamsdk.ResourceMatcher{{Pattern: "users/*"}}, rule.Resources)
}

// An admin-only grant must never be stored as a grant to everyone: the
// SDK's create keeps no subject selector, and an empty selector matches
// every subject, so the adapter refuses the policy.
func TestQuicBaaSIAMAdapter_CreatePolicy_RefusesSubjectRestrictions(t *testing.T) {
	cases := []struct {
		name     string
		specYAML string
	}{
		{"roles under spec", "spec:\n  subjects:\n    roles: [admin]\n  rules:\n  - name: admins\n    effect: allow\n    actions: ['*']\n    resources: ['*']\n"},
		{"users on a flat document", "subjects:\n  users: [alice]\nrules:\n- name: alice\n  effect: allow\n  actions: [read]\n  resources: ['*']\n"},
		{"a nested group selector", "spec:\n  subjects:\n    groups:\n      ids: [ops]\n  rules:\n  - name: ops\n    effect: allow\n    actions: [read]\n    resources: ['*']\n"},
		{"a scalar selector", "spec:\n  subjects:\n    role: admin\n  rules:\n  - name: admins\n    effect: allow\n    actions: [read]\n    resources: ['*']\n"},
		{"a list of subjects", "spec:\n  subjects: [admin]\n  rules:\n  - name: admins\n    effect: allow\n    actions: [read]\n    resources: ['*']\n"},
		{"a non-string selector", "spec:\n  subjects:\n    uid: 7\n  rules:\n  - name: admins\n    effect: allow\n    actions: [read]\n    resources: ['*']\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policies, err := createPolicyFromYAML(t, tc.specYAML)

			var invalid ErrInvalidPolicySpec
			require.ErrorAs(t, err, &invalid)
			assert.Contains(t, err.Error(), "subject selectors")
			assert.Empty(t, policies.created, "a refused policy must not be stored")
		})
	}
}

func TestQuicBaaSIAMAdapter_CreatePolicy_EmptySubjectsStillCreate(t *testing.T) {
	policies, err := createPolicyFromYAML(t, "spec:\n  subjects:\n    roles: []\n    users: ''\n  rules:\n  - name: readers\n    effect: allow\n    actions: [read]\n    resources: ['*']\n")

	require.NoError(t, err)
	require.Len(t, policies.created, 1)
	require.Len(t, policies.created[0].Rules, 1)
	assert.Equal(t, "readers", policies.created[0].Rules[0].Name)
}

// A wildcard rule whose effect is not exactly "allow" or "deny" must be
// refused, not defaulted to allow: defaulted, it is a tenant-wide grant.
func TestQuicBaaSIAMAdapter_CreatePolicy_RefusesAnyOtherEffect(t *testing.T) {
	cases := []struct {
		name   string
		effect string
	}{
		{"a missing effect", ""},
		{"upper-case DENY", "\n  effect: DENY"},
		{"capitalised Allow", "\n  effect: Allow"},
		{"an unknown effect", "\n  effect: permit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policies, err := createPolicyFromYAML(t, "rules:\n- name: everything"+tc.effect+"\n  actions: ['*']\n  resources: ['*']\n")

			var invalid ErrInvalidPolicySpec
			require.ErrorAs(t, err, &invalid)
			assert.Contains(t, err.Error(), `must be exactly "allow" or "deny"`)
			assert.Empty(t, policies.created, "a refused policy must not be stored")
		})
	}
}

func TestQuicBaaSIAMAdapter_CreatePolicy_KeepsAllowAndDeny(t *testing.T) {
	for effect, want := range map[string]iamsdk.Effect{"allow": iamsdk.EffectAllow, "deny": iamsdk.EffectDeny} {
		t.Run(effect, func(t *testing.T) {
			policies, err := createPolicyFromYAML(t, "rules:\n- name: everything\n  effect: "+effect+"\n  actions: ['*']\n  resources: ['*']\n")

			require.NoError(t, err)
			require.Len(t, policies.created, 1)
			require.Len(t, policies.created[0].Rules, 1)
			assert.Equal(t, want, policies.created[0].Rules[0].Effect)
		})
	}
}
