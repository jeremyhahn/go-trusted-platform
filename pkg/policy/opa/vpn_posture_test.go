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

package opa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

func newVPNPostureEngine(t *testing.T) *OPAEngine {
	t.Helper()
	engine := NewOPAEngine()
	require.NoError(t, engine.Initialize(context.Background(), &config.PolicyConfig{
		Engine:        config.PolicyEngineOPA,
		DefaultAction: config.DefaultActionDeny,
	}))
	t.Cleanup(func() { require.NoError(t, engine.Close()) })
	return engine
}

// compliantPosture is the input a fully compliant client with a passing
// verdict produces (docs/vpn/engineering.md §4).
func compliantPosture() map[string]interface{} {
	return map[string]interface{}{
		"posture": map[string]interface{}{
			"secure_boot":    map[string]interface{}{"enabled": true, "setup_mode": false, "available": true},
			"ima":            map[string]interface{}{"available": true, "enabled": true, "policy_loaded": true, "log_digest": "abcd"},
			"fde":            map[string]interface{}{"root_encrypted": true},
			"agent_version":  "0.1.0",
			"os_release":     "Alpine Linux v3.22",
			"kernel_release": "6.12.0",
			"collected_at":   "2026-09-08T12:00:00Z",
		},
		"verdict": map[string]interface{}{"passed": true, "cryptographic": true, "profile_id": 7},
	}
}

func ruleNames(result *EvaluationResult) []string {
	names := make([]string, 0, len(result.Violations))
	for _, v := range result.Violations {
		names = append(names, v.Rule)
	}
	return names
}

func TestVPNPosturePolicyLoaded(t *testing.T) {
	engine := newVPNPostureEngine(t)
	bundle, err := engine.GetPolicy("vpn_posture")
	require.NoError(t, err)
	assert.Equal(t, "data.vpn.posture", bundle.Package)
}

func TestVPNPosture_CompliantClientIsAllowed(t *testing.T) {
	engine := newVPNPostureEngine(t)
	result, err := engine.Evaluate(context.Background(), "vpn_posture", compliantPosture())
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Empty(t, result.Violations)
}

func TestVPNPosture_EachDriftIsANamedViolation(t *testing.T) {
	engine := newVPNPostureEngine(t)
	cases := map[string]struct {
		mutate func(in map[string]interface{})
		rule   string
	}{
		"secure boot off": {func(in map[string]interface{}) {
			in["posture"].(map[string]interface{})["secure_boot"].(map[string]interface{})["enabled"] = false
		}, "secure-boot-enabled"},
		"setup mode": {func(in map[string]interface{}) {
			in["posture"].(map[string]interface{})["secure_boot"].(map[string]interface{})["setup_mode"] = true
		}, "secure-boot-setup-mode"},
		"root not encrypted": {func(in map[string]interface{}) {
			in["posture"].(map[string]interface{})["fde"].(map[string]interface{})["root_encrypted"] = false
		}, "fde-root-encrypted"},
		"ima disabled": {func(in map[string]interface{}) {
			in["posture"].(map[string]interface{})["ima"].(map[string]interface{})["enabled"] = false
		}, "ima-enabled"},
		"ima policy missing": {func(in map[string]interface{}) {
			in["posture"].(map[string]interface{})["ima"].(map[string]interface{})["policy_loaded"] = false
		}, "ima-policy-loaded"},
		"agent version missing": {func(in map[string]interface{}) {
			delete(in["posture"].(map[string]interface{}), "agent_version")
		}, "agent-version"},
		"verdict failed": {func(in map[string]interface{}) {
			in["verdict"].(map[string]interface{})["passed"] = false
		}, "verdict-passed"},
		"verdict not cryptographic": {func(in map[string]interface{}) {
			in["verdict"].(map[string]interface{})["cryptographic"] = false
		}, "verdict-cryptographic"},
		"verdict missing": {func(in map[string]interface{}) { delete(in, "verdict") }, "verdict-required"},
		"posture missing": {func(in map[string]interface{}) { delete(in, "posture") }, "posture-required"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := compliantPosture()
			c.mutate(in)
			result, err := engine.Evaluate(context.Background(), "vpn_posture", in)
			require.NoError(t, err)
			assert.False(t, result.Allowed)
			assert.Contains(t, ruleNames(result), c.rule)
		})
	}
}

func TestVPNPosture_EmptyInputIsDenied(t *testing.T) {
	engine := newVPNPostureEngine(t)
	result, err := engine.Evaluate(context.Background(), "vpn_posture", map[string]interface{}{})
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.ElementsMatch(t, []string{"verdict-required", "posture-required"}, ruleNames(result))
}
