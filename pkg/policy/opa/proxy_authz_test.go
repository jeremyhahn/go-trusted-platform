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

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newProxyAuthzEngine initializes an OPA engine carrying the embedded
// proxy_authz policy.
func newProxyAuthzEngine(t *testing.T) *OPAEngine {
	t.Helper()
	engine := NewOPAEngine()
	err := engine.Initialize(context.Background(), &config.PolicyConfig{
		Engine:        config.PolicyEngineOPA,
		DefaultAction: config.DefaultActionDeny,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, engine.Close())
	})
	return engine
}

// proxyAuthzInput builds the canonical proxy_authz input document.
func proxyAuthzInput(zone, routeID, method string, allowedMethods []string) map[string]interface{} {
	route := map[string]interface{}{"id": routeID}
	if allowedMethods != nil {
		route["allowed_methods"] = allowedMethods
	}
	return map[string]interface{}{
		"client":  map[string]interface{}{"id": "client-1", "zone": zone, "attested": false},
		"route":   route,
		"request": map[string]interface{}{"method": method, "path": "/api"},
	}
}

// TestProxyAuthzPolicyLoaded verifies the embedded proxy_authz policy loads
// with the expected package.
func TestProxyAuthzPolicyLoaded(t *testing.T) {
	engine := newProxyAuthzEngine(t)
	bundle, err := engine.GetPolicy("proxy_authz")
	require.NoError(t, err)
	assert.Equal(t, "data.proxy.authz", bundle.Package)
}

// TestProxyAuthzPolicyDecisions table-tests the allow and deny rules of the
// embedded proxy_authz policy.
func TestProxyAuthzPolicyDecisions(t *testing.T) {
	engine := newProxyAuthzEngine(t)
	tests := []struct {
		name          string
		input         map[string]interface{}
		wantAllow     bool
		wantViolation string
	}{
		{
			name:      "zone and route allow",
			input:     proxyAuthzInput("trusted", "api", "GET", nil),
			wantAllow: true,
		},
		{
			name:      "allowed method allows",
			input:     proxyAuthzInput("trusted", "api", "GET", []string{"GET", "POST"}),
			wantAllow: true,
		},
		{
			name:          "quarantine zone always denied",
			input:         proxyAuthzInput("quarantine", "api", "GET", nil),
			wantAllow:     false,
			wantViolation: "client zone is quarantined",
		},
		{
			name:          "method not in allowed set denied",
			input:         proxyAuthzInput("trusted", "api", "DELETE", []string{"GET"}),
			wantAllow:     false,
			wantViolation: "method DELETE not allowed for route api",
		},
		{
			name:      "missing zone denied",
			input:     proxyAuthzInput("", "api", "GET", nil),
			wantAllow: false,
		},
		{
			name:      "missing route id denied",
			input:     proxyAuthzInput("trusted", "", "GET", nil),
			wantAllow: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Evaluate(context.Background(), "proxy_authz", tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllow, result.Allowed)
			if tt.wantViolation != "" {
				require.NotEmpty(t, result.Violations)
				found := false
				for _, v := range result.Violations {
					if v.Message == tt.wantViolation {
						found = true
					}
				}
				assert.True(t, found, "violation %q not found in %v", tt.wantViolation, result.Violations)
			}
		})
	}
}
