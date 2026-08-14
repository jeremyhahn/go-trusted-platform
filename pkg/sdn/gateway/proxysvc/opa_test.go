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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// proxyAuthzInput builds a minimal proxy_authz input document.
func proxyAuthzInput(zone, method string, allowedMethods []string) map[string]any {
	route := map[string]any{"id": "api"}
	if allowedMethods != nil {
		methods := make([]any, 0, len(allowedMethods))
		for _, m := range allowedMethods {
			methods = append(methods, m)
		}
		route["allowed_methods"] = methods
	}
	return map[string]any{
		"client":  map[string]any{"id": "device-1", "zone": zone},
		"route":   route,
		"request": map[string]any{"method": method, "path": "/api"},
	}
}

func TestNewOPAEvaluatorDisabled(t *testing.T) {
	var disabled *ErrOPADisabled
	if _, err := NewOPAEvaluator(context.Background(), nil); !errors.As(err, &disabled) {
		t.Errorf("nil config error = %v, want *ErrOPADisabled", err)
	}
	if _, err := NewOPAEvaluator(context.Background(), &OPAConfig{}); !errors.As(err, &disabled) {
		t.Errorf("disabled config error = %v, want *ErrOPADisabled", err)
	}
}

func TestNewOPAEvaluatorBadPolicyDir(t *testing.T) {
	if _, err := NewOPAEvaluator(context.Background(), &OPAConfig{
		Enabled:   true,
		PolicyDir: "/nonexistent/policy/dir",
	}); err == nil {
		t.Fatal("expected error for missing policy dir")
	}
}

func TestOPAEvaluatorProxyAuthz(t *testing.T) {
	eval, err := NewOPAEvaluator(context.Background(), &OPAConfig{Enabled: true})
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}
	ctx := context.Background()

	t.Run("authenticated zone allows", func(t *testing.T) {
		allowed, violations, err := eval.Evaluate(ctx, "proxy_authz", proxyAuthzInput("trusted", "GET", nil))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !allowed || len(violations) != 0 {
			t.Errorf("allowed=%v violations=%v, want allow", allowed, violations)
		}
	})

	t.Run("quarantine zone denies", func(t *testing.T) {
		allowed, violations, err := eval.Evaluate(ctx, "proxy_authz", proxyAuthzInput("quarantine", "GET", nil))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if allowed {
			t.Error("quarantined client must be denied")
		}
		found := false
		for _, v := range violations {
			if strings.Contains(v, "quarantined") {
				found = true
			}
		}
		if !found {
			t.Errorf("violations = %v, want quarantine message", violations)
		}
	})

	t.Run("empty zone denies by default", func(t *testing.T) {
		allowed, _, err := eval.Evaluate(ctx, "proxy_authz", proxyAuthzInput("", "GET", nil))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if allowed {
			t.Error("zoneless client must be denied by the default-deny rule")
		}
	})

	t.Run("method not in allowed methods denies", func(t *testing.T) {
		allowed, violations, err := eval.Evaluate(ctx, "proxy_authz",
			proxyAuthzInput("trusted", "DELETE", []string{"GET", "POST"}))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if allowed {
			t.Error("disallowed method must be denied")
		}
		found := false
		for _, v := range violations {
			if strings.Contains(v, "method DELETE not allowed") {
				found = true
			}
		}
		if !found {
			t.Errorf("violations = %v, want method message", violations)
		}
	})

	t.Run("method in allowed methods allows", func(t *testing.T) {
		allowed, _, err := eval.Evaluate(ctx, "proxy_authz",
			proxyAuthzInput("trusted", "GET", []string{"GET", "POST"}))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !allowed {
			t.Error("allowed method must pass")
		}
	})

	t.Run("unknown policy errors", func(t *testing.T) {
		if _, _, err := eval.Evaluate(ctx, "no_such_policy", proxyAuthzInput("trusted", "GET", nil)); err == nil {
			t.Fatal("unknown policy must error")
		}
	})
}

func TestOPAEvaluatorPolicyDirOverlay(t *testing.T) {
	dir := t.TempDir()
	policy := `package proxy.custom

import rego.v1

default allow := false

allow if {
	input.client.id == "device-1"
	count(violations) == 0
}

violations contains msg if {
	input.request.method == "DELETE"
	msg := "deletes are forbidden"
}
`
	if err := os.WriteFile(filepath.Join(dir, "proxy_custom.rego"), []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	eval, err := NewOPAEvaluator(context.Background(), &OPAConfig{Enabled: true, PolicyDir: dir})
	if err != nil {
		t.Fatalf("NewOPAEvaluator: %v", err)
	}
	ctx := context.Background()

	allowed, _, err := eval.Evaluate(ctx, "proxy_custom", proxyAuthzInput("trusted", "GET", nil))
	if err != nil {
		t.Fatalf("Evaluate custom: %v", err)
	}
	if !allowed {
		t.Error("custom policy must allow device-1 GET")
	}
	allowed, violations, err := eval.Evaluate(ctx, "proxy_custom", proxyAuthzInput("trusted", "DELETE", nil))
	if err != nil {
		t.Fatalf("Evaluate custom deny: %v", err)
	}
	if allowed || len(violations) != 1 {
		t.Errorf("allowed=%v violations=%v, want deny with one violation", allowed, violations)
	}

	// The embedded proxy_authz policy stays available alongside the overlay.
	if _, _, err := eval.Evaluate(ctx, "proxy_authz", proxyAuthzInput("trusted", "GET", nil)); err != nil {
		t.Errorf("embedded policy unavailable with overlay dir: %v", err)
	}
}
