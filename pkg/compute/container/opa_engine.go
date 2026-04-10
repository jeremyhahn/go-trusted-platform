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

package container

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// OPAEngine wraps the OPA Rego engine for policy evaluation.
type OPAEngine struct {
	modules map[string]string
	closed  atomic.Bool
	mu      sync.RWMutex
}

// NewOPAEngine creates a new OPA engine instance.
func NewOPAEngine() (*OPAEngine, error) {
	return &OPAEngine{
		modules: make(map[string]string),
	}, nil
}

// LoadBundle loads a policy bundle into the engine.
func (e *OPAEngine) LoadBundle(ctx context.Context, bundle *PolicyBundle) error {
	if e.closed.Load() {
		return ErrOrchestratorClosed
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear existing modules
	e.modules = make(map[string]string)

	// Validate and store all policies
	policies := bundle.GetAllPolicies()
	for name, content := range policies {
		// Parse to validate
		_, err := ast.ParseModule(name+".rego", content)
		if err != nil {
			return err
		}
		e.modules[name] = content
	}

	return nil
}

// Evaluate evaluates loaded policies against the provided input.
func (e *OPAEngine) Evaluate(ctx context.Context, input OPAPolicyInput) (*OPAPolicyDecision, error) {
	if e.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Convert input to JSON-compatible map
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	var inputMap map[string]interface{}
	if err := json.Unmarshal(inputJSON, &inputMap); err != nil {
		return nil, err
	}

	decision := &OPAPolicyDecision{
		Allow:    true,
		Denied:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Evaluate each module
	for name, content := range e.modules {
		// Extract package name from content
		packageName := extractPackageName(content)
		if packageName == "" {
			continue
		}

		// Evaluate deny rules
		denyResults, err := e.evaluateRule(ctx, name, content, packageName, "deny", inputMap)
		if err != nil {
			// Continue on error - rule might not exist
			continue
		}

		for _, reason := range denyResults {
			decision.Denied = append(decision.Denied, name+": "+reason)
			decision.Allow = false
		}

		// Evaluate warn rules
		warnResults, err := e.evaluateRule(ctx, name, content, packageName, "warn", inputMap)
		if err != nil {
			// Warnings are non-fatal, continue on error
			continue
		}

		for _, reason := range warnResults {
			decision.Warnings = append(decision.Warnings, name+": "+reason)
		}
	}

	return decision, nil
}

// extractPackageName extracts the package name from Rego source code.
func extractPackageName(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			// Extract the package name and trim any extra whitespace
			packageName := strings.TrimPrefix(line, "package ")
			return strings.TrimSpace(packageName)
		}
	}
	return ""
}

// evaluateRule evaluates a specific rule (deny or warn) in a module.
func (e *OPAEngine) evaluateRule(ctx context.Context, name, content, packageName, rule string, input map[string]interface{}) ([]string, error) {
	// Build the query
	query := "data." + packageName + "." + rule

	r := rego.New(
		rego.Query(query),
		rego.Module(name+".rego", content),
		rego.Input(input),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, err
	}

	return extractStringResults(rs), nil
}

// extractStringResults extracts string values from Rego result sets.
func extractStringResults(rs rego.ResultSet) []string {
	results := make([]string, 0)

	for _, result := range rs {
		for _, expr := range result.Expressions {
			results = append(results, extractStringsFromValue(expr.Value)...)
		}
	}

	return results
}

// extractStringsFromValue recursively extracts strings from a value.
func extractStringsFromValue(v interface{}) []string {
	results := make([]string, 0)

	switch val := v.(type) {
	case string:
		results = append(results, val)
	case []interface{}:
		for _, item := range val {
			results = append(results, extractStringsFromValue(item)...)
		}
	case map[string]interface{}:
		for _, item := range val {
			results = append(results, extractStringsFromValue(item)...)
		}
	}

	return results
}

// Close releases resources held by the engine.
func (e *OPAEngine) Close() error {
	if e.closed.Swap(true) {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.modules = nil

	return nil
}
