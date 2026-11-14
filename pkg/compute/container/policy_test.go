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

//go:build opa

package container

import (
	"context"
	"testing"
)

func TestPolicyDecisionMode_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		mode     PolicyDecisionMode
		expected bool
	}{
		{
			name:     "enforce mode is valid",
			mode:     PolicyModeEnforce,
			expected: true,
		},
		{
			name:     "audit mode is valid",
			mode:     PolicyModeAudit,
			expected: true,
		},
		{
			name:     "disabled mode is valid",
			mode:     PolicyModeDisabled,
			expected: true,
		},
		{
			name:     "empty mode is invalid",
			mode:     "",
			expected: false,
		},
		{
			name:     "unknown mode is invalid",
			mode:     PolicyDecisionMode("unknown"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.mode.IsValid()
			if result != tt.expected {
				t.Errorf("IsValid() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestPolicyDecisionMode_String(t *testing.T) {
	tests := []struct {
		name     string
		mode     PolicyDecisionMode
		expected string
	}{
		{
			name:     "enforce mode string",
			mode:     PolicyModeEnforce,
			expected: "enforce",
		},
		{
			name:     "audit mode string",
			mode:     PolicyModeAudit,
			expected: "audit",
		},
		{
			name:     "disabled mode string",
			mode:     PolicyModeDisabled,
			expected: "disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.mode.String()
			if result != tt.expected {
				t.Errorf("String() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestPolicyConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      PolicyConfig
		expectError bool
	}{
		{
			name:        "empty config is valid",
			config:      PolicyConfig{},
			expectError: false,
		},
		{
			name: "valid config with enforce mode",
			config: PolicyConfig{
				EnableBuiltinPolicies: true,
				DecisionMode:          PolicyModeEnforce,
			},
			expectError: false,
		},
		{
			name: "valid config with audit mode",
			config: PolicyConfig{
				EnableBuiltinPolicies: true,
				DecisionMode:          PolicyModeAudit,
			},
			expectError: false,
		},
		{
			name: "valid config with disabled mode",
			config: PolicyConfig{
				DecisionMode: PolicyModeDisabled,
			},
			expectError: false,
		},
		{
			name: "valid config with custom policy dir",
			config: PolicyConfig{
				EnableBuiltinPolicies: true,
				CustomPolicyDir:       "/etc/platformd/policies",
			},
			expectError: false,
		},
		{
			name: "valid config with bundle URL",
			config: PolicyConfig{
				PolicyBundleURL: "https://example.com/policies.rego",
			},
			expectError: false,
		},
		{
			name: "invalid decision mode",
			config: PolicyConfig{
				DecisionMode: PolicyDecisionMode("invalid"),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestPolicyConfig_GetDecisionMode(t *testing.T) {
	tests := []struct {
		name     string
		config   PolicyConfig
		expected PolicyDecisionMode
	}{
		{
			name:     "empty mode defaults to enforce",
			config:   PolicyConfig{},
			expected: PolicyModeEnforce,
		},
		{
			name: "explicit enforce mode",
			config: PolicyConfig{
				DecisionMode: PolicyModeEnforce,
			},
			expected: PolicyModeEnforce,
		},
		{
			name: "audit mode",
			config: PolicyConfig{
				DecisionMode: PolicyModeAudit,
			},
			expected: PolicyModeAudit,
		},
		{
			name: "disabled mode",
			config: PolicyConfig{
				DecisionMode: PolicyModeDisabled,
			},
			expected: PolicyModeDisabled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetDecisionMode()
			if result != tt.expected {
				t.Errorf("GetDecisionMode() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestNewContainerPolicyEvaluator(t *testing.T) {
	tests := []struct {
		name        string
		config      PolicyConfig
		expectError bool
	}{
		{
			name:        "default config succeeds",
			config:      PolicyConfig{},
			expectError: false,
		},
		{
			name: "config with builtin policies",
			config: PolicyConfig{
				EnableBuiltinPolicies: true,
			},
			expectError: false,
		},
		{
			name: "invalid config fails",
			config: PolicyConfig{
				DecisionMode: PolicyDecisionMode("invalid"),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator, err := NewContainerPolicyEvaluator(tt.config)
			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if evaluator != nil {
				evaluator.Close()
			}
		})
	}
}

func TestContainerPolicyEvaluator_Evaluate_DisabledMode(t *testing.T) {
	config := PolicyConfig{
		DecisionMode: PolicyModeDisabled,
	}

	evaluator, err := NewContainerPolicyEvaluator(config)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}
	defer evaluator.Close()

	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name:       "test-container",
			Privileged: true,
		},
	}

	ctx := context.Background()
	decision, err := evaluator.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allow {
		t.Error("expected Allow to be true in disabled mode")
	}
}

func TestContainerPolicyEvaluator_ShouldBlock(t *testing.T) {
	tests := []struct {
		name        string
		mode        PolicyDecisionMode
		decision    OPAPolicyDecision
		shouldBlock bool
	}{
		{
			name: "enforce mode blocks denied",
			mode: PolicyModeEnforce,
			decision: OPAPolicyDecision{
				Allow:  false,
				Denied: []string{"test denial"},
			},
			shouldBlock: true,
		},
		{
			name: "enforce mode allows permitted",
			mode: PolicyModeEnforce,
			decision: OPAPolicyDecision{
				Allow: true,
			},
			shouldBlock: false,
		},
		{
			name: "audit mode does not block",
			mode: PolicyModeAudit,
			decision: OPAPolicyDecision{
				Allow:  false,
				Denied: []string{"test denial"},
			},
			shouldBlock: false,
		},
		{
			name: "disabled mode does not block",
			mode: PolicyModeDisabled,
			decision: OPAPolicyDecision{
				Allow:  false,
				Denied: []string{"test denial"},
			},
			shouldBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := PolicyConfig{
				DecisionMode: tt.mode,
			}

			evaluator, err := NewContainerPolicyEvaluator(config)
			if err != nil {
				t.Fatalf("failed to create evaluator: %v", err)
			}
			defer evaluator.Close()

			result := evaluator.ShouldBlock(&tt.decision)
			if result != tt.shouldBlock {
				t.Errorf("ShouldBlock() = %v, expected %v", result, tt.shouldBlock)
			}
		})
	}
}

func TestContainerPolicyEvaluator_LoadAndEvaluate(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: true,
		DecisionMode:          PolicyModeEnforce,
	}

	evaluator, err := NewContainerPolicyEvaluator(config)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}
	defer evaluator.Close()

	ctx := context.Background()

	// Load policies
	err = evaluator.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	// Test with valid input (has resource limits)
	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name:       "test-container",
			Privileged: false,
			Resources: ResourceLimitsInfo{
				MemoryLimit:    1073741824, // 1GB
				CPULimit:       1.0,
				HasMemoryLimit: true,
				HasCPULimit:    true,
			},
		},
		Image: OPAImageInfo{
			Registry:   "docker.io",
			Repository: "library/alpine",
			Tag:        "latest",
		},
	}

	decision, err := evaluator.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allow {
		t.Errorf("expected Allow to be true, got denials: %v", decision.Denied)
	}
}

func TestContainerPolicyEvaluator_PrivilegedDenial(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: true,
		DecisionMode:          PolicyModeEnforce,
	}

	evaluator, err := NewContainerPolicyEvaluator(config)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}
	defer evaluator.Close()

	ctx := context.Background()

	err = evaluator.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	// Test privileged container without approval
	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name:            "test-container",
			Privileged:      true,
			AllowPrivileged: false,
			Resources: ResourceLimitsInfo{
				MemoryLimit:    1073741824,
				CPULimit:       1.0,
				HasMemoryLimit: true,
				HasCPULimit:    true,
			},
		},
		Image: OPAImageInfo{
			Registry:   "docker.io",
			Repository: "library/alpine",
			Tag:        "latest",
		},
	}

	decision, err := evaluator.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allow {
		t.Error("expected Allow to be false for privileged container without approval")
	}

	if len(decision.Denied) == 0 {
		t.Error("expected denial reasons")
	}
}

func TestContainerPolicyEvaluator_ResourceLimitsDenial(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: true,
		DecisionMode:          PolicyModeEnforce,
	}

	evaluator, err := NewContainerPolicyEvaluator(config)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}
	defer evaluator.Close()

	ctx := context.Background()

	err = evaluator.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	// Test container without resource limits
	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name: "test-container",
			Resources: ResourceLimitsInfo{
				HasMemoryLimit: false,
				HasCPULimit:    false,
			},
		},
		Image: OPAImageInfo{
			Registry:   "docker.io",
			Repository: "library/alpine",
			Tag:        "latest",
		},
	}

	decision, err := evaluator.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allow {
		t.Error("expected Allow to be false for container without resource limits")
	}

	if len(decision.Denied) == 0 {
		t.Error("expected denial reasons for missing resource limits")
	}
}

func TestContainerPolicyEvaluator_Close(t *testing.T) {
	config := PolicyConfig{}

	evaluator, err := NewContainerPolicyEvaluator(config)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	// Close should succeed
	err = evaluator.Close()
	if err != nil {
		t.Errorf("unexpected error on close: %v", err)
	}

	// Double close should be safe
	err = evaluator.Close()
	if err != nil {
		t.Errorf("unexpected error on second close: %v", err)
	}

	// Operations after close should fail
	ctx := context.Background()
	_, err = evaluator.Evaluate(ctx, OPAPolicyInput{})
	if err == nil {
		t.Error("expected error when evaluating after close")
	}
}

func TestContainerPolicyEvaluator_GetConfig(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: true,
		CustomPolicyDir:       "/test/dir",
		DecisionMode:          PolicyModeAudit,
	}

	evaluator, err := NewContainerPolicyEvaluator(config)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}
	defer evaluator.Close()

	result := evaluator.GetConfig()
	if result.EnableBuiltinPolicies != config.EnableBuiltinPolicies {
		t.Errorf("EnableBuiltinPolicies mismatch: got %v, expected %v",
			result.EnableBuiltinPolicies, config.EnableBuiltinPolicies)
	}
	if result.CustomPolicyDir != config.CustomPolicyDir {
		t.Errorf("CustomPolicyDir mismatch: got %v, expected %v",
			result.CustomPolicyDir, config.CustomPolicyDir)
	}
	if result.DecisionMode != config.DecisionMode {
		t.Errorf("DecisionMode mismatch: got %v, expected %v",
			result.DecisionMode, config.DecisionMode)
	}
}

func TestOPAPolicyDecision_ToLegacyDecision(t *testing.T) {
	decision := OPAPolicyDecision{
		Allow:    false,
		Denied:   []string{"reason1", "reason2"},
		Warnings: []string{"warning1"},
	}

	input := &PolicyInput{
		Container: &OrchestratorContainerSpec{Name: "test"},
	}

	legacy := decision.ToLegacyDecision("test-policy", input)

	if legacy.Allowed != decision.Allow {
		t.Error("Allowed field mismatch")
	}
	if len(legacy.Reasons) != len(decision.Denied) {
		t.Error("Reasons field mismatch")
	}
	if len(legacy.Warnings) != len(decision.Warnings) {
		t.Error("Warnings field mismatch")
	}
	if legacy.PolicyName != "test-policy" {
		t.Error("PolicyName not set correctly")
	}
	if legacy.Timestamp.IsZero() {
		t.Error("Timestamp not set")
	}
}

func TestContainerPolicyEvaluator_EvaluateLegacy(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: true,
		DecisionMode:          PolicyModeEnforce,
	}

	evaluator, err := NewContainerPolicyEvaluator(config)
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}
	defer evaluator.Close()

	ctx := context.Background()

	err = evaluator.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	input := &PolicyInput{
		Container: &OrchestratorContainerSpec{
			Name:       "test-container",
			Privileged: false,
			Resources: ResourceConfig{
				MemoryLimit: "1G",
				CPULimit:    "1",
			},
		},
		Image: &ImageInfo{
			Registry:   "docker.io",
			Repository: "library/alpine",
			Tag:        "latest",
		},
	}

	decision, err := evaluator.EvaluateLegacy(ctx, "test-policy", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision == nil {
		t.Fatal("decision is nil")
	}
	if decision.PolicyName != "test-policy" {
		t.Errorf("PolicyName mismatch: got %v, expected test-policy", decision.PolicyName)
	}
}
