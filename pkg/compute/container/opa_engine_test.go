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
	"testing"
)

func TestNewOPAEngine(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	if engine == nil {
		t.Fatal("NewOPAEngine returned nil")
	}
	if engine.modules == nil {
		t.Error("modules is nil")
	}
}

func TestOPAEngine_LoadBundle(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("test", `package test

import rego.v1

deny contains msg if {
    input.container.name == "blocked"
    msg := "container blocked"
}
`)

	ctx := context.Background()
	err = engine.LoadBundle(ctx, bundle)
	if err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	if len(engine.modules) != 1 {
		t.Errorf("expected 1 module, got %d", len(engine.modules))
	}
}

func TestOPAEngine_LoadBundle_InvalidRego(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("invalid", "this is not valid rego syntax {{{")

	ctx := context.Background()
	err = engine.LoadBundle(ctx, bundle)
	if err == nil {
		t.Error("expected error for invalid rego syntax")
	}
}

func TestOPAEngine_Evaluate_NoPolicies(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name: "test",
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allow {
		t.Error("expected Allow to be true with no policies")
	}
	if len(decision.Denied) != 0 {
		t.Errorf("expected no denials, got %d", len(decision.Denied))
	}
}

func TestOPAEngine_Evaluate_DenyRule(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("test", `package test

import rego.v1

deny contains msg if {
    input.container.name == "blocked"
    msg := "container name is blocked"
}
`)

	ctx := context.Background()
	if err := engine.LoadBundle(ctx, bundle); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	// Test with blocked container name
	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name: "blocked",
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allow {
		t.Error("expected Allow to be false")
	}
	if len(decision.Denied) == 0 {
		t.Error("expected denial reasons")
	}
}

func TestOPAEngine_Evaluate_AllowedInput(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("test", `package test

import rego.v1

deny contains msg if {
    input.container.name == "blocked"
    msg := "container name is blocked"
}
`)

	ctx := context.Background()
	if err := engine.LoadBundle(ctx, bundle); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	// Test with allowed container name
	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name: "allowed",
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allow {
		t.Errorf("expected Allow to be true, got denials: %v", decision.Denied)
	}
}

func TestOPAEngine_Evaluate_WarnRule(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("test", `package test

import rego.v1

warn contains msg if {
    input.container.name == "warning"
    msg := "container name triggers warning"
}
`)

	ctx := context.Background()
	if err := engine.LoadBundle(ctx, bundle); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name: "warning",
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allow {
		t.Error("expected Allow to be true with only warnings")
	}
	if len(decision.Warnings) == 0 {
		t.Error("expected warnings")
	}
}

func TestOPAEngine_Evaluate_MultiplePolicies(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("policy1", `package policy1

import rego.v1

deny contains msg if {
    input.container.privileged == true
    msg := "privileged not allowed"
}
`)
	bundle.AddPolicy("policy2", `package policy2

import rego.v1

deny contains msg if {
    input.container.name == "blocked"
    msg := "name is blocked"
}
`)

	ctx := context.Background()
	if err := engine.LoadBundle(ctx, bundle); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	// Test with both violations
	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name:       "blocked",
			Privileged: true,
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allow {
		t.Error("expected Allow to be false")
	}
	if len(decision.Denied) != 2 {
		t.Errorf("expected 2 denials, got %d: %v", len(decision.Denied), decision.Denied)
	}
}

func TestOPAEngine_Evaluate_ComplexInput(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("test", `package test

import rego.v1

deny contains msg if {
    input.image.registry != "trusted.registry.com"
    msg := sprintf("untrusted registry: %s", [input.image.registry])
}

deny contains msg if {
    input.container.resources.memory_limit > 4294967296
    msg := "memory limit exceeds 4GB"
}
`)

	ctx := context.Background()
	if err := engine.LoadBundle(ctx, bundle); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name: "test",
			Resources: ResourceLimitsInfo{
				MemoryLimit:    8589934592, // 8GB
				HasMemoryLimit: true,
			},
		},
		Image: OPAImageInfo{
			Registry:   "docker.io",
			Repository: "library/alpine",
			Tag:        "latest",
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allow {
		t.Error("expected Allow to be false")
	}
	if len(decision.Denied) != 2 {
		t.Errorf("expected 2 denials, got %d: %v", len(decision.Denied), decision.Denied)
	}
}

func TestOPAEngine_Close(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}

	// Close should succeed
	err = engine.Close()
	if err != nil {
		t.Errorf("unexpected error on close: %v", err)
	}

	// Double close should be safe
	err = engine.Close()
	if err != nil {
		t.Errorf("unexpected error on second close: %v", err)
	}

	// Operations after close should fail
	ctx := context.Background()
	_, err = engine.Evaluate(ctx, OPAPolicyInput{})
	if err == nil {
		t.Error("expected error when evaluating after close")
	}
}

func TestOPAEngine_LoadBundle_AfterClose(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}

	engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("test", "package test\n")

	ctx := context.Background()
	err = engine.LoadBundle(ctx, bundle)
	if err == nil {
		t.Error("expected error when loading after close")
	}
}

func TestOPAEngine_Evaluate_NestedInput(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("test", `package test

import rego.v1

deny contains msg if {
    input.device_profile.allow_privileged == false
    input.container.privileged == true
    msg := "privileged denied by device profile"
}

deny contains msg if {
    input.image.signature.verified == false
    msg := "image signature not verified"
}
`)

	ctx := context.Background()
	if err := engine.LoadBundle(ctx, bundle); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name:       "test",
			Privileged: true,
		},
		Image: OPAImageInfo{
			Registry: "docker.io",
			Signature: &OPASignatureInfo{
				Verified: false,
			},
		},
		DeviceProfile: &DeviceProfileInfo{
			Name:            "test-profile",
			AllowPrivileged: false,
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allow {
		t.Error("expected Allow to be false")
	}
	if len(decision.Denied) != 2 {
		t.Errorf("expected 2 denials, got %d: %v", len(decision.Denied), decision.Denied)
	}
}

func TestOPAEngine_Evaluate_ArrayResults(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("test", `package test

import rego.v1

deny contains msg if {
    some cap in input.container.capabilities.add
    dangerous_caps[cap]
    msg := sprintf("dangerous capability: %s", [cap])
}

dangerous_caps := {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"}
`)

	ctx := context.Background()
	if err := engine.LoadBundle(ctx, bundle); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name: "test",
			Capabilities: CapabilityConfig{
				Add: []string{"SYS_ADMIN", "NET_ADMIN"},
			},
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allow {
		t.Error("expected Allow to be false")
	}
	if len(decision.Denied) != 2 {
		t.Errorf("expected 2 denials, got %d: %v", len(decision.Denied), decision.Denied)
	}
}

func TestOPAEngine_LoadBundle_ClearsExisting(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Load first bundle
	bundle1 := NewPolicyBundle()
	bundle1.AddPolicy("policy1", `package policy1

import rego.v1

deny contains msg if {
    input.container.name == "first"
    msg := "first policy"
}
`)
	if err := engine.LoadBundle(ctx, bundle1); err != nil {
		t.Fatalf("failed to load first bundle: %v", err)
	}

	// Load second bundle
	bundle2 := NewPolicyBundle()
	bundle2.AddPolicy("policy2", `package policy2

import rego.v1

deny contains msg if {
    input.container.name == "second"
    msg := "second policy"
}
`)
	if err := engine.LoadBundle(ctx, bundle2); err != nil {
		t.Fatalf("failed to load second bundle: %v", err)
	}

	// Only second bundle should be active
	if len(engine.modules) != 1 {
		t.Errorf("expected 1 module, got %d", len(engine.modules))
	}

	// First policy should not trigger
	input := OPAPolicyInput{
		Container: ContainerPolicySpec{Name: "first"},
	}
	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Allow {
		t.Error("first policy should not be active")
	}

	// Second policy should trigger
	input.Container.Name = "second"
	decision, err = engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Allow {
		t.Error("second policy should be active")
	}
}

func TestOPAEngine_Evaluate_BooleanFields(t *testing.T) {
	engine, err := NewOPAEngine()
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}
	defer engine.Close()

	bundle := NewPolicyBundle()
	bundle.AddPolicy("test", `package test

import rego.v1

deny contains msg if {
    input.container.resources.has_memory_limit == false
    msg := "memory limit required"
}

deny contains msg if {
    input.container.resources.has_cpu_limit == false
    msg := "cpu limit required"
}
`)

	ctx := context.Background()
	if err := engine.LoadBundle(ctx, bundle); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	// Test without limits
	input := OPAPolicyInput{
		Container: ContainerPolicySpec{
			Name: "test",
			Resources: ResourceLimitsInfo{
				HasMemoryLimit: false,
				HasCPULimit:    false,
			},
		},
	}

	decision, err := engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Allow {
		t.Error("expected Allow to be false")
	}
	if len(decision.Denied) != 2 {
		t.Errorf("expected 2 denials, got %d", len(decision.Denied))
	}

	// Test with limits
	input.Container.Resources.HasMemoryLimit = true
	input.Container.Resources.HasCPULimit = true

	decision, err = engine.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Allow {
		t.Errorf("expected Allow to be true, got denials: %v", decision.Denied)
	}
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "simple package",
			content:  "package test\n",
			expected: "test",
		},
		{
			name:     "package with dots",
			content:  "package container.builtin.privileged\n",
			expected: "container.builtin.privileged",
		},
		{
			name:     "package after comments",
			content:  "# comment\npackage test\n",
			expected: "test",
		},
		{
			name:     "package with extra spaces",
			content:  "  package   test  \n",
			expected: "test",
		},
		{
			name:     "no package",
			content:  "deny := true\n",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPackageName(tt.content)
			if result != tt.expected {
				t.Errorf("extractPackageName() = %q, expected %q", result, tt.expected)
			}
		})
	}
}
