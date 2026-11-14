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

package opa

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPolicy = `package test.policy

import rego.v1

default allow := false

allow if {
	input.user == "admin"
}

violations contains msg if {
	not allow
	msg := "access denied for non-admin users"
}
`

const testPolicyWithData = `package test.datacheck

import rego.v1

default allow := false

allow if {
	input.role in data.allowed_roles
}

violations contains msg if {
	not allow
	msg := sprintf("role %v not in allowed roles", [input.role])
}
`

const testPolicyWithStructuredViolations = `package test.structured

import rego.v1

default allow := false

allow if {
	input.action == "read"
}

violations contains violation if {
	not allow
	violation := {
		"rule": "action_check",
		"message": "action not permitted",
		"severity": "warning"
	}
}
`

func TestNewOPAEngine(t *testing.T) {
	t.Run("creates new engine instance", func(t *testing.T) {
		engine := NewOPAEngine()
		require.NotNil(t, engine)
		assert.NotNil(t, engine.policies)
		assert.NotNil(t, engine.store)
		assert.False(t, engine.IsInitialized())
	})
}

func TestOPAEngine_Initialize(t *testing.T) {
	t.Run("successful initialization with empty config", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}

		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)
		assert.True(t, engine.IsInitialized())
	})

	t.Run("loads policies from directory", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		tmpDir := t.TempDir()
		policyPath := filepath.Join(tmpDir, "test.rego")
		err := os.WriteFile(policyPath, []byte(testPolicy), 0644)
		require.NoError(t, err)

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			PolicyDir:     tmpDir,
			DefaultAction: config.DefaultActionDeny,
		}

		err = engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		policies := engine.ListPolicies()
		found := false
		for _, p := range policies {
			if p.Name == "test" {
				found = true
				break
			}
		}
		assert.True(t, found, "test policy should be loaded")
	})

	t.Run("error with nil config", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		err := engine.Initialize(ctx, nil)
		require.Error(t, err)

		var nilConfigErr ErrNilConfig
		assert.ErrorAs(t, err, &nilConfigErr)
	})

	t.Run("error with non-existent policy directory", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			PolicyDir:     "/non/existent/path",
			DefaultAction: config.DefaultActionDeny,
		}

		err := engine.Initialize(ctx, cfg)
		require.Error(t, err)

		var dirNotFoundErr ErrPolicyDirNotFound
		assert.ErrorAs(t, err, &dirNotFoundErr)
	})

	t.Run("error when already initialized", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}

		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.Initialize(ctx, cfg)
		require.Error(t, err)

		var alreadyInitErr ErrEngineAlreadyInitialized
		assert.ErrorAs(t, err, &alreadyInitErr)
	})

	t.Run("error with invalid policy in directory", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		tmpDir := t.TempDir()
		policyPath := filepath.Join(tmpDir, "invalid.rego")
		err := os.WriteFile(policyPath, []byte("this is not valid rego!!!"), 0644)
		require.NoError(t, err)

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			PolicyDir:     tmpDir,
			DefaultAction: config.DefaultActionDeny,
		}

		err = engine.Initialize(ctx, cfg)
		require.Error(t, err)
	})

	t.Run("policy directory is a file not directory", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "notadir")
		err := os.WriteFile(filePath, []byte("content"), 0644)
		require.NoError(t, err)

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			PolicyDir:     filePath,
			DefaultAction: config.DefaultActionDeny,
		}

		err = engine.Initialize(ctx, cfg)
		require.Error(t, err)

		var dirNotFoundErr ErrPolicyDirNotFound
		assert.ErrorAs(t, err, &dirNotFoundErr)
	})

	t.Run("skips subdirectories and non-rego files in policy directory", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		tmpDir := t.TempDir()

		// Create a subdirectory (should be skipped)
		subDir := filepath.Join(tmpDir, "subdir")
		err := os.Mkdir(subDir, 0755)
		require.NoError(t, err)

		// Create a non-.rego file (should be skipped)
		txtFile := filepath.Join(tmpDir, "readme.txt")
		err = os.WriteFile(txtFile, []byte("This is not a policy"), 0644)
		require.NoError(t, err)

		// Create a valid policy file
		policyPath := filepath.Join(tmpDir, "valid.rego")
		err = os.WriteFile(policyPath, []byte(testPolicy), 0644)
		require.NoError(t, err)

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			PolicyDir:     tmpDir,
			DefaultAction: config.DefaultActionDeny,
		}

		err = engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		// Should only have loaded the valid.rego file plus embedded policies
		_, err = engine.GetPolicy("valid")
		require.NoError(t, err)
	})
}

func TestOPAEngine_LoadPolicy(t *testing.T) {
	t.Run("successful policy load", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		policy, err := engine.GetPolicy("testpolicy")
		require.NoError(t, err)
		assert.Equal(t, "testpolicy", policy.Name)
		assert.Contains(t, policy.Content, "package test.policy")
	})

	t.Run("error when not initialized", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		err := engine.LoadPolicy(ctx, "test", []byte(testPolicy))
		require.Error(t, err)

		var notInitErr ErrEngineNotInitialized
		assert.ErrorAs(t, err, &notInitErr)
	})

	t.Run("error with empty name", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "", []byte(testPolicy))
		require.Error(t, err)

		var invalidNameErr ErrInvalidPolicyName
		assert.ErrorAs(t, err, &invalidNameErr)
	})

	t.Run("error with empty content", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte{})
		require.Error(t, err)

		var emptyContentErr ErrEmptyPolicyContent
		assert.ErrorAs(t, err, &emptyContentErr)
	})

	t.Run("error with invalid rego syntax", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "badpolicy", []byte("not valid rego code!!!"))
		require.Error(t, err)

		var invalidPolicyErr ErrInvalidPolicy
		assert.ErrorAs(t, err, &invalidPolicyErr)
	})

	t.Run("policy update replaces existing policy", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		// Load initial policy
		err = engine.LoadPolicy(ctx, "mypolicy", []byte(testPolicy))
		require.NoError(t, err)

		// Update with new policy content
		newPolicy := `package updated.policy
import rego.v1
default allow := true
`
		err = engine.LoadPolicy(ctx, "mypolicy", []byte(newPolicy))
		require.NoError(t, err)

		// Verify the policy was updated
		policy, err := engine.GetPolicy("mypolicy")
		require.NoError(t, err)
		assert.Contains(t, policy.Content, "package updated.policy")
	})

	t.Run("policy with compilation conflict causes rollback", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		// Load a valid policy first
		err = engine.LoadPolicy(ctx, "validpolicy", []byte(testPolicy))
		require.NoError(t, err)

		// Try to load a policy that parses but fails compilation
		// This policy references an undefined function
		conflictPolicy := `package conflict
import rego.v1

allow if {
	undefined_builtin_function(input.x)
}
`
		err = engine.LoadPolicy(ctx, "conflictpolicy", []byte(conflictPolicy))
		require.Error(t, err)

		// The conflict policy should not exist (rolled back)
		_, err = engine.GetPolicy("conflictpolicy")
		require.Error(t, err)

		// The valid policy should still exist
		_, err = engine.GetPolicy("validpolicy")
		require.NoError(t, err)
	})
}

func TestOPAEngine_UnloadPolicy(t *testing.T) {
	t.Run("successful policy unload", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		err = engine.UnloadPolicy(ctx, "testpolicy")
		require.NoError(t, err)

		_, err = engine.GetPolicy("testpolicy")
		require.Error(t, err)

		var notFoundErr ErrPolicyNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})

	t.Run("error when not initialized", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		err := engine.UnloadPolicy(ctx, "test")
		require.Error(t, err)

		var notInitErr ErrEngineNotInitialized
		assert.ErrorAs(t, err, &notInitErr)
	})

	t.Run("error when policy not found", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.UnloadPolicy(ctx, "nonexistent")
		require.Error(t, err)

		var notFoundErr ErrPolicyNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})
}

func TestOPAEngine_Evaluate(t *testing.T) {
	t.Run("successful evaluation allow", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		input := map[string]interface{}{
			"user": "admin",
		}

		result, err := engine.Evaluate(ctx, "testpolicy", input)
		require.NoError(t, err)
		assert.True(t, result.Allowed)
		assert.Equal(t, "testpolicy", result.PolicyName)
		assert.Empty(t, result.Violations)
	})

	t.Run("successful evaluation deny with violations", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		input := map[string]interface{}{
			"user": "guest",
		}

		result, err := engine.Evaluate(ctx, "testpolicy", input)
		require.NoError(t, err)
		assert.False(t, result.Allowed)
		assert.NotEmpty(t, result.Violations)
	})

	t.Run("error when not initialized", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		input := map[string]interface{}{"user": "admin"}
		_, err := engine.Evaluate(ctx, "test", input)
		require.Error(t, err)

		var notInitErr ErrEngineNotInitialized
		assert.ErrorAs(t, err, &notInitErr)
	})

	t.Run("error with nil input", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		_, err = engine.Evaluate(ctx, "testpolicy", nil)
		require.Error(t, err)

		var invalidInputErr ErrInvalidInput
		assert.ErrorAs(t, err, &invalidInputErr)
	})

	t.Run("error when policy not found", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		input := map[string]interface{}{"user": "admin"}
		_, err = engine.Evaluate(ctx, "nonexistent", input)
		require.Error(t, err)

		var notFoundErr ErrPolicyNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})

	t.Run("evaluation duration is recorded", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		input := map[string]interface{}{"user": "admin"}
		result, err := engine.Evaluate(ctx, "testpolicy", input)
		require.NoError(t, err)

		assert.Greater(t, result.Duration, time.Duration(0))
	})

	t.Run("default action allow when no rules match", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionAllow,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		minimalPolicy := `package minimal
import rego.v1
# No allow rule defined
`
		err = engine.LoadPolicy(ctx, "minimal", []byte(minimalPolicy))
		require.NoError(t, err)

		input := map[string]interface{}{"anything": "value"}
		result, err := engine.Evaluate(ctx, "minimal", input)
		require.NoError(t, err)
		// Default is allow when configured
		assert.True(t, result.Allowed)
		assert.Contains(t, result.Reason, "default action")
	})

	t.Run("default action deny when no rules match", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		minimalPolicy := `package minimal
import rego.v1
# No allow rule defined
`
		err = engine.LoadPolicy(ctx, "minimal", []byte(minimalPolicy))
		require.NoError(t, err)

		input := map[string]interface{}{"anything": "value"}
		result, err := engine.Evaluate(ctx, "minimal", input)
		require.NoError(t, err)
		// Default is deny when configured
		assert.False(t, result.Allowed)
		assert.Contains(t, result.Reason, "default action")
	})

	t.Run("evaluation with structured violations", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "structured", []byte(testPolicyWithStructuredViolations))
		require.NoError(t, err)

		input := map[string]interface{}{
			"action": "write",
		}

		result, err := engine.Evaluate(ctx, "structured", input)
		require.NoError(t, err)
		assert.False(t, result.Allowed)
		require.NotEmpty(t, result.Violations)

		// Verify structured violation fields were parsed correctly
		violation := result.Violations[0]
		assert.Equal(t, "action_check", violation.Rule)
		assert.Equal(t, "action not permitted", violation.Message)
		assert.Equal(t, ViolationSeverity("warning"), violation.Severity)
	})
}

func TestOPAEngine_EvaluateWithData(t *testing.T) {
	t.Run("evaluation with data deny", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "datacheck", []byte(testPolicyWithData))
		require.NoError(t, err)

		input := map[string]interface{}{
			"role": "attacker",
		}
		data := map[string]interface{}{
			"allowed_roles": []interface{}{"admin", "editor", "viewer"},
		}

		result, err := engine.EvaluateWithData(ctx, "datacheck", input, data)
		require.NoError(t, err)
		assert.False(t, result.Allowed)
		assert.NotEmpty(t, result.Violations)
	})

	t.Run("evaluation with nil data", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		input := map[string]interface{}{"user": "admin"}
		result, err := engine.EvaluateWithData(ctx, "testpolicy", input, nil)
		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})

	t.Run("evaluation with data update replaces existing data", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "datacheck", []byte(testPolicyWithData))
		require.NoError(t, err)

		input := map[string]interface{}{
			"role": "editor",
		}

		// First evaluation with initial data
		data1 := map[string]interface{}{
			"allowed_roles": []interface{}{"admin"},
		}
		result, err := engine.EvaluateWithData(ctx, "datacheck", input, data1)
		require.NoError(t, err)
		assert.False(t, result.Allowed, "editor should not be allowed with only admin role")

		// Second evaluation with updated data (replace operation path)
		data2 := map[string]interface{}{
			"allowed_roles": []interface{}{"admin", "editor"},
		}
		result, err = engine.EvaluateWithData(ctx, "datacheck", input, data2)
		require.NoError(t, err)
		assert.True(t, result.Allowed, "editor should be allowed after data update")
	})

	t.Run("evaluation with nested data structure", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		nestedPolicy := `package nested

import rego.v1

default allow := false

allow if {
	data.config.enabled == true
	input.user in data.config.users
}
`
		err = engine.LoadPolicy(ctx, "nested", []byte(nestedPolicy))
		require.NoError(t, err)

		input := map[string]interface{}{
			"user": "alice",
		}
		data := map[string]interface{}{
			"config": map[string]interface{}{
				"enabled": true,
				"users":   []interface{}{"alice", "bob"},
			},
		}

		result, err := engine.EvaluateWithData(ctx, "nested", input, data)
		require.NoError(t, err)
		assert.True(t, result.Allowed)
	})
}

func TestOPAEngine_ListPolicies(t *testing.T) {
	t.Run("returns all loaded policies", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "policy1", []byte(testPolicy))
		require.NoError(t, err)

		policy2 := `package another
import rego.v1
default allow := true
`
		err = engine.LoadPolicy(ctx, "policy2", []byte(policy2))
		require.NoError(t, err)

		policies := engine.ListPolicies()
		// May include embedded policies
		assert.GreaterOrEqual(t, len(policies), 2)

		names := make(map[string]bool)
		for _, p := range policies {
			names[p.Name] = true
		}
		assert.True(t, names["policy1"])
		assert.True(t, names["policy2"])
	})

	t.Run("returns empty list when no policies loaded", func(t *testing.T) {
		engine := NewOPAEngine()
		policies := engine.ListPolicies()
		assert.Empty(t, policies)
	})

	t.Run("returns copies not references", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		policies := engine.ListPolicies()
		for _, p := range policies {
			if p.Name == "testpolicy" {
				p.Name = "modified"
				break
			}
		}

		// Original should be unchanged
		original, err := engine.GetPolicy("testpolicy")
		require.NoError(t, err)
		assert.Equal(t, "testpolicy", original.Name)
	})
}

func TestOPAEngine_GetPolicy(t *testing.T) {
	t.Run("policy includes checksum", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		policy, err := engine.GetPolicy("testpolicy")
		require.NoError(t, err)
		assert.NotEmpty(t, policy.Checksum)
		// SHA-256 hex string should be 64 characters
		assert.Len(t, policy.Checksum, 64)
	})
}

func TestOPAEngine_Reload(t *testing.T) {
	t.Run("successful reload from directory", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		tmpDir := t.TempDir()
		policyPath := filepath.Join(tmpDir, "test.rego")
		err := os.WriteFile(policyPath, []byte(testPolicy), 0644)
		require.NoError(t, err)

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			PolicyDir:     tmpDir,
			DefaultAction: config.DefaultActionDeny,
		}
		err = engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		// Add a new policy file
		newPolicyPath := filepath.Join(tmpDir, "new.rego")
		newPolicy := `package newpolicy
import rego.v1
default allow := true
`
		err = os.WriteFile(newPolicyPath, []byte(newPolicy), 0644)
		require.NoError(t, err)

		err = engine.Reload(ctx)
		require.NoError(t, err)

		_, err = engine.GetPolicy("new")
		require.NoError(t, err)
	})

	t.Run("error when not initialized", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		err := engine.Reload(ctx)
		require.Error(t, err)

		var notInitErr ErrEngineNotInitialized
		assert.ErrorAs(t, err, &notInitErr)
	})

	t.Run("reload without policy directory", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		// Load a policy programmatically
		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		// Reload should clear programmatically loaded policies
		// but keep embedded policies
		err = engine.Reload(ctx)
		require.NoError(t, err)

		// The programmatically loaded policy should be gone
		_, err = engine.GetPolicy("testpolicy")
		require.Error(t, err)
	})

	t.Run("reload with invalid policy in directory returns error", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		tmpDir := t.TempDir()
		policyPath := filepath.Join(tmpDir, "valid.rego")
		err := os.WriteFile(policyPath, []byte(testPolicy), 0644)
		require.NoError(t, err)

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			PolicyDir:     tmpDir,
			DefaultAction: config.DefaultActionDeny,
		}
		err = engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		// Add an invalid policy file
		invalidPath := filepath.Join(tmpDir, "invalid.rego")
		err = os.WriteFile(invalidPath, []byte("this is not valid rego!!!"), 0644)
		require.NoError(t, err)

		err = engine.Reload(ctx)
		require.Error(t, err)
	})
}

func TestOPAEngine_Close(t *testing.T) {
	t.Run("successful close", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.Close()
		require.NoError(t, err)
		assert.False(t, engine.IsInitialized())
	})

	t.Run("close when not initialized", func(t *testing.T) {
		engine := NewOPAEngine()
		err := engine.Close()
		require.NoError(t, err)
	})

	t.Run("policies cleared after close", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		err = engine.Close()
		require.NoError(t, err)

		policies := engine.ListPolicies()
		assert.Empty(t, policies)
	})
}

func TestOPAEngine_Stats(t *testing.T) {
	t.Run("initial stats are zero", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		stats := engine.Stats()
		assert.Equal(t, int64(0), stats.EvaluationCount)
		assert.Equal(t, int64(0), stats.AllowedCount)
		assert.Equal(t, int64(0), stats.DeniedCount)
	})

	t.Run("stats updated after evaluations", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		// Evaluate allow
		_, err = engine.Evaluate(ctx, "testpolicy", map[string]interface{}{"user": "admin"})
		require.NoError(t, err)

		// Evaluate deny
		_, err = engine.Evaluate(ctx, "testpolicy", map[string]interface{}{"user": "guest"})
		require.NoError(t, err)

		stats := engine.Stats()
		assert.Equal(t, int64(2), stats.EvaluationCount)
		assert.Equal(t, int64(1), stats.AllowedCount)
		assert.Equal(t, int64(1), stats.DeniedCount)
		assert.NotZero(t, stats.AverageEvaluationTime)
	})

	t.Run("error count tracked", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		// Cause an error
		_, err = engine.Evaluate(ctx, "nonexistent", map[string]interface{}{})
		require.Error(t, err)

		stats := engine.Stats()
		assert.Equal(t, int64(1), stats.ErrorCount)
	})

	t.Run("last evaluation time tracked", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		initializedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		current := initializedAt
		engine.now = func() time.Time { return current }

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		stats := engine.Stats()
		assert.True(t, stats.LastEvaluationTime.IsZero(), "no evaluation yet")

		evaluatedAt := initializedAt.Add(time.Minute)
		current = evaluatedAt

		_, err = engine.Evaluate(ctx, "testpolicy", map[string]interface{}{"user": "admin"})
		require.NoError(t, err)

		stats = engine.Stats()
		assert.True(t, stats.InitializedAt.Equal(initializedAt), "InitializedAt = %v", stats.InitializedAt)
		assert.True(t, stats.LastEvaluationTime.Equal(evaluatedAt), "LastEvaluationTime = %v", stats.LastEvaluationTime)
	})

	t.Run("policy count in stats", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		initialStats := engine.Stats()
		initialCount := initialStats.PolicyCount

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		afterLoadStats := engine.Stats()
		assert.Equal(t, initialCount+1, afterLoadStats.PolicyCount)
	})
}

func TestOPAEngine_Concurrency(t *testing.T) {
	t.Run("concurrent evaluations", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func(id int) {
				user := "guest"
				if id%2 == 0 {
					user = "admin"
				}
				input := map[string]interface{}{"user": user}
				_, err := engine.Evaluate(ctx, "testpolicy", input)
				assert.NoError(t, err)
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		stats := engine.Stats()
		assert.Equal(t, int64(10), stats.EvaluationCount)
	})

	t.Run("concurrent load and evaluate", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		err = engine.LoadPolicy(ctx, "testpolicy", []byte(testPolicy))
		require.NoError(t, err)

		done := make(chan bool)

		// Concurrent evaluations
		for i := 0; i < 5; i++ {
			go func() {
				input := map[string]interface{}{"user": "admin"}
				engine.Evaluate(ctx, "testpolicy", input)
				done <- true
			}()
		}

		// Concurrent loads
		for i := 0; i < 3; i++ {
			go func(id int) {
				policy := `package concurrent` + string(rune('a'+id)) + `
import rego.v1
default allow := true
`
				engine.LoadPolicy(ctx, "concurrent"+string(rune('a'+id)), []byte(policy))
				done <- true
			}(i)
		}

		for i := 0; i < 8; i++ {
			<-done
		}
	})
}

func TestValidatePolicyName(t *testing.T) {
	t.Run("valid names", func(t *testing.T) {
		validNames := []string{
			"policy",
			"Policy",
			"my-policy",
			"my_policy",
			"policy123",
			"Policy-Name-123",
			"a",
		}
		for _, name := range validNames {
			err := validatePolicyName(name)
			assert.NoError(t, err, "name %q should be valid", name)
		}
	})

	t.Run("invalid names", func(t *testing.T) {
		invalidNames := []string{
			"",
			"123policy",
			"-policy",
			"_policy",
			"policy name",
			"policy.name",
			"policy/name",
		}
		for _, name := range invalidNames {
			err := validatePolicyName(name)
			assert.Error(t, err, "name %q should be invalid", name)
		}
	})

	t.Run("name too long", func(t *testing.T) {
		longName := strings.Repeat("a", maxPolicyNameLength+1)
		err := validatePolicyName(longName)
		assert.Error(t, err)
	})
}

func TestOPAEngine_EmbeddedPolicies(t *testing.T) {
	t.Run("embedded policies are loaded on initialize", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		policies := engine.ListPolicies()
		// There should be embedded policies (container, host, image, quote, vm)
		assert.GreaterOrEqual(t, len(policies), 1)

		// Check for at least one embedded policy
		names := make(map[string]bool)
		for _, p := range policies {
			names[p.Name] = true
		}

		// At least one of these embedded policies should exist
		hasEmbedded := names["container"] || names["host"] || names["image"] || names["quote"] || names["vm"]
		assert.True(t, hasEmbedded, "should have at least one embedded policy")
	})

	t.Run("directory policies override embedded policies with same name", func(t *testing.T) {
		engine := NewOPAEngine()
		ctx := context.Background()

		tmpDir := t.TempDir()

		// Create a policy with the same name as an embedded one
		policyPath := filepath.Join(tmpDir, "container.rego")
		overridePolicy := `package container.override
import rego.v1
default allow := true

# This is an override policy
`
		err := os.WriteFile(policyPath, []byte(overridePolicy), 0644)
		require.NoError(t, err)

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			PolicyDir:     tmpDir,
			DefaultAction: config.DefaultActionDeny,
		}
		err = engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		// The directory policy should override the embedded one
		policy, err := engine.GetPolicy("container")
		require.NoError(t, err)
		assert.Contains(t, policy.Content, "override")
	})
}
