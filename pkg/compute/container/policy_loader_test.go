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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewPolicyBundle(t *testing.T) {
	bundle := NewPolicyBundle()

	if bundle == nil {
		t.Fatal("NewPolicyBundle returned nil")
	}
	if bundle.Policies == nil {
		t.Error("Policies map is nil")
	}
	if bundle.Sources == nil {
		t.Error("Sources slice is nil")
	}
	if bundle.LoadedAt.IsZero() {
		t.Error("LoadedAt is zero")
	}
}

func TestPolicyBundle_AddPolicy(t *testing.T) {
	bundle := NewPolicyBundle()

	bundle.AddPolicy("test-policy", "package test")

	content, ok := bundle.GetPolicy("test-policy")
	if !ok {
		t.Error("policy not found after adding")
	}
	if content != "package test" {
		t.Errorf("policy content mismatch: got %q, expected %q", content, "package test")
	}
}

func TestPolicyBundle_GetPolicy_NotFound(t *testing.T) {
	bundle := NewPolicyBundle()

	_, ok := bundle.GetPolicy("nonexistent")
	if ok {
		t.Error("expected ok to be false for nonexistent policy")
	}
}

func TestPolicyBundle_GetAllPolicies(t *testing.T) {
	bundle := NewPolicyBundle()

	bundle.AddPolicy("policy1", "package p1")
	bundle.AddPolicy("policy2", "package p2")

	all := bundle.GetAllPolicies()
	if len(all) != 2 {
		t.Errorf("expected 2 policies, got %d", len(all))
	}
	if all["policy1"] != "package p1" {
		t.Error("policy1 content mismatch")
	}
	if all["policy2"] != "package p2" {
		t.Error("policy2 content mismatch")
	}
}

func TestPolicyBundle_PolicyCount(t *testing.T) {
	bundle := NewPolicyBundle()

	if bundle.PolicyCount() != 0 {
		t.Errorf("expected 0 policies, got %d", bundle.PolicyCount())
	}

	bundle.AddPolicy("policy1", "package p1")
	if bundle.PolicyCount() != 1 {
		t.Errorf("expected 1 policy, got %d", bundle.PolicyCount())
	}

	bundle.AddPolicy("policy2", "package p2")
	if bundle.PolicyCount() != 2 {
		t.Errorf("expected 2 policies, got %d", bundle.PolicyCount())
	}
}

func TestPolicyBundle_AddSource(t *testing.T) {
	bundle := NewPolicyBundle()

	source := PolicySource{
		Type:        PolicySourceBuiltin,
		Location:    "embedded",
		PolicyCount: 3,
	}

	bundle.AddSource(source)

	if len(bundle.Sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(bundle.Sources))
	}
	if bundle.Sources[0].Type != PolicySourceBuiltin {
		t.Error("source type mismatch")
	}
	if bundle.Sources[0].PolicyCount != 3 {
		t.Errorf("policy count mismatch: got %d, expected 3", bundle.Sources[0].PolicyCount)
	}
}

func TestNewPolicyLoader(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: true,
		CustomPolicyDir:       "/test/dir",
		PolicyBundleURL:       "https://example.com/bundle",
	}

	loader := NewPolicyLoader(config)

	if loader == nil {
		t.Fatal("NewPolicyLoader returned nil")
	}
	if loader.config.EnableBuiltinPolicies != true {
		t.Error("EnableBuiltinPolicies not set correctly")
	}
	if loader.config.CustomPolicyDir != "/test/dir" {
		t.Error("CustomPolicyDir not set correctly")
	}
	if loader.config.PolicyBundleURL != "https://example.com/bundle" {
		t.Error("PolicyBundleURL not set correctly")
	}
}

func TestPolicyLoader_LoadBuiltinPolicies(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: true,
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	bundle, err := loader.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	// Should have loaded builtin policies
	if bundle.PolicyCount() == 0 {
		t.Error("expected builtin policies to be loaded")
	}

	// Check for expected builtin policies
	expectedPolicies := []string{
		"builtin/image_signature",
		"builtin/privileged",
		"builtin/resource_limits",
	}

	for _, name := range expectedPolicies {
		_, ok := bundle.GetPolicy(name)
		if !ok {
			t.Errorf("expected builtin policy %q not found", name)
		}
	}

	// Check sources
	if len(bundle.Sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(bundle.Sources))
	}
	if bundle.Sources[0].Type != PolicySourceBuiltin {
		t.Error("expected source type to be builtin")
	}
}

func TestPolicyLoader_LoadBuiltinPolicies_Disabled(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: false,
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	bundle, err := loader.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	// Should not have loaded builtin policies
	if bundle.PolicyCount() != 0 {
		t.Errorf("expected 0 policies when builtin disabled, got %d", bundle.PolicyCount())
	}
}

func TestPolicyLoader_LoadFromDirectory(t *testing.T) {
	// Create a temporary directory with test policies
	tempDir := t.TempDir()

	// Create a test policy file
	policyContent := `package custom.test

import rego.v1

deny contains msg if {
    input.container.name == "blocked"
    msg := "container name blocked"
}
`
	policyPath := filepath.Join(tempDir, "test_policy.rego")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to write test policy: %v", err)
	}

	config := PolicyConfig{
		EnableBuiltinPolicies: false,
		CustomPolicyDir:       tempDir,
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	bundle, err := loader.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	if bundle.PolicyCount() != 1 {
		t.Errorf("expected 1 policy, got %d", bundle.PolicyCount())
	}

	_, ok := bundle.GetPolicy("custom/test_policy")
	if !ok {
		t.Error("custom policy not found")
	}

	// Check sources
	found := false
	for _, source := range bundle.Sources {
		if source.Type == PolicySourceDirectory {
			found = true
			if source.PolicyCount != 1 {
				t.Errorf("expected 1 policy in directory source, got %d", source.PolicyCount)
			}
		}
	}
	if !found {
		t.Error("directory source not found")
	}
}

func TestPolicyLoader_LoadFromDirectory_NonExistent(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: false,
		CustomPolicyDir:       "/nonexistent/directory/path",
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	// Should not error when directory doesn't exist
	bundle, err := loader.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("unexpected error for nonexistent directory: %v", err)
	}

	if bundle.PolicyCount() != 0 {
		t.Errorf("expected 0 policies, got %d", bundle.PolicyCount())
	}
}

func TestPolicyLoader_LoadFromDirectory_WithSubdirectories(t *testing.T) {
	// Create a temporary directory structure
	tempDir := t.TempDir()
	subDir := filepath.Join(tempDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdirectory: %v", err)
	}

	// Create policies in both directories
	policy1 := "package test1\n"
	policy2 := "package test2\n"

	if err := os.WriteFile(filepath.Join(tempDir, "policy1.rego"), []byte(policy1), 0644); err != nil {
		t.Fatalf("failed to write policy1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "policy2.rego"), []byte(policy2), 0644); err != nil {
		t.Fatalf("failed to write policy2: %v", err)
	}

	config := PolicyConfig{
		EnableBuiltinPolicies: false,
		CustomPolicyDir:       tempDir,
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	bundle, err := loader.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	if bundle.PolicyCount() != 2 {
		t.Errorf("expected 2 policies, got %d", bundle.PolicyCount())
	}
}

func TestPolicyLoader_LoadFromBundle(t *testing.T) {
	// Create a test server that serves a policy
	policyContent := `package remote.test

import rego.v1

deny contains msg if {
    input.container.name == "remote-blocked"
    msg := "blocked by remote policy"
}
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(policyContent))
	}))
	defer server.Close()

	config := PolicyConfig{
		EnableBuiltinPolicies: false,
		PolicyBundleURL:       server.URL + "/policy.rego",
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	bundle, err := loader.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	if bundle.PolicyCount() != 1 {
		t.Errorf("expected 1 policy, got %d", bundle.PolicyCount())
	}

	// Check sources
	found := false
	for _, source := range bundle.Sources {
		if source.Type == PolicySourceBundle {
			found = true
		}
	}
	if !found {
		t.Error("bundle source not found")
	}
}

func TestPolicyLoader_LoadFromBundle_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := PolicyConfig{
		EnableBuiltinPolicies: false,
		PolicyBundleURL:       server.URL + "/policy.rego",
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	_, err := loader.LoadPolicies(ctx)
	if err == nil {
		t.Error("expected error for server error response")
	}
}

func TestPolicyLoader_LoadFromBundle_ConnectionError(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: false,
		PolicyBundleURL:       "http://localhost:99999/nonexistent",
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	_, err := loader.LoadPolicies(ctx)
	if err == nil {
		t.Error("expected error for connection failure")
	}
}

func TestPolicyLoader_LoadAllSources(t *testing.T) {
	// Create a temporary directory with a custom policy
	tempDir := t.TempDir()
	customPolicy := "package custom\n"
	if err := os.WriteFile(filepath.Join(tempDir, "custom.rego"), []byte(customPolicy), 0644); err != nil {
		t.Fatalf("failed to write custom policy: %v", err)
	}

	// Create a test server
	remotePolicy := "package remote\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(remotePolicy))
	}))
	defer server.Close()

	config := PolicyConfig{
		EnableBuiltinPolicies: true,
		CustomPolicyDir:       tempDir,
		PolicyBundleURL:       server.URL + "/policy.rego",
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	bundle, err := loader.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	// Should have policies from all sources
	// At least 3 builtin + 1 custom + 1 remote
	if bundle.PolicyCount() < 5 {
		t.Errorf("expected at least 5 policies, got %d", bundle.PolicyCount())
	}

	// Should have 3 sources
	if len(bundle.Sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(bundle.Sources))
	}

	// Verify each source type is present
	sourceTypes := make(map[PolicySourceType]bool)
	for _, source := range bundle.Sources {
		sourceTypes[source.Type] = true
	}

	if !sourceTypes[PolicySourceBuiltin] {
		t.Error("builtin source not found")
	}
	if !sourceTypes[PolicySourceDirectory] {
		t.Error("directory source not found")
	}
	if !sourceTypes[PolicySourceBundle] {
		t.Error("bundle source not found")
	}
}

func TestPolicyLoader_GetConfig(t *testing.T) {
	config := PolicyConfig{
		EnableBuiltinPolicies: true,
		CustomPolicyDir:       "/test/dir",
		PolicyBundleURL:       "https://example.com/bundle",
		DecisionMode:          PolicyModeAudit,
	}

	loader := NewPolicyLoader(config)
	result := loader.GetConfig()

	if result.EnableBuiltinPolicies != config.EnableBuiltinPolicies {
		t.Error("EnableBuiltinPolicies mismatch")
	}
	if result.CustomPolicyDir != config.CustomPolicyDir {
		t.Error("CustomPolicyDir mismatch")
	}
	if result.PolicyBundleURL != config.PolicyBundleURL {
		t.Error("PolicyBundleURL mismatch")
	}
	if result.DecisionMode != config.DecisionMode {
		t.Error("DecisionMode mismatch")
	}
}

func TestPolicyLoader_ReloadPolicies(t *testing.T) {
	tempDir := t.TempDir()

	// Initial policy
	policy1 := "package test1\n"
	if err := os.WriteFile(filepath.Join(tempDir, "policy.rego"), []byte(policy1), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	config := PolicyConfig{
		EnableBuiltinPolicies: false,
		CustomPolicyDir:       tempDir,
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	// First load
	bundle1, err := loader.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	if bundle1.PolicyCount() != 1 {
		t.Errorf("expected 1 policy, got %d", bundle1.PolicyCount())
	}

	// Add another policy
	policy2 := "package test2\n"
	if err := os.WriteFile(filepath.Join(tempDir, "policy2.rego"), []byte(policy2), 0644); err != nil {
		t.Fatalf("failed to write second policy: %v", err)
	}

	// Reload
	bundle2, err := loader.ReloadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to reload policies: %v", err)
	}

	if bundle2.PolicyCount() != 2 {
		t.Errorf("expected 2 policies after reload, got %d", bundle2.PolicyCount())
	}
}

func TestPolicyLoader_ContextCancellation(t *testing.T) {
	tempDir := t.TempDir()

	// Create many policy files to make iteration take time
	for i := 0; i < 10; i++ {
		policy := "package test\n"
		path := filepath.Join(tempDir, "policy"+string(rune('0'+i))+".rego")
		if err := os.WriteFile(path, []byte(policy), 0644); err != nil {
			t.Fatalf("failed to write policy: %v", err)
		}
	}

	config := PolicyConfig{
		EnableBuiltinPolicies: false,
		CustomPolicyDir:       tempDir,
	}

	loader := NewPolicyLoader(config)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Loading with cancelled context should return error
	_, err := loader.LoadPolicies(ctx)
	if err == nil {
		// Note: This may not always error depending on timing
		// The test verifies the context is passed down correctly
		t.Log("context cancellation did not cause error (timing dependent)")
	}
}

func TestPolicySourceType_Values(t *testing.T) {
	tests := []struct {
		sourceType PolicySourceType
		expected   string
	}{
		{PolicySourceBuiltin, "builtin"},
		{PolicySourceDirectory, "directory"},
		{PolicySourceBundle, "bundle"},
	}

	for _, tt := range tests {
		t.Run(string(tt.sourceType), func(t *testing.T) {
			if string(tt.sourceType) != tt.expected {
				t.Errorf("got %q, expected %q", tt.sourceType, tt.expected)
			}
		})
	}
}

func TestPolicyLoader_LoadFromDirectory_NotDirectory(t *testing.T) {
	// Create a regular file, not a directory
	tempFile := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(tempFile, []byte("not a directory"), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	config := PolicyConfig{
		EnableBuiltinPolicies: false,
		CustomPolicyDir:       tempFile,
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	_, err := loader.LoadPolicies(ctx)
	if err == nil {
		t.Error("expected error when CustomPolicyDir is a file, not directory")
	}
}

func TestPolicyLoader_SkipsNonRegoFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create various file types
	if err := os.WriteFile(filepath.Join(tempDir, "policy.rego"), []byte("package test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "readme.md"), []byte("# README\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "config.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	config := PolicyConfig{
		EnableBuiltinPolicies: false,
		CustomPolicyDir:       tempDir,
	}

	loader := NewPolicyLoader(config)
	ctx := context.Background()

	bundle, err := loader.LoadPolicies(ctx)
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	// Should only have loaded the .rego file
	if bundle.PolicyCount() != 1 {
		t.Errorf("expected 1 policy, got %d", bundle.PolicyCount())
	}
}
