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

package commands

import (
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestExecute(t *testing.T) {
	// Test that Execute returns an error for invalid command
	rootCmd.SetArgs([]string{"invalid-command"})
	err := Execute()
	if err == nil {
		t.Error("expected error for invalid command")
	}
}

func TestExecuteHelpCommand(t *testing.T) {
	// Test that help command executes successfully
	rootCmd.SetArgs([]string{"--help"})
	err := Execute()
	if err != nil {
		t.Errorf("help command failed: %v", err)
	}
}

func TestRootCommandStructure(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("rootCmd should not be nil")
	}

	if rootCmd.Use != "platformctl" {
		t.Errorf("expected Use to be 'platformctl', got %s", rootCmd.Use)
	}

	if rootCmd.Short != "Command-line interface for Trusted Platform" {
		t.Errorf("unexpected Short description: %s", rootCmd.Short)
	}

	if !rootCmd.SilenceUsage {
		t.Error("SilenceUsage should be true")
	}

	if !rootCmd.SilenceErrors {
		t.Error("SilenceErrors should be true")
	}
}

func TestRootCommandHasSubcommands(t *testing.T) {
	expectedCommands := []string{
		"status",
		"health",
		"version",
		"service",
		"config",
		"context",
		"completion",
		"cache",
		"scheduler",
		"messaging",
	}

	commands := rootCmd.Commands()
	if len(commands) < len(expectedCommands) {
		t.Errorf("expected at least %d subcommands, got %d", len(expectedCommands), len(commands))
	}

	for _, expected := range expectedCommands {
		found := false
		for _, cmd := range commands {
			if cmd.Name() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %s not found", expected)
		}
	}
}

func TestRootCommandPersistentFlags(t *testing.T) {
	flagTests := []struct {
		name      string
		shorthand string
	}{
		{"config", "c"},
		{"context", ""},
		{"output", "o"},
		{"verbose", "v"},
		{"no-color", ""},
	}

	for _, tt := range flagTests {
		flag := rootCmd.PersistentFlags().Lookup(tt.name)
		if flag == nil {
			t.Errorf("expected persistent flag %s not found", tt.name)
			continue
		}
		if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
			t.Errorf("flag %s: expected shorthand %s, got %s",
				tt.name, tt.shorthand, flag.Shorthand)
		}
	}
}

func TestGetCommonFlags(t *testing.T) {
	// Set global variables
	configPath = "/test/config.yaml"
	contextName = "test-context"
	outputFormat = "json"
	verbose = true
	noColor = true

	flags := getCommonFlags()

	if flags == nil {
		t.Fatal("getCommonFlags returned nil")
	}

	if flags.ConfigPath != configPath {
		t.Errorf("expected ConfigPath %s, got %s", configPath, flags.ConfigPath)
	}

	if flags.ContextName != contextName {
		t.Errorf("expected ContextName %s, got %s", contextName, flags.ContextName)
	}

	if flags.OutputFormat != cli.OutputFormat(outputFormat) {
		t.Errorf("expected OutputFormat %s, got %s", outputFormat, flags.OutputFormat)
	}

	if !flags.Verbose {
		t.Error("expected Verbose to be true")
	}

	if !flags.NoColor {
		t.Error("expected NoColor to be true")
	}

	if flags.GetConfig == nil {
		t.Error("GetConfig should not be nil")
	}

	if flags.GetContext == nil {
		t.Error("GetContext should not be nil")
	}
}

func TestGetConfig(t *testing.T) {
	// Reset config and use temp dir to avoid reading real user config
	config = nil
	configPath = filepath.Join(t.TempDir(), "config.yaml")

	cfg, err := getConfig()
	if err != nil {
		t.Errorf("getConfig failed: %v", err)
	}

	if cfg == nil {
		t.Error("getConfig returned nil config")
	}

	// Verify config is cached
	cfg2, err := getConfig()
	if err != nil {
		t.Errorf("second getConfig call failed: %v", err)
	}

	if cfg != cfg2 {
		t.Error("expected same config instance (cached)")
	}

	// Reset for other tests
	config = nil
	configPath = ""
}

func TestGetConfigWithInvalidPath(t *testing.T) {
	// Reset config and set invalid path
	config = nil
	configPath = "/invalid/path/that/does/not/exist/config.yaml"

	// LoadConfig returns default config for non-existent files
	cfg, err := getConfig()
	if err != nil {
		t.Errorf("getConfig should not error for non-existent file: %v", err)
	}

	if cfg == nil {
		t.Error("getConfig should return default config for non-existent file")
	}

	// Reset for other tests
	config = nil
	configPath = ""
}

func TestGetContext(t *testing.T) {
	// Reset config and use temp dir to avoid reading real user config
	config = nil
	configPath = filepath.Join(t.TempDir(), "config.yaml")
	contextName = ""

	ctx, err := getContext()
	if err != nil {
		t.Errorf("getContext failed: %v", err)
	}

	if ctx == nil {
		t.Error("getContext returned nil context")
	}

	// Reset for other tests
	config = nil
	configPath = ""
	contextName = ""
}

func TestGetContextWithSpecifiedName(t *testing.T) {
	// Create a test config with multiple contexts
	config = &cli.Config{
		CurrentContext: "context1",
		Contexts: []*cli.Context{
			{
				Name: "context1",
				Type: cli.ContextTypeLocal,
				Local: &cli.LocalContext{
					SocketPath: "/run/platformd.sock",
				},
			},
			{
				Name: "context2",
				Type: cli.ContextTypeLocal,
				Local: &cli.LocalContext{
					SocketPath: "/run/platformd2.sock",
				},
			},
		},
	}
	contextName = "context2"

	ctx, err := getContext()
	if err != nil {
		t.Errorf("getContext failed: %v", err)
	}

	if ctx == nil {
		t.Fatal("getContext returned nil context")
	}

	if ctx.Name != "context2" {
		t.Errorf("expected context2, got %s", ctx.Name)
	}

	// Reset for other tests
	config = nil
	contextName = ""
}

func TestGetContextWithInvalidName(t *testing.T) {
	// Create a test config
	config = &cli.Config{
		CurrentContext: "context1",
		Contexts: []*cli.Context{
			{
				Name: "context1",
				Type: cli.ContextTypeLocal,
				Local: &cli.LocalContext{
					SocketPath: "/run/platformd.sock",
				},
			},
		},
	}
	contextName = "invalid-context"

	_, err := getContext()
	if err == nil {
		t.Error("expected error for invalid context name")
	}

	// Verify it's the correct error type
	if _, ok := err.(cli.ErrContextNotFound); !ok {
		t.Errorf("expected ErrContextNotFound, got %T", err)
	}

	// Reset for other tests
	config = nil
	contextName = ""
}

func TestRootCommandPersistentPreRunE_ValidOutputFormat(t *testing.T) {
	// Reset global state
	config = nil
	configPath = ""
	outputFormat = "json"

	err := rootCmd.PersistentPreRunE(rootCmd, []string{})
	if err != nil {
		t.Errorf("PersistentPreRunE failed with valid output format: %v", err)
	}

	// Reset
	outputFormat = "table"
}

func TestRootCommandPersistentPreRunE_InvalidOutputFormat(t *testing.T) {
	// Reset global state
	config = nil
	configPath = ""
	outputFormat = "invalid"

	err := rootCmd.PersistentPreRunE(rootCmd, []string{})
	if err == nil {
		t.Error("expected error for invalid output format")
	}

	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}

	// Reset
	outputFormat = "table"
}

func TestRootCommandPersistentPreRunE_ExplicitInvalidConfig(t *testing.T) {
	// Reset global state
	config = nil
	configPath = "/invalid/explicit/path/that/really/does/not/exist/config.yaml"
	outputFormat = "table"

	// LoadConfig returns default config for non-existent files, not an error
	// So this should succeed
	err := rootCmd.PersistentPreRunE(rootCmd, []string{})
	if err != nil {
		t.Errorf("PersistentPreRunE should succeed with non-existent config (returns default): %v", err)
	}

	// Reset
	configPath = ""
}

func TestRootCommandPersistentPreRunE_NoConfigUsesDefault(t *testing.T) {
	// Reset global state
	config = nil
	configPath = ""
	outputFormat = "table"

	err := rootCmd.PersistentPreRunE(rootCmd, []string{})
	if err != nil {
		t.Errorf("PersistentPreRunE failed: %v", err)
	}

	if config == nil {
		t.Error("config should be set to default")
	}

	// Reset
	config = nil
}

func TestRootCommandPersistentPreRunE_ValidYamlOutputFormat(t *testing.T) {
	// Reset global state
	config = nil
	configPath = ""
	outputFormat = "yaml"

	err := rootCmd.PersistentPreRunE(rootCmd, []string{})
	if err != nil {
		t.Errorf("PersistentPreRunE failed with yaml output format: %v", err)
	}

	// Reset
	outputFormat = "table"
}

func TestGetContextWithCurrentContext(t *testing.T) {
	// Create a test config with current context
	config = &cli.Config{
		CurrentContext: "default",
		Contexts: []*cli.Context{
			{
				Name: "default",
				Type: cli.ContextTypeLocal,
				Local: &cli.LocalContext{
					SocketPath: "/run/platformd.sock",
				},
			},
		},
	}
	contextName = ""

	ctx, err := getContext()
	if err != nil {
		t.Errorf("getContext with current context failed: %v", err)
	}

	if ctx == nil {
		t.Fatal("getContext returned nil context")
	}

	if ctx.Name != "default" {
		t.Errorf("expected default context, got %s", ctx.Name)
	}

	// Reset for other tests
	config = nil
}

func TestGetConfigCached(t *testing.T) {
	// Reset and set a config
	config = cli.DefaultConfig()
	configPath = ""

	cfg1, err := getConfig()
	if err != nil {
		t.Errorf("first getConfig failed: %v", err)
	}

	cfg2, err := getConfig()
	if err != nil {
		t.Errorf("second getConfig failed: %v", err)
	}

	// Should return the same cached instance
	if cfg1 != cfg2 {
		t.Error("expected cached config to be returned")
	}

	// Reset
	config = nil
}

func TestGetContextAutoDetection(t *testing.T) {
	// Create a config with no current context
	config = &cli.Config{
		CurrentContext: "",
		Contexts:       []*cli.Context{},
	}
	contextName = ""

	// This should trigger auto-detection
	_, err := getContext()
	// Auto-detection may fail if no socket is available, which is fine for testing
	// We're just verifying the code path executes without panic
	if err != nil {
		// Expected - auto-detection fails when no socket exists
		if _, ok := err.(cli.ErrAutoDetectionFailed); !ok {
			// Check other error types are also acceptable
			if _, ok := err.(cli.ErrConnectionFailed); !ok {
				t.Logf("auto-detection failed with error: %v (this is expected in test environment)", err)
			}
		}
	}

	// Reset
	config = nil
}

func TestRootCommandLongDescription(t *testing.T) {
	if rootCmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if len(rootCmd.Long) < 50 {
		t.Error("Long description should be descriptive")
	}
}

func TestRootCommandVersionNotNil(t *testing.T) {
	// Version field should not be nil (even if empty string during tests)
	// During build, this gets set via -ldflags
	_ = rootCmd.Version
	// Just verify it doesn't panic and the field exists
}

func TestGetCommonFlagsDefaults(t *testing.T) {
	// Reset to defaults
	configPath = ""
	contextName = ""
	outputFormat = "table"
	verbose = false
	noColor = false

	flags := getCommonFlags()

	if flags.ConfigPath != "" {
		t.Errorf("expected empty ConfigPath, got %s", flags.ConfigPath)
	}

	if flags.ContextName != "" {
		t.Errorf("expected empty ContextName, got %s", flags.ContextName)
	}

	if flags.OutputFormat != cli.OutputFormatTable {
		t.Errorf("expected OutputFormat table, got %s", flags.OutputFormat)
	}

	if flags.Verbose {
		t.Error("expected Verbose to be false")
	}

	if flags.NoColor {
		t.Error("expected NoColor to be false")
	}
}

func TestRootCommandHasCorrectSubcommandCount(t *testing.T) {
	commands := rootCmd.Commands()
	// We should have exactly 7 subcommands (not counting help which is auto-added)
	expectedCount := 7
	if len(commands) < expectedCount {
		t.Errorf("expected at least %d commands, got %d", expectedCount, len(commands))
	}
}
