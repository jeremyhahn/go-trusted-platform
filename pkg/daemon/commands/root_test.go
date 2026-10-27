package commands

import (
	"testing"
)

func TestRootCommandProperties(t *testing.T) {
	if rootCmd.Use != "platformd" {
		t.Errorf("expected Use 'platformd', got %s", rootCmd.Use)
	}
	if rootCmd.Short == "" {
		t.Error("Short description should not be empty")
	}
	if rootCmd.Long == "" {
		t.Error("Long description should not be empty")
	}
	if !rootCmd.TraverseChildren {
		t.Error("TraverseChildren should be true")
	}
}

func TestRootCommandSubcommands(t *testing.T) {
	expectedSubs := []string{"serve", "version"}
	commands := rootCmd.Commands()

	for _, expected := range expectedSubs {
		found := false
		for _, subcmd := range commands {
			if subcmd.Name() == expected {
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
	expectedFlags := []string{
		"debug", "debug-secrets", "env",
		"platform-dir", "config-dir", "config",
		"log-dir", "ca-dir",
		"intermediate", "so-pin", "pin", "init",
		"raw-so-pin", "raw-pin",
	}

	for _, flagName := range expectedFlags {
		flag := rootCmd.PersistentFlags().Lookup(flagName)
		if flag == nil {
			t.Errorf("persistent flag %s should exist", flagName)
		}
	}
}

func TestVersionCommandProperties(t *testing.T) {
	if versionCmd.Use != "version" {
		t.Errorf("expected Use 'version', got %s", versionCmd.Use)
	}
	if versionCmd.Short == "" {
		t.Error("Short description should not be empty")
	}
	if versionCmd.Long == "" {
		t.Error("Long description should not be empty")
	}
	if versionCmd.Run == nil {
		t.Error("Run should not be nil")
	}
}

func TestVersionCommandExecutes(t *testing.T) {
	// The version command should execute without error (it just prints)
	versionCmd.Run(versionCmd, []string{})
}

func TestInitParamsInitialized(t *testing.T) {
	if InitParams == nil {
		t.Fatal("InitParams should be initialized in init()")
	}
}
