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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/spf13/cobra"
)

func TestNewConfigCommand(t *testing.T) {
	cmd := NewConfigCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	})

	if cmd == nil {
		t.Fatal("NewConfigCommand returned nil")
	}

	if cmd.Use != "config" {
		t.Errorf("expected Use to be 'config', got %s", cmd.Use)
	}

	if cmd.Short != "Manage platform configuration" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}
}

func TestConfigCommandSubcommands(t *testing.T) {
	cmd := NewConfigCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedSubcommands := []string{
		"get",
		"set",
		"reload",
	}

	commands := cmd.Commands()
	if len(commands) != len(expectedSubcommands) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubcommands), len(commands))
	}

	for _, expected := range expectedSubcommands {
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

func TestNewConfigGetCommand(t *testing.T) {
	cmd := newConfigGetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd == nil {
		t.Fatal("newConfigGetCommand returned nil")
	}

	if cmd.Use != "get [section]" {
		t.Errorf("expected Use to be 'get [section]', got %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}

	if cmd.Args == nil {
		t.Error("Args should not be nil")
	}
}

func TestNewConfigGetCommandRunEWithSection(t *testing.T) {
	cmd := newConfigGetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	// Test with section argument - exercises the section assignment path
	err := cmd.RunE(cmd, []string{"tpm"})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestNewConfigSetCommand(t *testing.T) {
	cmd := newConfigSetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd == nil {
		t.Fatal("newConfigSetCommand returned nil")
	}

	if cmd.Use != "set <section> <key=value> [key=value...]" {
		t.Errorf("expected Use to be 'set <section> <key=value> [key=value...]', got %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}

	// Verify persist flag
	persistFlag := cmd.Flags().Lookup("persist")
	if persistFlag == nil {
		t.Fatal("persist flag not found")
	}
	if persistFlag.Shorthand != "p" {
		t.Errorf("expected persist flag shorthand to be 'p', got %s", persistFlag.Shorthand)
	}
	if persistFlag.DefValue != "false" {
		t.Errorf("expected persist flag default to be false, got %s", persistFlag.DefValue)
	}
}

func TestNewConfigReloadCommand(t *testing.T) {
	cmd := newConfigReloadCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd == nil {
		t.Fatal("newConfigReloadCommand returned nil")
	}

	if cmd.Use != "reload" {
		t.Errorf("expected Use to be 'reload', got %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestConfigCommandStructures(t *testing.T) {
	tests := []struct {
		name    string
		cmdFunc func(func() *cli.CommonFlags) *cobra.Command
	}{
		{"get", newConfigGetCommand},
		{"set", newConfigSetCommand},
		{"reload", newConfigReloadCommand},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmdFunc(func() *cli.CommonFlags {
				return &cli.CommonFlags{}
			})

			if cmd.Long == "" {
				t.Errorf("%s command: Long description should not be empty", tt.name)
			}
		})
	}
}

func TestConfigGetCommandArgs(t *testing.T) {
	cmd := newConfigGetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	// Should accept 0 or 1 arguments
	if cmd.Args == nil {
		t.Error("Args validation should not be nil")
	}
}

func TestConfigSetCommandArgs(t *testing.T) {
	cmd := newConfigSetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	// Should require at least 2 arguments
	if cmd.Args == nil {
		t.Error("Args validation should not be nil")
	}
}

func TestConfigReloadCommandArgs(t *testing.T) {
	cmd := newConfigReloadCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestConfigCommandLongDescriptions(t *testing.T) {
	cmd := NewConfigCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Long == "" {
		t.Error("Config command Long description should not be empty")
	}
}

func TestConfigGetCommandShortDescription(t *testing.T) {
	cmd := newConfigGetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Short != "Get configuration" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}
}

func TestConfigSetCommandShortDescription(t *testing.T) {
	cmd := newConfigSetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Short != "Set configuration values" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}
}

func TestConfigReloadCommandShortDescription(t *testing.T) {
	cmd := newConfigReloadCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Short != "Reload configuration" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}
}

func TestConfigGetRunEWithNoConnection(t *testing.T) {
	cmd := newConfigGetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestConfigSetRunEWithNoConnection(t *testing.T) {
	cmd := newConfigSetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	err := cmd.RunE(cmd, []string{"section", "key=value"})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestConfigSetRunEWithMultipleKeyValues(t *testing.T) {
	cmd := newConfigSetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	err := cmd.RunE(cmd, []string{"section", "key1=value1", "key2=value2"})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestConfigReloadRunEWithNoConnection(t *testing.T) {
	cmd := newConfigReloadCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestConfigSetPersistFlagUsage(t *testing.T) {
	cmd := newConfigSetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	persistFlag := cmd.Flags().Lookup("persist")
	if persistFlag == nil {
		t.Fatal("persist flag should exist")
	}

	if persistFlag.Usage != "persist changes to disk" {
		t.Errorf("unexpected persist flag usage: %s", persistFlag.Usage)
	}
}

func TestConfigGetCommandLongDescription(t *testing.T) {
	cmd := newConfigGetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedLong := "Get platform configuration for all sections or a specific section"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %s, want %s", cmd.Long, expectedLong)
	}
}

func TestConfigSetCommandLongDescription(t *testing.T) {
	cmd := newConfigSetCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedLong := "Set configuration values for a specific section"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %s, want %s", cmd.Long, expectedLong)
	}
}

func TestConfigReloadCommandLongDescription(t *testing.T) {
	cmd := newConfigReloadCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedLong := "Reload platform configuration from disk"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %s, want %s", cmd.Long, expectedLong)
	}
}

func TestConfigParentCommandLongDescription(t *testing.T) {
	cmd := NewConfigCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedLong := "Get, set, and reload platform configuration"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %s, want %s", cmd.Long, expectedLong)
	}
}
