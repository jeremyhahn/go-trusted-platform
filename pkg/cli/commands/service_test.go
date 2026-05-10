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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewServiceCommand(t *testing.T) {
	cmd := NewServiceCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	})

	if cmd == nil {
		t.Fatal("NewServiceCommand returned nil")
	}

	if cmd.Use != "service" {
		t.Errorf("expected Use to be 'service', got %s", cmd.Use)
	}

	if cmd.Short != "Manage platform services" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}
}

func TestServiceCommandSubcommands(t *testing.T) {
	cmd := NewServiceCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedSubcommands := []string{
		"list",
		"start",
		"stop",
		"restart",
		"status",
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

func TestNewServiceListCommand(t *testing.T) {
	cmd := newServiceListCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd == nil {
		t.Fatal("newServiceListCommand returned nil")
	}

	if cmd.Use != "list" {
		t.Errorf("expected Use to be 'list', got %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestNewServiceStartCommand(t *testing.T) {
	cmd := newServiceStartCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd == nil {
		t.Fatal("newServiceStartCommand returned nil")
	}

	if cmd.Use != "start <service-type>" {
		t.Errorf("expected Use to be 'start <service-type>', got %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestNewServiceStopCommand(t *testing.T) {
	cmd := newServiceStopCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd == nil {
		t.Fatal("newServiceStopCommand returned nil")
	}

	if cmd.Use != "stop <service-type>" {
		t.Errorf("expected Use to be 'stop <service-type>', got %s", cmd.Use)
	}

	// Verify flags
	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Fatal("force flag not found")
	}
	if forceFlag.Shorthand != "f" {
		t.Errorf("expected force flag shorthand to be 'f', got %s", forceFlag.Shorthand)
	}

	timeoutFlag := cmd.Flags().Lookup("timeout")
	if timeoutFlag == nil {
		t.Fatal("timeout flag not found")
	}
	if timeoutFlag.Shorthand != "t" {
		t.Errorf("expected timeout flag shorthand to be 't', got %s", timeoutFlag.Shorthand)
	}
}

func TestNewServiceRestartCommand(t *testing.T) {
	cmd := newServiceRestartCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd == nil {
		t.Fatal("newServiceRestartCommand returned nil")
	}

	if cmd.Use != "restart <service-type>" {
		t.Errorf("expected Use to be 'restart <service-type>', got %s", cmd.Use)
	}

	// Verify timeout flag
	timeoutFlag := cmd.Flags().Lookup("timeout")
	if timeoutFlag == nil {
		t.Fatal("timeout flag not found")
	}
	if timeoutFlag.Shorthand != "t" {
		t.Errorf("expected timeout flag shorthand to be 't', got %s", timeoutFlag.Shorthand)
	}
}

func TestNewServiceStatusCommand(t *testing.T) {
	cmd := newServiceStatusCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd == nil {
		t.Fatal("newServiceStatusCommand returned nil")
	}

	if cmd.Use != "status <service-type>" {
		t.Errorf("expected Use to be 'status <service-type>', got %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestServiceCommandStructures(t *testing.T) {
	tests := []struct {
		name    string
		cmdFunc func(func() *cli.CommonFlags) *cobra.Command
	}{
		{"list", newServiceListCommand},
		{"start", newServiceStartCommand},
		{"stop", newServiceStopCommand},
		{"restart", newServiceRestartCommand},
		{"status", newServiceStatusCommand},
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

func TestServiceCommandArgs(t *testing.T) {
	tests := []struct {
		name        string
		cmdFunc     func(func() *cli.CommonFlags) *cobra.Command
		expectsArgs bool
	}{
		{"list", newServiceListCommand, false},
		{"start", newServiceStartCommand, true},
		{"stop", newServiceStopCommand, true},
		{"restart", newServiceRestartCommand, true},
		{"status", newServiceStatusCommand, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmdFunc(func() *cli.CommonFlags {
				return &cli.CommonFlags{}
			})

			// List command doesn't require args, others do
			if tt.expectsArgs {
				if cmd.Args == nil {
					t.Errorf("%s command: Args validation should not be nil", tt.name)
				}
			}
		})
	}
}

func TestServiceListRunEWithNoConnection(t *testing.T) {
	cmd := newServiceListCommand(func() *cli.CommonFlags {
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

func TestServiceStartRunEWithNoConnection(t *testing.T) {
	cmd := newServiceStartCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	err := cmd.RunE(cmd, []string{"tpm"})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestServiceStopRunEWithNoConnection(t *testing.T) {
	cmd := newServiceStopCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	err := cmd.RunE(cmd, []string{"tpm"})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestServiceRestartRunEWithNoConnection(t *testing.T) {
	cmd := newServiceRestartCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	err := cmd.RunE(cmd, []string{"tpm"})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestServiceStatusRunEWithNoConnection(t *testing.T) {
	cmd := newServiceStatusCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	err := cmd.RunE(cmd, []string{"tpm"})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestServiceCommandLongDescription(t *testing.T) {
	cmd := NewServiceCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedLong := "Start, stop, restart, and query platform services"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %s, want %s", cmd.Long, expectedLong)
	}
}

func TestServiceStopForceFlagDefaults(t *testing.T) {
	cmd := newServiceStopCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag.DefValue != "false" {
		t.Errorf("expected force flag default to be false, got %s", forceFlag.DefValue)
	}

	timeoutFlag := cmd.Flags().Lookup("timeout")
	if timeoutFlag.DefValue != "30" {
		t.Errorf("expected timeout flag default to be 30, got %s", timeoutFlag.DefValue)
	}
}

func TestServiceRestartTimeoutFlagDefault(t *testing.T) {
	cmd := newServiceRestartCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	timeoutFlag := cmd.Flags().Lookup("timeout")
	if timeoutFlag.DefValue != "30" {
		t.Errorf("expected timeout flag default to be 30, got %s", timeoutFlag.DefValue)
	}
}

func TestServiceSubcommandShortDescriptions(t *testing.T) {
	tests := []struct {
		name          string
		cmdFunc       func(func() *cli.CommonFlags) *cobra.Command
		expectedShort string
	}{
		{"list", newServiceListCommand, "List all services"},
		{"start", newServiceStartCommand, "Start a service"},
		{"stop", newServiceStopCommand, "Stop a service"},
		{"restart", newServiceRestartCommand, "Restart a service"},
		{"status", newServiceStatusCommand, "Get service status"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmdFunc(func() *cli.CommonFlags {
				return &cli.CommonFlags{}
			})

			if cmd.Short != tt.expectedShort {
				t.Errorf("expected Short '%s', got '%s'", tt.expectedShort, cmd.Short)
			}
		})
	}
}

func TestServiceStopFlagUsages(t *testing.T) {
	cmd := newServiceStopCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag.Usage != "force stop the service" {
		t.Errorf("unexpected force flag usage: %s", forceFlag.Usage)
	}

	timeoutFlag := cmd.Flags().Lookup("timeout")
	if timeoutFlag.Usage != "timeout in seconds" {
		t.Errorf("unexpected timeout flag usage: %s", timeoutFlag.Usage)
	}
}

func TestServiceRestartFlagUsage(t *testing.T) {
	cmd := newServiceRestartCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	timeoutFlag := cmd.Flags().Lookup("timeout")
	if timeoutFlag.Usage != "timeout in seconds" {
		t.Errorf("unexpected timeout flag usage: %s", timeoutFlag.Usage)
	}
}

func TestErrInvalidServiceTypeMessage(t *testing.T) {
	err := cli.ErrInvalidServiceType{Type: "custom"}
	expected := "invalid service type: custom"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}
