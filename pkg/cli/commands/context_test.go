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
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/spf13/cobra"
)

func TestNewContextCommand(t *testing.T) {
	cmd := NewContextCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	if cmd == nil {
		t.Fatal("NewContextCommand returned nil")
	}

	if cmd.Use != "context" {
		t.Errorf("expected Use to be 'context', got %s", cmd.Use)
	}

	if cmd.Short != "Manage connection contexts" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}
}

func TestContextCommandSubcommands(t *testing.T) {
	cmd := NewContextCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	expectedSubcommands := []string{
		"list",
		"use",
		"current",
		"add",
		"delete",
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

func TestNewContextListCommand(t *testing.T) {
	cmd := newContextListCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	if cmd == nil {
		t.Fatal("newContextListCommand returned nil")
	}

	if cmd.Use != "list" {
		t.Errorf("expected Use to be 'list', got %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestNewContextListCommandRunE(t *testing.T) {
	cmd := newContextListCommand(func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "local",
			Contexts: []*cli.Context{
				{
					Name: "local",
					Type: cli.ContextTypeLocal,
					Local: &cli.LocalContext{
						SocketPath: "/run/platformd.sock",
					},
				},
			},
		}, nil
	})

	err := cmd.RunE(cmd, []string{})
	if err != nil {
		t.Errorf("RunE failed: %v", err)
	}
}

func TestNewContextUseCommand(t *testing.T) {
	cmd := newContextUseCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	if cmd == nil {
		t.Fatal("newContextUseCommand returned nil")
	}

	if cmd.Use != "use <context-name>" {
		t.Errorf("expected Use to be 'use <context-name>', got %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestNewContextUseCommandRunE(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &cli.Config{
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
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	cmd := newContextUseCommand(func() (*cli.Config, error) {
		return cli.LoadConfig(configPath)
	})

	err := cmd.RunE(cmd, []string{"context2"})
	if err != nil {
		t.Errorf("RunE failed: %v", err)
	}
}

func TestNewContextCurrentCommand(t *testing.T) {
	cmd := newContextCurrentCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	if cmd == nil {
		t.Fatal("newContextCurrentCommand returned nil")
	}

	if cmd.Use != "current" {
		t.Errorf("expected Use to be 'current', got %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestNewContextCurrentCommandRunE(t *testing.T) {
	cmd := newContextCurrentCommand(func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "local",
			Contexts: []*cli.Context{
				{
					Name: "local",
					Type: cli.ContextTypeLocal,
					Local: &cli.LocalContext{
						SocketPath: "/run/platformd.sock",
					},
				},
			},
		}, nil
	})

	err := cmd.RunE(cmd, []string{})
	if err != nil {
		t.Errorf("RunE failed: %v", err)
	}
}

func TestNewContextAddCommand(t *testing.T) {
	cmd := newContextAddCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	if cmd == nil {
		t.Fatal("newContextAddCommand returned nil")
	}

	if cmd.Use != "add <context-name>" {
		t.Errorf("expected Use to be 'add <context-name>', got %s", cmd.Use)
	}

	// Verify flags
	requiredFlags := []struct {
		name         string
		shorthand    string
		defaultValue string
	}{
		{"type", "t", "local"},
		{"socket-path", "", "/run/platformd.sock"},
		{"server", "", ""},
		{"ca-cert", "", ""},
		{"client-cert", "", ""},
		{"client-key", "", ""},
	}

	for _, rf := range requiredFlags {
		flag := cmd.Flags().Lookup(rf.name)
		if flag == nil {
			t.Errorf("flag %s not found", rf.name)
			continue
		}
		if rf.shorthand != "" && flag.Shorthand != rf.shorthand {
			t.Errorf("flag %s: expected shorthand %s, got %s",
				rf.name, rf.shorthand, flag.Shorthand)
		}
	}
}

func TestNewContextAddCommandRunE(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := cli.DefaultConfig()
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	cmd := newContextAddCommand(func() (*cli.Config, error) {
		return cli.LoadConfig(configPath)
	})

	err := cmd.RunE(cmd, []string{"new-context"})
	if err != nil {
		t.Errorf("RunE failed: %v", err)
	}
}

func TestNewContextDeleteCommand(t *testing.T) {
	cmd := newContextDeleteCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	if cmd == nil {
		t.Fatal("newContextDeleteCommand returned nil")
	}

	if cmd.Use != "delete <context-name>" {
		t.Errorf("expected Use to be 'delete <context-name>', got %s", cmd.Use)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestNewContextDeleteCommandRunE(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &cli.Config{
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
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	cmd := newContextDeleteCommand(func() (*cli.Config, error) {
		return cli.LoadConfig(configPath)
	})

	err := cmd.RunE(cmd, []string{"context2"})
	if err != nil {
		t.Errorf("RunE failed: %v", err)
	}
}

func TestRunContextList(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "local",
			Contexts: []*cli.Context{
				{
					Name: "local",
					Type: cli.ContextTypeLocal,
					Local: &cli.LocalContext{
						SocketPath: "/run/platformd.sock",
					},
				},
				{
					Name: "remote",
					Type: cli.ContextTypeRemote,
					Remote: &cli.RemoteContext{
						Server: "https://example.com:8443",
					},
				},
			},
		}, nil
	}

	err := runContextList(getConfig)
	if err != nil {
		t.Errorf("runContextList failed: %v", err)
	}
}

func TestRunContextListError(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return nil, cli.ErrConfigFileNotFound{Path: "/nonexistent"}
	}

	err := runContextList(getConfig)
	if err == nil {
		t.Error("expected error when getConfig fails")
	}
}

func TestRunContextCurrent(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "local",
			Contexts: []*cli.Context{
				{
					Name: "local",
					Type: cli.ContextTypeLocal,
					Local: &cli.LocalContext{
						SocketPath: "/run/platformd.sock",
					},
				},
			},
		}, nil
	}

	err := runContextCurrent(getConfig)
	if err != nil {
		t.Errorf("runContextCurrent failed: %v", err)
	}
}

func TestRunContextCurrentError(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return nil, cli.ErrConfigFileNotFound{Path: "/nonexistent"}
	}

	err := runContextCurrent(getConfig)
	if err == nil {
		t.Error("expected error when getConfig fails")
	}
}

func TestRunContextCurrentNoContext(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "",
			Contexts:       []*cli.Context{},
		}, nil
	}

	err := runContextCurrent(getConfig)
	if err == nil {
		t.Error("expected error when no context is set")
	}

	if _, ok := err.(cli.ErrNoContextSet); !ok {
		t.Errorf("expected ErrNoContextSet, got %T", err)
	}
}

func TestRunContextCurrentInvalidContext(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "nonexistent",
			Contexts:       []*cli.Context{},
		}, nil
	}

	err := runContextCurrent(getConfig)
	if err == nil {
		t.Error("expected error when current context doesn't exist")
	}

	if _, ok := err.(cli.ErrContextNotFound); !ok {
		t.Errorf("expected ErrContextNotFound, got %T", err)
	}
}

func TestRunContextAddLocal(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := cli.DefaultConfig()
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	getConfig := func() (*cli.Config, error) {
		return cli.LoadConfig(configPath)
	}

	err := runContextAdd(getConfig, "test-local", "local", "",
		"/run/test.sock", "", "", "", "", "")
	if err != nil {
		t.Fatalf("runContextAdd failed: %v", err)
	}

	added, err := reloadConfig(t, configPath).GetContext("test-local")
	if err != nil {
		t.Fatalf("added context must be in the --config file: %v", err)
	}
	if added.Local == nil || added.Local.SocketPath != "/run/test.sock" {
		t.Errorf("added context local = %+v, want socket /run/test.sock", added.Local)
	}
}

// reloadConfig reads configPath back from disk, proving a command saved to
// the file it loaded rather than to the default path.
func reloadConfig(t *testing.T, configPath string) *cli.Config {
	t.Helper()
	cfg, err := cli.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("reload %s: %v", configPath, err)
	}
	return cfg
}

func TestRunContextAddRemote(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := cli.DefaultConfig()
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	getConfig := func() (*cli.Config, error) {
		return cli.LoadConfig(configPath)
	}

	err := runContextAdd(getConfig, "test-remote", "remote", "",
		"", "https://example.com:8443", "/path/ca.crt",
		"/path/client.crt", "/path/client.key", "")
	if err != nil {
		t.Errorf("runContextAdd remote failed: %v", err)
	}
}

func TestRunContextAddRemoteWithToken(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := cli.DefaultConfig()
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	getConfig := func() (*cli.Config, error) {
		return cli.LoadConfig(configPath)
	}

	err := runContextAdd(getConfig, "test-remote-token", "remote", "",
		"", "https://example.com:8443", "", "", "", "my-token")
	if err != nil {
		t.Errorf("runContextAdd remote with token failed: %v", err)
	}
}

func TestRunContextAddRemoteNoServer(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	}

	err := runContextAdd(getConfig, "test-remote", "remote", "",
		"", "", "", "", "", "")
	if err == nil {
		t.Error("expected error when remote context has no server")
	}
}

func TestRunContextAddInvalidType(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	}

	err := runContextAdd(getConfig, "test", "invalid", "",
		"", "", "", "", "", "")
	if err == nil {
		t.Error("expected error for invalid context type")
	}
}

func TestRunContextAddError(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return nil, cli.ErrConfigFileNotFound{Path: "/nonexistent"}
	}

	err := runContextAdd(getConfig, "test", "local", "",
		"/run/test.sock", "", "", "", "", "")
	if err == nil {
		t.Error("expected error when getConfig fails")
	}
}

func TestRunContextUse(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &cli.Config{
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
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	getConfig := func() (*cli.Config, error) {
		return cli.LoadConfig(configPath)
	}

	err := runContextUse(getConfig, "context2")
	if err != nil {
		t.Fatalf("runContextUse failed: %v", err)
	}

	if got := reloadConfig(t, configPath).CurrentContext; got != "context2" {
		t.Errorf("current context in the --config file = %q, want context2", got)
	}
}

func TestRunContextUseError(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return nil, cli.ErrConfigFileNotFound{Path: "/nonexistent"}
	}

	err := runContextUse(getConfig, "context")
	if err == nil {
		t.Error("expected error when getConfig fails")
	}
}

func TestRunContextUseInvalidContext(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := cli.DefaultConfig()
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	getConfig := func() (*cli.Config, error) {
		return cli.LoadConfig(configPath)
	}

	err := runContextUse(getConfig, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent context")
	}

	if _, ok := err.(cli.ErrContextNotFound); !ok {
		t.Errorf("expected ErrContextNotFound, got %T", err)
	}
}

func TestRunContextDelete(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &cli.Config{
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
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	getConfig := func() (*cli.Config, error) {
		return cli.LoadConfig(configPath)
	}

	err := runContextDelete(getConfig, "context2")
	if err != nil {
		t.Fatalf("runContextDelete failed: %v", err)
	}

	reloaded := reloadConfig(t, configPath)
	if _, err := reloaded.GetContext("context2"); err == nil {
		t.Error("deleted context must be gone from the --config file")
	}
}

func TestRunContextDeleteError(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return nil, cli.ErrConfigFileNotFound{Path: "/nonexistent"}
	}

	err := runContextDelete(getConfig, "context")
	if err == nil {
		t.Error("expected error when getConfig fails")
	}
}

func TestRunContextDeleteInvalidContext(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := cli.DefaultConfig()
	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	getConfig := func() (*cli.Config, error) {
		return cli.LoadConfig(configPath)
	}

	err := runContextDelete(getConfig, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent context")
	}

	if _, ok := err.(cli.ErrContextNotFound); !ok {
		t.Errorf("expected ErrContextNotFound, got %T", err)
	}
}

func TestContextCommandStructures(t *testing.T) {
	tests := []struct {
		name    string
		cmdFunc func(func() (*cli.Config, error)) *cobra.Command
	}{
		{"list", newContextListCommand},
		{"use", newContextUseCommand},
		{"current", newContextCurrentCommand},
		{"add", newContextAddCommand},
		{"delete", newContextDeleteCommand},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmdFunc(func() (*cli.Config, error) {
				return cli.DefaultConfig(), nil
			})

			if cmd.Long == "" {
				t.Errorf("%s command: Long description should not be empty", tt.name)
			}
		})
	}
}

func TestRunContextCurrentRemoteContext(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "remote",
			Contexts: []*cli.Context{
				{
					Name: "remote",
					Type: cli.ContextTypeRemote,
					Remote: &cli.RemoteContext{
						Server:     "https://example.com:8443",
						CACert:     "/path/ca.crt",
						ClientCert: "/path/client.crt",
					},
				},
			},
		}, nil
	}

	err := runContextCurrent(getConfig)
	if err != nil {
		t.Errorf("runContextCurrent for remote context failed: %v", err)
	}
}

func TestRunContextCurrentRemoteContextMinimal(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "remote",
			Contexts: []*cli.Context{
				{
					Name: "remote",
					Type: cli.ContextTypeRemote,
					Remote: &cli.RemoteContext{
						Server: "https://example.com:8443",
					},
				},
			},
		}, nil
	}

	err := runContextCurrent(getConfig)
	if err != nil {
		t.Errorf("runContextCurrent for remote context failed: %v", err)
	}
}

func TestRunContextListEmptyContexts(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "",
			Contexts:       []*cli.Context{},
		}, nil
	}

	err := runContextList(getConfig)
	if err != nil {
		t.Errorf("runContextList with empty contexts failed: %v", err)
	}
}

func TestRunContextListNilLocal(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "local",
			Contexts: []*cli.Context{
				{
					Name:  "local",
					Type:  cli.ContextTypeLocal,
					Local: nil, // nil Local context
				},
			},
		}, nil
	}

	err := runContextList(getConfig)
	if err != nil {
		t.Errorf("runContextList with nil local context failed: %v", err)
	}
}

func TestRunContextListNilRemote(t *testing.T) {
	getConfig := func() (*cli.Config, error) {
		return &cli.Config{
			CurrentContext: "remote",
			Contexts: []*cli.Context{
				{
					Name:   "remote",
					Type:   cli.ContextTypeRemote,
					Remote: nil, // nil Remote context
				},
			},
		}, nil
	}

	err := runContextList(getConfig)
	if err != nil {
		t.Errorf("runContextList with nil remote context failed: %v", err)
	}
}

func TestContextAddCommandFlagDefaults(t *testing.T) {
	cmd := newContextAddCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	tests := []struct {
		name     string
		defValue string
	}{
		{"type", "local"},
		{"socket-path", "/run/platformd.sock"},
		{"server", ""},
		{"ca-cert", ""},
		{"client-cert", ""},
		{"client-key", ""},
	}

	for _, tt := range tests {
		flag := cmd.Flags().Lookup(tt.name)
		if flag == nil {
			t.Errorf("flag %s not found", tt.name)
			continue
		}
		if flag.DefValue != tt.defValue {
			t.Errorf("flag %s: expected default %s, got %s",
				tt.name, tt.defValue, flag.DefValue)
		}
	}
}

func TestContextCommandLongDescription(t *testing.T) {
	cmd := NewContextCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	expectedLong := "Manage connection contexts for local and remote platform connections"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %s, want %s", cmd.Long, expectedLong)
	}
}

func TestContextUseCommandArgs(t *testing.T) {
	cmd := newContextUseCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	if cmd.Args == nil {
		t.Error("Args should not be nil")
	}
}

func TestContextDeleteCommandArgs(t *testing.T) {
	cmd := newContextDeleteCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	if cmd.Args == nil {
		t.Error("Args should not be nil")
	}
}

func TestContextAddCommandArgs(t *testing.T) {
	cmd := newContextAddCommand(func() (*cli.Config, error) {
		return cli.DefaultConfig(), nil
	})

	if cmd.Args == nil {
		t.Error("Args should not be nil")
	}
}

// Cleanup function to reset environment after tests
func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
