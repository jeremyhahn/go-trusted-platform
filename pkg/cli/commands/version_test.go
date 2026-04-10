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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewVersionCommand(t *testing.T) {
	cmd := NewVersionCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	})

	if cmd == nil {
		t.Fatal("NewVersionCommand returned nil")
	}

	if cmd.Use != "version" {
		t.Errorf("expected Use to be 'version', got %s", cmd.Use)
	}

	if cmd.Short != "Show version information" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}

	// Verify client flag exists
	flag := cmd.Flags().Lookup("client")
	if flag == nil {
		t.Error("expected --client flag not found")
	}
}

func TestGetClientVersion(t *testing.T) {
	version := getClientVersion()
	if version == "" {
		t.Error("client version should not be empty")
	}

	// When app.Version is not set (e.g., during tests), we expect "dev"
	// When built with ldflags, it will return the actual version
	if version != "dev" && version != app.Version {
		t.Errorf("expected version 'dev' or app.Version, got %s", version)
	}
}

func TestPrintVersionTable(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	resp := &platformv1.GetVersionResponse{
		Version:   "1.4.0",
		BuildTime: "2025-01-01T00:00:00Z",
		GitCommit: "abc123",
		GoVersion: "go1.21.0",
		Components: map[string]string{
			"tpm":  "2.0",
			"acme": "1.0",
		},
	}

	err := printVersionTable(printer, resp)
	if err != nil {
		t.Errorf("printVersionTable failed: %v", err)
	}
}

func TestPrintVersionTableNoComponents(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	resp := &platformv1.GetVersionResponse{
		Version:    "1.4.0",
		BuildTime:  "2025-01-01T00:00:00Z",
		GitCommit:  "abc123",
		GoVersion:  "go1.21.0",
		Components: nil,
	}

	err := printVersionTable(printer, resp)
	if err != nil {
		t.Errorf("printVersionTable failed: %v", err)
	}
}

func TestPrintVersionTableEmptyComponents(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	resp := &platformv1.GetVersionResponse{
		Version:    "1.4.0",
		BuildTime:  "2025-01-01T00:00:00Z",
		GitCommit:  "abc123",
		GoVersion:  "go1.21.0",
		Components: map[string]string{},
	}

	err := printVersionTable(printer, resp)
	if err != nil {
		t.Errorf("printVersionTable failed: %v", err)
	}
}

func TestVersionCommandStructure(t *testing.T) {
	cmd := NewVersionCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestVersionCommandFlags(t *testing.T) {
	cmd := NewVersionCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	clientFlag := cmd.Flags().Lookup("client")
	if clientFlag == nil {
		t.Fatal("client flag not found")
	}

	if clientFlag.DefValue != "false" {
		t.Errorf("expected client flag default to be false, got %s", clientFlag.DefValue)
	}
}

func TestVersionRunEWithNoConnection(t *testing.T) {
	cmd := NewVersionCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	// Without client-only flag, should fail to connect
	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestVersionCommandLongDescription(t *testing.T) {
	cmd := NewVersionCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedLong := "Display version information for platformctl and the platform server"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %s, want %s", cmd.Long, expectedLong)
	}
}

func TestVersionClientFlagUsage(t *testing.T) {
	cmd := NewVersionCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	clientFlag := cmd.Flags().Lookup("client")
	if clientFlag == nil {
		t.Fatal("client flag should exist")
	}

	if clientFlag.Usage != "show client version only" {
		t.Errorf("unexpected client flag usage: %s", clientFlag.Usage)
	}
}

func TestRunVersionClientOnlyTable(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	err := runVersion(flags, true)
	if err != nil {
		t.Errorf("runVersion client-only with table format failed: %v", err)
	}
}

func TestRunVersionClientOnlyJSON(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err := runVersion(flags, true)
	if err != nil {
		t.Errorf("runVersion client-only with JSON format failed: %v", err)
	}
}

func TestRunVersionClientOnlyYAML(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatYAML,
		NoColor:      true,
	}

	err := runVersion(flags, true)
	if err != nil {
		t.Errorf("runVersion client-only with YAML format failed: %v", err)
	}
}
