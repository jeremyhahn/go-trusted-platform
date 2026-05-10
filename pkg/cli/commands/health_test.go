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
)

func TestNewHealthCommand(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	})

	if cmd == nil {
		t.Fatal("NewHealthCommand returned nil")
	}

	if cmd.Use != "health" {
		t.Errorf("expected Use to be 'health', got %s", cmd.Use)
	}

	if cmd.Short != "Show platform health status" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestHealthCommandFlags(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	detailedFlag := cmd.Flags().Lookup("detailed")
	if detailedFlag == nil {
		t.Fatal("detailed flag not found")
	}

	if detailedFlag.Shorthand != "d" {
		t.Errorf("expected detailed flag shorthand to be 'd', got %s", detailedFlag.Shorthand)
	}

	if detailedFlag.DefValue != "false" {
		t.Errorf("expected detailed flag default to be false, got %s", detailedFlag.DefValue)
	}
}

func TestHealthCommandStructure(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestHealthRunEWithNoConnection(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
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

func TestHealthCommandLongDescription(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedLong := "Display the health status of the Trusted Platform and its components"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %s, want %s", cmd.Long, expectedLong)
	}
}

func TestHealthDetailedFlagUsage(t *testing.T) {
	cmd := NewHealthCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	detailedFlag := cmd.Flags().Lookup("detailed")
	if detailedFlag == nil {
		t.Fatal("detailed flag should exist")
	}

	if detailedFlag.Usage != "show detailed component health" {
		t.Errorf("unexpected detailed flag usage: %s", detailedFlag.Usage)
	}
}
