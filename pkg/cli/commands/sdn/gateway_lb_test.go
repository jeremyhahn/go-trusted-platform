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

package sdn

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func TestNewGatewayLBCommand(t *testing.T) {
	cmd := newGatewayLBCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("newGatewayLBCommand returned nil")
	}
	if cmd.Use != "lb" {
		t.Errorf("expected Use 'lb', got %s", cmd.Use)
	}

	expectedSubs := []string{"status", "vip"}
	commands := cmd.Commands()
	if len(commands) != len(expectedSubs) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubs), len(commands))
	}
	for _, expected := range expectedSubs {
		found := false
		for _, subcmd := range commands {
			if subcmd.Name() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing subcommand %s", expected)
		}
	}
}

func TestGatewayLBVIPCommandTree(t *testing.T) {
	cmd := newGatewayLBVIPCommand(testGetFlags())
	if cmd.Use != "vip" {
		t.Errorf("expected Use 'vip', got %s", cmd.Use)
	}

	expectedSubs := map[string]bool{
		"add": false, "remove": false, "get": false, "list": false, "set-backends": false,
	}
	for _, subcmd := range cmd.Commands() {
		if _, ok := expectedSubs[subcmd.Name()]; ok {
			expectedSubs[subcmd.Name()] = true
		}
	}
	for name, found := range expectedSubs {
		if !found {
			t.Errorf("missing vip subcommand %s", name)
		}
	}
}

func TestGatewayLBVIPAddCommandFlags(t *testing.T) {
	cmd := newGatewayLBVIPCommand(testGetFlags())
	var addCmd = findSubcommand(t, cmd, "add")

	for _, flag := range []string{"protocol", "address", "port", "algorithm", "backend"} {
		if addCmd.Flags().Lookup(flag) == nil {
			t.Errorf("add command missing --%s flag", flag)
		}
	}
}

func TestGatewayLBVIPKeyedCommandFlags(t *testing.T) {
	cmd := newGatewayLBVIPCommand(testGetFlags())
	for _, name := range []string{"remove", "get", "set-backends"} {
		sub := findSubcommand(t, cmd, name)
		for _, flag := range []string{"protocol", "address", "port"} {
			if sub.Flags().Lookup(flag) == nil {
				t.Errorf("%s command missing --%s flag", name, flag)
			}
		}
	}
}

func TestParseBackendSpecs(t *testing.T) {
	backends, err := parseBackendSpecs([]string{"10.0.1.5:8443:2", "10.0.1.6:8443"})
	if err != nil {
		t.Fatalf("parseBackendSpecs: %v", err)
	}
	if len(backends) != 2 {
		t.Fatalf("backends = %d, want 2", len(backends))
	}
	if backends[0].Address != "10.0.1.5" || backends[0].Port != 8443 || backends[0].Weight != 2 {
		t.Errorf("backend[0] = %+v", backends[0])
	}
	if backends[1].Weight != 0 {
		t.Errorf("backend[1] weight = %d, want 0 (defaulted server-side)", backends[1].Weight)
	}
}

func TestParseBackendSpecsErrors(t *testing.T) {
	tests := []struct {
		name string
		spec string
	}{
		{"missing port", "10.0.1.5"},
		{"zero port", "10.0.1.5:0"},
		{"bad port", "10.0.1.5:notaport"},
		{"bad weight", "10.0.1.5:8443:heavy"},
		{"too many parts", "10.0.1.5:8443:2:extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseBackendSpecs([]string{tt.spec})
			var specErr *ErrInvalidBackendSpec
			if !errors.As(err, &specErr) {
				t.Errorf("parseBackendSpecs(%q) = %v, want ErrInvalidBackendSpec", tt.spec, err)
			}
		})
	}
}

// findSubcommand resolves a named subcommand or fails the test.
func findSubcommand(t *testing.T, parent *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, sub := range parent.Commands() {
		if sub.Name() == name {
			return sub
		}
	}
	t.Fatalf("subcommand %s not found", name)
	return nil
}
