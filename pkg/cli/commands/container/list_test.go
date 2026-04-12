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
	"testing"

	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewListCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newListCommand(getFlags)

	if cmd == nil {
		t.Fatal("newListCommand returned nil")
	}

	if cmd.Use != "list" {
		t.Errorf("expected Use to be 'list', got %q", cmd.Use)
	}

	if cmd.Short != "List containers" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewListCommand_HasAliases(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newListCommand(getFlags)

	expectedAliases := []string{"ls", "ps"}
	if len(cmd.Aliases) != len(expectedAliases) {
		t.Errorf("expected %d aliases, got %d", len(expectedAliases), len(cmd.Aliases))
	}

	for i, alias := range expectedAliases {
		if cmd.Aliases[i] != alias {
			t.Errorf("expected alias %q at index %d, got %q", alias, i, cmd.Aliases[i])
		}
	}
}

func TestNewListCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newListCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewListCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newListCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
		defValue  string
	}{
		{"all", "a", "false"},
		{"filter", "f", "[]"},
		{"limit", "l", "100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.name)
			if flag == nil {
				t.Errorf("--%s flag not found", tt.name)
				return
			}

			if flag.Shorthand != tt.shorthand {
				t.Errorf("--%s flag shorthand: got %q, want %q", tt.name, flag.Shorthand, tt.shorthand)
			}

			if flag.DefValue != tt.defValue {
				t.Errorf("--%s flag default: got %q, want %q", tt.name, flag.DefValue, tt.defValue)
			}
		})
	}
}

func TestParseFilters(t *testing.T) {
	tests := []struct {
		name        string
		filters     []string
		expectErr   bool
		expectState bool
		expectLabel bool
	}{
		{
			name:        "empty filters",
			filters:     []string{},
			expectErr:   false,
			expectState: false,
			expectLabel: false,
		},
		{
			name:        "state filter",
			filters:     []string{"state=running"},
			expectErr:   false,
			expectState: true,
			expectLabel: false,
		},
		{
			name:        "label filter",
			filters:     []string{"label=app=myapp"},
			expectErr:   false,
			expectState: false,
			expectLabel: true,
		},
		{
			name:        "name filter",
			filters:     []string{"name=mycontainer"},
			expectErr:   false,
			expectState: false,
			expectLabel: true,
		},
		{
			name:        "invalid filter format",
			filters:     []string{"invalid"},
			expectErr:   true,
			expectState: false,
			expectLabel: false,
		},
		{
			name:        "unknown filter key",
			filters:     []string{"unknown=value"},
			expectErr:   true,
			expectState: false,
			expectLabel: false,
		},
		{
			name:        "invalid state value",
			filters:     []string{"state=invalid"},
			expectErr:   true,
			expectState: false,
			expectLabel: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector, states, err := parseFilters(tt.filters)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectState && len(states) == 0 {
				t.Error("expected states, got none")
			}

			if tt.expectLabel && selector == nil {
				t.Error("expected selector, got nil")
			}
		})
	}
}

func TestParseFilters_MultipleFilters(t *testing.T) {
	filters := []string{"state=running", "label=app=myapp", "name=test"}

	selector, states, err := parseFilters(filters)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(states) != 1 {
		t.Errorf("expected 1 state, got %d", len(states))
	}

	if selector == nil {
		t.Fatal("expected selector, got nil")
	}

	if len(selector) != 2 {
		t.Errorf("expected 2 labels in selector, got %d", len(selector))
	}
}

func TestFormatPorts(t *testing.T) {
	tests := []struct {
		name     string
		ports    []*computesvc.PortMapping
		expected string
	}{
		{
			name:     "empty ports",
			ports:    nil,
			expected: "",
		},
		{
			name:     "empty slice",
			ports:    []*computesvc.PortMapping{},
			expected: "",
		},
		{
			name: "single port",
			ports: []*computesvc.PortMapping{
				{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			},
			expected: "8080->80/tcp",
		},
		{
			name: "multiple ports",
			ports: []*computesvc.PortMapping{
				{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
				{HostPort: 443, ContainerPort: 443, Protocol: "tcp"},
			},
			expected: "8080->80/tcp, 443->443/tcp",
		},
		{
			name: "port with host IP",
			ports: []*computesvc.PortMapping{
				{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			},
			expected: "127.0.0.1:8080->80/tcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatPorts(tt.ports)
			if result != tt.expected {
				t.Errorf("formatPorts() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestListOptions_Defaults(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newListCommand(getFlags)

	all, err := cmd.Flags().GetBool("all")
	if err != nil {
		t.Fatalf("error getting all flag: %v", err)
	}
	if all {
		t.Error("expected default all to be false")
	}

	pageSize, err := cmd.Flags().GetInt32("limit")
	if err != nil {
		t.Fatalf("error getting limit flag: %v", err)
	}
	if pageSize != 100 {
		t.Errorf("expected default limit to be 100, got %d", pageSize)
	}
}
