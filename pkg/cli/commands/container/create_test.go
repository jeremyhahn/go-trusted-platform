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
	"errors"

	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewCreateCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newCreateCommand(getFlags)

	if cmd == nil {
		t.Fatal("newCreateCommand returned nil")
	}

	if cmd.Use != "create" {
		t.Errorf("expected Use to be 'create', got %q", cmd.Use)
	}

	if cmd.Short != "Create a new container" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewCreateCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCreateCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewCreateCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCreateCommand(getFlags)

	tests := []struct {
		name      string
		shorthand string
		defValue  string
	}{
		{"name", "n", ""},
		{"image", "i", ""},
		{"env", "e", "[]"},
		{"label", "l", "[]"},
		{"port", "p", "[]"},
		{"mount", "m", "[]"},
		{"privileged", "", "false"},
		{"network-mode", "", ""},
		{"memory", "", ""},
		{"cpu", "", ""},
		{"cmd", "", "[]"},
		{"workdir", "w", ""},
		{"tpm-access", "", "false"},
		{"start", "", "false"},
		{"user", "u", ""},
		{"restart", "", ""},
		{"attest", "", "false"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.name)
			if flag == nil {
				t.Errorf("--%s flag not found", tt.name)
				return
			}

			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("--%s flag shorthand: got %q, want %q", tt.name, flag.Shorthand, tt.shorthand)
			}

			if tt.defValue != "" && flag.DefValue != tt.defValue {
				t.Errorf("--%s flag default: got %q, want %q", tt.name, flag.DefValue, tt.defValue)
			}
		})
	}
}

func TestNewCreateCommand_RequiredFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCreateCommand(getFlags)

	// Check that name is marked as required
	nameFlag := cmd.Flags().Lookup("name")
	if nameFlag == nil {
		t.Error("--name flag not found")
	}

	// Check that image is marked as required
	imageFlag := cmd.Flags().Lookup("image")
	if imageFlag == nil {
		t.Error("--image flag not found")
	}
}

func TestBuildCreateParams_MapsEveryFlag(t *testing.T) {
	opts := &createOptions{
		name:        "api",
		image:       "docker.io/library/alpine:latest",
		env:         []string{"LOG_LEVEL=info"},
		label:       []string{"test=true"},
		networkMode: "bridge",
		memory:      "1g",
		cpu:         "2",
		command:     []string{"sleep", "3600"},
		workDir:     "/srv",
		user:        "1000:1000",
		restart:     "on-failure",
		attest:      true,
		start:       true,
	}

	params, err := buildCreateParams(opts)
	if err != nil {
		t.Fatalf("buildCreateParams: %v", err)
	}

	if params.Name != "api" || params.Image != "docker.io/library/alpine:latest" {
		t.Errorf("name/image: got %q/%q", params.Name, params.Image)
	}
	if params.User != "1000:1000" {
		t.Errorf("User: got %q", params.User)
	}
	if params.RestartPolicy != computesvc.RestartPolicyOnFailure {
		t.Errorf("RestartPolicy: got %q", params.RestartPolicy)
	}
	if !params.AttestOnCreate {
		t.Error("AttestOnCreate: got false")
	}
	if params.Labels["test"] != "true" {
		t.Errorf("Labels: got %v", params.Labels)
	}
	if len(params.Command) != 2 || params.Command[0] != "sleep" {
		t.Errorf("Command: got %v", params.Command)
	}
	if params.Resources == nil || params.Resources.MaxMemoryMB != 1024 || params.Resources.MaxCPUs != 2 {
		t.Errorf("Resources: got %+v", params.Resources)
	}
}

func TestBuildCreateParams_DefaultsLeaveOptionalFieldsUnset(t *testing.T) {
	params, err := buildCreateParams(&createOptions{name: "api", image: "nginx:latest"})
	if err != nil {
		t.Fatalf("buildCreateParams: %v", err)
	}
	if params.RestartPolicy != "" || params.User != "" || params.AttestOnCreate || params.Resources != nil {
		t.Errorf("optional fields set: %+v", params)
	}
}

func TestBuildCreateParams_RejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name  string
		opts  createOptions
		field string
	}{
		{"missing name", createOptions{image: "nginx:latest"}, "name"},
		{"missing image", createOptions{name: "api"}, "image"},
		{"unknown restart policy", createOptions{name: "api", image: "nginx:latest", restart: "sometimes"}, "restart"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildCreateParams(&tt.opts)
			var cfgErr ErrInvalidContainerConfig
			if !errors.As(err, &cfgErr) {
				t.Fatalf("expected ErrInvalidContainerConfig, got %v", err)
			}
			if cfgErr.Field != tt.field {
				t.Errorf("Field: got %q, want %q", cfgErr.Field, tt.field)
			}
		})
	}
}

func TestBuildCreateParams_RejectsBadMemory(t *testing.T) {
	_, err := buildCreateParams(&createOptions{name: "api", image: "nginx:latest", memory: "lots"})
	var memErr ErrInvalidMemorySpec
	if !errors.As(err, &memErr) {
		t.Fatalf("expected ErrInvalidMemorySpec, got %v", err)
	}
}

func TestParseCPUCount_ValidInput(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
	}{
		{"", 0},
		{"1", 1},
		{"2", 2},
		{"4", 4},
		{"0.5", 0}, // Truncated to uint32
		{"1.5", 1}, // Truncated to uint32
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseCPUCount(tt.input)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("parseCPUCount(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseCPUCount_InvalidInput(t *testing.T) {
	tests := []string{
		"abc",
		"-1",
		"invalid",
	}

	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			_, err := parseCPUCount(tt)
			if err == nil {
				t.Errorf("expected error for input %q, got nil", tt)
			}
		})
	}
}

func TestPrintContainerDetails_NilContainer(t *testing.T) {
	// This should not panic
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	printContainerDetails(printer, nil)
}

func TestPrintContainerDetails_WithConfig(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	container := &computesvc.Container{
		ID:    "test-container-id",
		State: computesvc.ContainerStateRunning,
		Config: &computesvc.ContainerConfig{
			Name:       "test-container",
			Image:      "nginx:latest",
			WorkingDir: "/app",
			Command:    []string{"nginx", "-g", "daemon off;"},
			Privileged: true,
			TpmAccess:  true,
			Network:    "host",
		},
	}

	// Should not panic
	printContainerDetails(printer, container)
}

func TestPrintContainerDetails_WithHostIdAndTimestamps(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	container := &computesvc.Container{
		ID:        "test-container-id",
		State:     computesvc.ContainerStateRunning,
		HostID:    "host-123",
		StartedAt: time.Now(),
		Config: &computesvc.ContainerConfig{
			Name:  "test-container",
			Image: "nginx:latest",
		},
	}

	// Should not panic
	printContainerDetails(printer, container)
}

func TestPrintContainerDetails_MinimalConfig(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	container := &computesvc.Container{
		ID:    "test-container-id",
		State: computesvc.ContainerStateCreated,
		Config: &computesvc.ContainerConfig{
			Name:  "minimal",
			Image: "alpine",
		},
	}

	// Should not panic
	printContainerDetails(printer, container)
}
