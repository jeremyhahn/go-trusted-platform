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

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewGetCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newGetCommand(getFlags)

	if cmd == nil {
		t.Fatal("newGetCommand returned nil")
	}

	if cmd.Use != "get <container-id>" {
		t.Errorf("expected Use to be 'get <container-id>', got %q", cmd.Use)
	}

	if cmd.Short != "Get container details" {
		t.Errorf("unexpected Short description: %q", cmd.Short)
	}
}

func TestNewGetCommand_HasAliases(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newGetCommand(getFlags)

	expectedAliases := []string{"inspect", "describe"}
	if len(cmd.Aliases) != len(expectedAliases) {
		t.Errorf("expected %d aliases, got %d", len(expectedAliases), len(cmd.Aliases))
	}

	for i, alias := range expectedAliases {
		if cmd.Aliases[i] != alias {
			t.Errorf("expected alias %q at index %d, got %q", alias, i, cmd.Aliases[i])
		}
	}
}

func TestNewGetCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newGetCommand(getFlags)

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewGetCommand_RequiresOneArg(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newGetCommand(getFlags)

	if cmd.Args == nil {
		t.Error("Args should not be nil")
	}

	err := cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("expected error when no args provided")
	}

	err = cmd.Args(cmd, []string{"container-id"})
	if err != nil {
		t.Errorf("unexpected error with one arg: %v", err)
	}
}

func TestRunGet_EmptyContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	err := runGet(flags, "")
	if err == nil {
		t.Error("expected error for empty container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

func TestFormatRestartPolicy(t *testing.T) {
	tests := []struct {
		policy   platformv1.RestartPolicy
		expected string
	}{
		{platformv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED, "Unknown"},
		{platformv1.RestartPolicy_RESTART_POLICY_NO, "No"},
		{platformv1.RestartPolicy_RESTART_POLICY_ON_FAILURE, "On Failure"},
		{platformv1.RestartPolicy_RESTART_POLICY_ALWAYS, "Always"},
		{platformv1.RestartPolicy_RESTART_POLICY_UNLESS_STOPPED, "Unless Stopped"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatRestartPolicy(tt.policy)
			if result != tt.expected {
				t.Errorf("formatRestartPolicy(%v) = %q, want %q", tt.policy, result, tt.expected)
			}
		})
	}
}

func TestPrintFullContainerDetails_NilContainer(t *testing.T) {
	// This should not panic even with nil container
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	err := printFullContainerDetails(printer, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintFullContainerDetails_MinimalContainer(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	container := &platformv1.Container{
		Id:    "test-container-id",
		State: platformv1.ContainerState_CONTAINER_STATE_RUNNING,
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintFullContainerDetails_FullContainer(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	container := &platformv1.Container{
		Id:     "test-container-id",
		State:  platformv1.ContainerState_CONTAINER_STATE_RUNNING,
		HostId: "host-1",
		Config: &platformv1.ContainerConfig{
			Name:       "test-container",
			Image:      "nginx:latest",
			ImageHash:  "sha256:abc123",
			WorkingDir: "/app",
			Command:    []string{"nginx", "-g", "daemon off;"},
			Privileged: false,
			TpmAccess:  true,
			Network:    "bridge",
			Env: []*platformv1.EnvVar{
				{Name: "ENV", Value: "prod"},
			},
			Ports: []*platformv1.PortMapping{
				{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			},
			Volumes: []*platformv1.VolumeMount{
				{Source: "/host", Destination: "/container", Readonly: true},
			},
			Capabilities: []string{"NET_ADMIN"},
			Resources: &platformv1.ResourceLimits{
				MaxMemoryMb: 512,
				MaxCpus:     2,
			},
			Labels: map[string]string{
				"app": "nginx",
			},
			Metadata: map[string]string{
				"version": "1.0",
			},
			RestartPolicy: platformv1.RestartPolicy_RESTART_POLICY_ALWAYS,
		},
		Metrics: &platformv1.ContainerMetrics{
			CpuUsagePercent: 25.5,
			MemoryUsedMb:    256,
			MemoryLimitMb:   512,
			DiskReadBytes:   1024 * 1024,
			DiskWriteBytes:  512 * 1024,
			NetworkRxBytes:  2 * 1024 * 1024,
			NetworkTxBytes:  1 * 1024 * 1024,
			UptimeSeconds:   3600,
		},
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintFullContainerDetails_ExitedContainer(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	container := &platformv1.Container{
		Id:       "test-container-id",
		State:    platformv1.ContainerState_CONTAINER_STATE_EXITED,
		ExitCode: 0,
		Config: &platformv1.ContainerConfig{
			Name:  "exited-container",
			Image: "alpine",
		},
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintFullContainerDetails_WithNonZeroExitCode(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	container := &platformv1.Container{
		Id:       "test-container-id",
		State:    platformv1.ContainerState_CONTAINER_STATE_EXITED,
		ExitCode: 1,
		Config: &platformv1.ContainerConfig{
			Name:  "failed-container",
			Image: "alpine",
		},
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintFullContainerDetails_WithArgs(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	container := &platformv1.Container{
		Id:    "test-container-id",
		State: platformv1.ContainerState_CONTAINER_STATE_RUNNING,
		Config: &platformv1.ContainerConfig{
			Name:  "container-with-args",
			Image: "alpine",
			Args:  []string{"arg1", "arg2"},
		},
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintFullContainerDetails_WithPortMappingAndHostIP(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	container := &platformv1.Container{
		Id:    "test-container-id",
		State: platformv1.ContainerState_CONTAINER_STATE_RUNNING,
		Config: &platformv1.ContainerConfig{
			Name:  "container-with-host-ip",
			Image: "nginx",
			Ports: []*platformv1.PortMapping{
				{HostPort: 8080, ContainerPort: 80, Protocol: "tcp", HostIp: "127.0.0.1"},
			},
		},
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintFullContainerDetails_WithFinishedAt(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, true)
	now := timestamppb.Now()
	container := &platformv1.Container{
		Id:         "test-container-id",
		State:      platformv1.ContainerState_CONTAINER_STATE_EXITED,
		StartedAt:  now,
		FinishedAt: now,
		Config: &platformv1.ContainerConfig{
			Name:  "finished-container",
			Image: "alpine",
		},
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
