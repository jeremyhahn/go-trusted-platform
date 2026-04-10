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

package mcp

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
)

func TestToOrchestratorContainerSpec(t *testing.T) {
	t.Run("full spec conversion", func(t *testing.T) {
		req := &ContainerCreateRequest{
			Name:       "test-container",
			Image:      "alpine:latest",
			Command:    []string{"/bin/sh"},
			Args:       []string{"-c", "echo hello"},
			Env:        map[string]string{"FOO": "bar"},
			Labels:     map[string]string{"app": "test"},
			WorkingDir: "/app",
			User:       "nobody",
			Privileged: true,
			Mounts: []MountRequest{
				{
					Source:   "/host/path",
					Target:   "/container/path",
					ReadOnly: true,
					Type:     "volume",
				},
				{
					Source: "/host/bind",
					Target: "/container/bind",
				},
			},
			Ports: []PortRequest{
				{
					ContainerPort: 8080,
					HostPort:      9090,
					HostIP:        "0.0.0.0",
					Protocol:      "udp",
				},
				{
					ContainerPort: 443,
					HostPort:      443,
				},
			},
			Resources: &ResourceRequest{
				CPULimit:    "2",
				MemoryLimit: "512m",
				PidsLimit:   100,
			},
		}

		spec := req.ToOrchestratorContainerSpec()

		if spec.Name != "test-container" {
			t.Errorf("expected name 'test-container', got %s", spec.Name)
		}
		if spec.Image != "alpine:latest" {
			t.Errorf("expected image 'alpine:latest', got %s", spec.Image)
		}
		if len(spec.Command) != 1 || spec.Command[0] != "/bin/sh" {
			t.Errorf("unexpected command: %v", spec.Command)
		}
		if len(spec.Args) != 2 {
			t.Errorf("expected 2 args, got %d", len(spec.Args))
		}
		if spec.Env["FOO"] != "bar" {
			t.Errorf("expected env FOO=bar, got %v", spec.Env)
		}
		if spec.Labels["app"] != "test" {
			t.Errorf("expected label app=test, got %v", spec.Labels)
		}
		if spec.WorkingDir != "/app" {
			t.Errorf("expected working dir '/app', got %s", spec.WorkingDir)
		}
		if spec.User != "nobody" {
			t.Errorf("expected user 'nobody', got %s", spec.User)
		}
		if !spec.Privileged {
			t.Error("expected privileged=true")
		}

		// Verify mounts
		if len(spec.Mounts) != 2 {
			t.Fatalf("expected 2 mounts, got %d", len(spec.Mounts))
		}
		if spec.Mounts[0].Type != container.MountType("volume") {
			t.Errorf("expected first mount type 'volume', got %s", spec.Mounts[0].Type)
		}
		if !spec.Mounts[0].ReadOnly {
			t.Error("expected first mount to be read-only")
		}
		if spec.Mounts[1].Type != container.MountTypeBind {
			t.Errorf("expected second mount type default 'bind', got %s", spec.Mounts[1].Type)
		}

		// Verify ports
		if len(spec.Ports) != 2 {
			t.Fatalf("expected 2 ports, got %d", len(spec.Ports))
		}
		if spec.Ports[0].Protocol != "udp" {
			t.Errorf("expected first port protocol 'udp', got %s", spec.Ports[0].Protocol)
		}
		if spec.Ports[0].HostPort != 9090 {
			t.Errorf("expected first port host port 9090, got %d", spec.Ports[0].HostPort)
		}
		if spec.Ports[1].Protocol != "tcp" {
			t.Errorf("expected second port protocol default 'tcp', got %s", spec.Ports[1].Protocol)
		}

		// Verify resources
		if spec.Resources.CPULimit != "2" {
			t.Errorf("expected CPU limit '2', got %s", spec.Resources.CPULimit)
		}
		if spec.Resources.MemoryLimit != "512m" {
			t.Errorf("expected memory limit '512m', got %s", spec.Resources.MemoryLimit)
		}
		if spec.Resources.PidsLimit != 100 {
			t.Errorf("expected pids limit 100, got %d", spec.Resources.PidsLimit)
		}
	})

	t.Run("minimal spec without optional fields", func(t *testing.T) {
		req := &ContainerCreateRequest{
			Name:  "minimal",
			Image: "busybox",
		}

		spec := req.ToOrchestratorContainerSpec()

		if spec.Name != "minimal" {
			t.Errorf("expected name 'minimal', got %s", spec.Name)
		}
		if spec.Image != "busybox" {
			t.Errorf("expected image 'busybox', got %s", spec.Image)
		}
		if len(spec.Mounts) != 0 {
			t.Errorf("expected 0 mounts, got %d", len(spec.Mounts))
		}
		if len(spec.Ports) != 0 {
			t.Errorf("expected 0 ports, got %d", len(spec.Ports))
		}
		if spec.Resources.CPULimit != "" {
			t.Errorf("expected empty CPU limit, got %s", spec.Resources.CPULimit)
		}
	})
}
