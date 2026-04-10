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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package mcp

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
)

// =============================================================================
// Container Error Tests
// =============================================================================

func TestContainerErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      *ContainerError
		expected string
	}{
		{
			name:     "ErrContainerServiceUnavailable",
			err:      ErrContainerServiceUnavailable,
			expected: "CONTAINER_SERVICE_UNAVAILABLE: container service is not available",
		},
		{
			name:     "ErrContainerNameRequired",
			err:      ErrContainerNameRequired,
			expected: "CONTAINER_NAME_REQUIRED: container name is required",
		},
		{
			name:     "ErrContainerImageRequired",
			err:      ErrContainerImageRequired,
			expected: "CONTAINER_IMAGE_REQUIRED: container image is required",
		},
		{
			name:     "ErrContainerIDRequired",
			err:      ErrContainerIDRequired,
			expected: "CONTAINER_ID_REQUIRED: container ID is required",
		},
		{
			name:     "ErrContainerNotFound",
			err:      ErrContainerNotFound,
			expected: "CONTAINER_NOT_FOUND: container not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestContainerError_CustomError(t *testing.T) {
	err := &ContainerError{
		Code:    "CUSTOM_ERROR",
		Message: "custom error message",
	}
	expected := "CUSTOM_ERROR: custom error message"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

// =============================================================================
// Container Tool Execution Tests
// =============================================================================

func TestExecuteContainerCreate_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":        "test-container",
		"image":       "nginx:latest",
		"command":     []interface{}{"nginx"},
		"args":        []interface{}{"-g", "daemon off;"},
		"working_dir": "/var/www",
		"user":        "nginx",
		"privileged":  true,
		"env": map[string]interface{}{
			"PORT": "8080",
		},
		"labels": map[string]interface{}{
			"app": "web",
		},
	}

	result, err := registry.executeContainerCreate(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Error("result should not be nil")
	}
}

func TestExecuteContainerCreate_MissingName(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"image": "nginx:latest",
	}

	_, err := registry.executeContainerCreate(ctx, args)
	if err != ErrContainerNameRequired {
		t.Errorf("expected ErrContainerNameRequired, got %v", err)
	}
}

func TestExecuteContainerCreate_MissingImage(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-container",
	}

	_, err := registry.executeContainerCreate(ctx, args)
	if err != ErrContainerImageRequired {
		t.Errorf("expected ErrContainerImageRequired, got %v", err)
	}
}

func TestExecuteContainerCreate_WithMountsPortsResources(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":  "full-config-container",
		"image": "nginx:latest",
		"mounts": []interface{}{
			map[string]interface{}{
				"source":    "/host/data",
				"target":    "/container/data",
				"type":      "bind",
				"read_only": true,
			},
		},
		"ports": []interface{}{
			map[string]interface{}{
				"container_port": 80,
				"host_port":      8080,
				"protocol":       "tcp",
			},
		},
		"resources": map[string]interface{}{
			"cpu_limit":    "2",
			"memory_limit": "512Mi",
		},
	}

	result, err := registry.executeContainerCreate(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Error("result should not be nil")
	}
}

func TestExecuteContainerStart_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	result, err := registry.executeContainerStart(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["success"] != true {
		t.Error("expected success = true")
	}
}

func TestExecuteContainerStart_MissingID(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeContainerStart(ctx, map[string]interface{}{})
	if err != ErrContainerIDRequired {
		t.Errorf("expected ErrContainerIDRequired, got %v", err)
	}
}

func TestExecuteContainerStop_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id":      "container-123",
		"timeout": float64(30),
	}

	result, err := registry.executeContainerStop(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["success"] != true {
		t.Error("expected success = true")
	}
}

func TestExecuteContainerStop_DefaultTimeout(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	result, err := registry.executeContainerStop(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["success"] != true {
		t.Error("expected success = true")
	}
}

func TestExecuteContainerStop_MissingID(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeContainerStop(ctx, map[string]interface{}{})
	if err != ErrContainerIDRequired {
		t.Errorf("expected ErrContainerIDRequired, got %v", err)
	}
}

func TestExecuteContainerRemove_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id":    "container-123",
		"force": true,
	}

	result, err := registry.executeContainerRemove(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["success"] != true {
		t.Error("expected success = true")
	}
}

func TestExecuteContainerRemove_MissingID(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeContainerRemove(ctx, map[string]interface{}{})
	if err != ErrContainerIDRequired {
		t.Errorf("expected ErrContainerIDRequired, got %v", err)
	}
}

func TestExecuteContainerGet_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	result, err := registry.executeContainerGet(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Error("result should not be nil")
	}
}

func TestExecuteContainerGet_MissingID(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeContainerGet(ctx, map[string]interface{}{})
	if err != ErrContainerIDRequired {
		t.Errorf("expected ErrContainerIDRequired, got %v", err)
	}
}

func TestExecuteContainerList_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"all":   true,
		"limit": float64(100),
		"filters": map[string]interface{}{
			"label": []interface{}{"app=web"},
			"name":  "test",
		},
	}

	result, err := registry.executeContainerList(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if _, ok := resultMap["containers"]; !ok {
		t.Error("expected containers in result")
	}
}

func TestExecuteContainerList_DefaultLimit(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeContainerList(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if _, ok := resultMap["containers"]; !ok {
		t.Error("expected containers in result")
	}
}

func TestExecuteContainerLogs_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id":         "container-123",
		"stdout":     true,
		"stderr":     true,
		"tail":       "50",
		"timestamps": true,
	}

	result, err := registry.executeContainerLogs(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if _, ok := resultMap["logs"]; !ok {
		t.Error("expected logs in result")
	}
}

func TestExecuteContainerLogs_MissingID(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeContainerLogs(ctx, map[string]interface{}{})
	if err != ErrContainerIDRequired {
		t.Errorf("expected ErrContainerIDRequired, got %v", err)
	}
}

func TestExecuteContainerAttest_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	result, err := registry.executeContainerAttest(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Error("result should not be nil")
	}
}

func TestExecuteContainerAttest_MissingID(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeContainerAttest(ctx, map[string]interface{}{})
	if err != ErrContainerIDRequired {
		t.Errorf("expected ErrContainerIDRequired, got %v", err)
	}
}

// =============================================================================
// ToOrchestratorContainerSpec Tests
// =============================================================================

func TestContainerCreateRequest_ToOrchestratorContainerSpec_Full(t *testing.T) {
	req := &ContainerCreateRequest{
		Name:       "test-container",
		Image:      "nginx:latest",
		Command:    []string{"nginx"},
		Args:       []string{"-g", "daemon off;"},
		Env:        map[string]string{"PORT": "8080"},
		Labels:     map[string]string{"app": "web"},
		WorkingDir: "/var/www",
		User:       "nginx",
		Privileged: true,
		Mounts: []MountRequest{
			{
				Source:   "/host/data",
				Target:   "/container/data",
				ReadOnly: true,
				Type:     "bind",
			},
			{
				Source: "my-volume",
				Target: "/container/vol",
				Type:   "volume",
			},
		},
		Ports: []PortRequest{
			{
				ContainerPort: 80,
				HostPort:      8080,
				HostIP:        "0.0.0.0",
				Protocol:      "tcp",
			},
			{
				ContainerPort: 443,
			},
		},
		Resources: &ResourceRequest{
			CPULimit:    "2",
			MemoryLimit: "512M",
			PidsLimit:   100,
		},
	}

	spec := req.ToOrchestratorContainerSpec()

	if spec.Name != "test-container" {
		t.Errorf("Name = %s, want test-container", spec.Name)
	}
	if spec.Image != "nginx:latest" {
		t.Errorf("Image = %s, want nginx:latest", spec.Image)
	}
	if len(spec.Command) != 1 || spec.Command[0] != "nginx" {
		t.Errorf("Command = %v, want [nginx]", spec.Command)
	}
	if len(spec.Args) != 2 {
		t.Errorf("Args = %v, want [-g daemon off;]", spec.Args)
	}
	if spec.Env["PORT"] != "8080" {
		t.Errorf("Env[PORT] = %s, want 8080", spec.Env["PORT"])
	}
	if spec.Labels["app"] != "web" {
		t.Errorf("Labels[app] = %s, want web", spec.Labels["app"])
	}
	if spec.WorkingDir != "/var/www" {
		t.Errorf("WorkingDir = %s, want /var/www", spec.WorkingDir)
	}
	if spec.User != "nginx" {
		t.Errorf("User = %s, want nginx", spec.User)
	}
	if !spec.Privileged {
		t.Error("expected Privileged = true")
	}

	if len(spec.Mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(spec.Mounts))
	}
	if spec.Mounts[0].Source != "/host/data" {
		t.Errorf("Mounts[0].Source = %s, want /host/data", spec.Mounts[0].Source)
	}
	if spec.Mounts[0].Type != container.MountTypeBind {
		t.Errorf("Mounts[0].Type = %s, want bind", spec.Mounts[0].Type)
	}
	if !spec.Mounts[0].ReadOnly {
		t.Error("expected Mounts[0].ReadOnly = true")
	}

	if len(spec.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(spec.Ports))
	}
	if spec.Ports[0].ContainerPort != 80 {
		t.Errorf("Ports[0].ContainerPort = %d, want 80", spec.Ports[0].ContainerPort)
	}
	if spec.Ports[0].Protocol != "tcp" {
		t.Errorf("Ports[0].Protocol = %s, want tcp", spec.Ports[0].Protocol)
	}
	if spec.Ports[1].Protocol != "tcp" {
		t.Errorf("Ports[1].Protocol = %s, want tcp (default)", spec.Ports[1].Protocol)
	}

	if spec.Resources.CPULimit != "2" {
		t.Errorf("Resources.CPULimit = %s, want 2", spec.Resources.CPULimit)
	}
	if spec.Resources.MemoryLimit != "512M" {
		t.Errorf("Resources.MemoryLimit = %s, want 512M", spec.Resources.MemoryLimit)
	}
	if spec.Resources.PidsLimit != 100 {
		t.Errorf("Resources.PidsLimit = %d, want 100", spec.Resources.PidsLimit)
	}
}

func TestContainerCreateRequest_ToOrchestratorContainerSpec_Minimal(t *testing.T) {
	req := &ContainerCreateRequest{
		Name:  "minimal-container",
		Image: "alpine:latest",
	}

	spec := req.ToOrchestratorContainerSpec()

	if spec.Name != "minimal-container" {
		t.Errorf("Name = %s, want minimal-container", spec.Name)
	}
	if spec.Image != "alpine:latest" {
		t.Errorf("Image = %s, want alpine:latest", spec.Image)
	}
	if len(spec.Command) != 0 {
		t.Errorf("Command = %v, want empty", spec.Command)
	}
	if len(spec.Mounts) != 0 {
		t.Errorf("Mounts = %v, want empty", spec.Mounts)
	}
	if len(spec.Ports) != 0 {
		t.Errorf("Ports = %v, want empty", spec.Ports)
	}
}

func TestContainerCreateRequest_ToOrchestratorContainerSpec_DefaultMountType(t *testing.T) {
	req := &ContainerCreateRequest{
		Name:  "test",
		Image: "test:latest",
		Mounts: []MountRequest{
			{
				Source: "/host/path",
				Target: "/container/path",
			},
		},
	}

	spec := req.ToOrchestratorContainerSpec()

	if len(spec.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(spec.Mounts))
	}
	if spec.Mounts[0].Type != container.MountTypeBind {
		t.Errorf("Type = %s, want bind (default)", spec.Mounts[0].Type)
	}
}

// =============================================================================
// Container Tool Registration Tests
// =============================================================================

func TestRegisterContainerTools(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	expectedTools := []string{
		"container_create",
		"container_start",
		"container_stop",
		"container_remove",
		"container_get",
		"container_list",
		"container_logs",
		"container_attest",
	}

	tools := registry.ListTools()
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolNames[tool.Name] = true
	}

	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("missing expected tool: %s", name)
		}
	}
}
