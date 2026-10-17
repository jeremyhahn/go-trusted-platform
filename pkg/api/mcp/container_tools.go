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
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Container Request/Response Types
// =============================================================================

// ContainerCreateRequest represents the MCP request for creating a container.
type ContainerCreateRequest struct {
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	Command    []string          `json:"command,omitempty"`
	Args       []string          `json:"args,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	User       string            `json:"user,omitempty"`
	Privileged bool              `json:"privileged,omitempty"`
	Mounts     []MountRequest    `json:"mounts,omitempty"`
	Ports      []PortRequest     `json:"ports,omitempty"`
	Resources  *ResourceRequest  `json:"resources,omitempty"`
}

// MountRequest represents a mount configuration in MCP requests.
type MountRequest struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
	Type     string `json:"type,omitempty"`
}

// PortRequest represents a port mapping in MCP requests.
type PortRequest struct {
	ContainerPort uint16 `json:"container_port"`
	HostPort      uint16 `json:"host_port,omitempty"`
	HostIP        string `json:"host_ip,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
}

// ResourceRequest represents resource limits in MCP requests.
type ResourceRequest struct {
	CPULimit    string `json:"cpu_limit,omitempty"`
	MemoryLimit string `json:"memory_limit,omitempty"`
	PidsLimit   int64  `json:"pids_limit,omitempty"`
}

// =============================================================================
// Container Error Types
// =============================================================================

// ErrContainerServiceUnavailable indicates the container service is not available.
var ErrContainerServiceUnavailable = &ContainerError{
	Code:    "CONTAINER_SERVICE_UNAVAILABLE",
	Message: "container service is not available",
}

// ErrContainerNameRequired indicates a container name is required.
var ErrContainerNameRequired = &ContainerError{
	Code:    "CONTAINER_NAME_REQUIRED",
	Message: container.ErrContainerNameRequired.Error(),
}

// ErrContainerImageRequired indicates a container image is required.
var ErrContainerImageRequired = &ContainerError{
	Code:    "CONTAINER_IMAGE_REQUIRED",
	Message: "container image is required",
}

// ErrContainerIDRequired indicates a container ID is required.
var ErrContainerIDRequired = &ContainerError{
	Code:    "CONTAINER_ID_REQUIRED",
	Message: "container ID is required",
}

// ErrContainerNotFound indicates a container was not found.
var ErrContainerNotFound = &ContainerError{
	Code:    "CONTAINER_NOT_FOUND",
	Message: "container not found",
}

// ContainerError represents a container operation error.
type ContainerError struct {
	Code    string
	Message string
}

func (e *ContainerError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GRPCStatus classifies the error by its Code (codeClass), so the MCP
// server answers it with the matching JSON-RPC code.
func (e *ContainerError) GRPCStatus() *status.Status {
	return codeStatus(e.Code, e.Error())
}

// =============================================================================
// Container Tool Registration
// =============================================================================

// registerContainerTools registers container-related MCP tools.
func (r *ToolRegistry) registerContainerTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "container_create",
		Description: "Create a new container from an image specification",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Container name (required, must start with a letter, alphanumeric with hyphens/underscores)",
				},
				"image": map[string]interface{}{
					"type":        "string",
					"description": "Container image reference (required, format: [registry/]repository[:tag|@digest])",
				},
				"command": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Override the default command",
				},
				"args": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Arguments to the command",
				},
				"env": map[string]interface{}{
					"type":        "object",
					"description": "Environment variables as key-value pairs",
				},
				"labels": map[string]interface{}{
					"type":        "object",
					"description": "Container labels as key-value pairs",
				},
				"working_dir": map[string]interface{}{
					"type":        "string",
					"description": "Working directory inside the container",
				},
				"user": map[string]interface{}{
					"type":        "string",
					"description": "User to run the container as",
				},
				"privileged": map[string]interface{}{
					"type":        "boolean",
					"description": "Run container in privileged mode (avoid unless necessary)",
					"default":     false,
				},
				"mounts": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"source":    map[string]interface{}{"type": "string", "description": "Source path on host"},
							"target":    map[string]interface{}{"type": "string", "description": "Target path in container"},
							"read_only": map[string]interface{}{"type": "boolean", "description": "Mount as read-only"},
							"type":      map[string]interface{}{"type": "string", "description": "Mount type (bind, volume, tmpfs)"},
						},
						"required": []string{"source", "target"},
					},
					"description": "Filesystem mounts",
				},
				"ports": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"container_port": map[string]interface{}{"type": "integer", "description": "Port inside the container"},
							"host_port":      map[string]interface{}{"type": "integer", "description": "Port on the host"},
							"host_ip":        map[string]interface{}{"type": "string", "description": "Host IP to bind to"},
							"protocol":       map[string]interface{}{"type": "string", "description": "Protocol (tcp, udp)"},
						},
						"required": []string{"container_port"},
					},
					"description": "Port mappings",
				},
				"resources": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"cpu_limit":    map[string]interface{}{"type": "string", "description": "CPU limit (e.g., '2' or '0.5')"},
						"memory_limit": map[string]interface{}{"type": "string", "description": "Memory limit (e.g., '512M', '2G')"},
						"pids_limit":   map[string]interface{}{"type": "integer", "description": "Maximum number of processes"},
					},
					"description": "Resource limits",
				},
			},
			"required": []string{"name", "image"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "container_start",
		Description: "Start a stopped container",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Container ID or name",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "container_stop",
		Description: "Stop a running container",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Container ID or name",
				},
				"timeout": map[string]interface{}{
					"type":        "integer",
					"description": "Timeout in seconds before force kill",
					"default":     10,
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "container_remove",
		Description: "Remove a container",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Container ID or name",
				},
				"force": map[string]interface{}{
					"type":        "boolean",
					"description": "Force removal of running container",
					"default":     false,
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "container_get",
		Description: "Get detailed information about a container",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Container ID or name",
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "container_list",
		Description: "List containers with optional filters",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"all": map[string]interface{}{
					"type":        "boolean",
					"description": "Include stopped containers",
					"default":     false,
				},
				"filters": map[string]interface{}{
					"type":        "object",
					"description": "Label-based filters as key-value arrays",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum number of containers to return",
					"default":     50,
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "container_logs",
		Description: "Get logs from a container",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Container ID or name",
				},
				"stdout": map[string]interface{}{
					"type":        "boolean",
					"description": "Include stdout",
					"default":     true,
				},
				"stderr": map[string]interface{}{
					"type":        "boolean",
					"description": "Include stderr",
					"default":     true,
				},
				"tail": map[string]interface{}{
					"type":        "string",
					"description": "Number of lines from the end (e.g., '100' or 'all')",
					"default":     "100",
				},
				"timestamps": map[string]interface{}{
					"type":        "boolean",
					"description": "Include timestamps in output",
					"default":     false,
				},
			},
			"required": []string{"id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "container_attest",
		Description: "Perform TPM attestation for a container, generating a cryptographic proof of its integrity",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Container ID or name",
				},
			},
			"required": []string{"id"},
		},
	})
}

// ToOrchestratorContainerSpec converts a ContainerCreateRequest to an OrchestratorContainerSpec.
func (req *ContainerCreateRequest) ToOrchestratorContainerSpec() *container.OrchestratorContainerSpec {
	spec := &container.OrchestratorContainerSpec{
		Name:       req.Name,
		Image:      req.Image,
		Command:    req.Command,
		Args:       req.Args,
		Env:        req.Env,
		Labels:     req.Labels,
		WorkingDir: req.WorkingDir,
		User:       req.User,
		Privileged: req.Privileged,
	}

	// Convert mounts
	for _, m := range req.Mounts {
		mountType := container.MountTypeBind
		if m.Type != "" {
			mountType = container.MountType(m.Type)
		}
		spec.Mounts = append(spec.Mounts, container.MountConfig{
			Source:   m.Source,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
			Type:     mountType,
		})
	}

	// Convert ports
	for _, p := range req.Ports {
		protocol := "tcp"
		if p.Protocol != "" {
			protocol = p.Protocol
		}
		spec.Ports = append(spec.Ports, container.PortMapping{
			ContainerPort: p.ContainerPort,
			HostPort:      p.HostPort,
			HostIP:        p.HostIP,
			Protocol:      protocol,
		})
	}

	// Convert resources
	if req.Resources != nil {
		spec.Resources = container.ResourceConfig{
			CPULimit:    req.Resources.CPULimit,
			MemoryLimit: req.Resources.MemoryLimit,
			PidsLimit:   req.Resources.PidsLimit,
		}
	}

	return spec
}
