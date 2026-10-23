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
	"context"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// ContainerOpsServiceProvider is the optional capability a ServiceProvider
// implements to serve the operational container tools (container_exec,
// container_metrics). It follows the same optional-interface pattern used by
// the PXE, tenant, and switch tool groups so the core ServiceProvider
// interface stays stable while new capabilities are added out-of-band.
type ContainerOpsServiceProvider interface {
	// ContainerExec executes a command inside a running container and returns
	// a response model carrying stdout, stderr, and the exit code.
	ContainerExec(ctx context.Context, id string, command []string, env map[string]string, workingDir string, tty bool) (interface{}, error)

	// ContainerMetrics returns a resource-usage snapshot for a running container.
	ContainerMetrics(ctx context.Context, id string) (interface{}, error)
}

// registerContainerOpsTools registers the operational container tools
// (container_exec, container_metrics). container_attach is an interactive
// streaming session that has no single-response MCP tool model; it is exposed
// on the gRPC (server-streaming) and REST transports instead.
func (r *ToolRegistry) registerContainerOpsTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "container_exec",
		Description: "Execute a command inside a running container and return its stdout, stderr, and exit code",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "Container ID or name",
				},
				"command": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Command and arguments to execute (argv[0] is the binary)",
				},
				"env": map[string]interface{}{
					"type":        "object",
					"description": "Environment variables as key-value pairs",
				},
				"working_dir": map[string]interface{}{
					"type":        "string",
					"description": "Working directory for the executed process",
				},
				"tty": map[string]interface{}{
					"type":        "boolean",
					"description": "Allocate a pseudo-terminal (combined output is returned on stdout)",
					"default":     false,
				},
			},
			"required": []string{"id", "command"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "container_metrics",
		Description: "Get resource-usage metrics (CPU, memory, disk I/O, network) for a running container",
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

// executeContainerExec routes the container_exec tool to the service provider's
// ContainerExec verb, returning the buffered stdout/stderr and exit code.
func (r *ToolRegistry) executeContainerExec(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	if id == "" {
		return nil, ErrContainerIDRequired
	}

	command := getStringSlice(args, "command")
	if len(command) == 0 {
		return nil, &ContainerError{Code: "CONTAINER_COMMAND_REQUIRED", Message: "container exec command is required"}
	}

	provider, ok := r.service.(ContainerOpsServiceProvider)
	if !ok {
		return nil, ErrContainerServiceUnavailable
	}

	env := getStringMap(args, "env")
	workingDir := getString(args, "working_dir")
	tty := getBool(args, "tty")

	result, err := provider.ContainerExec(ctx, id, command, env, workingDir, tty)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeContainerMetrics routes the container_metrics tool to the service
// provider's ContainerMetrics verb.
func (r *ToolRegistry) executeContainerMetrics(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	if id == "" {
		return nil, ErrContainerIDRequired
	}

	provider, ok := r.service.(ContainerOpsServiceProvider)
	if !ok {
		return nil, ErrContainerServiceUnavailable
	}

	result, err := provider.ContainerMetrics(ctx, id)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
