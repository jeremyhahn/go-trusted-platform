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
)

// ErrDaemonServiceNameRequired indicates that a service name parameter is required.
type ErrDaemonServiceNameRequired struct{}

func (e ErrDaemonServiceNameRequired) Error() string {
	return "service name is required"
}

// registerDaemonTools registers daemon management tools.
func (r *ToolRegistry) registerDaemonTools() {
	r.addTool(ToolDefinition{
		Name:        "platform_daemon_status",
		Description: "Get daemon status including system info and uptime",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "platform_daemon_version",
		Description: "Get daemon version information",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "platform_daemon_list_services",
		Description: "List all managed services",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "platform_daemon_get_service",
		Description: "Get status of a specific service",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Service name"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "platform_daemon_start_service",
		Description: "Start a managed service",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Service name"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "platform_daemon_stop_service",
		Description: "Stop a managed service",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Service name"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "platform_daemon_restart_service",
		Description: "Restart a managed service",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"name": map[string]interface{}{"type": "string", "description": "Service name"},
			},
			"required": []string{"name"},
		},
	})

	r.addTool(ToolDefinition{
		Name:        "platform_daemon_list_protocols",
		Description: "List all supported protocol endpoints",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
}

// executeDaemonStatus returns the daemon status.
func (r *ToolRegistry) executeDaemonStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DaemonStatus(ctx)
	if err != nil {
		return nil, &WrappedError{Msg: "daemon status", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonVersion returns the daemon version information.
func (r *ToolRegistry) executeDaemonVersion(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DaemonVersion(ctx)
	if err != nil {
		return nil, &WrappedError{Msg: "daemon version", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonListServices lists all managed services.
func (r *ToolRegistry) executeDaemonListServices(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DaemonListServices(ctx)
	if err != nil {
		return nil, &WrappedError{Msg: "daemon list services", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonGetService returns the status of a specific service.
func (r *ToolRegistry) executeDaemonGetService(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, ErrDaemonServiceNameRequired{}
	}
	result, err := r.service.DaemonGetService(ctx, name)
	if err != nil {
		return nil, &WrappedError{Msg: "daemon get service", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonStartService starts a managed service.
func (r *ToolRegistry) executeDaemonStartService(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, ErrDaemonServiceNameRequired{}
	}
	result, err := r.service.DaemonStartService(ctx, name)
	if err != nil {
		return nil, &WrappedError{Msg: "daemon start service", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonStopService stops a managed service.
func (r *ToolRegistry) executeDaemonStopService(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, ErrDaemonServiceNameRequired{}
	}
	result, err := r.service.DaemonStopService(ctx, name)
	if err != nil {
		return nil, &WrappedError{Msg: "daemon stop service", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonRestartService restarts a managed service.
func (r *ToolRegistry) executeDaemonRestartService(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, ErrDaemonServiceNameRequired{}
	}
	result, err := r.service.DaemonRestartService(ctx, name)
	if err != nil {
		return nil, &WrappedError{Msg: "daemon restart service", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonListProtocols lists all supported protocol endpoints.
func (r *ToolRegistry) executeDaemonListProtocols(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DaemonListProtocols(ctx)
	if err != nil {
		return nil, &WrappedError{Msg: "daemon list protocols", Err: err}
	}
	return marshalResult(result)
}
