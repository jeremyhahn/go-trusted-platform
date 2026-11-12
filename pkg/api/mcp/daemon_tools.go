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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrDaemonServiceNameRequired indicates that a service name parameter is required.
type ErrDaemonServiceNameRequired struct{}

func (e ErrDaemonServiceNameRequired) Error() string {
	return "service name is required"
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrDaemonServiceNameRequired) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// registerDaemonTools registers daemon management tools.
func (r *ToolRegistry) registerDaemonTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_daemon_status",
		Description: "Get daemon status including system info and uptime",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_daemon_version",
		Description: "Get daemon version information",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_daemon_list_services",
		Description: "List all managed services",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
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

	r.addTool(mcpwire.ToolDefinition{
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

	r.addTool(mcpwire.ToolDefinition{
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

	r.addTool(mcpwire.ToolDefinition{
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

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_daemon_list_protocols",
		Description: "List all supported protocol endpoints",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_daemon_get_config",
		Description: "Get the daemon configuration, one section or all of them",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"section": map[string]interface{}{"type": "string", "description": "Config section; empty returns every section"},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_daemon_reload_config",
		Description: "Reload the daemon configuration from disk",
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
		return nil, &mcpwire.WrappedError{Msg: "daemon status", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonVersion returns the daemon version information.
func (r *ToolRegistry) executeDaemonVersion(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DaemonVersion(ctx)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "daemon version", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonListServices lists all managed services.
func (r *ToolRegistry) executeDaemonListServices(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DaemonListServices(ctx)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "daemon list services", Err: err}
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
		return nil, &mcpwire.WrappedError{Msg: "daemon get service", Err: err}
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
		return nil, &mcpwire.WrappedError{Msg: "daemon start service", Err: err}
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
		return nil, &mcpwire.WrappedError{Msg: "daemon stop service", Err: err}
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
		return nil, &mcpwire.WrappedError{Msg: "daemon restart service", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonListProtocols lists all supported protocol endpoints.
func (r *ToolRegistry) executeDaemonListProtocols(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DaemonListProtocols(ctx)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "daemon list protocols", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonGetConfig returns the daemon configuration.
func (r *ToolRegistry) executeDaemonGetConfig(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DaemonGetConfig(ctx, getString(args, "section"))
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "daemon get config", Err: err}
	}
	return marshalResult(result)
}

// executeDaemonReloadConfig reloads the daemon configuration from disk.
func (r *ToolRegistry) executeDaemonReloadConfig(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.DaemonReloadConfig(ctx)
	if err != nil {
		return nil, &mcpwire.WrappedError{Msg: "daemon reload config", Err: err}
	}
	return marshalResult(reloadConfigResponseShape(result))
}

// reloadConfigResponseShape nests a flattened success/message answer under
// "status", the field platformv1.ReloadConfigResponse carries, so the SDK MCP
// adapter decodes the same status object the gRPC method returns. A result
// that already carries "status", or is not a map, passes through unchanged.
func reloadConfigResponseShape(result interface{}) interface{} {
	m, ok := result.(map[string]interface{})
	if !ok {
		return result
	}
	if _, has := m["status"]; has {
		return result
	}
	_, hasSuccess := m["success"]
	_, hasMessage := m["message"]
	if !hasSuccess && !hasMessage {
		return result
	}
	shaped := make(map[string]interface{}, len(m))
	status := map[string]interface{}{}
	for k, v := range m {
		switch k {
		case "success", "message":
			status[k] = v
		default:
			shaped[k] = v
		}
	}
	shaped["status"] = status
	return shaped
}
