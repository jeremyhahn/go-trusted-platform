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

// =============================================================================
// Gateway Load Balancer Error Types
// =============================================================================

// ErrLBVIPTargetRequired indicates the protocol/address/port triple is
// missing or incomplete.
var ErrLBVIPTargetRequired = &GatewayError{
	Code:    "LB_VIP_TARGET_REQUIRED",
	Message: "VIP protocol, address, and port are required",
}

// ErrLBBackendsRequired indicates a VIP request carries no backends.
var ErrLBBackendsRequired = &GatewayError{
	Code:    "LB_BACKENDS_REQUIRED",
	Message: "at least one backend is required",
}

// =============================================================================
// Gateway Load Balancer Request Types
// =============================================================================

// LBBackendRequest is one load-balanced endpoint behind a VIP.
type LBBackendRequest struct {
	Address string
	Port    uint16
	Weight  uint16
}

// LBVIPAddRequest defines a load-balanced virtual IP.
type LBVIPAddRequest struct {
	Address   string
	Port      uint16
	Protocol  string
	Algorithm string
	Backends  []*LBBackendRequest
}

// =============================================================================
// Gateway Load Balancer Tool Registration
// =============================================================================

// lbVIPTargetProperties is the shared protocol/address/port schema of every
// keyed VIP tool.
func lbVIPTargetProperties() map[string]interface{} {
	return map[string]interface{}{
		"protocol": map[string]interface{}{
			"type":        "string",
			"description": "VIP protocol: tcp or udp",
		},
		"address": map[string]interface{}{
			"type":        "string",
			"description": "Virtual IPv4 address",
		},
		"port": map[string]interface{}{
			"type":        "integer",
			"description": "Virtual L4 port (1-65535)",
		},
	}
}

// lbBackendsProperty is the shared backends array schema.
func lbBackendsProperty() map[string]interface{} {
	return map[string]interface{}{
		"type":        "array",
		"description": "Backend endpoints",
		"items": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"address": map[string]interface{}{"type": "string", "description": "Backend IPv4 address"},
				"port":    map[string]interface{}{"type": "integer", "description": "Backend L4 port"},
				"weight":  map[string]interface{}{"type": "integer", "description": "Relative selection weight (0 means 1)"},
			},
			"required": []string{"address", "port"},
		},
	}
}

// registerGatewayLBTools registers gateway load balancer MCP tools.
func (r *ToolRegistry) registerGatewayLBTools() {
	addProps := lbVIPTargetProperties()
	addProps["algorithm"] = map[string]interface{}{
		"type":        "string",
		"description": "Balancing algorithm: hash or round-robin (both hash-based select-group balancing)",
	}
	addProps["backends"] = lbBackendsProperty()
	r.addTool(mcpwire.ToolDefinition{
		Name:        "gateway_lb_vip_add",
		Description: "Install a load-balanced virtual IP (VIP) distributing connections across backends via the OVS group-select + conntrack datapath",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": addProps,
			"required":   []string{"protocol", "address", "port", "backends"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "gateway_lb_vip_remove",
		Description: "Tear down a load-balanced virtual IP",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": lbVIPTargetProperties(),
			"required":   []string{"protocol", "address", "port"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "gateway_lb_vip_get",
		Description: "Get the status of one load-balanced virtual IP including per-backend health",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": lbVIPTargetProperties(),
			"required":   []string{"protocol", "address", "port"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "gateway_lb_vip_list",
		Description: "List every load-balanced virtual IP and its per-backend health",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})

	setProps := lbVIPTargetProperties()
	setProps["backends"] = lbBackendsProperty()
	r.addTool(mcpwire.ToolDefinition{
		Name:        "gateway_lb_vip_set_backends",
		Description: "Replace the backend set of a load-balanced virtual IP",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": setProps,
			"required":   []string{"protocol", "address", "port", "backends"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "gateway_lb_status",
		Description: "Get the load balancer service health (active state, VIP count, healthy/total backends)",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
}

// =============================================================================
// Gateway Load Balancer Tool Dispatch
// =============================================================================

// gatewayLBToolExecutors dispatches gateway_lb_* tools (map-based for O(1)
// routing per project conventions).
var gatewayLBToolExecutors = map[string]func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error){
	"gateway_lb_vip_add":          (*ToolRegistry).executeGatewayLBVIPAdd,
	"gateway_lb_vip_remove":       (*ToolRegistry).executeGatewayLBVIPRemove,
	"gateway_lb_vip_get":          (*ToolRegistry).executeGatewayLBVIPGet,
	"gateway_lb_vip_list":         (*ToolRegistry).executeGatewayLBVIPList,
	"gateway_lb_vip_set_backends": (*ToolRegistry).executeGatewayLBVIPSetBackends,
	"gateway_lb_status":           (*ToolRegistry).executeGatewayLBStatus,
}

// dispatchGatewayLBTool routes gateway_lb_* tools through the executor map.
// It returns handled=false when the tool name is not a load balancer tool.
func (r *ToolRegistry) dispatchGatewayLBTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	exec, ok := gatewayLBToolExecutors[name]
	if !ok {
		return nil, false, nil
	}
	result, err := exec(r, ctx, args)
	return result, true, err
}

// lbTargetFromArgs extracts and validates the protocol/address/port triple.
func lbTargetFromArgs(args map[string]interface{}) (protocol, address string, port uint16, err error) {
	protocol = getString(args, "protocol")
	address = getString(args, "address")
	portValue := getInt(args, "port")
	if protocol == "" || address == "" || portValue <= 0 || portValue > 65535 {
		return "", "", 0, ErrLBVIPTargetRequired
	}
	return protocol, address, uint16(portValue), nil
}

// lbBackendsFromArgs extracts the backends array.
func lbBackendsFromArgs(args map[string]interface{}) ([]*LBBackendRequest, error) {
	raw, ok := args["backends"].([]interface{})
	if !ok || len(raw) == 0 {
		return nil, ErrLBBackendsRequired
	}
	backends := make([]*LBBackendRequest, 0, len(raw))
	for _, entry := range raw {
		m, ok := entry.(map[string]interface{})
		if !ok {
			return nil, ErrLBBackendsRequired
		}
		port := getInt(m, "port")
		weight := getInt(m, "weight")
		if port <= 0 || port > 65535 || weight < 0 || weight > 65535 {
			return nil, ErrLBBackendsRequired
		}
		backends = append(backends, &LBBackendRequest{
			Address: getString(m, "address"),
			Port:    uint16(port),
			Weight:  uint16(weight),
		})
	}
	return backends, nil
}

func (r *ToolRegistry) executeGatewayLBVIPAdd(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	protocol, address, port, err := lbTargetFromArgs(args)
	if err != nil {
		return nil, err
	}
	backends, err := lbBackendsFromArgs(args)
	if err != nil {
		return nil, err
	}

	result, err := r.service.GatewayLBVIPAdd(ctx, &LBVIPAddRequest{
		Address:   address,
		Port:      port,
		Protocol:  protocol,
		Algorithm: getString(args, "algorithm"),
		Backends:  backends,
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayLBVIPRemove(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	protocol, address, port, err := lbTargetFromArgs(args)
	if err != nil {
		return nil, err
	}
	if err := r.service.GatewayLBVIPRemove(ctx, protocol, address, port); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true}, nil
}

func (r *ToolRegistry) executeGatewayLBVIPGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	protocol, address, port, err := lbTargetFromArgs(args)
	if err != nil {
		return nil, err
	}
	result, err := r.service.GatewayLBVIPGet(ctx, protocol, address, port)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayLBVIPList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	vips, err := r.service.GatewayLBVIPList(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"vips": vips}, nil
}

func (r *ToolRegistry) executeGatewayLBVIPSetBackends(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	protocol, address, port, err := lbTargetFromArgs(args)
	if err != nil {
		return nil, err
	}
	backends, err := lbBackendsFromArgs(args)
	if err != nil {
		return nil, err
	}
	result, err := r.service.GatewayLBVIPSetBackends(ctx, protocol, address, port, backends)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeGatewayLBStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.GatewayLBStatus(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
