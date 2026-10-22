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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Orchestrator (go-quicbaas agent fleet) Tool Registration
// =============================================================================

// Argument names are the json names of the platform.v1 Orchestrator request
// fields, so the SDK MCP adapter's request round-trip lands on them as-is.

// orchestratorPageProperty is the schema of the OrchestratorPage argument.
func orchestratorPageProperty() map[string]interface{} {
	return map[string]interface{}{
		"type":        "object",
		"description": "Page selection; omit for the server's default page",
		"properties": map[string]interface{}{
			"limit":  map[string]interface{}{"type": "integer", "description": "Page size; the server caps it at its maximum"},
			"offset": map[string]interface{}{"type": "integer", "description": "How many records to skip"},
		},
	}
}

// registerOrchestratorTools registers the orchestrator MCP tools. Every
// result is answered by the go-quicbaas orchestrator through the platform
// service layer (pkg/orchestrator); the platform holds no fleet state.
func (r *ToolRegistry) registerOrchestratorTools() {
	tenant := vpnStringProperty("Tenant ID")
	agent := vpnStringProperty("Agent ID")
	job := vpnStringProperty("Job ID")

	r.addTool(mcpwire.ToolDefinition{
		Name:        "orchestrator_health",
		Description: "Report the orchestrator's health: healthy flag, overall status, and the status of each component",
		InputSchema: emptyObjectSchema(),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "orchestrator_agent_list",
		Description: "List one page of a tenant's registered fleet agents, optionally narrowed by status, host or backend",
		InputSchema: vpnToolSchema(map[string]interface{}{
			"tenant_id": tenant,
			"status":    vpnStringProperty("Only agents in this status; omit for all"),
			"host":      vpnStringProperty("Only agents on this host; omit for all"),
			"backend":   vpnStringProperty("Only agents of this backend; omit for all"),
			"page":      orchestratorPageProperty(),
		}, "tenant_id"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "orchestrator_agent_get",
		Description: "Get one registered fleet agent",
		InputSchema: vpnToolSchema(map[string]interface{}{"tenant_id": tenant, "agent_id": agent}, "tenant_id", "agent_id"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "orchestrator_agent_disable",
		Description: "Administratively disable a fleet agent and revoke its credentials",
		InputSchema: vpnToolSchema(map[string]interface{}{"tenant_id": tenant, "agent_id": agent}, "tenant_id", "agent_id"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "orchestrator_agent_enable",
		Description: "Re-activate a disabled fleet agent",
		InputSchema: vpnToolSchema(map[string]interface{}{"tenant_id": tenant, "agent_id": agent}, "tenant_id", "agent_id"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "orchestrator_session_list",
		Description: "List one page of agent sessions, optionally narrowed by status, job or agent",
		InputSchema: vpnToolSchema(map[string]interface{}{
			"status":   vpnStringProperty("Only sessions in this status; omit for all"),
			"job_id":   vpnStringProperty("Only sessions of this job; omit for all"),
			"agent_id": vpnStringProperty("Only sessions of this agent; omit for all"),
			"page":     orchestratorPageProperty(),
		}),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "orchestrator_session_close",
		Description: "Terminate an agent session",
		InputSchema: vpnToolSchema(map[string]interface{}{"session_id": vpnStringProperty("Session ID")}, "session_id"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "orchestrator_job_list",
		Description: "List one page of a tenant's orchestration jobs, optionally narrowed to some states",
		InputSchema: vpnToolSchema(map[string]interface{}{
			"tenant_id": tenant,
			"statuses": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "Only jobs in any of these states; omit for all",
			},
			"page": orchestratorPageProperty(),
		}, "tenant_id"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "orchestrator_job_get",
		Description: "Get the current status of one orchestration job",
		InputSchema: vpnToolSchema(map[string]interface{}{"tenant_id": tenant, "job_id": job}, "tenant_id", "job_id"),
	})
	r.addTool(mcpwire.ToolDefinition{
		Name:        "orchestrator_job_cancel",
		Description: "Cancel a running orchestration job",
		InputSchema: vpnToolSchema(map[string]interface{}{"tenant_id": tenant, "job_id": job}, "tenant_id", "job_id"),
	})
}

// =============================================================================
// Orchestrator Tool Dispatch
// =============================================================================

// orchestratorPage reads the page argument; nil when it was omitted, which
// the service layer answers with the server's default page.
func orchestratorPage(args map[string]interface{}) *platformv1.OrchestratorPage {
	page := getMap(args, "page")
	if page == nil {
		return nil
	}
	return &platformv1.OrchestratorPage{
		Limit:  int32(getInt(page, "limit")),
		Offset: int32(getInt(page, "offset")),
	}
}

// orchestratorToolExecutor executes one orchestrator tool against the
// service provider.
type orchestratorToolExecutor func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error)

// orchestratorToolExecutors dispatches orchestrator_* tools (map-based for
// O(1) routing per the project conventions).
var orchestratorToolExecutors = map[string]orchestratorToolExecutor{
	"orchestrator_health": func(r *ToolRegistry, ctx context.Context, _ map[string]interface{}) (interface{}, error) {
		return r.service.OrchestratorHealth(ctx)
	},
	"orchestrator_agent_list": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.OrchestratorListAgents(ctx, &platformv1.ListOrchestratorAgentsRequest{
			TenantId: getString(args, "tenant_id"),
			Status:   getString(args, "status"),
			Host:     getString(args, "host"),
			Backend:  getString(args, "backend"),
			Page:     orchestratorPage(args),
		})
	},
	"orchestrator_agent_get": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.OrchestratorGetAgent(ctx, &platformv1.GetOrchestratorAgentRequest{
			TenantId: getString(args, "tenant_id"),
			AgentId:  getString(args, "agent_id"),
		})
	},
	"orchestrator_agent_disable": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.OrchestratorDisableAgent(ctx, &platformv1.DisableOrchestratorAgentRequest{
			TenantId: getString(args, "tenant_id"),
			AgentId:  getString(args, "agent_id"),
		})
	},
	"orchestrator_agent_enable": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.OrchestratorEnableAgent(ctx, &platformv1.EnableOrchestratorAgentRequest{
			TenantId: getString(args, "tenant_id"),
			AgentId:  getString(args, "agent_id"),
		})
	},
	"orchestrator_session_list": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.OrchestratorListSessions(ctx, &platformv1.ListOrchestratorSessionsRequest{
			Status:  getString(args, "status"),
			JobId:   getString(args, "job_id"),
			AgentId: getString(args, "agent_id"),
			Page:    orchestratorPage(args),
		})
	},
	"orchestrator_session_close": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.OrchestratorCloseSession(ctx, &platformv1.CloseOrchestratorSessionRequest{
			SessionId: getString(args, "session_id"),
		})
	},
	"orchestrator_job_list": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.OrchestratorListJobs(ctx, &platformv1.ListOrchestratorJobsRequest{
			TenantId: getString(args, "tenant_id"),
			Statuses: getStringSlice(args, "statuses"),
			Page:     orchestratorPage(args),
		})
	},
	"orchestrator_job_get": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.OrchestratorGetJob(ctx, &platformv1.GetOrchestratorJobRequest{
			TenantId: getString(args, "tenant_id"),
			JobId:    getString(args, "job_id"),
		})
	},
	"orchestrator_job_cancel": func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return r.service.OrchestratorCancelJob(ctx, &platformv1.CancelOrchestratorJobRequest{
			TenantId: getString(args, "tenant_id"),
			JobId:    getString(args, "job_id"),
		})
	},
}

// dispatchOrchestratorTool routes orchestrator_* tools through the executor
// map. It returns handled=false when the tool name is not an orchestrator
// tool.
func (r *ToolRegistry) dispatchOrchestratorTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	exec, ok := orchestratorToolExecutors[name]
	if !ok {
		return nil, false, nil
	}
	result, err := exec(r, ctx, args)
	if err != nil {
		return nil, true, err
	}
	result, err = marshalResult(result)
	return result, true, err
}
