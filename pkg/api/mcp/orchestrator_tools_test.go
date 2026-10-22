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
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// orchestratorToolCase is one orchestrator tool call: the arguments a client
// sends, the platform.v1 request the provider must receive, and a result
// field that proves the response message came back.
type orchestratorToolCase struct {
	args      map[string]interface{}
	want      proto.Message
	resultKey string
}

var orchestratorToolCases = map[string]orchestratorToolCase{
	"orchestrator_health": {
		want:      &platformv1.OrchestratorHealthRequest{},
		resultKey: "healthy",
	},
	"orchestrator_agent_list": {
		args: map[string]interface{}{
			"tenant_id": "acme", "status": "active", "host": "h1", "backend": "claude",
			"page": map[string]interface{}{"limit": float64(10), "offset": float64(20)},
		},
		want: &platformv1.ListOrchestratorAgentsRequest{
			TenantId: "acme", Status: "active", Host: "h1", Backend: "claude",
			Page: &platformv1.OrchestratorPage{Limit: 10, Offset: 20},
		},
		resultKey: "agents",
	},
	"orchestrator_agent_get": {
		args:      map[string]interface{}{"tenant_id": "acme", "agent_id": "a1"},
		want:      &platformv1.GetOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"},
		resultKey: "agent",
	},
	"orchestrator_agent_disable": {
		args:      map[string]interface{}{"tenant_id": "acme", "agent_id": "a1"},
		want:      &platformv1.DisableOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"},
		resultKey: "disabled",
	},
	"orchestrator_agent_enable": {
		args:      map[string]interface{}{"tenant_id": "acme", "agent_id": "a1"},
		want:      &platformv1.EnableOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"},
		resultKey: "enabled",
	},
	"orchestrator_session_list": {
		args: map[string]interface{}{"status": "open", "job_id": "j1", "agent_id": "a1"},
		want: &platformv1.ListOrchestratorSessionsRequest{Status: "open", JobId: "j1", AgentId: "a1"},
		// The page argument was omitted, so the request carries no page.
		resultKey: "sessions",
	},
	"orchestrator_session_close": {
		args:      map[string]interface{}{"session_id": "s1"},
		want:      &platformv1.CloseOrchestratorSessionRequest{SessionId: "s1"},
		resultKey: "closed",
	},
	"orchestrator_job_list": {
		args: map[string]interface{}{
			"tenant_id": "acme",
			"statuses":  []interface{}{"running", "failed"},
		},
		want:      &platformv1.ListOrchestratorJobsRequest{TenantId: "acme", Statuses: []string{"running", "failed"}},
		resultKey: "jobs",
	},
	"orchestrator_job_get": {
		args:      map[string]interface{}{"tenant_id": "acme", "job_id": "j1"},
		want:      &platformv1.GetOrchestratorJobRequest{TenantId: "acme", JobId: "j1"},
		resultKey: "job",
	},
	"orchestrator_job_cancel": {
		args:      map[string]interface{}{"tenant_id": "acme", "job_id": "j1"},
		want:      &platformv1.CancelOrchestratorJobRequest{TenantId: "acme", JobId: "j1"},
		resultKey: "cancelled",
	},
}

func TestOrchestratorToolsAreRegisteredWithSchemas(t *testing.T) {
	registry := NewToolRegistry(&mockServiceProvider{}, nil)

	byName := make(map[string]mcpwire.ToolDefinition)
	for _, tool := range registry.ListTools() {
		byName[tool.Name] = tool
	}

	for name := range orchestratorToolCases {
		tool, ok := byName[name]
		if !ok {
			t.Fatalf("tool %q is not registered", name)
		}
		if tool.Description == "" {
			t.Fatalf("tool %q has no description", name)
		}
		if tool.InputSchema["type"] != "object" {
			t.Fatalf("tool %q schema = %v, want an object", name, tool.InputSchema)
		}
	}

	required, _ := byName["orchestrator_job_cancel"].InputSchema["required"].([]string)
	if len(required) != 2 || required[0] != "tenant_id" || required[1] != "job_id" {
		t.Fatalf("orchestrator_job_cancel required = %v, want [tenant_id job_id]", required)
	}
}

func TestOrchestratorToolsSendTheRequestAndReturnTheResponse(t *testing.T) {
	for name, tc := range orchestratorToolCases {
		t.Run(name, func(t *testing.T) {
			provider := &mockServiceProvider{}
			registry := NewToolRegistry(provider, nil)

			result, err := registry.ExecuteTool(context.Background(), name, tc.args)
			if err != nil {
				t.Fatalf("%s error = %v", name, err)
			}

			got, ok := provider.orchestratorRequest.(proto.Message)
			if !ok || !proto.Equal(got, tc.want) {
				t.Fatalf("provider received %v, want %v", provider.orchestratorRequest, tc.want)
			}

			resultMap, ok := result.(map[string]interface{})
			if !ok {
				t.Fatalf("result = %T, want a JSON object", result)
			}
			if _, ok := resultMap[tc.resultKey]; !ok {
				t.Fatalf("result = %v, want the %q field", resultMap, tc.resultKey)
			}
		})
	}
}

func TestOrchestratorToolsPropagateProviderFailures(t *testing.T) {
	failure := errors.New("orchestrator unavailable")

	for name, tc := range orchestratorToolCases {
		t.Run(name, func(t *testing.T) {
			registry := NewToolRegistry(&mockServiceProvider{orchestratorErr: failure}, nil)

			result, err := registry.ExecuteTool(context.Background(), name, tc.args)
			if !errors.Is(err, failure) {
				t.Fatalf("%s error = %v, want the provider failure", name, err)
			}
			if result != nil {
				t.Fatalf("%s result = %v, want nil on failure", name, result)
			}
		})
	}
}

func TestOrchestratorToolDispatchIgnoresForeignToolNames(t *testing.T) {
	registry := NewToolRegistry(&mockServiceProvider{}, nil)

	result, handled, err := registry.dispatchOrchestratorTool(context.Background(), "ntp_status", nil)
	if handled || err != nil || result != nil {
		t.Fatalf("dispatchOrchestratorTool(ntp_status) = %v, %v, %v; want unhandled", result, handled, err)
	}
}

func TestOrchestratorToolPermissionsGateWritesSeparatelyFromReads(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	writes := map[string]bool{
		"orchestrator_agent_disable": true,
		"orchestrator_agent_enable":  true,
		"orchestrator_session_close": true,
		"orchestrator_job_cancel":    true,
	}
	for name := range orchestratorToolCases {
		want := "orchestrator:read"
		if writes[name] {
			want = "orchestrator:write"
		}
		if got := checker.toolPermissions[name]; got != want {
			t.Fatalf("permission for %s = %q, want %q", name, got, want)
		}
	}
}
