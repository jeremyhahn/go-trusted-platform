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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestOrchestratorMethodsMapToTheServerTools(t *testing.T) {
	cases := map[string]string{
		platformv1.OrchestratorService_Health_FullMethodName:       "orchestrator_health",
		platformv1.OrchestratorService_ListAgents_FullMethodName:   "orchestrator_agent_list",
		platformv1.OrchestratorService_GetAgent_FullMethodName:     "orchestrator_agent_get",
		platformv1.OrchestratorService_DisableAgent_FullMethodName: "orchestrator_agent_disable",
		platformv1.OrchestratorService_EnableAgent_FullMethodName:  "orchestrator_agent_enable",
		platformv1.OrchestratorService_ListSessions_FullMethodName: "orchestrator_session_list",
		platformv1.OrchestratorService_CloseSession_FullMethodName: "orchestrator_session_close",
		platformv1.OrchestratorService_ListJobs_FullMethodName:     "orchestrator_job_list",
		platformv1.OrchestratorService_GetJob_FullMethodName:       "orchestrator_job_get",
		platformv1.OrchestratorService_CancelJob_FullMethodName:    "orchestrator_job_cancel",
	}

	for method, want := range cases {
		t.Run(method, func(t *testing.T) {
			got, ok := grpcMethodToMCPToolMap[method]
			if !ok {
				t.Fatalf("%s has no MCP tool mapping", method)
			}
			if got != want {
				t.Fatalf("tool = %q, want %q", got, want)
			}
		})
	}
}

// Every RPC the service descriptor declares must reach a tool; an RPC added
// to the proto without a mapping fails here instead of at a client call.
func TestEveryOrchestratorRPCHasAnMCPTool(t *testing.T) {
	for _, method := range platformv1.OrchestratorService_ServiceDesc.Methods {
		fullName := "/" + platformv1.OrchestratorService_ServiceDesc.ServiceName + "/" + method.MethodName
		if _, ok := grpcMethodToMCPToolMap[fullName]; !ok {
			t.Fatalf("%s has no MCP tool mapping", fullName)
		}
	}
}
