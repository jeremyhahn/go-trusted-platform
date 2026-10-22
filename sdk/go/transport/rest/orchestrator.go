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

package rest

import (
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// orchestratorBasePath is the daemon's agent-fleet REST prefix
// (pkg/api/rest/orchestrator_handlers.go).
const orchestratorBasePath = "/api/v1/orchestrator"

// init maps every OrchestratorService RPC onto its daemon route. Fields that
// are not in the path (list filters, paging) travel in the JSON body, which
// the daemon merges with the path variables.
func init() {
	tenant := pathParam{placeholder: "{tenant_id}", field: "tenant_id"}
	agent := pathParam{placeholder: "{agent_id}", field: "agent_id"}
	job := pathParam{placeholder: "{job_id}", field: "job_id"}
	const agents = orchestratorBasePath + "/tenants/{tenant_id}/agents"
	const jobs = orchestratorBasePath + "/tenants/{tenant_id}/jobs"

	templatedRouteTable[platformv1.OrchestratorService_Health_FullMethodName] = templatedRoute{
		path:   orchestratorBasePath + "/health",
		method: http.MethodGet,
	}
	templatedRouteTable[platformv1.OrchestratorService_ListAgents_FullMethodName] = templatedRoute{
		path:       agents,
		method:     http.MethodGet,
		pathParams: []pathParam{tenant},
	}
	templatedRouteTable[platformv1.OrchestratorService_GetAgent_FullMethodName] = templatedRoute{
		path:       agents + "/{agent_id}",
		method:     http.MethodGet,
		pathParams: []pathParam{tenant, agent},
	}
	templatedRouteTable[platformv1.OrchestratorService_DisableAgent_FullMethodName] = templatedRoute{
		path:       agents + "/{agent_id}/disable",
		method:     http.MethodPost,
		pathParams: []pathParam{tenant, agent},
	}
	templatedRouteTable[platformv1.OrchestratorService_EnableAgent_FullMethodName] = templatedRoute{
		path:       agents + "/{agent_id}/enable",
		method:     http.MethodPost,
		pathParams: []pathParam{tenant, agent},
	}
	templatedRouteTable[platformv1.OrchestratorService_ListSessions_FullMethodName] = templatedRoute{
		path:   orchestratorBasePath + "/sessions",
		method: http.MethodGet,
	}
	templatedRouteTable[platformv1.OrchestratorService_CloseSession_FullMethodName] = templatedRoute{
		path:       orchestratorBasePath + "/sessions/{session_id}",
		method:     http.MethodDelete,
		pathParams: []pathParam{{placeholder: "{session_id}", field: "session_id"}},
	}
	templatedRouteTable[platformv1.OrchestratorService_ListJobs_FullMethodName] = templatedRoute{
		path:       jobs,
		method:     http.MethodGet,
		pathParams: []pathParam{tenant},
	}
	templatedRouteTable[platformv1.OrchestratorService_GetJob_FullMethodName] = templatedRoute{
		path:       jobs + "/{job_id}",
		method:     http.MethodGet,
		pathParams: []pathParam{tenant, job},
	}
	templatedRouteTable[platformv1.OrchestratorService_CancelJob_FullMethodName] = templatedRoute{
		path:       jobs + "/{job_id}/cancel",
		method:     http.MethodPost,
		pathParams: []pathParam{tenant, job},
	}
}
