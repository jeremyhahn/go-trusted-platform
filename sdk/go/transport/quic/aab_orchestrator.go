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

package quic

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// orchestratorSubOpcodes maps every OrchestratorService RPC to its sub-opcode
// under quicwire.OpOrchestratorCategory. The daemon dispatcher is
// pkg/api/daemon/quic_orchestrator.go.
var orchestratorSubOpcodes = map[string]byte{
	platformv1.OrchestratorService_Health_FullMethodName:       quicwire.OrchestratorSubHealth,
	platformv1.OrchestratorService_ListAgents_FullMethodName:   quicwire.OrchestratorSubListAgents,
	platformv1.OrchestratorService_GetAgent_FullMethodName:     quicwire.OrchestratorSubGetAgent,
	platformv1.OrchestratorService_DisableAgent_FullMethodName: quicwire.OrchestratorSubDisableAgent,
	platformv1.OrchestratorService_EnableAgent_FullMethodName:  quicwire.OrchestratorSubEnableAgent,
	platformv1.OrchestratorService_ListSessions_FullMethodName: quicwire.OrchestratorSubListSessions,
	platformv1.OrchestratorService_CloseSession_FullMethodName: quicwire.OrchestratorSubCloseSession,
	platformv1.OrchestratorService_ListJobs_FullMethodName:     quicwire.OrchestratorSubListJobs,
	platformv1.OrchestratorService_GetJob_FullMethodName:       quicwire.OrchestratorSubGetJob,
	platformv1.OrchestratorService_CancelJob_FullMethodName:    quicwire.OrchestratorSubCancelJob,
}

// init registers the orchestrator category and routes every
// OrchestratorService RPC through it with its sub-opcode.
func init() {
	categoryOpcodes[quicwire.OpOrchestratorCategory] = struct{}{}
	for method, sub := range orchestratorSubOpcodes {
		grpcMethodToOpcodeMap[method] = quicwire.OpOrchestratorCategory
		categorySubOpcodeMap[method] = sub
	}
}
