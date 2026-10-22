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

package quicwire

// Orchestrator category opcode.
//
// OrchestratorService (the go-quicbaas agent fleet: health, agents, sessions
// and jobs) multiplexes under one category: payload[0] selects the
// sub-operation and payload[1:] carries the MessagePack-encoded platform.v1
// request. The server-side dispatcher lives at
// pkg/api/daemon/quic_orchestrator.go::handleOrchestratorCategory.
//
// The opcode space is otherwise fully allocated, so this takes 0x66, one of
// the top-level bytes the VM opcodes left when they moved under
// OpVMExtendedCategory.
const (
	// OpOrchestratorCategory multiplexes the orchestrator sub-operations.
	OpOrchestratorCategory byte = 0x66
)

// Orchestrator sub-opcodes for the OpOrchestratorCategory (0x66) category
// opcode. These constants are the canonical wire-format definition and are
// consumed by the SDK QUIC adapter (sdk/go/transport/quic/aab_orchestrator.go).
const (
	// OrchestratorSubHealth reports the orchestrator's health.
	OrchestratorSubHealth byte = 0x01

	// OrchestratorSubListAgents lists a tenant's registered agents.
	OrchestratorSubListAgents byte = 0x02

	// OrchestratorSubGetAgent returns one registered agent.
	OrchestratorSubGetAgent byte = 0x03

	// OrchestratorSubDisableAgent administratively disables an agent.
	OrchestratorSubDisableAgent byte = 0x04

	// OrchestratorSubEnableAgent re-activates a disabled agent.
	OrchestratorSubEnableAgent byte = 0x05

	// OrchestratorSubListSessions lists agent sessions.
	OrchestratorSubListSessions byte = 0x06

	// OrchestratorSubCloseSession terminates an agent session.
	OrchestratorSubCloseSession byte = 0x07

	// OrchestratorSubListJobs lists a tenant's orchestration jobs.
	OrchestratorSubListJobs byte = 0x08

	// OrchestratorSubGetJob returns the status of one orchestration job.
	OrchestratorSubGetJob byte = 0x09

	// OrchestratorSubCancelJob cancels a running orchestration job.
	OrchestratorSubCancelJob byte = 0x0A
)
