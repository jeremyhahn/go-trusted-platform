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

package orchestrator

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/orchestrator"
)

// Client is the orchestrator client returned by
// quicbaas.Client.Orchestrator().
type Client = upstream.Client

// Sessions: spawn, prompt, inspect, rotate and close an agent session.
type (
	SpawnSessionRequest            = upstream.SpawnSessionRequest
	SpawnSessionResponse           = upstream.SpawnSessionResponse
	PromptSessionRequest           = upstream.PromptSessionRequest
	PromptSessionResponse          = upstream.PromptSessionResponse
	PromptContentBlock             = upstream.PromptContentBlock
	SessionStatusRequest           = upstream.SessionStatusRequest
	SessionStatusResponse          = upstream.SessionStatusResponse
	CloseSessionRequest            = upstream.CloseSessionRequest
	CloseSessionResponse           = upstream.CloseSessionResponse
	ListSessionsRequest            = upstream.ListSessionsRequest
	ListSessionsResponse           = upstream.ListSessionsResponse
	RotateSessionAccountRequest    = upstream.RotateSessionAccountRequest
	RotateSessionAccountResponse   = upstream.RotateSessionAccountResponse
	GetSessionHistoryRequest       = upstream.GetSessionHistoryRequest
	GetSessionHistoryResponse      = upstream.GetSessionHistoryResponse
	GetSessionConversationRequest  = upstream.GetSessionConversationRequest
	GetSessionConversationResponse = upstream.GetSessionConversationResponse
	SubscribeSessionEventsRequest  = upstream.SubscribeSessionEventsRequest
	SessionEventEnvelope           = upstream.SessionEventEnvelope
	SessionTurn                    = upstream.SessionTurn
	SessionTurnRole                = upstream.SessionTurnRole
	SessionToolUse                 = upstream.SessionToolUse
	SessionTokenUsage              = upstream.SessionTokenUsage
	SandboxMode                    = upstream.SandboxMode
	MCPServerConfig                = upstream.MCPServerConfig
)

// Prompt errors. A PromptSession call returns them for a malformed answer;
// match them with errors.As.
type (
	// EmptyTurnError reports a stateless prompt response that carried neither
	// content nor a stop reason.
	EmptyTurnError = upstream.EmptyTurnError
	// MissingTurnIDError reports an acceptance acknowledgement with no turn ID.
	MissingTurnIDError = upstream.MissingTurnIDError
)

// Tasks and their artifacts.
type (
	Task                        = upstream.Task
	TaskSpec                    = upstream.TaskSpec
	TaskSource                  = upstream.TaskSource
	TaskRouting                 = upstream.TaskRouting
	TaskResult                  = upstream.TaskResult
	TaskArtifact                = upstream.TaskArtifact
	TaskArtifactRef             = upstream.TaskArtifactRef
	WorkItem                    = upstream.WorkItem
	CreateTaskRequest           = upstream.CreateTaskRequest
	GetTaskRequest              = upstream.GetTaskRequest
	ListTasksRequest            = upstream.ListTasksRequest
	ListTasksResponse           = upstream.ListTasksResponse
	ClaimTaskRequest            = upstream.ClaimTaskRequest
	ClaimTaskResponse           = upstream.ClaimTaskResponse
	CompleteTaskRequest         = upstream.CompleteTaskRequest
	CompleteTaskResponse        = upstream.CompleteTaskResponse
	BlockTaskRequest            = upstream.BlockTaskRequest
	BlockTaskResponse           = upstream.BlockTaskResponse
	ReadmitTaskRequest          = upstream.ReadmitTaskRequest
	ReadmitTaskResponse         = upstream.ReadmitTaskResponse
	DeleteTaskRequest           = upstream.DeleteTaskRequest
	DeleteTaskResponse          = upstream.DeleteTaskResponse
	DecomposeTaskRequest        = upstream.DecomposeTaskRequest
	DecomposeTaskResponse       = upstream.DecomposeTaskResponse
	SubmitTaskArtifactsRequest  = upstream.SubmitTaskArtifactsRequest
	SubmitTaskArtifactsResponse = upstream.SubmitTaskArtifactsResponse
	GetTaskArtifactRequest      = upstream.GetTaskArtifactRequest
	ListTaskArtifactsRequest    = upstream.ListTaskArtifactsRequest
	ListTaskArtifactsResponse   = upstream.ListTaskArtifactsResponse
)

// Jobs: the autonomous orchestration control loop.
type (
	StartJobRequest           = upstream.StartJobRequest
	StartJobResponse          = upstream.StartJobResponse
	SpawnChildJobRequest      = upstream.SpawnChildJobRequest
	SpawnChildJobResponse     = upstream.SpawnChildJobResponse
	GetJobStatusRequest       = upstream.GetJobStatusRequest
	ListJobsRequest           = upstream.ListJobsRequest
	ListJobsResponse          = upstream.ListJobsResponse
	CancelJobRequest          = upstream.CancelJobRequest
	CancelJobResponse         = upstream.CancelJobResponse
	SubscribeJobEventsRequest = upstream.SubscribeJobEventsRequest
	ListJobRunnersResponse    = upstream.ListJobRunnersResponse
	JobStatus                 = upstream.JobStatus
	JobSummary                = upstream.JobSummary
	JobEvent                  = upstream.JobEvent
	JobAuditEvent             = upstream.JobAuditEvent
	JobAttemptRecord          = upstream.JobAttemptRecord
	JobStageRecord            = upstream.JobStageRecord
	JobReviewRound            = upstream.JobReviewRound
	JobDelivery               = upstream.JobDelivery
	JobVerificationResult     = upstream.JobVerificationResult
	JobRunnerInfo             = upstream.JobRunnerInfo
	JobStateSpec              = upstream.JobStateSpec
)

// Workflows.
type (
	WorkflowDefinition    = upstream.WorkflowDefinition
	WorkflowSettings      = upstream.WorkflowSettings
	WorkflowMode          = upstream.WorkflowMode
	AgentRoleSpec         = upstream.AgentRoleSpec
	CreateWorkflowRequest = upstream.CreateWorkflowRequest
	GetWorkflowRequest    = upstream.GetWorkflowRequest
	ListWorkflowsRequest  = upstream.ListWorkflowsRequest
	ListWorkflowsResponse = upstream.ListWorkflowsResponse
	UpdateWorkflowRequest = upstream.UpdateWorkflowRequest
	DeleteWorkflowRequest = upstream.DeleteWorkflowRequest
)

// The fleet nodes (the agent fleet, renamed upstream).
type (
	FleetNode                  = upstream.FleetNode
	RegisterFleetNodeRequest   = upstream.RegisterFleetNodeRequest
	RegisterFleetNodeResponse  = upstream.RegisterFleetNodeResponse
	GetFleetNodeRequest        = upstream.GetFleetNodeRequest
	ListFleetNodesRequest      = upstream.ListFleetNodesRequest
	ListFleetNodesResponse     = upstream.ListFleetNodesResponse
	RemoveFleetNodeRequest     = upstream.RemoveFleetNodeRequest
	RemoveFleetNodeResponse    = upstream.RemoveFleetNodeResponse
	FleetNodeHeartbeatRequest  = upstream.FleetNodeHeartbeatRequest
	FleetNodeHeartbeatResponse = upstream.FleetNodeHeartbeatResponse
	DisableFleetNodeRequest    = upstream.DisableFleetNodeRequest
	DisableFleetNodeResponse   = upstream.DisableFleetNodeResponse
	EnableFleetNodeRequest     = upstream.EnableFleetNodeRequest
	EnableFleetNodeResponse    = upstream.EnableFleetNodeResponse
)

// Backends, stateless inference and health.
type (
	BackendInfo               = upstream.BackendInfo
	ListBackendsResponse      = upstream.ListBackendsResponse
	ListBackendModelsRequest  = upstream.ListBackendModelsRequest
	ListBackendModelsResponse = upstream.ListBackendModelsResponse
	InferenceRequest          = upstream.InferenceRequest
	InferenceResponse         = upstream.InferenceResponse
	InferenceChunk            = upstream.InferenceChunk
	InferenceContentBlock     = upstream.InferenceContentBlock
	HealthCheckReport         = upstream.HealthCheckReport
)

// The consumption ledger.
type (
	GetSpendReportRequest  = upstream.GetSpendReportRequest
	GetSpendReportResponse = upstream.GetSpendReportResponse
	SpendAccount           = upstream.SpendAccount
	SpendBreakerVerdict    = upstream.SpendBreakerVerdict
	SpendChild             = upstream.SpendChild
	SpendLevel             = upstream.SpendLevel
	SpendModel             = upstream.SpendModel
	SpendPolicyStatus      = upstream.SpendPolicyStatus
	SpendWindowStatus      = upstream.SpendWindowStatus
)

const (
	// TurnStatusAccepted is the status the server reports when it has
	// accepted a turn for background execution.
	TurnStatusAccepted = upstream.TurnStatusAccepted

	// SpendUnattributed addresses the ledger entries that have no value at a
	// chain level; supply it as a scope level to open the Unattributed row.
	SpendUnattributed = upstream.SpendUnattributed
)

// Sandbox modes of a session.
const (
	SandboxModeDefault  = upstream.SandboxModeDefault
	SandboxModeRequired = upstream.SandboxModeRequired
	SandboxModeNone     = upstream.SandboxModeNone
)

// The roles a SessionTurn can carry.
const (
	SessionTurnRoleUser      = upstream.SessionTurnRoleUser
	SessionTurnRoleAssistant = upstream.SessionTurnRoleAssistant
	SessionTurnRoleSystem    = upstream.SessionTurnRoleSystem
)

// The ledger's attribution chain levels, outermost first.
const (
	SpendLevelTenant  = upstream.SpendLevelTenant
	SpendLevelProject = upstream.SpendLevelProject
	SpendLevelTask    = upstream.SpendLevelTask
	SpendLevelJob     = upstream.SpendLevelJob
	SpendLevelSession = upstream.SpendLevelSession
	SpendLevelRound   = upstream.SpendLevelRound
)

// What the server could establish about an account's allowance. "none" and
// "unknown" are different facts and must not be collapsed.
const (
	SpendPolicyUnknown = upstream.SpendPolicyUnknown
	SpendPolicyNone    = upstream.SpendPolicyNone
	SpendPolicyMetered = upstream.SpendPolicyMetered
)

// Workflow modes, from fully predetermined to fully autonomous.
const (
	WorkflowModeCanned      = upstream.WorkflowModeCanned
	WorkflowModeConstrained = upstream.WorkflowModeConstrained
	WorkflowModeAutonomous  = upstream.WorkflowModeAutonomous
)
