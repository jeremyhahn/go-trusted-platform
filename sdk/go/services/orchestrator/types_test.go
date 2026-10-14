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
	"errors"
	"fmt"
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/orchestrator"
)

// TestTypes_AreUpstreamAliases proves every re-exported type IS the upstream
// type, so a value crosses the boundary without conversion. A defined type
// in place of an alias would be a distinct reflect.Type.
func TestTypes_AreUpstreamAliases(t *testing.T) {
	cases := []struct {
		name     string
		got      reflect.Type
		upstream reflect.Type
	}{
		{"Client", reflect.TypeFor[Client](), reflect.TypeFor[upstream.Client]()},
		{"SpawnSessionRequest", reflect.TypeFor[SpawnSessionRequest](), reflect.TypeFor[upstream.SpawnSessionRequest]()},
		{"SpawnSessionResponse", reflect.TypeFor[SpawnSessionResponse](), reflect.TypeFor[upstream.SpawnSessionResponse]()},
		{"PromptSessionRequest", reflect.TypeFor[PromptSessionRequest](), reflect.TypeFor[upstream.PromptSessionRequest]()},
		{"PromptSessionResponse", reflect.TypeFor[PromptSessionResponse](), reflect.TypeFor[upstream.PromptSessionResponse]()},
		{"PromptContentBlock", reflect.TypeFor[PromptContentBlock](), reflect.TypeFor[upstream.PromptContentBlock]()},
		{"SessionStatusRequest", reflect.TypeFor[SessionStatusRequest](), reflect.TypeFor[upstream.SessionStatusRequest]()},
		{"SessionStatusResponse", reflect.TypeFor[SessionStatusResponse](), reflect.TypeFor[upstream.SessionStatusResponse]()},
		{"CloseSessionRequest", reflect.TypeFor[CloseSessionRequest](), reflect.TypeFor[upstream.CloseSessionRequest]()},
		{"CloseSessionResponse", reflect.TypeFor[CloseSessionResponse](), reflect.TypeFor[upstream.CloseSessionResponse]()},
		{"ListSessionsRequest", reflect.TypeFor[ListSessionsRequest](), reflect.TypeFor[upstream.ListSessionsRequest]()},
		{"ListSessionsResponse", reflect.TypeFor[ListSessionsResponse](), reflect.TypeFor[upstream.ListSessionsResponse]()},
		{"RotateSessionAccountRequest", reflect.TypeFor[RotateSessionAccountRequest](), reflect.TypeFor[upstream.RotateSessionAccountRequest]()},
		{"RotateSessionAccountResponse", reflect.TypeFor[RotateSessionAccountResponse](), reflect.TypeFor[upstream.RotateSessionAccountResponse]()},
		{"GetSessionHistoryRequest", reflect.TypeFor[GetSessionHistoryRequest](), reflect.TypeFor[upstream.GetSessionHistoryRequest]()},
		{"GetSessionHistoryResponse", reflect.TypeFor[GetSessionHistoryResponse](), reflect.TypeFor[upstream.GetSessionHistoryResponse]()},
		{"GetSessionConversationRequest", reflect.TypeFor[GetSessionConversationRequest](), reflect.TypeFor[upstream.GetSessionConversationRequest]()},
		{"GetSessionConversationResponse", reflect.TypeFor[GetSessionConversationResponse](), reflect.TypeFor[upstream.GetSessionConversationResponse]()},
		{"SubscribeSessionEventsRequest", reflect.TypeFor[SubscribeSessionEventsRequest](), reflect.TypeFor[upstream.SubscribeSessionEventsRequest]()},
		{"SessionEventEnvelope", reflect.TypeFor[SessionEventEnvelope](), reflect.TypeFor[upstream.SessionEventEnvelope]()},
		{"SessionTurn", reflect.TypeFor[SessionTurn](), reflect.TypeFor[upstream.SessionTurn]()},
		{"SessionTurnRole", reflect.TypeFor[SessionTurnRole](), reflect.TypeFor[upstream.SessionTurnRole]()},
		{"SessionToolUse", reflect.TypeFor[SessionToolUse](), reflect.TypeFor[upstream.SessionToolUse]()},
		{"SessionTokenUsage", reflect.TypeFor[SessionTokenUsage](), reflect.TypeFor[upstream.SessionTokenUsage]()},
		{"SandboxMode", reflect.TypeFor[SandboxMode](), reflect.TypeFor[upstream.SandboxMode]()},
		{"MCPServerConfig", reflect.TypeFor[MCPServerConfig](), reflect.TypeFor[upstream.MCPServerConfig]()},
		{"EmptyTurnError", reflect.TypeFor[EmptyTurnError](), reflect.TypeFor[upstream.EmptyTurnError]()},
		{"MissingTurnIDError", reflect.TypeFor[MissingTurnIDError](), reflect.TypeFor[upstream.MissingTurnIDError]()},
		{"Task", reflect.TypeFor[Task](), reflect.TypeFor[upstream.Task]()},
		{"TaskSpec", reflect.TypeFor[TaskSpec](), reflect.TypeFor[upstream.TaskSpec]()},
		{"TaskSource", reflect.TypeFor[TaskSource](), reflect.TypeFor[upstream.TaskSource]()},
		{"TaskRouting", reflect.TypeFor[TaskRouting](), reflect.TypeFor[upstream.TaskRouting]()},
		{"TaskResult", reflect.TypeFor[TaskResult](), reflect.TypeFor[upstream.TaskResult]()},
		{"TaskArtifact", reflect.TypeFor[TaskArtifact](), reflect.TypeFor[upstream.TaskArtifact]()},
		{"TaskArtifactRef", reflect.TypeFor[TaskArtifactRef](), reflect.TypeFor[upstream.TaskArtifactRef]()},
		{"WorkItem", reflect.TypeFor[WorkItem](), reflect.TypeFor[upstream.WorkItem]()},
		{"CreateTaskRequest", reflect.TypeFor[CreateTaskRequest](), reflect.TypeFor[upstream.CreateTaskRequest]()},
		{"GetTaskRequest", reflect.TypeFor[GetTaskRequest](), reflect.TypeFor[upstream.GetTaskRequest]()},
		{"ListTasksRequest", reflect.TypeFor[ListTasksRequest](), reflect.TypeFor[upstream.ListTasksRequest]()},
		{"ListTasksResponse", reflect.TypeFor[ListTasksResponse](), reflect.TypeFor[upstream.ListTasksResponse]()},
		{"ClaimTaskRequest", reflect.TypeFor[ClaimTaskRequest](), reflect.TypeFor[upstream.ClaimTaskRequest]()},
		{"ClaimTaskResponse", reflect.TypeFor[ClaimTaskResponse](), reflect.TypeFor[upstream.ClaimTaskResponse]()},
		{"CompleteTaskRequest", reflect.TypeFor[CompleteTaskRequest](), reflect.TypeFor[upstream.CompleteTaskRequest]()},
		{"CompleteTaskResponse", reflect.TypeFor[CompleteTaskResponse](), reflect.TypeFor[upstream.CompleteTaskResponse]()},
		{"BlockTaskRequest", reflect.TypeFor[BlockTaskRequest](), reflect.TypeFor[upstream.BlockTaskRequest]()},
		{"BlockTaskResponse", reflect.TypeFor[BlockTaskResponse](), reflect.TypeFor[upstream.BlockTaskResponse]()},
		{"ReadmitTaskRequest", reflect.TypeFor[ReadmitTaskRequest](), reflect.TypeFor[upstream.ReadmitTaskRequest]()},
		{"ReadmitTaskResponse", reflect.TypeFor[ReadmitTaskResponse](), reflect.TypeFor[upstream.ReadmitTaskResponse]()},
		{"DeleteTaskRequest", reflect.TypeFor[DeleteTaskRequest](), reflect.TypeFor[upstream.DeleteTaskRequest]()},
		{"DeleteTaskResponse", reflect.TypeFor[DeleteTaskResponse](), reflect.TypeFor[upstream.DeleteTaskResponse]()},
		{"DecomposeTaskRequest", reflect.TypeFor[DecomposeTaskRequest](), reflect.TypeFor[upstream.DecomposeTaskRequest]()},
		{"DecomposeTaskResponse", reflect.TypeFor[DecomposeTaskResponse](), reflect.TypeFor[upstream.DecomposeTaskResponse]()},
		{"SubmitTaskArtifactsRequest", reflect.TypeFor[SubmitTaskArtifactsRequest](), reflect.TypeFor[upstream.SubmitTaskArtifactsRequest]()},
		{"SubmitTaskArtifactsResponse", reflect.TypeFor[SubmitTaskArtifactsResponse](), reflect.TypeFor[upstream.SubmitTaskArtifactsResponse]()},
		{"GetTaskArtifactRequest", reflect.TypeFor[GetTaskArtifactRequest](), reflect.TypeFor[upstream.GetTaskArtifactRequest]()},
		{"ListTaskArtifactsRequest", reflect.TypeFor[ListTaskArtifactsRequest](), reflect.TypeFor[upstream.ListTaskArtifactsRequest]()},
		{"ListTaskArtifactsResponse", reflect.TypeFor[ListTaskArtifactsResponse](), reflect.TypeFor[upstream.ListTaskArtifactsResponse]()},
		{"StartJobRequest", reflect.TypeFor[StartJobRequest](), reflect.TypeFor[upstream.StartJobRequest]()},
		{"StartJobResponse", reflect.TypeFor[StartJobResponse](), reflect.TypeFor[upstream.StartJobResponse]()},
		{"SpawnChildJobRequest", reflect.TypeFor[SpawnChildJobRequest](), reflect.TypeFor[upstream.SpawnChildJobRequest]()},
		{"SpawnChildJobResponse", reflect.TypeFor[SpawnChildJobResponse](), reflect.TypeFor[upstream.SpawnChildJobResponse]()},
		{"GetJobStatusRequest", reflect.TypeFor[GetJobStatusRequest](), reflect.TypeFor[upstream.GetJobStatusRequest]()},
		{"ListJobsRequest", reflect.TypeFor[ListJobsRequest](), reflect.TypeFor[upstream.ListJobsRequest]()},
		{"ListJobsResponse", reflect.TypeFor[ListJobsResponse](), reflect.TypeFor[upstream.ListJobsResponse]()},
		{"CancelJobRequest", reflect.TypeFor[CancelJobRequest](), reflect.TypeFor[upstream.CancelJobRequest]()},
		{"CancelJobResponse", reflect.TypeFor[CancelJobResponse](), reflect.TypeFor[upstream.CancelJobResponse]()},
		{"SubscribeJobEventsRequest", reflect.TypeFor[SubscribeJobEventsRequest](), reflect.TypeFor[upstream.SubscribeJobEventsRequest]()},
		{"ListJobRunnersResponse", reflect.TypeFor[ListJobRunnersResponse](), reflect.TypeFor[upstream.ListJobRunnersResponse]()},
		{"JobStatus", reflect.TypeFor[JobStatus](), reflect.TypeFor[upstream.JobStatus]()},
		{"JobSummary", reflect.TypeFor[JobSummary](), reflect.TypeFor[upstream.JobSummary]()},
		{"JobEvent", reflect.TypeFor[JobEvent](), reflect.TypeFor[upstream.JobEvent]()},
		{"JobAuditEvent", reflect.TypeFor[JobAuditEvent](), reflect.TypeFor[upstream.JobAuditEvent]()},
		{"JobAttemptRecord", reflect.TypeFor[JobAttemptRecord](), reflect.TypeFor[upstream.JobAttemptRecord]()},
		{"JobStageRecord", reflect.TypeFor[JobStageRecord](), reflect.TypeFor[upstream.JobStageRecord]()},
		{"JobReviewRound", reflect.TypeFor[JobReviewRound](), reflect.TypeFor[upstream.JobReviewRound]()},
		{"JobDelivery", reflect.TypeFor[JobDelivery](), reflect.TypeFor[upstream.JobDelivery]()},
		{"JobVerificationResult", reflect.TypeFor[JobVerificationResult](), reflect.TypeFor[upstream.JobVerificationResult]()},
		{"JobRunnerInfo", reflect.TypeFor[JobRunnerInfo](), reflect.TypeFor[upstream.JobRunnerInfo]()},
		{"JobStateSpec", reflect.TypeFor[JobStateSpec](), reflect.TypeFor[upstream.JobStateSpec]()},
		{"WorkflowDefinition", reflect.TypeFor[WorkflowDefinition](), reflect.TypeFor[upstream.WorkflowDefinition]()},
		{"WorkflowSettings", reflect.TypeFor[WorkflowSettings](), reflect.TypeFor[upstream.WorkflowSettings]()},
		{"WorkflowMode", reflect.TypeFor[WorkflowMode](), reflect.TypeFor[upstream.WorkflowMode]()},
		{"AgentRoleSpec", reflect.TypeFor[AgentRoleSpec](), reflect.TypeFor[upstream.AgentRoleSpec]()},
		{"CreateWorkflowRequest", reflect.TypeFor[CreateWorkflowRequest](), reflect.TypeFor[upstream.CreateWorkflowRequest]()},
		{"GetWorkflowRequest", reflect.TypeFor[GetWorkflowRequest](), reflect.TypeFor[upstream.GetWorkflowRequest]()},
		{"ListWorkflowsRequest", reflect.TypeFor[ListWorkflowsRequest](), reflect.TypeFor[upstream.ListWorkflowsRequest]()},
		{"ListWorkflowsResponse", reflect.TypeFor[ListWorkflowsResponse](), reflect.TypeFor[upstream.ListWorkflowsResponse]()},
		{"UpdateWorkflowRequest", reflect.TypeFor[UpdateWorkflowRequest](), reflect.TypeFor[upstream.UpdateWorkflowRequest]()},
		{"DeleteWorkflowRequest", reflect.TypeFor[DeleteWorkflowRequest](), reflect.TypeFor[upstream.DeleteWorkflowRequest]()},
		{"FleetNode", reflect.TypeFor[FleetNode](), reflect.TypeFor[upstream.FleetNode]()},
		{"RegisterFleetNodeRequest", reflect.TypeFor[RegisterFleetNodeRequest](), reflect.TypeFor[upstream.RegisterFleetNodeRequest]()},
		{"RegisterFleetNodeResponse", reflect.TypeFor[RegisterFleetNodeResponse](), reflect.TypeFor[upstream.RegisterFleetNodeResponse]()},
		{"GetFleetNodeRequest", reflect.TypeFor[GetFleetNodeRequest](), reflect.TypeFor[upstream.GetFleetNodeRequest]()},
		{"ListFleetNodesRequest", reflect.TypeFor[ListFleetNodesRequest](), reflect.TypeFor[upstream.ListFleetNodesRequest]()},
		{"ListFleetNodesResponse", reflect.TypeFor[ListFleetNodesResponse](), reflect.TypeFor[upstream.ListFleetNodesResponse]()},
		{"RemoveFleetNodeRequest", reflect.TypeFor[RemoveFleetNodeRequest](), reflect.TypeFor[upstream.RemoveFleetNodeRequest]()},
		{"RemoveFleetNodeResponse", reflect.TypeFor[RemoveFleetNodeResponse](), reflect.TypeFor[upstream.RemoveFleetNodeResponse]()},
		{"FleetNodeHeartbeatRequest", reflect.TypeFor[FleetNodeHeartbeatRequest](), reflect.TypeFor[upstream.FleetNodeHeartbeatRequest]()},
		{"FleetNodeHeartbeatResponse", reflect.TypeFor[FleetNodeHeartbeatResponse](), reflect.TypeFor[upstream.FleetNodeHeartbeatResponse]()},
		{"DisableFleetNodeRequest", reflect.TypeFor[DisableFleetNodeRequest](), reflect.TypeFor[upstream.DisableFleetNodeRequest]()},
		{"DisableFleetNodeResponse", reflect.TypeFor[DisableFleetNodeResponse](), reflect.TypeFor[upstream.DisableFleetNodeResponse]()},
		{"EnableFleetNodeRequest", reflect.TypeFor[EnableFleetNodeRequest](), reflect.TypeFor[upstream.EnableFleetNodeRequest]()},
		{"EnableFleetNodeResponse", reflect.TypeFor[EnableFleetNodeResponse](), reflect.TypeFor[upstream.EnableFleetNodeResponse]()},
		{"BackendInfo", reflect.TypeFor[BackendInfo](), reflect.TypeFor[upstream.BackendInfo]()},
		{"ListBackendsResponse", reflect.TypeFor[ListBackendsResponse](), reflect.TypeFor[upstream.ListBackendsResponse]()},
		{"ListBackendModelsRequest", reflect.TypeFor[ListBackendModelsRequest](), reflect.TypeFor[upstream.ListBackendModelsRequest]()},
		{"ListBackendModelsResponse", reflect.TypeFor[ListBackendModelsResponse](), reflect.TypeFor[upstream.ListBackendModelsResponse]()},
		{"InferenceRequest", reflect.TypeFor[InferenceRequest](), reflect.TypeFor[upstream.InferenceRequest]()},
		{"InferenceResponse", reflect.TypeFor[InferenceResponse](), reflect.TypeFor[upstream.InferenceResponse]()},
		{"InferenceChunk", reflect.TypeFor[InferenceChunk](), reflect.TypeFor[upstream.InferenceChunk]()},
		{"InferenceContentBlock", reflect.TypeFor[InferenceContentBlock](), reflect.TypeFor[upstream.InferenceContentBlock]()},
		{"HealthCheckReport", reflect.TypeFor[HealthCheckReport](), reflect.TypeFor[upstream.HealthCheckReport]()},
		{"GetSpendReportRequest", reflect.TypeFor[GetSpendReportRequest](), reflect.TypeFor[upstream.GetSpendReportRequest]()},
		{"GetSpendReportResponse", reflect.TypeFor[GetSpendReportResponse](), reflect.TypeFor[upstream.GetSpendReportResponse]()},
		{"SpendAccount", reflect.TypeFor[SpendAccount](), reflect.TypeFor[upstream.SpendAccount]()},
		{"SpendBreakerVerdict", reflect.TypeFor[SpendBreakerVerdict](), reflect.TypeFor[upstream.SpendBreakerVerdict]()},
		{"SpendChild", reflect.TypeFor[SpendChild](), reflect.TypeFor[upstream.SpendChild]()},
		{"SpendLevel", reflect.TypeFor[SpendLevel](), reflect.TypeFor[upstream.SpendLevel]()},
		{"SpendModel", reflect.TypeFor[SpendModel](), reflect.TypeFor[upstream.SpendModel]()},
		{"SpendPolicyStatus", reflect.TypeFor[SpendPolicyStatus](), reflect.TypeFor[upstream.SpendPolicyStatus]()},
		{"SpendWindowStatus", reflect.TypeFor[SpendWindowStatus](), reflect.TypeFor[upstream.SpendWindowStatus]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported constant carries the
// upstream value and type, so a filter or comparison written against this
// package means what the server means.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"TurnStatusAccepted", TurnStatusAccepted, upstream.TurnStatusAccepted},
		{"SpendUnattributed", SpendUnattributed, upstream.SpendUnattributed},
		{"SandboxModeDefault", SandboxModeDefault, upstream.SandboxModeDefault},
		{"SandboxModeRequired", SandboxModeRequired, upstream.SandboxModeRequired},
		{"SandboxModeNone", SandboxModeNone, upstream.SandboxModeNone},
		{"SessionTurnRoleUser", SessionTurnRoleUser, upstream.SessionTurnRoleUser},
		{"SessionTurnRoleAssistant", SessionTurnRoleAssistant, upstream.SessionTurnRoleAssistant},
		{"SessionTurnRoleSystem", SessionTurnRoleSystem, upstream.SessionTurnRoleSystem},
		{"SpendLevelTenant", SpendLevelTenant, upstream.SpendLevelTenant},
		{"SpendLevelProject", SpendLevelProject, upstream.SpendLevelProject},
		{"SpendLevelTask", SpendLevelTask, upstream.SpendLevelTask},
		{"SpendLevelJob", SpendLevelJob, upstream.SpendLevelJob},
		{"SpendLevelSession", SpendLevelSession, upstream.SpendLevelSession},
		{"SpendLevelRound", SpendLevelRound, upstream.SpendLevelRound},
		{"SpendPolicyUnknown", SpendPolicyUnknown, upstream.SpendPolicyUnknown},
		{"SpendPolicyNone", SpendPolicyNone, upstream.SpendPolicyNone},
		{"SpendPolicyMetered", SpendPolicyMetered, upstream.SpendPolicyMetered},
		{"WorkflowModeCanned", WorkflowModeCanned, upstream.WorkflowModeCanned},
		{"WorkflowModeConstrained", WorkflowModeConstrained, upstream.WorkflowModeConstrained},
		{"WorkflowModeAutonomous", WorkflowModeAutonomous, upstream.WorkflowModeAutonomous},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestPromptErrors_MatchAcrossTheBoundary proves a caller holding only this
// package can recognise the prompt errors the upstream client returns, even
// wrapped, and that one error type does not match the other.
func TestPromptErrors_MatchAcrossTheBoundary(t *testing.T) {
	empty := fmt.Errorf("prompt: %w", &upstream.EmptyTurnError{SessionID: "s-1"})
	missing := fmt.Errorf("prompt: %w", &upstream.MissingTurnIDError{SessionID: "s-2"})

	var emptyTarget *EmptyTurnError
	if !errors.As(empty, &emptyTarget) {
		t.Fatalf("errors.As(%v, *EmptyTurnError) = false, want true", empty)
	}
	if emptyTarget.SessionID != "s-1" {
		t.Errorf("EmptyTurnError.SessionID = %q, want s-1", emptyTarget.SessionID)
	}

	var missingTarget *MissingTurnIDError
	if !errors.As(missing, &missingTarget) {
		t.Fatalf("errors.As(%v, *MissingTurnIDError) = false, want true", missing)
	}
	if missingTarget.SessionID != "s-2" {
		t.Errorf("MissingTurnIDError.SessionID = %q, want s-2", missingTarget.SessionID)
	}

	if errors.As(empty, &missingTarget) {
		t.Errorf("errors.As(EmptyTurnError, *MissingTurnIDError) = true, want false")
	}
}
