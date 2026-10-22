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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkorch "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/orchestrator"
)

// pageParams returns the SDK limit and offset of page. A nil page asks for
// the server's default page.
func pageParams(page *platformv1.OrchestratorPage) (limit, offset int, err error) {
	if page.GetLimit() < 0 || page.GetOffset() < 0 {
		return 0, 0, ErrInvalidPage{}
	}
	return int(page.GetLimit()), int(page.GetOffset()), nil
}

func pageInfo(total, limit, offset int) *platformv1.OrchestratorPageInfo {
	return &platformv1.OrchestratorPageInfo{
		Total:  int32(total),
		Limit:  int32(limit),
		Offset: int32(offset),
	}
}

func agentToPb(agent *sdkorch.AgentRegistration) *platformv1.OrchestratorAgent {
	if agent == nil {
		return nil
	}
	return &platformv1.OrchestratorAgent{
		Id:           agent.ID,
		TenantId:     agent.TenantID,
		Name:         agent.Name,
		Host:         agent.Host,
		Backend:      agent.Backend,
		Model:        agent.Model,
		AgentType:    agent.AgentType,
		Status:       agent.Status,
		LastSeen:     agent.LastSeen,
		RegisteredAt: agent.RegisteredAt,
		Metadata:     agent.Metadata,
	}
}

func sessionToPb(session *sdkorch.SessionStatusResponse) *platformv1.OrchestratorSession {
	if session == nil {
		return nil
	}
	return &platformv1.OrchestratorSession{
		SessionId:  session.SessionID,
		Backend:    session.Backend,
		Model:      session.Model,
		Status:     session.Status,
		CreatedAt:  session.CreatedAt,
		LastActive: session.LastActive,
		JobId:      session.JobID,
		Runner:     session.Runner,
		AgentId:    session.AgentID,
	}
}

func jobSummaryToPb(job *sdkorch.JobSummary) *platformv1.OrchestratorJob {
	return &platformv1.OrchestratorJob{
		JobId:       job.JobID,
		State:       job.State,
		Description: job.Description,
		TaskCount:   int32(job.TaskCount),
		Completed:   int32(job.Completed),
		Failed:      int32(job.Failed),
		StartedAt:   job.StartedAt,
		UpdatedAt:   job.UpdatedAt,
		Error:       job.Error,
		TaskId:      job.TaskID,
	}
}

func jobStatusToPb(job *sdkorch.JobStatus) *platformv1.OrchestratorJob {
	if job == nil {
		return nil
	}
	return &platformv1.OrchestratorJob{
		JobId:       job.JobID,
		State:       job.State,
		Description: job.Description,
		TaskCount:   int32(job.TaskCount),
		Completed:   int32(job.Completed),
		Failed:      int32(job.Failed),
		StartedAt:   job.StartedAt,
		UpdatedAt:   job.UpdatedAt,
		Error:       job.Error,
		TaskId:      job.TaskID,
		Runner:      job.Runner,
	}
}
