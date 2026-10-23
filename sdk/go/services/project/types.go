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

package project

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/project"
)

// Client is the agentic project client returned by
// quicbaas.Client.Project().
type Client = upstream.Client

// Project records and the value types they carry.
type (
	// ProjectInfo is a project as the server stores it.
	ProjectInfo = upstream.ProjectInfo
	// ProjectGit describes the git repository linked to a project.
	ProjectGit = upstream.ProjectGit
	// GitAuthor is the identity workspace commits are authored as.
	GitAuthor = upstream.GitAuthor
	// CommitSigning decides whether and how workspace commits are signed.
	CommitSigning = upstream.CommitSigning
	// KMSKeyRef names a KMS-held key by name, scope and owner; never material.
	KMSKeyRef = upstream.KMSKeyRef
	// ContextRepo names a repository the worker clones beside the project.
	ContextRepo = upstream.ContextRepo
	// ProjectWorkspace describes the agent workspace of a project.
	ProjectWorkspace = upstream.ProjectWorkspace
	// ProjectPermissions holds the agent-level access roles of a project.
	ProjectPermissions = upstream.ProjectPermissions
	// ProjectQuotas holds the resource limits of a project.
	ProjectQuotas = upstream.ProjectQuotas
	// ProjectRole is the role an agent has within a project.
	ProjectRole = upstream.ProjectRole
)

// Requests and responses of the Client verbs.
type (
	CreateProjectRequest    = upstream.CreateProjectRequest
	GetProjectRequest       = upstream.GetProjectRequest
	GetProjectByNameRequest = upstream.GetProjectByNameRequest
	UpdateProjectRequest    = upstream.UpdateProjectRequest
	DeleteProjectRequest    = upstream.DeleteProjectRequest
	DeleteProjectResponse   = upstream.DeleteProjectResponse
	ListProjectsRequest     = upstream.ListProjectsRequest
	ListProjectsResponse    = upstream.ListProjectsResponse
	GrantAgentRoleRequest   = upstream.GrantAgentRoleRequest
	GrantAgentRoleResponse  = upstream.GrantAgentRoleResponse
	RevokeAgentRoleRequest  = upstream.RevokeAgentRoleRequest
	RevokeAgentRoleResponse = upstream.RevokeAgentRoleResponse
)

// Project roles. ProjectRoleDenied explicitly prohibits access.
const (
	ProjectRoleLead     = upstream.ProjectRoleLead
	ProjectRoleWorker   = upstream.ProjectRoleWorker
	ProjectRoleObserver = upstream.ProjectRoleObserver
	ProjectRoleDenied   = upstream.ProjectRoleDenied
)
