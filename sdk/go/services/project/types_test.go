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
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/project"
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
		{"ProjectInfo", reflect.TypeFor[ProjectInfo](), reflect.TypeFor[upstream.ProjectInfo]()},
		{"ProjectGit", reflect.TypeFor[ProjectGit](), reflect.TypeFor[upstream.ProjectGit]()},
		{"GitAuthor", reflect.TypeFor[GitAuthor](), reflect.TypeFor[upstream.GitAuthor]()},
		{"CommitSigning", reflect.TypeFor[CommitSigning](), reflect.TypeFor[upstream.CommitSigning]()},
		{"KMSKeyRef", reflect.TypeFor[KMSKeyRef](), reflect.TypeFor[upstream.KMSKeyRef]()},
		{"ContextRepo", reflect.TypeFor[ContextRepo](), reflect.TypeFor[upstream.ContextRepo]()},
		{"ProjectWorkspace", reflect.TypeFor[ProjectWorkspace](), reflect.TypeFor[upstream.ProjectWorkspace]()},
		{"ProjectPermissions", reflect.TypeFor[ProjectPermissions](), reflect.TypeFor[upstream.ProjectPermissions]()},
		{"ProjectQuotas", reflect.TypeFor[ProjectQuotas](), reflect.TypeFor[upstream.ProjectQuotas]()},
		{"ProjectRole", reflect.TypeFor[ProjectRole](), reflect.TypeFor[upstream.ProjectRole]()},
		{"CreateProjectRequest", reflect.TypeFor[CreateProjectRequest](), reflect.TypeFor[upstream.CreateProjectRequest]()},
		{"GetProjectRequest", reflect.TypeFor[GetProjectRequest](), reflect.TypeFor[upstream.GetProjectRequest]()},
		{"GetProjectByNameRequest", reflect.TypeFor[GetProjectByNameRequest](), reflect.TypeFor[upstream.GetProjectByNameRequest]()},
		{"UpdateProjectRequest", reflect.TypeFor[UpdateProjectRequest](), reflect.TypeFor[upstream.UpdateProjectRequest]()},
		{"DeleteProjectRequest", reflect.TypeFor[DeleteProjectRequest](), reflect.TypeFor[upstream.DeleteProjectRequest]()},
		{"DeleteProjectResponse", reflect.TypeFor[DeleteProjectResponse](), reflect.TypeFor[upstream.DeleteProjectResponse]()},
		{"ListProjectsRequest", reflect.TypeFor[ListProjectsRequest](), reflect.TypeFor[upstream.ListProjectsRequest]()},
		{"ListProjectsResponse", reflect.TypeFor[ListProjectsResponse](), reflect.TypeFor[upstream.ListProjectsResponse]()},
		{"GrantFleetNodeRoleRequest", reflect.TypeFor[GrantFleetNodeRoleRequest](), reflect.TypeFor[upstream.GrantFleetNodeRoleRequest]()},
		{"GrantFleetNodeRoleResponse", reflect.TypeFor[GrantFleetNodeRoleResponse](), reflect.TypeFor[upstream.GrantFleetNodeRoleResponse]()},
		{"RevokeFleetNodeRoleRequest", reflect.TypeFor[RevokeFleetNodeRoleRequest](), reflect.TypeFor[upstream.RevokeFleetNodeRoleRequest]()},
		{"RevokeFleetNodeRoleResponse", reflect.TypeFor[RevokeFleetNodeRoleResponse](), reflect.TypeFor[upstream.RevokeFleetNodeRoleResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported role carries the
// upstream value and type, so a role granted through this package is the
// role the server enforces.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"ProjectRoleLead", ProjectRoleLead, upstream.ProjectRoleLead},
		{"ProjectRoleWorker", ProjectRoleWorker, upstream.ProjectRoleWorker},
		{"ProjectRoleObserver", ProjectRoleObserver, upstream.ProjectRoleObserver},
		{"ProjectRoleDenied", ProjectRoleDenied, upstream.ProjectRoleDenied},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
