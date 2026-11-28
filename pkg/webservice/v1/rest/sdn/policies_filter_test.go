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

package sdn

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestListPolicies_QueryFiltersReachTheService: GET /api/v1/sdn/policies
// hands the service the type and target_id query filters the SDK sends, over
// the body's filters.
func TestListPolicies_QueryFiltersReachTheService(t *testing.T) {
	cases := []struct {
		name   string
		target string
		body   string
		want   *platformv1.ListPoliciesRequest
	}{
		{
			name:   "type and target_id in the query",
			target: "/api/v1/sdn/policies?type=qos&target_id=eth1",
			want:   &platformv1.ListPoliciesRequest{Type: "qos", TargetId: "eth1"},
		},
		{
			name:   "type alone in the query",
			target: "/api/v1/sdn/policies?type=acl",
			want:   &platformv1.ListPoliciesRequest{Type: "acl"},
		},
		{
			name:   "target_id alone in the query",
			target: "/api/v1/sdn/policies?target_id=eth2",
			want:   &platformv1.ListPoliciesRequest{TargetId: "eth2"},
		},
		{
			name:   "filters in the body",
			target: "/api/v1/sdn/policies",
			body:   `{"type":"qos","targetId":"eth1"}`,
			want:   &platformv1.ListPoliciesRequest{Type: "qos", TargetId: "eth1"},
		},
		{
			name:   "the query wins over the body",
			target: "/api/v1/sdn/policies?type=acl",
			body:   `{"type":"qos","targetId":"eth1"}`,
			want:   &platformv1.ListPoliciesRequest{Type: "acl", TargetId: "eth1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &scriptedSDNServer{resp: &platformv1.ListPoliciesResponse{}}
			rec := serve(server, http.MethodGet, tc.target, tc.body)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.True(t, proto.Equal(tc.want, server.got), "service got %v, want %v", server.got, tc.want)
		})
	}
}

// TestListPolicies_QueryFiltersAnswerTheList: the query form answers the
// service's policy list in the envelope.
func TestListPolicies_QueryFiltersAnswerTheList(t *testing.T) {
	want := &platformv1.ListPoliciesResponse{Policies: []*platformv1.Policy{testPolicy()}}
	server := &scriptedSDNServer{resp: want}
	rec := serve(server, http.MethodGet, "/api/v1/sdn/policies?type=qos&target_id=eth1", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	got := &platformv1.ListPoliciesResponse{}
	payload(t, rec, got)
	assert.True(t, proto.Equal(want, got), "payload %v, want %v", got, want)
	assert.True(t, proto.Equal(&platformv1.ListPoliciesRequest{Type: "qos", TargetId: "eth1"}, server.got),
		"service got %v", server.got)
}
