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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newListVMsTestService seeds four VMs and one container:
//
//	vm-a  web    running    created t0+2h
//	vm-b  db     stopped    created t0+1h
//	vm-c  api    running    created t0
//	vm-d  cache  suspended  created t0+3h
//
// The container must never appear in a VM list.
func newListVMsTestService(t *testing.T) *ComputeGRPCService {
	t.Helper()
	t0 := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	orchestrator := newGRPCMockOrchestrator()
	seed := []struct {
		id, name string
		state    compute.InstanceState
		created  time.Duration
	}{
		{"vm-a", "web", compute.StateRunning, 2 * time.Hour},
		{"vm-b", "db", compute.StateStopped, time.Hour},
		{"vm-c", "api", compute.StateRunning, 0},
		{"vm-d", "cache", compute.StateSuspended, 3 * time.Hour},
	}
	for _, vm := range seed {
		orchestrator.instances[vm.id] = &compute.Instance{
			ID:        vm.id,
			Name:      vm.name,
			Type:      compute.ComputeTypeVM,
			State:     vm.state,
			CreatedAt: t0.Add(vm.created),
			UpdatedAt: t0.Add(vm.created),
		}
	}
	orchestrator.instances["ctr-1"] = &compute.Instance{
		ID:    "ctr-1",
		Name:  "sidecar",
		Type:  compute.ComputeTypeContainer,
		State: compute.StateRunning,
	}
	return NewComputeGRPCService(logging.DefaultLogger(), orchestrator)
}

// listedVMIDs returns the ids of a ListVMs response in order.
func listedVMIDs(resp *platformv1.ListVMsResponse) []string {
	ids := make([]string, 0, len(resp.GetVms()))
	for _, vm := range resp.GetVms() {
		ids = append(ids, vm.GetId())
	}
	return ids
}

func TestComputeGRPCService_ListVMs_Filters(t *testing.T) {
	running := platformv1.VMState_VM_STATE_RUNNING
	tests := []struct {
		name     string
		req      *platformv1.ListVMsRequest
		wantIDs  []string
		wantPage *platformv1.PaginationResponse
	}{
		{
			name:     "no filter lists every VM by id",
			req:      &platformv1.ListVMsRequest{},
			wantIDs:  []string{"vm-a", "vm-b", "vm-c", "vm-d"},
			wantPage: &platformv1.PaginationResponse{Page: 1, PageSize: 4, TotalPages: 1, TotalItems: 4},
		},
		{
			name:     "one state",
			req:      &platformv1.ListVMsRequest{States: []platformv1.VMState{running}},
			wantIDs:  []string{"vm-a", "vm-c"},
			wantPage: &platformv1.PaginationResponse{Page: 1, PageSize: 2, TotalPages: 1, TotalItems: 2},
		},
		{
			name: "several states",
			req: &platformv1.ListVMsRequest{States: []platformv1.VMState{
				running, platformv1.VMState_VM_STATE_PAUSED,
			}},
			wantIDs:  []string{"vm-a", "vm-c", "vm-d"},
			wantPage: &platformv1.PaginationResponse{Page: 1, PageSize: 3, TotalPages: 1, TotalItems: 3},
		},
		{
			name:     "no VM in the state is an empty list",
			req:      &platformv1.ListVMsRequest{States: []platformv1.VMState{platformv1.VMState_VM_STATE_ERROR}},
			wantIDs:  []string{},
			wantPage: &platformv1.PaginationResponse{Page: 1, PageSize: 0, TotalPages: 1, TotalItems: 0},
		},
		{
			name: "no VM carries the label is an empty list",
			req: &platformv1.ListVMsRequest{Selector: &platformv1.LabelSelector{
				MatchLabels: map[string]string{"tier": "web"},
			}},
			wantIDs:  []string{},
			wantPage: &platformv1.PaginationResponse{Page: 1, PageSize: 0, TotalPages: 1, TotalItems: 0},
		},
		{
			name:     "sort by name ascending",
			req:      &platformv1.ListVMsRequest{Pagination: &platformv1.PaginationRequest{SortBy: "name", Ascending: true}},
			wantIDs:  []string{"vm-c", "vm-d", "vm-b", "vm-a"},
			wantPage: &platformv1.PaginationResponse{Page: 1, PageSize: 4, TotalPages: 1, TotalItems: 4},
		},
		{
			name:     "sort by created_at descending",
			req:      &platformv1.ListVMsRequest{Pagination: &platformv1.PaginationRequest{SortBy: "created_at"}},
			wantIDs:  []string{"vm-d", "vm-a", "vm-b", "vm-c"},
			wantPage: &platformv1.PaginationResponse{Page: 1, PageSize: 4, TotalPages: 1, TotalItems: 4},
		},
		{
			name:     "first page",
			req:      &platformv1.ListVMsRequest{Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 3}},
			wantIDs:  []string{"vm-a", "vm-b", "vm-c"},
			wantPage: &platformv1.PaginationResponse{Page: 1, PageSize: 3, TotalPages: 2, TotalItems: 4},
		},
		{
			name:     "last page",
			req:      &platformv1.ListVMsRequest{Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 3}},
			wantIDs:  []string{"vm-d"},
			wantPage: &platformv1.PaginationResponse{Page: 2, PageSize: 3, TotalPages: 2, TotalItems: 4},
		},
		{
			name:     "page past the end is an empty list",
			req:      &platformv1.ListVMsRequest{Pagination: &platformv1.PaginationRequest{Page: 3, PageSize: 3}},
			wantIDs:  []string{},
			wantPage: &platformv1.PaginationResponse{Page: 3, PageSize: 3, TotalPages: 2, TotalItems: 4},
		},
		{
			name: "state, sort and page combine",
			req: &platformv1.ListVMsRequest{
				States:     []platformv1.VMState{running},
				Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 1, SortBy: "created_at", Ascending: true},
			},
			wantIDs:  []string{"vm-c"},
			wantPage: &platformv1.PaginationResponse{Page: 1, PageSize: 1, TotalPages: 2, TotalItems: 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newListVMsTestService(t)

			resp, err := svc.ListVMs(context.Background(), tt.req)

			require.NoError(t, err)
			assert.Equal(t, tt.wantIDs, listedVMIDs(resp))
			assert.Equal(t, tt.wantPage, resp.GetPagination())
		})
	}
}

func TestComputeGRPCService_ListVMs_InvalidFilter(t *testing.T) {
	tests := []struct {
		name    string
		req     *platformv1.ListVMsRequest
		wantErr error
	}{
		{
			name:    "unknown state",
			req:     &platformv1.ListVMsRequest{States: []platformv1.VMState{platformv1.VMState_VM_STATE_RUNNING, 99}},
			wantErr: ErrVMListUnknownState{State: 99},
		},
		{
			name: "selector expression",
			req: &platformv1.ListVMsRequest{Selector: &platformv1.LabelSelector{
				MatchExpressions: []string{"env=prod"},
			}},
			wantErr: ErrVMListSelectorExpression{Expression: "env=prod"},
		},
		{
			name:    "unsupported sort field",
			req:     &platformv1.ListVMsRequest{Pagination: &platformv1.PaginationRequest{SortBy: "memory"}},
			wantErr: ErrVMListUnsupportedSortField{Field: "memory"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newListVMsTestService(t)

			resp, err := svc.ListVMs(context.Background(), tt.req)

			assert.Nil(t, resp)
			require.Error(t, err)
			assert.Equal(t, tt.wantErr, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestComputeGRPCService_ListVMs_FilterRefusedBeforeListing(t *testing.T) {
	orchestrator := newGRPCMockOrchestrator()
	orchestrator.listFunc = func(context.Context, *compute.InstanceFilter) ([]*compute.Instance, error) {
		return nil, errors.New("list must not run for an invalid filter")
	}
	svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

	_, err := svc.ListVMs(context.Background(), &platformv1.ListVMsRequest{
		States: []platformv1.VMState{42},
	})

	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestVMMatchesListFilter(t *testing.T) {
	vm := &platformv1.VM{
		Id:    "vm-1",
		State: platformv1.VMState_VM_STATE_RUNNING,
		Config: &platformv1.VMConfig{
			Labels: map[string]string{"env": "prod", "tier": "web"},
		},
	}
	tests := []struct {
		name   string
		states []platformv1.VMState
		labels map[string]string
		want   bool
	}{
		{name: "no filter", want: true},
		{name: "one matching label", labels: map[string]string{"env": "prod"}, want: true},
		{name: "every label matches", labels: map[string]string{"env": "prod", "tier": "web"}, want: true},
		{name: "label value differs", labels: map[string]string{"env": "dev"}, want: false},
		{name: "label key missing", labels: map[string]string{"owner": ""}, want: false},
		{name: "one of several labels differs", labels: map[string]string{"env": "prod", "tier": "db"}, want: false},
		{
			name:   "state and label match",
			states: []platformv1.VMState{platformv1.VMState_VM_STATE_RUNNING},
			labels: map[string]string{"tier": "web"},
			want:   true,
		},
		{
			name:   "label matches but state does not",
			states: []platformv1.VMState{platformv1.VMState_VM_STATE_STOPPED},
			labels: map[string]string{"tier": "web"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &platformv1.ListVMsRequest{
				States:   tt.states,
				Selector: &platformv1.LabelSelector{MatchLabels: tt.labels},
			}
			assert.Equal(t, tt.want, vmMatchesListFilter(vm, req))
		})
	}
}
