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

package tenant

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// pagedIAMClient stands for a token-paging remote IAM backend: at most 50
// tenants per page (its default page when PageSize is 0), a NextPageToken
// while more remain, and a TotalCount of 0.
type pagedIAMClient struct {
	*mockIAMClient
	ordered []iam.Tenant
}

func newPagedIAMClient(n int) *pagedIAMClient {
	p := &pagedIAMClient{mockIAMClient: newMockIAMClient()}
	p.ordered = orderedTenants(n)
	return p
}

func orderedTenants(n int) []iam.Tenant {
	out := make([]iam.Tenant, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("t-%03d", i)
		out = append(out, iam.Tenant{ID: id, Name: id})
	}
	return out
}

func (p *pagedIAMClient) List(_ context.Context, req *iam.ListTenantsRequest) (*iam.ListTenantsResponse, error) {
	start := 0
	if req.PageToken != "" {
		n, err := strconv.Atoi(req.PageToken)
		if err != nil {
			return nil, err
		}
		start = n
	}
	size := req.PageSize
	if size <= 0 || size > 50 {
		size = 50
	}
	if start > len(p.ordered) {
		start = len(p.ordered)
	}
	end := min(start+size, len(p.ordered))
	resp := &iam.ListTenantsResponse{Tenants: append([]iam.Tenant(nil), p.ordered[start:end]...)}
	if end < len(p.ordered) {
		resp.Pagination.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

// embeddedIAMClient behaves like the pinned SDK's embedded IAM tenant list
// handler: it ignores PageToken, returns the first PageSize tenants (all of
// them when PageSize is 0) and never sets Pagination.
type embeddedIAMClient struct {
	*mockIAMClient
	ordered []iam.Tenant
	lastReq iam.ListTenantsRequest
}

func (e *embeddedIAMClient) List(_ context.Context, req *iam.ListTenantsRequest) (*iam.ListTenantsResponse, error) {
	e.lastReq = *req
	end := len(e.ordered)
	if req.PageSize > 0 && req.PageSize < end {
		end = req.PageSize
	}
	return &iam.ListTenantsResponse{Tenants: append([]iam.Tenant(nil), e.ordered[:end]...)}, nil
}

func newListManager(t *testing.T, client iam.TenantClient, roles *mockIAMClient) *Manager {
	t.Helper()
	cfg := &ManagerConfig{
		IAMTenantClient: client,
		IAMRoleClient:   roles,
		Config:          DefaultConfig(),
		Logger:          newTestLogger(),
	}
	cfg.Config.EnableDEKIsolation = false
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	return manager
}

type listCase struct {
	limit, offset int
	wantLen       int
	wantFirst     string
}

func checkListCases(t *testing.T, manager *Manager, wantTotal int, cases []listCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(fmt.Sprintf("limit=%d,offset=%d", tc.limit, tc.offset), func(t *testing.T) {
			got, total, err := manager.ListTenants(context.Background(), tc.limit, tc.offset)
			if err != nil {
				t.Fatalf("ListTenants: %v", err)
			}
			if total != wantTotal {
				t.Errorf("total = %d, want %d", total, wantTotal)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(got), tc.wantLen)
			}
			if tc.wantLen > 0 && got[0].ID != tc.wantFirst {
				t.Errorf("first = %q, want %q", got[0].ID, tc.wantFirst)
			}
		})
	}
}

func TestListTenants_WalksIAMPageTokens(t *testing.T) {
	paged := newPagedIAMClient(120)
	manager := newListManager(t, paged, paged.mockIAMClient)
	checkListCases(t, manager, 120, []listCase{
		{50, 0, 50, "t-000"},
		{50, 50, 50, "t-050"},
		{50, 100, 20, "t-100"},
		{50, 150, 0, ""},
	})
}

func TestListTenants_ReadsTheWholeEmbeddedList(t *testing.T) {
	embedded := &embeddedIAMClient{mockIAMClient: newMockIAMClient(), ordered: orderedTenants(51)}
	manager := newListManager(t, embedded, embedded.mockIAMClient)
	checkListCases(t, manager, 51, []listCase{
		{50, 0, 50, "t-000"},
		{50, 50, 1, "t-050"},
	})
	if ps := embedded.lastReq.PageSize; ps != 0 && ps < 51 {
		t.Errorf("last request PageSize = %d, want 0 or at least 51", ps)
	}
}
