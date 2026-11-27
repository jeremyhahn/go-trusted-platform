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

// pagedIAMClient serves its tenants by page token the way the IAM backend
// does: at most 50 per page, a NextPageToken while more remain, and a
// TotalCount of 0, as the embedded IAM list handler reports.
type pagedIAMClient struct {
	*mockIAMClient
	ordered []iam.Tenant
}

func newPagedIAMClient(n int) *pagedIAMClient {
	p := &pagedIAMClient{mockIAMClient: newMockIAMClient()}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("t-%03d", i)
		p.ordered = append(p.ordered, iam.Tenant{ID: id, Name: id})
	}
	return p
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
	size := min(req.PageSize, 50)
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

func TestListTenants_WalksIAMPageTokens(t *testing.T) {
	paged := newPagedIAMClient(120)
	cfg := &ManagerConfig{
		IAMTenantClient: paged,
		IAMRoleClient:   paged.mockIAMClient,
		Config:          DefaultConfig(),
		Logger:          newTestLogger(),
	}
	cfg.Config.EnableDEKIsolation = false
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	cases := []struct {
		limit, offset int
		wantLen       int
		wantFirst     string
	}{
		{50, 0, 50, "t-000"},
		{50, 50, 50, "t-050"},
		{50, 100, 20, "t-100"},
		{50, 150, 0, ""},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("limit=%d,offset=%d", tc.limit, tc.offset), func(t *testing.T) {
			got, total, err := manager.ListTenants(context.Background(), tc.limit, tc.offset)
			if err != nil {
				t.Fatalf("ListTenants: %v", err)
			}
			if total != 120 {
				t.Errorf("total = %d, want 120", total)
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
