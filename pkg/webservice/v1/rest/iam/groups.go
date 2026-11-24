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

package iam

import (
	"time"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// SDKGroup is an IAM group as the IAMClient group methods carry it.
type SDKGroup struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SDKCreateGroupRequest is a request to create an IAM group.
type SDKCreateGroupRequest struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// SDKUpdateGroupRequest is a request to update an IAM group.
type SDKUpdateGroupRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// SDKListGroupsRequest is a request to list IAM groups.
type SDKListGroupsRequest struct {
	PageSize  int    `json:"page_size,omitempty"`
	PageToken string `json:"page_token,omitempty"`
}

// SDKListGroupsResponse is one page of IAM groups.
type SDKListGroupsResponse struct {
	Groups     []SDKGroup            `json:"groups"`
	Pagination iamsdk.PaginationInfo `json:"pagination"`
}

// ErrGroupsNotSupported is returned by every group operation of the
// QuicBaaS IAM adapter: the QuicBaaS IAM client has no group API.
type ErrGroupsNotSupported struct {
	Op string
}

func (e ErrGroupsNotSupported) Error() string {
	return "rest/iam: IAM groups are not supported by the QuicBaaS IAM client: " + e.Op
}
