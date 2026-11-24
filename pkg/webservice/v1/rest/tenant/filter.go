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
	"net/url"
	"strconv"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	listLimit  = "limit"
	listOffset = "offset"
)

// ErrInvalidListQuery is returned when a ListTenants query parameter cannot
// be a ListTenantsRequest value.
type ErrInvalidListQuery struct {
	Parameter string
	Value     string
	Reason    string
}

func (e *ErrInvalidListQuery) Error() string {
	return "invalid tenant list query " + e.Parameter + "=" + e.Value + ": " + e.Reason
}

// listRequest reads GET /api/v1/tenants' limit and offset into a
// ListTenantsRequest. Absent bounds stay zero: the server's default page.
func listRequest(query url.Values) (*platformv1.ListTenantsRequest, error) {
	req := &platformv1.ListTenantsRequest{}
	var err error
	if req.Limit, err = pageBound(query, listLimit); err != nil {
		return nil, err
	}
	if req.Offset, err = pageBound(query, listOffset); err != nil {
		return nil, err
	}
	return req, nil
}

// pageBound reads the limit or offset parameter: a non-negative count, where
// zero (or absent) means the server's default.
func pageBound(query url.Values, parameter string) (int32, error) {
	value := query.Get(parameter)
	if value == "" {
		return 0, nil
	}
	count, err := strconv.ParseInt(value, 10, 32)
	if err != nil || count < 0 {
		return 0, &ErrInvalidListQuery{Parameter: parameter, Value: value, Reason: "not a non-negative count"}
	}
	return int32(count), nil
}
