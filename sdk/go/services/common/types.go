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

// Package common provides shared types and utilities for service clients.
package common

// Pagination holds pagination parameters for list operations.
type Pagination struct {
	Page     uint32
	PageSize uint32
	SortBy   string
	Asc      bool
}

// PageResult holds pagination results from list operations.
type PageResult struct {
	Page       uint32
	PageSize   uint32
	TotalPages uint32
	TotalItems uint64
}

// ListOptions provides common options for list operations.
type ListOptions struct {
	Pagination  *Pagination
	Labels      map[string]string
	Expressions []string
}

// NewPagination creates a new Pagination with the specified page and page size.
func NewPagination(page, pageSize uint32) *Pagination {
	return &Pagination{
		Page:     page,
		PageSize: pageSize,
	}
}

// WithSort adds sorting configuration to pagination.
func (p *Pagination) WithSort(field string, ascending bool) *Pagination {
	p.SortBy = field
	p.Asc = ascending
	return p
}
