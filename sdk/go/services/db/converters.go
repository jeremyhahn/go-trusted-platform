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

package db

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// DumpEntryFromProto converts a proto DumpEntityTypeResponse to a domain DumpEntry.
func DumpEntryFromProto(resp *platformv1.DumpEntityTypeResponse) *DumpEntry {
	if resp == nil {
		return nil
	}
	return &DumpEntry{
		EntityType: resp.EntityType,
		EntityID:   resp.EntityId,
		Data:       resp.Data,
	}
}

// ListEntityTypesResultFromProto converts a proto ListEntityTypesResponse to a domain ListEntityTypesResult.
func ListEntityTypesResultFromProto(resp *platformv1.ListEntityTypesResponse) *ListEntityTypesResult {
	if resp == nil {
		return nil
	}
	result := &ListEntityTypesResult{
		DatabasePath:  resp.DatabasePath,
		TotalEntities: resp.TotalEntities,
		ActiveTypes:   resp.ActiveTypes,
	}
	if len(resp.EntityTypes) > 0 {
		result.EntityTypes = make([]*EntityTypeInfo, len(resp.EntityTypes))
		for i, et := range resp.EntityTypes {
			result.EntityTypes[i] = &EntityTypeInfo{
				Name:        et.Name,
				EntityCount: et.EntityCount,
				Status:      et.Status,
			}
		}
	}
	return result
}
