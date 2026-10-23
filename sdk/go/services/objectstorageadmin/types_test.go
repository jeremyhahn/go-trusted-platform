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

package objectstorageadmin

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorageadmin"
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
		{"BackendInfo", reflect.TypeFor[BackendInfo](), reflect.TypeFor[upstream.BackendInfo]()},
		{"BackendType", reflect.TypeFor[BackendType](), reflect.TypeFor[upstream.BackendType]()},
		{"StorageTier", reflect.TypeFor[StorageTier](), reflect.TypeFor[upstream.StorageTier]()},
		{"TenantUsage", reflect.TypeFor[TenantUsage](), reflect.TypeFor[upstream.TenantUsage]()},
		{"GarbageCollectionStatus", reflect.TypeFor[GarbageCollectionStatus](), reflect.TypeFor[upstream.GarbageCollectionStatus]()},
		{"CreateBackendRequest", reflect.TypeFor[CreateBackendRequest](), reflect.TypeFor[upstream.CreateBackendRequest]()},
		{"CreateBackendResponse", reflect.TypeFor[CreateBackendResponse](), reflect.TypeFor[upstream.CreateBackendResponse]()},
		{"UpdateBackendRequest", reflect.TypeFor[UpdateBackendRequest](), reflect.TypeFor[upstream.UpdateBackendRequest]()},
		{"UpdateBackendResponse", reflect.TypeFor[UpdateBackendResponse](), reflect.TypeFor[upstream.UpdateBackendResponse]()},
		{"DeleteBackendRequest", reflect.TypeFor[DeleteBackendRequest](), reflect.TypeFor[upstream.DeleteBackendRequest]()},
		{"DeleteBackendResponse", reflect.TypeFor[DeleteBackendResponse](), reflect.TypeFor[upstream.DeleteBackendResponse]()},
		{"SetBackendStatusRequest", reflect.TypeFor[SetBackendStatusRequest](), reflect.TypeFor[upstream.SetBackendStatusRequest]()},
		{"SetBackendStatusResponse", reflect.TypeFor[SetBackendStatusResponse](), reflect.TypeFor[upstream.SetBackendStatusResponse]()},
		{"CompactBackendRequest", reflect.TypeFor[CompactBackendRequest](), reflect.TypeFor[upstream.CompactBackendRequest]()},
		{"CompactBackendResponse", reflect.TypeFor[CompactBackendResponse](), reflect.TypeFor[upstream.CompactBackendResponse]()},
		{"GetStorageStatsRequest", reflect.TypeFor[GetStorageStatsRequest](), reflect.TypeFor[upstream.GetStorageStatsRequest]()},
		{"GetStorageStatsResponse", reflect.TypeFor[GetStorageStatsResponse](), reflect.TypeFor[upstream.GetStorageStatsResponse]()},
		{"RunGarbageCollectionRequest", reflect.TypeFor[RunGarbageCollectionRequest](), reflect.TypeFor[upstream.RunGarbageCollectionRequest]()},
		{"RunGarbageCollectionResponse", reflect.TypeFor[RunGarbageCollectionResponse](), reflect.TypeFor[upstream.RunGarbageCollectionResponse]()},
		{"GetGarbageCollectionProgressRequest", reflect.TypeFor[GetGarbageCollectionProgressRequest](), reflect.TypeFor[upstream.GetGarbageCollectionProgressRequest]()},
		{"GetGarbageCollectionProgressResponse", reflect.TypeFor[GetGarbageCollectionProgressResponse](), reflect.TypeFor[upstream.GetGarbageCollectionProgressResponse]()},
		{"RepairObjectRequest", reflect.TypeFor[RepairObjectRequest](), reflect.TypeFor[upstream.RepairObjectRequest]()},
		{"RepairObjectResponse", reflect.TypeFor[RepairObjectResponse](), reflect.TypeFor[upstream.RepairObjectResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported backend type, storage
// tier and garbage collection state carries the upstream value and type, so
// a backend built through this package means what the server reads.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"BackendTypeUnspecified", BackendTypeUnspecified, upstream.BackendTypeUnspecified},
		{"BackendTypeLocal", BackendTypeLocal, upstream.BackendTypeLocal},
		{"BackendTypeS3", BackendTypeS3, upstream.BackendTypeS3},
		{"BackendTypeGCS", BackendTypeGCS, upstream.BackendTypeGCS},
		{"BackendTypeAzure", BackendTypeAzure, upstream.BackendTypeAzure},
		{"BackendTypeMinio", BackendTypeMinio, upstream.BackendTypeMinio},
		{"BackendTypePebble", BackendTypePebble, upstream.BackendTypePebble},
		{"BackendTypeRaft", BackendTypeRaft, upstream.BackendTypeRaft},
		{"StorageTierUnspecified", StorageTierUnspecified, upstream.StorageTierUnspecified},
		{"StorageTierHot", StorageTierHot, upstream.StorageTierHot},
		{"StorageTierWarm", StorageTierWarm, upstream.StorageTierWarm},
		{"StorageTierCold", StorageTierCold, upstream.StorageTierCold},
		{"StorageTierArchive", StorageTierArchive, upstream.StorageTierArchive},
		{"GCStatusRunning", GCStatusRunning, upstream.GCStatusRunning},
		{"GCStatusCompleted", GCStatusCompleted, upstream.GCStatusCompleted},
		{"GCStatusFailed", GCStatusFailed, upstream.GCStatusFailed},
		{"GCStatusCanceled", GCStatusCanceled, upstream.GCStatusCanceled},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
