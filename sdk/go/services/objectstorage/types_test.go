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

package objectstorage

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
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
		{"ObjectMetadata", reflect.TypeFor[ObjectMetadata](), reflect.TypeFor[upstream.ObjectMetadata]()},
		{"ObjectSummary", reflect.TypeFor[ObjectSummary](), reflect.TypeFor[upstream.ObjectSummary]()},
		{"ObjectChunk", reflect.TypeFor[ObjectChunk](), reflect.TypeFor[upstream.ObjectChunk]()},
		{"StreamGetReader", reflect.TypeFor[StreamGetReader](), reflect.TypeFor[upstream.StreamGetReader]()},
		{"StreamPutWriter", reflect.TypeFor[StreamPutWriter](), reflect.TypeFor[upstream.StreamPutWriter]()},
		{"StreamPutOptions", reflect.TypeFor[StreamPutOptions](), reflect.TypeFor[upstream.StreamPutOptions]()},
		{"RetentionPolicy", reflect.TypeFor[RetentionPolicy](), reflect.TypeFor[upstream.RetentionPolicy]()},
		{"ReplicationPolicy", reflect.TypeFor[ReplicationPolicy](), reflect.TypeFor[upstream.ReplicationPolicy]()},
		{"ReplicationMode", reflect.TypeFor[ReplicationMode](), reflect.TypeFor[upstream.ReplicationMode]()},
		{"ReplicationResult", reflect.TypeFor[ReplicationResult](), reflect.TypeFor[upstream.ReplicationResult]()},
		{"ArchivePolicy", reflect.TypeFor[ArchivePolicy](), reflect.TypeFor[upstream.ArchivePolicy]()},
		{"VerificationResult", reflect.TypeFor[VerificationResult](), reflect.TypeFor[upstream.VerificationResult]()},
		{"BackendInfo", reflect.TypeFor[BackendInfo](), reflect.TypeFor[upstream.BackendInfo]()},
		{"BackendHealthInfo", reflect.TypeFor[BackendHealthInfo](), reflect.TypeFor[upstream.BackendHealthInfo]()},
		{"PutObjectRequest", reflect.TypeFor[PutObjectRequest](), reflect.TypeFor[upstream.PutObjectRequest]()},
		{"PutObjectResponse", reflect.TypeFor[PutObjectResponse](), reflect.TypeFor[upstream.PutObjectResponse]()},
		{"GetObjectRequest", reflect.TypeFor[GetObjectRequest](), reflect.TypeFor[upstream.GetObjectRequest]()},
		{"GetObjectResponse", reflect.TypeFor[GetObjectResponse](), reflect.TypeFor[upstream.GetObjectResponse]()},
		{"HeadObjectRequest", reflect.TypeFor[HeadObjectRequest](), reflect.TypeFor[upstream.HeadObjectRequest]()},
		{"HeadObjectResponse", reflect.TypeFor[HeadObjectResponse](), reflect.TypeFor[upstream.HeadObjectResponse]()},
		{"DeleteObjectRequest", reflect.TypeFor[DeleteObjectRequest](), reflect.TypeFor[upstream.DeleteObjectRequest]()},
		{"DeleteObjectResponse", reflect.TypeFor[DeleteObjectResponse](), reflect.TypeFor[upstream.DeleteObjectResponse]()},
		{"CopyObjectRequest", reflect.TypeFor[CopyObjectRequest](), reflect.TypeFor[upstream.CopyObjectRequest]()},
		{"CopyObjectResponse", reflect.TypeFor[CopyObjectResponse](), reflect.TypeFor[upstream.CopyObjectResponse]()},
		{"ListObjectsRequest", reflect.TypeFor[ListObjectsRequest](), reflect.TypeFor[upstream.ListObjectsRequest]()},
		{"ListObjectsResponse", reflect.TypeFor[ListObjectsResponse](), reflect.TypeFor[upstream.ListObjectsResponse]()},
		{"ListByTagRequest", reflect.TypeFor[ListByTagRequest](), reflect.TypeFor[upstream.ListByTagRequest]()},
		{"ListByTagResponse", reflect.TypeFor[ListByTagResponse](), reflect.TypeFor[upstream.ListByTagResponse]()},
		{"ListByTenantRequest", reflect.TypeFor[ListByTenantRequest](), reflect.TypeFor[upstream.ListByTenantRequest]()},
		{"ListByTenantResponse", reflect.TypeFor[ListByTenantResponse](), reflect.TypeFor[upstream.ListByTenantResponse]()},
		{"BatchPutObjectsRequest", reflect.TypeFor[BatchPutObjectsRequest](), reflect.TypeFor[upstream.BatchPutObjectsRequest]()},
		{"BatchPutObjectsResponse", reflect.TypeFor[BatchPutObjectsResponse](), reflect.TypeFor[upstream.BatchPutObjectsResponse]()},
		{"BatchGetObjectsRequest", reflect.TypeFor[BatchGetObjectsRequest](), reflect.TypeFor[upstream.BatchGetObjectsRequest]()},
		{"BatchGetObjectsResponse", reflect.TypeFor[BatchGetObjectsResponse](), reflect.TypeFor[upstream.BatchGetObjectsResponse]()},
		{"BatchDeleteObjectsRequest", reflect.TypeFor[BatchDeleteObjectsRequest](), reflect.TypeFor[upstream.BatchDeleteObjectsRequest]()},
		{"BatchDeleteObjectsResponse", reflect.TypeFor[BatchDeleteObjectsResponse](), reflect.TypeFor[upstream.BatchDeleteObjectsResponse]()},
		{"GetObjectPolicyRequest", reflect.TypeFor[GetObjectPolicyRequest](), reflect.TypeFor[upstream.GetObjectPolicyRequest]()},
		{"GetObjectPolicyResponse", reflect.TypeFor[GetObjectPolicyResponse](), reflect.TypeFor[upstream.GetObjectPolicyResponse]()},
		{"SetObjectPolicyRequest", reflect.TypeFor[SetObjectPolicyRequest](), reflect.TypeFor[upstream.SetObjectPolicyRequest]()},
		{"SetObjectPolicyResponse", reflect.TypeFor[SetObjectPolicyResponse](), reflect.TypeFor[upstream.SetObjectPolicyResponse]()},
		{"ArchiveObjectRequest", reflect.TypeFor[ArchiveObjectRequest](), reflect.TypeFor[upstream.ArchiveObjectRequest]()},
		{"ArchiveObjectResponse", reflect.TypeFor[ArchiveObjectResponse](), reflect.TypeFor[upstream.ArchiveObjectResponse]()},
		{"RestoreObjectRequest", reflect.TypeFor[RestoreObjectRequest](), reflect.TypeFor[upstream.RestoreObjectRequest]()},
		{"RestoreObjectResponse", reflect.TypeFor[RestoreObjectResponse](), reflect.TypeFor[upstream.RestoreObjectResponse]()},
		{"ReplicateObjectRequest", reflect.TypeFor[ReplicateObjectRequest](), reflect.TypeFor[upstream.ReplicateObjectRequest]()},
		{"ReplicateObjectResponse", reflect.TypeFor[ReplicateObjectResponse](), reflect.TypeFor[upstream.ReplicateObjectResponse]()},
		{"MigrateObjectRequest", reflect.TypeFor[MigrateObjectRequest](), reflect.TypeFor[upstream.MigrateObjectRequest]()},
		{"MigrateObjectResponse", reflect.TypeFor[MigrateObjectResponse](), reflect.TypeFor[upstream.MigrateObjectResponse]()},
		{"VerifyObjectRequest", reflect.TypeFor[VerifyObjectRequest](), reflect.TypeFor[upstream.VerifyObjectRequest]()},
		{"VerifyObjectResponse", reflect.TypeFor[VerifyObjectResponse](), reflect.TypeFor[upstream.VerifyObjectResponse]()},
		{"ListBackendsRequest", reflect.TypeFor[ListBackendsRequest](), reflect.TypeFor[upstream.ListBackendsRequest]()},
		{"ListBackendsResponse", reflect.TypeFor[ListBackendsResponse](), reflect.TypeFor[upstream.ListBackendsResponse]()},
		{"GetBackendHealthRequest", reflect.TypeFor[GetBackendHealthRequest](), reflect.TypeFor[upstream.GetBackendHealthRequest]()},
		{"GetBackendHealthResponse", reflect.TypeFor[GetBackendHealthResponse](), reflect.TypeFor[upstream.GetBackendHealthResponse]()},
		{"GetTenantQuotasRequest", reflect.TypeFor[GetTenantQuotasRequest](), reflect.TypeFor[upstream.GetTenantQuotasRequest]()},
		{"GetTenantQuotasResponse", reflect.TypeFor[GetTenantQuotasResponse](), reflect.TypeFor[upstream.GetTenantQuotasResponse]()},
		{"SetTenantQuotasRequest", reflect.TypeFor[SetTenantQuotasRequest](), reflect.TypeFor[upstream.SetTenantQuotasRequest]()},
		{"SetTenantQuotasResponse", reflect.TypeFor[SetTenantQuotasResponse](), reflect.TypeFor[upstream.SetTenantQuotasResponse]()},
		{"GetTenantUsageRequest", reflect.TypeFor[GetTenantUsageRequest](), reflect.TypeFor[upstream.GetTenantUsageRequest]()},
		{"GetTenantUsageResponse", reflect.TypeFor[GetTenantUsageResponse](), reflect.TypeFor[upstream.GetTenantUsageResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported replication mode
// carries the upstream value and type, so a policy set through this package
// replicates the way the server reads it.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"ReplicationModeSync", ReplicationModeSync, upstream.ReplicationModeSync},
		{"ReplicationModeAsync", ReplicationModeAsync, upstream.ReplicationModeAsync},
		{"ReplicationModeQuorum", ReplicationModeQuorum, upstream.ReplicationModeQuorum},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
