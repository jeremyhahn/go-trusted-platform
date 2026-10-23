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
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
)

// Client is the object storage client returned by
// quicbaas.Client.ObjectStorage().
type Client = upstream.Client

// Objects, policies, backends and the value types they carry.
type (
	// ObjectMetadata is the metadata stored with an object.
	ObjectMetadata = upstream.ObjectMetadata
	// ObjectSummary is an object as a listing reports it.
	ObjectSummary = upstream.ObjectSummary
	// ObjectChunk is one chunk of a streamed object.
	ObjectChunk = upstream.ObjectChunk
	// StreamGetReader reads a streamed object.
	StreamGetReader = upstream.StreamGetReader
	// StreamPutWriter writes a streamed object.
	StreamPutWriter = upstream.StreamPutWriter
	// StreamPutOptions configures a streamed put.
	StreamPutOptions = upstream.StreamPutOptions
	// RetentionPolicy governs how long an object is kept.
	RetentionPolicy = upstream.RetentionPolicy
	// ReplicationPolicy governs where and how an object is replicated.
	ReplicationPolicy = upstream.ReplicationPolicy
	// ReplicationMode is when a replicated write is acknowledged.
	ReplicationMode = upstream.ReplicationMode
	// ReplicationResult is the outcome of replicating to one backend.
	ReplicationResult = upstream.ReplicationResult
	// ArchivePolicy governs archiving of an object.
	ArchivePolicy = upstream.ArchivePolicy
	// VerificationResult is the outcome of verifying an object's integrity.
	VerificationResult = upstream.VerificationResult
	// BackendInfo describes a storage backend.
	BackendInfo = upstream.BackendInfo
	// BackendHealthInfo is the health of a storage backend.
	BackendHealthInfo = upstream.BackendHealthInfo
)

// Requests and responses of the Client verbs.
type (
	PutObjectRequest           = upstream.PutObjectRequest
	PutObjectResponse          = upstream.PutObjectResponse
	GetObjectRequest           = upstream.GetObjectRequest
	GetObjectResponse          = upstream.GetObjectResponse
	HeadObjectRequest          = upstream.HeadObjectRequest
	HeadObjectResponse         = upstream.HeadObjectResponse
	DeleteObjectRequest        = upstream.DeleteObjectRequest
	DeleteObjectResponse       = upstream.DeleteObjectResponse
	CopyObjectRequest          = upstream.CopyObjectRequest
	CopyObjectResponse         = upstream.CopyObjectResponse
	ListObjectsRequest         = upstream.ListObjectsRequest
	ListObjectsResponse        = upstream.ListObjectsResponse
	ListByTagRequest           = upstream.ListByTagRequest
	ListByTagResponse          = upstream.ListByTagResponse
	ListByTenantRequest        = upstream.ListByTenantRequest
	ListByTenantResponse       = upstream.ListByTenantResponse
	BatchPutObjectsRequest     = upstream.BatchPutObjectsRequest
	BatchPutObjectsResponse    = upstream.BatchPutObjectsResponse
	BatchGetObjectsRequest     = upstream.BatchGetObjectsRequest
	BatchGetObjectsResponse    = upstream.BatchGetObjectsResponse
	BatchDeleteObjectsRequest  = upstream.BatchDeleteObjectsRequest
	BatchDeleteObjectsResponse = upstream.BatchDeleteObjectsResponse
	GetObjectPolicyRequest     = upstream.GetObjectPolicyRequest
	GetObjectPolicyResponse    = upstream.GetObjectPolicyResponse
	SetObjectPolicyRequest     = upstream.SetObjectPolicyRequest
	SetObjectPolicyResponse    = upstream.SetObjectPolicyResponse
	ArchiveObjectRequest       = upstream.ArchiveObjectRequest
	ArchiveObjectResponse      = upstream.ArchiveObjectResponse
	RestoreObjectRequest       = upstream.RestoreObjectRequest
	RestoreObjectResponse      = upstream.RestoreObjectResponse
	ReplicateObjectRequest     = upstream.ReplicateObjectRequest
	ReplicateObjectResponse    = upstream.ReplicateObjectResponse
	MigrateObjectRequest       = upstream.MigrateObjectRequest
	MigrateObjectResponse      = upstream.MigrateObjectResponse
	VerifyObjectRequest        = upstream.VerifyObjectRequest
	VerifyObjectResponse       = upstream.VerifyObjectResponse
	ListBackendsRequest        = upstream.ListBackendsRequest
	ListBackendsResponse       = upstream.ListBackendsResponse
	GetBackendHealthRequest    = upstream.GetBackendHealthRequest
	GetBackendHealthResponse   = upstream.GetBackendHealthResponse
	GetTenantQuotasRequest     = upstream.GetTenantQuotasRequest
	GetTenantQuotasResponse    = upstream.GetTenantQuotasResponse
	SetTenantQuotasRequest     = upstream.SetTenantQuotasRequest
	SetTenantQuotasResponse    = upstream.SetTenantQuotasResponse
	GetTenantUsageRequest      = upstream.GetTenantUsageRequest
	GetTenantUsageResponse     = upstream.GetTenantUsageResponse
)

// Replication modes.
const (
	ReplicationModeSync   = upstream.ReplicationModeSync
	ReplicationModeAsync  = upstream.ReplicationModeAsync
	ReplicationModeQuorum = upstream.ReplicationModeQuorum
)
