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
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorageadmin"
)

// Client is the object storage administration client returned by
// quicbaas.Client.ObjectStorageAdmin().
type Client = upstream.Client

// Backends, usage and the value types they carry.
type (
	// BackendInfo is a storage backend as the server reports it.
	BackendInfo = upstream.BackendInfo
	// BackendType is the kind of store a backend writes to.
	BackendType = upstream.BackendType
	// StorageTier is a backend's cost and performance tier.
	StorageTier = upstream.StorageTier
	// TenantUsage is one tenant's storage usage.
	TenantUsage = upstream.TenantUsage
	// GarbageCollectionStatus is the state of a garbage collection run.
	GarbageCollectionStatus = upstream.GarbageCollectionStatus
)

// Requests and responses of the Client verbs.
type (
	CreateBackendRequest                 = upstream.CreateBackendRequest
	CreateBackendResponse                = upstream.CreateBackendResponse
	UpdateBackendRequest                 = upstream.UpdateBackendRequest
	UpdateBackendResponse                = upstream.UpdateBackendResponse
	DeleteBackendRequest                 = upstream.DeleteBackendRequest
	DeleteBackendResponse                = upstream.DeleteBackendResponse
	SetBackendStatusRequest              = upstream.SetBackendStatusRequest
	SetBackendStatusResponse             = upstream.SetBackendStatusResponse
	CompactBackendRequest                = upstream.CompactBackendRequest
	CompactBackendResponse               = upstream.CompactBackendResponse
	GetStorageStatsRequest               = upstream.GetStorageStatsRequest
	GetStorageStatsResponse              = upstream.GetStorageStatsResponse
	RunGarbageCollectionRequest          = upstream.RunGarbageCollectionRequest
	RunGarbageCollectionResponse         = upstream.RunGarbageCollectionResponse
	GetGarbageCollectionProgressRequest  = upstream.GetGarbageCollectionProgressRequest
	GetGarbageCollectionProgressResponse = upstream.GetGarbageCollectionProgressResponse
	RepairObjectRequest                  = upstream.RepairObjectRequest
	RepairObjectResponse                 = upstream.RepairObjectResponse
)

// Backend types.
const (
	BackendTypeUnspecified = upstream.BackendTypeUnspecified
	BackendTypeLocal       = upstream.BackendTypeLocal
	BackendTypeS3          = upstream.BackendTypeS3
	BackendTypeGCS         = upstream.BackendTypeGCS
	BackendTypeAzure       = upstream.BackendTypeAzure
	BackendTypeMinio       = upstream.BackendTypeMinio
	BackendTypePebble      = upstream.BackendTypePebble
	BackendTypeRaft        = upstream.BackendTypeRaft
)

// Storage tiers.
const (
	StorageTierUnspecified = upstream.StorageTierUnspecified
	StorageTierHot         = upstream.StorageTierHot
	StorageTierWarm        = upstream.StorageTierWarm
	StorageTierCold        = upstream.StorageTierCold
	StorageTierArchive     = upstream.StorageTierArchive
)

// Garbage collection states.
const (
	GCStatusRunning   = upstream.GCStatusRunning
	GCStatusCompleted = upstream.GCStatusCompleted
	GCStatusFailed    = upstream.GCStatusFailed
	GCStatusCanceled  = upstream.GCStatusCanceled
)
