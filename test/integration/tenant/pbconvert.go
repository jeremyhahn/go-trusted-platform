//go:build integration

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

// This file converts the platformv1 tenant messages every proto-speaking
// adapter (gRPC, Unix, REST) receives into the suite's data types.
package tenant

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// pbTenantStates maps the wire tenant states to the platform's states.
var pbTenantStates = map[platformv1.TenantState]tenant.State{
	platformv1.TenantState_TENANT_STATE_PENDING:   tenant.StateCreated,
	platformv1.TenantState_TENANT_STATE_ACTIVE:    tenant.StateActive,
	platformv1.TenantState_TENANT_STATE_SUSPENDED: tenant.StateSuspended,
	platformv1.TenantState_TENANT_STATE_DELETING:  tenant.StateDeleting,
	platformv1.TenantState_TENANT_STATE_DELETED:   tenant.StateDeleted,
}

func pbToTenantData(pb *platformv1.Tenant) *TenantData {
	if pb == nil {
		return nil
	}

	data := &TenantData{
		ID:           pb.GetId(),
		Name:         pb.GetName(),
		DisplayName:  pb.GetDisplayName(),
		State:        pbToTenantState(pb.GetState()),
		Labels:       pb.GetLabels(),
		Annotations:  pb.GetAnnotations(),
		ComputeQuota: pbToComputeQuotaData(pb.GetComputeQuota()),
		NetworkQuota: pbToNetworkQuotaData(pb.GetNetworkQuota()),
		StorageQuota: pbToStorageQuotaData(pb.GetStorageQuota()),
	}

	if pb.GetCreatedAt() != nil {
		data.CreatedAt = pb.GetCreatedAt().AsTime()
	}

	if pb.GetUpdatedAt() != nil {
		data.UpdatedAt = pb.GetUpdatedAt().AsTime()
	}

	return data
}

func pbToTenantState(state platformv1.TenantState) tenant.State {
	if s, ok := pbTenantStates[state]; ok {
		return s
	}
	return tenant.StateCreated
}

func pbToComputeQuotaData(pb *platformv1.ComputeQuota) *ComputeQuotaData {
	if pb == nil {
		return nil
	}
	return &ComputeQuotaData{
		MaxVMs:        pb.GetMaxVms(),
		MaxContainers: pb.GetMaxContainers(),
		MaxVCPUs:      pb.GetMaxVcpus(),
		MaxMemoryMB:   pb.GetMaxMemoryMb(),
	}
}

func pbToNetworkQuotaData(pb *platformv1.NetworkQuota) *NetworkQuotaData {
	if pb == nil {
		return nil
	}
	return &NetworkQuotaData{
		MaxBridges:       pb.GetMaxBridges(),
		MaxPorts:         pb.GetMaxPorts(),
		MaxBandwidthMbps: pb.GetMaxBandwidthMbps(),
	}
}

func pbToStorageQuotaData(pb *platformv1.StorageQuota) *StorageQuotaData {
	if pb == nil {
		return nil
	}
	return &StorageQuotaData{
		MaxVolumesGB: pb.GetMaxVolumesGb(),
		MaxSnapshots: pb.GetMaxSnapshots(),
	}
}
