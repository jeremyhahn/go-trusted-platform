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
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// protoStateToTenantState converts a platformv1.TenantState to the domain TenantState.
var protoStateToTenantState = map[platformv1.TenantState]TenantState{
	platformv1.TenantState_TENANT_STATE_UNSPECIFIED: StateUnspecified,
	platformv1.TenantState_TENANT_STATE_PENDING:     StatePending,
	platformv1.TenantState_TENANT_STATE_ACTIVE:      StateActive,
	platformv1.TenantState_TENANT_STATE_SUSPENDED:   StateSuspended,
	platformv1.TenantState_TENANT_STATE_DELETING:    StateDeleting,
	platformv1.TenantState_TENANT_STATE_DELETED:     StateDeleted,
}

// tenantFromProto converts a platformv1.Tenant to the domain Tenant type.
func tenantFromProto(p *platformv1.Tenant) *Tenant {
	if p == nil {
		return nil
	}

	state, ok := protoStateToTenantState[p.State]
	if !ok {
		state = StateUnspecified
	}

	t := &Tenant{
		ID:          p.Id,
		Name:        p.Name,
		DisplayName: p.DisplayName,
		State:       state,
		OVSBridge:   p.OvsBridge,
		VLANStart:   p.VlanStart,
		VLANEnd:     p.VlanEnd,
		Labels:      p.Labels,
		Annotations: p.Annotations,
		CreatedAt:   timestampToTime(p.CreatedAt),
		UpdatedAt:   timestampToTime(p.UpdatedAt),
	}

	if p.ComputeQuota != nil {
		t.ComputeQuota = computeQuotaFromProto(p.ComputeQuota)
	}

	if p.NetworkQuota != nil {
		t.NetworkQuota = networkQuotaFromProto(p.NetworkQuota)
	}

	if p.StorageQuota != nil {
		t.StorageQuota = storageQuotaFromProto(p.StorageQuota)
	}

	return t
}

// computeQuotaFromProto converts a platformv1.ComputeQuota to the domain ComputeQuota.
func computeQuotaFromProto(p *platformv1.ComputeQuota) *ComputeQuota {
	if p == nil {
		return nil
	}
	return &ComputeQuota{
		MaxVMs:        p.MaxVms,
		MaxContainers: p.MaxContainers,
		MaxVCPUs:      p.MaxVcpus,
		MaxMemoryMB:   p.MaxMemoryMb,
	}
}

// networkQuotaFromProto converts a platformv1.NetworkQuota to the domain NetworkQuota.
func networkQuotaFromProto(p *platformv1.NetworkQuota) *NetworkQuota {
	if p == nil {
		return nil
	}
	return &NetworkQuota{
		MaxBridges:       p.MaxBridges,
		MaxPorts:         p.MaxPorts,
		MaxBandwidthMbps: p.MaxBandwidthMbps,
	}
}

// storageQuotaFromProto converts a platformv1.StorageQuota to the domain StorageQuota.
func storageQuotaFromProto(p *platformv1.StorageQuota) *StorageQuota {
	if p == nil {
		return nil
	}
	return &StorageQuota{
		MaxVolumesGB: p.MaxVolumesGb,
		MaxSnapshots: p.MaxSnapshots,
	}
}

// createParamsToProto converts CreateParams to a platformv1.CreateTenantRequest.
func createParamsToProto(params *CreateParams) *platformv1.CreateTenantRequest {
	req := &platformv1.CreateTenantRequest{
		Name:           params.Name,
		DisplayName:    params.DisplayName,
		VlanRangeStart: params.VLANRangeStart,
		VlanRangeEnd:   params.VLANRangeEnd,
	}

	if params.ComputeQuota != nil {
		req.ComputeQuota = computeQuotaToProto(params.ComputeQuota)
	}

	if params.NetworkQuota != nil {
		req.NetworkQuota = networkQuotaToProto(params.NetworkQuota)
	}

	if params.StorageQuota != nil {
		req.StorageQuota = storageQuotaToProto(params.StorageQuota)
	}

	return req
}

// updateQuotasParamsToProto converts UpdateQuotasParams to a platformv1.UpdateQuotasRequest.
func updateQuotasParamsToProto(params *UpdateQuotasParams) *platformv1.UpdateQuotasRequest {
	req := &platformv1.UpdateQuotasRequest{
		TenantId: params.TenantID,
	}

	if params.ComputeQuota != nil {
		req.Compute = computeQuotaToProto(params.ComputeQuota)
	}

	if params.NetworkQuota != nil {
		req.Network = networkQuotaToProto(params.NetworkQuota)
	}

	if params.StorageQuota != nil {
		req.Storage = storageQuotaToProto(params.StorageQuota)
	}

	return req
}

// computeQuotaToProto converts a domain ComputeQuota to platformv1.ComputeQuota.
func computeQuotaToProto(q *ComputeQuota) *platformv1.ComputeQuota {
	if q == nil {
		return nil
	}
	return &platformv1.ComputeQuota{
		MaxVms:        q.MaxVMs,
		MaxContainers: q.MaxContainers,
		MaxVcpus:      q.MaxVCPUs,
		MaxMemoryMb:   q.MaxMemoryMB,
	}
}

// networkQuotaToProto converts a domain NetworkQuota to platformv1.NetworkQuota.
func networkQuotaToProto(q *NetworkQuota) *platformv1.NetworkQuota {
	if q == nil {
		return nil
	}
	return &platformv1.NetworkQuota{
		MaxBridges:       q.MaxBridges,
		MaxPorts:         q.MaxPorts,
		MaxBandwidthMbps: q.MaxBandwidthMbps,
	}
}

// storageQuotaToProto converts a domain StorageQuota to platformv1.StorageQuota.
func storageQuotaToProto(q *StorageQuota) *platformv1.StorageQuota {
	if q == nil {
		return nil
	}
	return &platformv1.StorageQuota{
		MaxVolumesGb: q.MaxVolumesGB,
		MaxSnapshots: q.MaxSnapshots,
	}
}

// timestampToTime converts a protobuf Timestamp to time.Time.
func timestampToTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}
