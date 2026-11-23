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

// VRFQuota defines the routing resource quotas for a tenant: its VRFs, the
// networks inside them and the services it publishes.
type VRFQuota struct {
	// Limits
	MaxVRFs     int64 // Maximum number of VRFs
	MaxNetworks int64 // Maximum number of networks across the tenant's VRFs
	MaxServices int64 // Maximum number of services

	// Usage tracking
	UsedVRFs     int64 // Currently used VRFs
	UsedNetworks int64 // Currently used networks
	UsedServices int64 // Currently used services
}

// HasCapacity checks if the quota has capacity for the requested resources.
func (q *VRFQuota) HasCapacity(vrfs, networks, services int64) bool {
	if vrfs > 0 && q.UsedVRFs+vrfs > q.MaxVRFs {
		return false
	}
	if networks > 0 && q.UsedNetworks+networks > q.MaxNetworks {
		return false
	}
	if services > 0 && q.UsedServices+services > q.MaxServices {
		return false
	}
	return true
}

// Reserve reserves the specified resources from the quota.
// It checks every resource before changing any counter, so a refusal
// returns ErrQuotaExceeded and leaves the quota unchanged.
func (q *VRFQuota) Reserve(tenantID string, vrfs, networks, services int64) error {
	if vrfs > 0 && q.UsedVRFs+vrfs > q.MaxVRFs {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "VRFs",
			Requested: vrfs,
			Available: q.MaxVRFs - q.UsedVRFs,
		}
	}
	if networks > 0 && q.UsedNetworks+networks > q.MaxNetworks {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "networks",
			Requested: networks,
			Available: q.MaxNetworks - q.UsedNetworks,
		}
	}
	if services > 0 && q.UsedServices+services > q.MaxServices {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  "services",
			Requested: services,
			Available: q.MaxServices - q.UsedServices,
		}
	}

	q.UsedVRFs += vrfs
	q.UsedNetworks += networks
	q.UsedServices += services

	return nil
}

// Release releases the specified resources back to the quota. No counter
// goes below zero.
func (q *VRFQuota) Release(vrfs, networks, services int64) {
	q.UsedVRFs = max(0, q.UsedVRFs-vrfs)
	q.UsedNetworks = max(0, q.UsedNetworks-networks)
	q.UsedServices = max(0, q.UsedServices-services)
}

// SetLimits copies the limits of l into q and leaves q's usage counters
// alone: usage changes only through Reserve and Release.
func (q *VRFQuota) SetLimits(l VRFQuota) {
	q.MaxVRFs = l.MaxVRFs
	q.MaxNetworks = l.MaxNetworks
	q.MaxServices = l.MaxServices
}

// GetUtilization returns the utilization percentage for each resource type.
func (q *VRFQuota) GetUtilization() map[string]float64 {
	utilization := make(map[string]float64)

	utilization["vrfs"] = safePercentage(q.UsedVRFs, q.MaxVRFs)
	utilization["networks"] = safePercentage(q.UsedNetworks, q.MaxNetworks)
	utilization["services"] = safePercentage(q.UsedServices, q.MaxServices)

	return utilization
}

// AvailableVRFs returns the number of VRFs that can still be created.
func (q *VRFQuota) AvailableVRFs() int64 {
	return max(0, q.MaxVRFs-q.UsedVRFs)
}

// AvailableNetworks returns the number of networks that can still be created.
func (q *VRFQuota) AvailableNetworks() int64 {
	return max(0, q.MaxNetworks-q.UsedNetworks)
}

// AvailableServices returns the number of services that can still be created.
func (q *VRFQuota) AvailableServices() int64 {
	return max(0, q.MaxServices-q.UsedServices)
}
